import base64
import unittest
from unittest.mock import patch
from pink_vpn_052_gateway import validate
import pink_vpn_052_install as installer


class PeerBoundary(unittest.TestCase):
    def payload(self):
        return {'operation':'upsert','public_key':base64.b64encode(bytes([3])*32).decode(),
                'address':'10.66.0.3','expires_at':1200}

    def test_backend_accepts_only_public_key_and_assigned_subnet(self):
        self.assertEqual(validate(self.payload(),123,123,1000),'10.66.0.3')
        for address in ['127.0.0.1','10.66.0.1','10.66.0.2','10.66.0.255','::1','8.8.8.8']:
            with self.assertRaises(ValueError):
                validate(self.payload() | {'address':address},123,123,1000)

    def test_only_root_can_use_reserved_proof_peer(self):
        self.assertEqual(validate(self.payload() | {'address':'10.66.0.2'},0,123,1000),'10.66.0.2')

    def test_peer_key_deadline_and_caller_fail_closed(self):
        for changes in [{'private_key':'forbidden'},{'operation':'shell'},{'expires_at':1306},
                        {'expires_at':999},{'public_key':base64.b64encode(bytes(32)).decode()}]:
            with self.assertRaises(ValueError):
                validate(self.payload() | changes,123,123,1000)
        with self.assertRaises(ValueError):
            validate(self.payload(),999,123,1000)

    def test_inverse_never_recurses_into_its_own_unit_or_flushes_host_rules(self):
        with patch.object(installer,'run',return_value='') as command:
            installer.network_down()
        calls = [args for args,kwargs in command.call_args_list]
        self.assertFalse(any(c[0] == 'systemctl' for c in calls))
        self.assertFalse(any('-F' in c or '--flush' in c for c in calls))
        self.assertEqual(calls[0],('ip','link','delete','pinkvpn'))
        self.assertTrue(all(c[0] != 'iptables' or
            any(x.startswith('PINK052_') for x in c) for c in calls))


if __name__ == '__main__':
    unittest.main()
