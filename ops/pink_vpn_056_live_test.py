import unittest
from pink_vpn_056_live import fixed_live_diagnostics
class LivePrivacyTests(unittest.TestCase):
    def test_exact_pid_phase_and_reason(self):
        self.assertEqual(fixed_live_diagnostics('456:authoritative-catalog','456:VPN_LOST',456),['LIVE_FLOW_PHASE=authoritative-catalog','LIVE_FAIL_CLOSED_CAUSE=VPN_LOST'])
    def test_stale_pid_unclassified_messages_are_rejected(self):
        for a,b in [('123:authoritative-catalog','123:VPN_LOST'),('456:authoritative-catalog secret','456:VPN_LOST secret'),('456:https://private.example','456:PRIVATE_VALUE')]:
            self.assertEqual(fixed_live_diagnostics(a,b,456),['LIVE_FLOW_PHASE=UNVERIFIED','LIVE_FAIL_CLOSED_CAUSE=UNVERIFIED'])
    def test_missing_or_truncated_records_cannot_certify(self):
        self.assertEqual(fixed_live_diagnostics('','',456),['LIVE_FLOW_PHASE=UNVERIFIED','LIVE_FAIL_CLOSED_CAUSE=UNVERIFIED'])
    def test_no_account_values_are_forwarded(self):
        output='\n'.join(fixed_live_diagnostics('456:password=private','456:token=private',456))
        self.assertNotIn('private',output);self.assertNotIn('password',output);self.assertNotIn('token',output)
if __name__=='__main__': unittest.main()
