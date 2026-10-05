import unittest
from pink_vpn_056_recovery import outage_boundary

class OutageProofTests(unittest.TestCase):
    def exit_lines(self, pid=456, reason=2, status=9):
        return ['ApplicationExitInfo #0:',
                f' timestamp=2026-10-05 01:00:00.000 pid={pid} realUid=1 packageUid=1 definingUid=0 user=0',
                f' process=com.pinkiptv.extreme reason={reason} (PRIVATE_VALUE) subreason=0 (UNKNOWN) status={status}']
    def test_exact_outage_process_and_signal_are_required(self):
        self.assertEqual(outage_boundary('456:VPN_LOST','WIFI_DISABLING',456,self.exit_lines()),'VPN_LOST')
        self.assertEqual(outage_boundary('456:RECOVERY_EXHAUSTED','WIFI_DISABLED',456,self.exit_lines()),'RECOVERY_EXHAUSTED')
    def test_stale_pid_unknown_phase_or_missing_signal_cannot_pass(self):
        for record, phase, lines in [('123:VPN_LOST','WIFI_DISABLED',self.exit_lines()),
                                     ('456:VPN_LOST','COLD_START',self.exit_lines()),
                                     ('456:VPN_LOST','WIFI_DISABLED',self.exit_lines(pid=123)),
                                     ('456:VPN_LOST','WIFI_DISABLED',self.exit_lines(reason=5,status=6)),
                                     ('456:VPN_LOST','WIFI_DISABLED',[])]:
            self.assertIsNone(outage_boundary(record,phase,456,lines))
    def test_expiration_or_unclassified_crash_is_not_network_recovery(self):
        for record in ['456:GRANT_EXPIRED','456:NATIVE_CRASH','456:VPN_LOST PRIVATE_VALUE','https://private.example']:
            self.assertIsNone(outage_boundary(record,'WIFI_DISABLED',456,self.exit_lines()))
    def test_reason_and_phase_messages_are_never_forwarded(self):
        self.assertIsNone(outage_boundary('456:VPN_LOST','WIFI_DISABLED PRIVATE_VALUE',456,self.exit_lines()))

if __name__=='__main__': unittest.main()
