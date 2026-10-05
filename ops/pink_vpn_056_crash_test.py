import unittest
from pink_vpn_056_crash import public_crash, public_exit

class CrashPrivacyTests(unittest.TestCase):
    def test_java_exception_and_source_position_omit_secret_message(self):
        lines = ['10-05 01:00:00.000 123 456 E AndroidRuntime: java.lang.IllegalStateException: PRIVATE_VALUE https://private.example/u/p',
                 '10-05 01:00:00.000 123 456 E AndroidRuntime: \tat com.pinkiptv.extreme.VideoActivity.onCreate(VideoActivity.kt:164)']
        self.assertEqual(public_crash(lines), ['EXCEPTION_CLASS=java.lang.IllegalStateException', 'STACK=com.pinkiptv.extreme.VideoActivity.onCreate(VideoActivity.kt:164)'])
    def test_url_or_provider_message_cannot_impersonate_a_stack(self):
        self.assertEqual(public_crash(['E AndroidRuntime: https://private.example java.lang.RuntimeException: PRIVATE_VALUE', 'E AndroidRuntime: at provider.secret.value(Secret.kt:42)', 'E OtherTag: java.lang.RuntimeException: PRIVATE_VALUE']), [])
    def test_nested_exception_retains_only_class(self):
        self.assertEqual(public_crash(['E AndroidRuntime: Caused by: android.view.InflateException: PRIVATE_VALUE']), ['EXCEPTION_CLASS=android.view.InflateException'])
    def test_native_structures_omit_addresses_paths_and_symbols(self):
        lines=['F libc: FORTIFY: pthread_mutex_lock called on a destroyed mutex (0xdeadbeef)',
               'F libc: Fatal signal 6 (SIGABRT), code -1 in tid 456 (PRIVATE_VALUE)',
               'F DEBUG: #00 pc 000abc /apex/runtime/lib64/bionic/libc.so (PRIVATE_VALUE+1) (BuildId: PRIVATE_VALUE)']
        self.assertEqual(public_crash(lines), ['NATIVE_DESTROYED_MUTEX','NATIVE_SIGNAL=6:SIGABRT','NATIVE_FRAME=00:libc.so'])
    def test_arbitrary_paths_and_unknown_libraries_are_dropped(self):
        self.assertEqual(public_crash(['F DEBUG: #00 pc abc /data/private/SECRET.so (PRIVATE_VALUE)', 'E AndroidRuntime: at java.lang.X(https://private.example:42)']), [])
    def test_exit_reason_omits_descriptions_and_private_fields(self):
        self.assertEqual(public_exit(['  reason=5 (CRASH NATIVE), description=PRIVATE_VALUE https://private.example', 'description=PRIVATE_VALUE', 'timestamp=PRIVATE_VALUE']), ['EXIT_REASON=CRASH_NATIVE'])
    def test_unknown_or_nonstructural_exit_data_is_dropped(self):
        self.assertEqual(public_exit(['reason=999 (PRIVATE_VALUE)', 'https://private.example/reason=5 (PRIVATE_VALUE)']), [])
    def test_platform_renderer_frames_omit_symbols_and_paths(self):
        self.assertEqual(public_crash(['F DEBUG: #04 pc abc /system/lib64/libhwui.so (PRIVATE_VALUE+1)']), ['NATIVE_FRAME=04:libhwui.so'])
    def test_other_process_crashes_are_not_attributed_to_pink(self):
        lines=['10-05 01:00:00.000 999 888 F libc: FORTIFY: pthread_mutex_lock called on a destroyed mutex (PRIVATE_VALUE)',
               '10-05 01:00:00.000 444 555 F DEBUG: pid: 999, tid: 888, name: OtherApp',
               '10-05 01:00:00.000 444 555 F DEBUG: #00 pc abc /system/lib64/libhwui.so (PRIVATE_VALUE)']
        self.assertEqual(public_crash(lines,123), [])
    def test_own_debugger_process_frames_are_retained_after_pid_header(self):
        lines=['10-05 01:00:00.000 444 555 F DEBUG: pid: 123, tid: 321, name: PRIVATE_VALUE',
               '10-05 01:00:00.000 444 555 F DEBUG: #00 pc abc /system/lib64/libapp_lib.so (PRIVATE_VALUE)']
        self.assertEqual(public_crash(lines,123), ['NATIVE_FRAME=00:libapp_lib.so'])
    def test_other_libc_message_after_own_debug_header_is_ignored(self):
        lines=['10-05 01:00:00.000 444 555 F DEBUG: pid: 123, tid: 321, name: PRIVATE_VALUE',
               '10-05 01:00:00.000 999 888 F libc: FORTIFY: pthread_mutex_lock called on a destroyed mutex (PRIVATE_VALUE)']
        self.assertEqual(public_crash(lines,123), [])
    def test_duplicate_records_are_bounded(self):
        self.assertEqual(public_crash(['E AndroidRuntime: java.lang.RuntimeException: PRIVATE_VALUE']*200), ['EXCEPTION_CLASS=java.lang.RuntimeException'])

if __name__=='__main__': unittest.main()
