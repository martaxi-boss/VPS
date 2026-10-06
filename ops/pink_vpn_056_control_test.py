import unittest
from pink_vpn_056_control import request_statuses,resolution_category

class ControlPrivacyTests(unittest.TestCase):
    def test_only_fixed_routes_and_codes_are_returned(self):
        logs=['PRIVATE_VALUE "POST /v1/session/resolve HTTP/1.1" 200 PRIVATE_VALUE',
              'PRIVATE_VALUE "POST /v1/vpn/enroll HTTP/1.1" 503 PRIVATE_VALUE',
              'PRIVATE_VALUE "GET /private?password=PRIVATE_VALUE HTTP/1.1" 200',
              'PRIVATE_VALUE "POST /v1/session/resolve?password=PRIVATE_VALUE HTTP/1.1" 401']
        self.assertEqual(request_statuses(logs),{'SESSION_RESOLVE_HTTP_200':1,'VPN_ENROLL_HTTP_503':1})
    def test_resolution_drops_token_and_origin(self):
        reply={'code':'SUCCESS','xtream_base_url':'https://private.example/','session_token':'PRIVATE_VALUE'}
        self.assertEqual(resolution_category(reply,'https://private.example'),'SUCCESS_ORIGIN_MATCH')
        self.assertEqual(resolution_category(reply,'https://other.example'),'ORIGIN_MISMATCH')
    def test_untrusted_codes_never_become_output(self):
        self.assertEqual(resolution_category({'code':'PRIVATE_VALUE'},'https://private.example'),'NON_SUCCESS')
        self.assertEqual(resolution_category([],''),'INVALID_RESPONSE')

if __name__=='__main__': unittest.main()
