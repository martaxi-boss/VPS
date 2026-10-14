"""Local-only MCP ingress contract, identity boundary and asynchronous transfer tests."""
from __future__ import annotations

import http.client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from ops import chatgpt_media_mcp as mcp
from ops import chatgpt_attachment_ingress as ingress


class ChatGPTMediaMCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.inbox = self.base / 'inbox'
        self.inbox.mkdir(mode=0o700)
        self.keyfile = self.base / 'auth.key'
        self.keyfile.write_bytes(b'SERVER_GENERATED_OWNER_SECRET_NOT_FROM_MODEL_000000')
        self.keyfile.chmod(0o600)
        self.descriptor = Path(mcp.__file__).with_name('chatgpt_coordinator_file_tool.json')
        self.tool = mcp.MediaTool(inbox=self.inbox,key_file=self.keyfile,descriptor=self.descriptor)
        self.server = ThreadingHTTPServer(('127.0.0.1',0),mcp.Handler)
        self.server.media_tool = self.tool
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.media = [{
            'file_id':'file_00000000originalPhoto', 'file_name':'original.jpg',
            'mime_type':'image/jpeg',
            'download_url':'https://files.oaiusercontent.com/signed/photo?SECRET=PRIVATE'
        }]

    def call(self, obj, *, secret=True, headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        body=json.dumps(obj).encode()
        h={'Content-Type':'application/json','Content-Length':str(len(body))}
        if secret:
            h['Authorization']='Bearer SERVER_GENERATED_OWNER_SECRET_NOT_FROM_MODEL_000000'
        h.update(headers or {})
        connection.request('POST','/mcp',body,headers=h)
        response=connection.getresponse()
        payload=response.read()
        connection.close()
        return response.status, json.loads(payload) if payload else None

    def request(self, method, args=None, ident=17):
        o={'jsonrpc':'2.0','id':ident,'method':method}
        if args is not None:
            o['params']=args
        return o

    def test_only_server_owner_secret_can_call_private_tool(self):
        status,response=self.call(self.request('tools/list'),secret=False)
        self.assertEqual(status,401)
        self.assertEqual(response['error'],'UNAUTHORIZED')
        status,_=self.call(self.request('tools/list'),headers={'Authorization':'Bearer wrong'})
        self.assertEqual(status,401)
        status,response=self.call(self.request('tools/list'))
        self.assertEqual(status,200)
        self.assertEqual(response['result']['tools'][0]['_meta']['openai/fileParams'],['files'])

    def test_mcp_initialize_and_only_two_tools_no_coordinator_exec(self):
        status,response=self.call(self.request('initialize',{'protocolVersion':'2025-06-18'}))
        self.assertEqual(status,200)
        self.assertEqual(response['result']['protocolVersion'],'2025-06-18')
        status,response=self.call(self.request('tools/list'))
        self.assertEqual([t['name'] for t in response['result']['tools']],
                         ['stage_selected_owner_files','status_selected_owner_files'])
        status,response=self.call(self.request('tools/call',{'name':'start_workers','arguments':{}}))
        self.assertEqual(status,200)
        self.assertEqual(response['error']['message'],'TOOL_NOT_ALLOWED')

    def test_selected_files_are_staged_async_but_never_execute_order(self):
        good=ingress.Receipt('0'*32,1,(ingress.FileReceipt('file_00000000originalPhoto',
                                    'original.jpg','1'*64,123),))
        with mock.patch.object(ingress,'stage',return_value=good) as stage:
            status,output=self.call(self.request('tools/call',{'name':'stage_selected_owner_files',
                                            'arguments':{'files':self.media}}))
            self.assertEqual(status,200)
            transfer=json.loads(output['result']['content'][0]['text'])
            self.assertEqual(transfer['status'],'TRANSFERRING')
            self.assertRegex(transfer['job_id'],r'^[0-9a-f]{32}$')
            for _ in range(70):
                status,poll=self.call(self.request('tools/call',{
                    'name':'status_selected_owner_files',
                    'arguments':{'job_id':transfer['job_id']}}))
                result=json.loads(poll['result']['content'][0]['text'])
                if result['status']!='TRANSFERRING':break
                time.sleep(.01)
        self.assertEqual(result['status'],'READY')
        self.assertEqual(result['bundle_id'],'0'*32)
        self.assertEqual(result['originals'][0]['sha256'],'1'*64)
        self.assertEqual(stage.call_args.kwargs['verified_owner'],'martaxi-boss')
        self.assertEqual(stage.call_args.args[0],self.media)
        jobs=' '.join(x.read_text() for x in (self.inbox/'.mcp-jobs').glob('*.json'))
        self.assertNotIn('SECRET=PRIVATE',jobs)
        self.assertNotIn('download_url',jobs)
        self.assertEqual((self.inbox/'.mcp-jobs'/ (transfer['job_id']+'.json')).stat().st_mode & 0o077,0)

    def test_invalid_selection_no_network_and_no_pending_job(self):
        with mock.patch.object(ingress,'stage') as stage:
            for bad in ([],[dict(self.media[0],download_url='http://127.0.0.1/internal')],
                        [dict(self.media[0],file_name='../wrong.jpg')],
                        self.media*2):
                _,out=self.call(self.request('tools/call',{'name':'stage_selected_owner_files',
                                                      'arguments':{'files':bad}}))
                self.assertIn('error',out)
        stage.assert_not_called()
        self.assertEqual(list((self.inbox/'.mcp-jobs').iterdir()),[])

    def test_owner_secret_file_fail_closed_on_open_permissions(self):
        self.keyfile.chmod(0o644)
        with self.assertRaisesRegex(mcp.MCPRefused,'OWNER_KEY_NOT_PROVISIONED'):
            mcp.MediaTool(inbox=self.inbox,key_file=self.keyfile,descriptor=self.descriptor)

    def test_backend_error_returns_static_status_and_never_url(self):
        def raise_bad(*a,**k):
            raise RuntimeError('signed URL secret=PRIVATE must not escape')
        with mock.patch.object(ingress,'stage',side_effect=raise_bad):
            _,out=self.call(self.request('tools/call',{'name':'stage_selected_owner_files',
                                                       'arguments':{'files':self.media}}))
            job=json.loads(out['result']['content'][0]['text'])['job_id']
            for _ in range(70):
                _,out=self.call(self.request('tools/call',{'name':'status_selected_owner_files',
                                                          'arguments':{'job_id':job}}))
                res=json.loads(out['result']['content'][0]['text'])
                if res['status']!='TRANSFERRING':break
                time.sleep(.01)
        self.assertEqual(res['status'],'FAILED')
        self.assertNotIn('PRIVATE',str(res))
        self.assertNotIn('PRIVATE',(self.inbox/'.mcp-jobs'/(job+'.json')).read_text())

    def test_private_inbox_capacity_enforced(self):
        for x in ('0'*32,'1'*32):
            (self.inbox / x).mkdir(mode=0o700)
        status,out=self.call(self.request('tools/call',{
            'name':'stage_selected_owner_files','arguments':{'files':self.media}}))
        self.assertEqual(status,200)
        self.assertEqual(out['error']['message'],'PRIVATE_INBOX_CAPACITY_REACHED')

    def test_1gib_backend_streaming_contract_and_restricted_bind(self):
        self.assertEqual(ingress.MAX_TOTAL_BYTES,1024**3)
        self.assertEqual(ingress.TRANSFER_CHUNK_BYTES,1024**2)
        self.assertEqual(self.server.server_address[0],'127.0.0.1')
        with self.assertRaisesRegex(mcp.MCPRefused,'INVALID_LISTEN_PORT'):
            mcp.make_server(self.tool,port=0)


if __name__ == '__main__':
    unittest.main()