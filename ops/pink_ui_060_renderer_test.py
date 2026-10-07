"""Privacy, frame bounds and loopback-only tests for the read-only sampler."""
import json
import struct
import unittest
from unittest.mock import patch
from pink_ui_060_renderer import CDP, MAX_FRAME, summarize, summarize_interval


class SocketStub:
    def __init__(self, data=b''):
        self.data, self.sent = data, []
    def settimeout(self, _):
        pass
    def recv(self, count):
        result, self.data = self.data[:count], self.data[count:]
        return result
    def sendall(self, data):
        self.sent.append(data)


def client(data=b''):
    cdp = CDP.__new__(CDP)
    cdp.sock, cdp.buffer, cdp.sequence = SocketStub(data), b'', 0
    return cdp


def frame(value):
    data = json.dumps(value).encode()
    return bytes([129, len(data)]) + data if len(data)<126 else bytes([129,126])+struct.pack('!H',len(data))+data


class RendererTests(unittest.TestCase):
    def test_never_outputs_names_remote_urls_or_page_data(self):
        profile = {'nodes':[
            {'id':1,'callFrame':{'url':'https://tauri.localhost/_astro/stream.Abc123.js?fixture-password','functionName':'fixture_user','lineNumber':0,'columnNumber':121}},
            {'id':2,'callFrame':{'url':'https://private-provider.example/fixture-user/fixture-password','functionName':'fixture_user'}},
            {'id':3,'callFrame':{'url':'','functionName':'(idle)'}},
            {'id':4,'callFrame':{'url':'','functionName':'(garbage collector)'}}], 'samples':[1,1,2,3,4]}
        summary = summarize(profile)
        self.assertEqual(summary['owned_hotspots'], [{'asset':'stream.Abc123.js','line':0,'column':121,'samples':2}])
        encoded=json.dumps(summary)
        for private in ('fixture','password','provider','https','functionName'):
            self.assertNotIn(private, encoded)
        self.assertEqual(summary['kind_samples'], {'OWNED_JS':2,'OTHER':1,'IDLE':1,'GC':1})

    def test_native_leaf_retains_only_static_owned_ancestor(self):
        profile={'nodes':[{'id':1,'children':[2],'callFrame':{'url':'http://tauri.localhost/_astro/stream.Abc.js','lineNumber':0,'columnNumber':52}},
            {'id':2,'callFrame':{'url':'','functionName':'fixture_private_value'}}], 'samples':[2,2]}
        result=summarize(profile)
        self.assertEqual(result['kind_samples'], {'OWNED_ANCESTOR':2})
        self.assertEqual(result['owned_hotspots'][0]['column'],52)
        self.assertNotIn('fixture',json.dumps(result))

    def test_rejects_remote_or_wrong_port_before_connect(self):
        with patch('pink_ui_060_renderer.socket.create_connection') as connect:
            for url in ('ws://private.example:9222/devtools/page/id','ws://127.0.0.1:9223/devtools/page/id','ws://127.0.0.1:9222/not-devtools','ws://127.0.0.1:9222/devtools/page/id?secret'):
                with self.assertRaises(AssertionError):
                    CDP(url,9222)
            connect.assert_not_called()

    def test_core_ipc_stack_emits_only_fixed_names_and_numeric_positions(self):
        profile={'nodes':[
            {'id':1,'children':[2],'callFrame':{'url':'http://tauri.localhost/_astro/core.Abc.js','lineNumber':0,'columnNumber':2407}},
            {'id':2,'children':[3],'callFrame':{'url':'','functionName':'action','lineNumber':88,'columnNumber':19}},
            {'id':3,'children':[4],'callFrame':{'url':'','functionName':'fixture_password','lineNumber':40,'columnNumber':7}},
            {'id':4,'callFrame':{'url':'','functionName':'postMessage','lineNumber':-1,'columnNumber':-1}}], 'samples':[4,4]}
        result=summarize(profile)
        self.assertEqual(result['ipc_stacks'], [{'frames':[
            {'kind':'POST_MESSAGE','line':-1,'column':-1},
            {'kind':'OTHER','line':40,'column':7},
            {'kind':'ACTION','line':88,'column':19}], 'samples':2}])
        self.assertNotIn('fixture',json.dumps(result))

    def test_tail_separates_initial_idle_from_later_ipc_wait(self):
        profile={'nodes':[
            {'id':1,'callFrame':{'url':'','functionName':'(idle)'}},
            {'id':2,'children':[3],'callFrame':{'url':'http://tauri.localhost/_astro/core.Abc.js','lineNumber':0,'columnNumber':2407}},
            {'id':3,'callFrame':{'url':'','functionName':'postMessage','lineNumber':-1,'columnNumber':-1}}], 'samples':[1,1,3,3]}
        result=summarize_interval(profile)
        self.assertEqual(result['kind_samples'], {'IDLE':2,'OWNED_ANCESTOR':2})
        self.assertEqual(result['tail_half']['kind_samples'], {'OWNED_ANCESTOR':2})
        self.assertEqual(result['tail_half']['ipc_stacks'][0]['frames'][0]['kind'],'POST_MESSAGE')

    def test_client_frames_are_masked_and_commands_do_not_change_ui(self):
        cdp=client(frame({'method':'Profiler.consoleProfileFinished'})+frame({'id':1,'result':{}}))
        self.assertEqual(cdp.call('Profiler.start'), {})
        message=cdp.sock.sent[0]
        self.assertEqual(message[0],129)
        self.assertTrue(message[1]&128)
        size=message[1]&127
        mask=message[2:6]
        payload=bytes(value^mask[i%4] for i,value in enumerate(message[6:6+size]))
        self.assertEqual(json.loads(payload), {'id':1,'method':'Profiler.start','params':{}})

    def test_fragmented_reply_and_ping_preserve_json(self):
        raw=json.dumps({'id':1,'result':{'profile':{}}}).encode()
        split=len(raw)//2
        data=bytes([1,split])+raw[:split]+bytes([137,1])+b'x'+bytes([128,len(raw)-split])+raw[split:]
        cdp=client(data)
        self.assertEqual(cdp.call('Profiler.stop'), {'profile':{}})
        self.assertEqual(cdp.sock.sent[-1][0],138)

    def test_oversize_reply_fails_before_reading_payload(self):
        cdp=client(bytes([129,127])+struct.pack('!Q',MAX_FRAME+1))
        with self.assertRaises(ValueError):
            cdp.call('Profiler.stop')


if __name__ == '__main__':
    unittest.main()
