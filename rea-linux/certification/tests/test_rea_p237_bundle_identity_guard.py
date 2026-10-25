"""No-network, source-owned synthetic preservation/negative tests (not REA MCP)."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from rea_p237_bundle_identity_guard import PreservationFailure, compare_exports

E1='ev_'+('a'*64)
E2='ev_'+('b'*64)
U='unk_'+('c'*64)
A='d'*64
B='e'*64


def bundle(unknowns=False):
    return {
        'artifacts': [], 'providers': [], 'environments': [],
        'scenarios': [], 'captures': [],
        'records': [{'evidence_id':E1,'normalized_result':{'x':[1,2]}},
                    {'evidence_id':E2,'normalized_result':{'x':3}}],
        'unknowns': ([{'unknown_id':U,'revision':1,'revision_digest':A,
                      'previous_revision_digest':None,'status':'open'},
                     {'unknown_id':U,'revision':2,'revision_digest':B,
                      'previous_revision_digest':A,'status':'investigating'}]
                     if unknowns else []),
    }

class BundleRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rea-p237-')
        self.addCleanup(self.temp.cleanup)
        self.before=Path(self.temp.name)/'before.json'
        self.after=Path(self.temp.name)/'after.json'

    def write(self,a=None,b=None):
        for p,obj in [(self.before,bundle(True) if a is None else a),
                      (self.after,bundle(True) if b is None else b)]:
            p.write_text(json.dumps(obj,sort_keys=True))
            p.chmod(0o600)

    def test_identical_full_evidence_and_two_revisions_pass(self):
        self.write()
        x=compare_exports(self.before,self.after)
        self.assertEqual((x['evidence'],x['unknown_revisions'],x['unknown_heads']),(2,2,1))

    def test_zero_unknowns_still_comparable(self):
        self.write(bundle(),bundle())
        self.assertEqual(compare_exports(self.before,self.after)['unknown_revisions'],0)

    def test_dropped_evidence_blocks(self):
        a=bundle(True);b=copy.deepcopy(a);b['records'].pop()
        self.write(a,b)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_same_id_but_changed_data_blocks(self):
        a=bundle(True);b=copy.deepcopy(a);b['records'][0]['normalized_result']['x']=[1,9]
        self.write(a,b)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_missing_unknown_revision_blocks(self):
        a=bundle(True);b=copy.deepcopy(a);b['unknowns'].pop(0)
        self.write(a,b)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_broken_previous_digest_blocks(self):
        a=bundle(True);b=copy.deepcopy(a);b['unknowns'][1]['previous_revision_digest']='f'*64
        self.write(a,b)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_duplicate_evidence_id_blocks(self):
        a=bundle(True);a['records'][1]['evidence_id']=E1
        self.write(a,a)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_duplicate_unknown_revision_blocks(self):
        a=bundle(True);a['unknowns'].append(copy.deepcopy(a['unknowns'][1]))
        self.write(a,a)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_changed_manifests_blocks(self):
        a=bundle(True);b=copy.deepcopy(a);b['providers'].append({'name':'unsafe'})
        self.write(a,b)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_same_file_blocks(self):
        self.write()
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.before)

    def test_hardlink_blocks(self):
        self.write();self.after.unlink();os.link(self.before,self.after)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_symlink_blocks(self):
        self.write();self.after.unlink();self.after.symlink_to(self.before)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_world_readable_blocks(self):
        self.write();self.after.chmod(0o644)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_noncanonical_evidence_order_blocks(self):
        a=bundle(True);a['records'].reverse()
        self.write(a,a)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_empty_invalid_unknown_head_blocks(self):
        a=bundle(True);a['unknowns'][0]['revision']=2
        self.write(a,a)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_wrong_document_kind_blocks(self):
        self.write({'hello':'world'},bundle(True))
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

    def test_invalid_json_blocks(self):
        self.write();self.after.write_text('{bad json');self.after.chmod(0o600)
        with self.assertRaises(PreservationFailure):compare_exports(self.before,self.after)

if __name__=='__main__':unittest.main()
