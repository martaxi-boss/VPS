"""P238 adversarial regressions for existing P237 operator comparator; no MCP."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from rea_p237_bundle_identity_guard import PreservationFailure, compare_exports

EVIDENCE = 'ev_' + 'a' * 64
UNKNOWN = 'unk_' + 'b' * 64
DIGEST1 = 'c' * 64
DIGEST2 = 'd' * 64


def bundle(value=1):
    return {
        'artifacts': [], 'providers': [], 'environments': [],
        'scenarios': [], 'captures': [],
        'unknowns': [
            {'unknown_id': UNKNOWN, 'revision': 1, 'revision_digest': DIGEST1, 'previous_revision_digest': None, 'status': 'open'},
            {'unknown_id': UNKNOWN, 'revision': 2, 'revision_digest': DIGEST2, 'previous_revision_digest': DIGEST1, 'status': 'investigating'},
        ],
        'records': [{'evidence_id': EVIDENCE, 'normalized_result': {'nested': {'flag': value}}}],
    }


class StrictFullBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rea-p238-')
        self.addCleanup(self.temp.cleanup)
        self.before = Path(self.temp.name) / 'before.json'
        self.after = Path(self.temp.name) / 'after.json'

    def write(self, a=None, b=None, raw_a=None, raw_b=None):
        for p, obj, raw in ((self.before, bundle() if a is None else a, raw_a),
                            (self.after, bundle() if b is None else b, raw_b)):
            p.write_text(json.dumps(obj, separators=(',', ':')) if raw is None else raw, encoding='utf-8')
            p.chmod(0o600)

    def test_identical_full_bundle_keeps_two_unknown_revisions(self):
        self.write()
        result = compare_exports(self.before, self.after)
        self.assertEqual((result['evidence'], result['unknown_revisions'], result['unknown_heads']), (1, 2, 1))

    def test_bool_to_int_evidence_mutation_blocked(self):
        self.write(bundle(True), bundle(1))
        with self.assertRaises(PreservationFailure): compare_exports(self.before, self.after)

    def test_int_to_float_evidence_mutation_blocked(self):
        self.write(bundle(1), bundle(1.0))
        with self.assertRaises(PreservationFailure): compare_exports(self.before, self.after)

    def test_nested_bool_to_int_unknown_revision_mutation_blocked(self):
        a = bundle(); b = copy.deepcopy(a)
        a['unknowns'][1]['custom'] = {'priority': True}
        b['unknowns'][1]['custom'] = {'priority': 1}
        self.write(a,b)
        with self.assertRaises(PreservationFailure): compare_exports(self.before,self.after)

    def test_duplicate_top_level_json_key_blocked(self):
        raw = json.dumps(bundle(), separators=(',', ':'))
        raw = raw.replace('"artifacts":[]', '"artifacts":[],"artifacts":[]')
        self.write(raw_a=raw, raw_b=raw)
        with self.assertRaises(PreservationFailure): compare_exports(self.before,self.after)

    def test_duplicate_nested_json_key_blocked(self):
        raw = json.dumps(bundle(), separators=(',', ':'))
        raw = raw.replace('"flag":1', '"flag":1,"flag":1')
        self.write(raw_a=raw, raw_b=raw)
        with self.assertRaises(PreservationFailure): compare_exports(self.before,self.after)

    def test_nonfinite_infinity_disallowed(self):
        raw = json.dumps(bundle(), separators=(',', ':')).replace('"flag":1', '"flag":Infinity')
        self.write(raw_a=raw, raw_b=raw)
        with self.assertRaises(PreservationFailure): compare_exports(self.before,self.after)

    def test_same_semantics_different_json_whitespace_passes(self):
        a = json.dumps(bundle(), separators=(',', ':'))
        b = json.dumps(bundle(), separators=(', ', ': '))
        self.write(raw_a=a, raw_b=b)
        self.assertEqual(compare_exports(self.before,self.after)['evidence'], 1)

    def test_dropped_unknown_revision_still_blocked(self):
        a=bundle();b=copy.deepcopy(a);b['unknowns'].pop(0)
        self.write(a,b)
        with self.assertRaises(PreservationFailure): compare_exports(self.before,self.after)


if __name__ == '__main__': unittest.main()
