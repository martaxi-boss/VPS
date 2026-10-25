#!/usr/bin/env python3
"""Offline exact-completeness comparator for two original REA Evidence bundles.

This operator-side check is NOT the original REA parser, not an MCP, and not
an owner authorization. It MUST be used only after each source and poststate
bundle has been independently exported and validated by original REA.

It blocks unequal Evidence IDs/bodies, incomplete Unknown revision chains,
changed manifests, or the accidental comparison of one file to itself.
It does not import, export, open, or close sessions; it never contacts VPS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 25_000_000
BUNDLE_KEYS = frozenset({
    'artifacts', 'providers', 'environments', 'scenarios',
    'captures', 'unknowns', 'records',
})
EVIDENCE_ID = re.compile(r'^ev_[0-9a-f]{64}$')
UNKNOWN_ID = re.compile(r'^unk_[0-9a-f]{64}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')


class PreservationFailure(ValueError):
    """Fail-closed input or Evidence/Unknown preservation violation."""


def _unique_json_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise PreservationFailure('duplicate JSON object key')
        data[key] = value
    return data


def _reject_nonfinite(value):
    raise PreservationFailure('nonfinite JSON numeric constant: ' + value)


def _load(path):
    p = Path(path)
    # Inspect and read the *same opened file descriptor*: no symlink-following
    # after lstat, and no unbounded reads if the file grows concurrently.
    try:
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(p, flags), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise PreservationFailure('bundle must be a regular non-symlink file')
            if info.st_size == 0 or info.st_size > MAX_BYTES:
                raise PreservationFailure('invalid or oversized bundle')
            if info.st_mode & 0o077:
                raise PreservationFailure('bundle must be private (mode 0600 or stricter)')
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != info.st_size or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns
                or after.st_ino != info.st_ino or after.st_dev != info.st_dev
                or after.st_mode != info.st_mode):
            raise PreservationFailure('bundle changed while being read')
        bundle = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_json_keys,
                            parse_constant=_reject_nonfinite)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreservationFailure('bundle could not be read and parsed') from exc
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_KEYS:
        raise PreservationFailure('not a complete original REA Evidence bundle')
    if any(not isinstance(bundle[key], list) for key in BUNDLE_KEYS):
        raise PreservationFailure('bundle lists invalid')
    return bundle, (info.st_dev, info.st_ino), hashlib.sha256(raw).hexdigest()

def _validate(bundle):
    seen_records = set()
    record_order = []
    for record in bundle['records']:
        if not isinstance(record, dict):
            raise PreservationFailure('non-object Evidence')
        eid = record.get('evidence_id')
        if not isinstance(eid, str) or not EVIDENCE_ID.fullmatch(eid):
            raise PreservationFailure('malformed Evidence ID')
        if eid in seen_records:
            raise PreservationFailure('duplicate Evidence ID')
        seen_records.add(eid)
        record_order.append(eid)
    if record_order != sorted(record_order):
        raise PreservationFailure('non-canonical Evidence ID ordering')
    revision_keys = []
    unknowns = {}
    for unknown in bundle['unknowns']:
        if not isinstance(unknown, dict):
            raise PreservationFailure('non-object Unknown revision')
        uid, rev = unknown.get('unknown_id'), unknown.get('revision')
        digest = unknown.get('revision_digest')
        previous = unknown.get('previous_revision_digest')
        if (not isinstance(uid, str) or not UNKNOWN_ID.fullmatch(uid)
                or type(rev) is not int or rev < 1
                or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                or (previous is not None and
                    (not isinstance(previous, str) or not DIGEST.fullmatch(previous)))):
            raise PreservationFailure('malformed Unknown revision')
        key = uid, rev
        if key in revision_keys:
            raise PreservationFailure('duplicate Unknown revision')
        revision_keys.append(key)
        unknowns.setdefault(uid, {})[rev] = unknown
    if revision_keys != sorted(revision_keys):
        raise PreservationFailure('non-canonical Unknown revision ordering')
    for uid, items in unknowns.items():
        if list(sorted(items)) != list(range(1, len(items) + 1)):
            raise PreservationFailure('missing Unknown revision history')
        if items[1]['previous_revision_digest'] is not None:
            raise PreservationFailure('first Unknown revision must have no predecessor')
        for revision in range(2, len(items) + 1):
            if items[revision]['previous_revision_digest'] != items[revision - 1]['revision_digest']:
                raise PreservationFailure('Unknown revision digest chain is broken')
    return {
        'evidence': len(seen_records),
        'unknown_revisions': len(revision_keys),
        'unknown_heads': len(unknowns),
    }


def _exact_json(left, right):
    """Preserve JSON scalar types (Python otherwise equates True == 1 == 1.0)."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (left.keys() == right.keys() and
                all(_exact_json(value, right[key]) for key, value in left.items()))
    if isinstance(left, list):
        return (len(left) == len(right) and
                all(_exact_json(a, b) for a, b in zip(left, right)))
    return left == right


def compare_exports(before_path, after_path):
    original, original_inode, original_raw_hash = _load(before_path)
    restored, restored_inode, restored_raw_hash = _load(after_path)
    if original_inode == restored_inode:
        raise PreservationFailure('source and poststate are the same file or hardlink')
    counts = _validate(original)
    after_counts = _validate(restored)
    if counts != after_counts:
        raise PreservationFailure('Evidence count or Unknown revision history changed')
    if not _exact_json(original, restored):
        raise PreservationFailure('Evidence, Unknown revisions or manifests changed')
    # Python canonical JSON here is a COMPARISON digest, not the REA RFC8785 file hash.
    semantic = json.dumps(original, ensure_ascii=True, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('ascii')
    return {
        'status': 'PASS_IDENTICAL_FULL_REA_BUNDLES',
        **counts,
        'semantic_sha256': hashlib.sha256(semantic).hexdigest(),
        'source_file_sha256': original_raw_hash,
        'poststate_file_sha256': restored_raw_hash,
        'note': 'This is not REA semantic authenticity or owner authorization',
        'p238_strict_json_types': True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--after', required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_exports(args.before, args.after)
    except (PreservationFailure, ValueError) as exc:
        print('REA_P237_BUNDLE_PRESERVATION=BLOCK ' + str(exc), file=sys.stderr)
        return 3
    print('REA_P237_BUNDLE_PRESERVATION=PASS ' + json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
