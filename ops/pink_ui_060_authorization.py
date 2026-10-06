"""Emit a bounded authorization draft only after canonical schema validation."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


def build(source, prepared_revision, prepared_run, attempt):
    return {
        "schema_version": "1.0",
        "transition_id": f"PINK-IPTV-ACTUAL-UI-PROOF-060-EXECUTE-R{attempt}",
        "task_id": "PINK-IPTV-ACTUAL-UI-PROOF-060",
        "repository": "martaxi-boss/VPS",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "action": "staging_operational_proof",
        "effect_class": "E3_DESTRUCTIVE_EXTERNAL_PRIVILEGED",
        "authority": {
            "source": "STANDING_OWNER_GRANT",
            "binding_mode": "EXACT_REVISION_BOUND",
            "summary": "Covered task060 staging Recovery under owner-standing-autonomy-v1. "
                "Exact source CI and original/relayed APK provenance, checksums and payload independently verified. "
                "One Android13 actual UI login/catalog/native AV/cold/roaming proof using fixture9040240 and disposable own peer only. "
                "Preserve captured VPN data plane, fixed TLS control, identity, strict UI/player gates and fixed diagnostic enums. "
                "Mandatory own-peer cleanup and protected before/after audits. "
                "No equivalent failed retry, persistent host change, credential output, routing/architecture bypass or physical-device claim.",
        },
        "target": {
            "kind": "bounded_android_operational_proof",
            "identifier": f"OVH:vps-32bea5b6;PINK:{source};artifact-run:{prepared_run}",
            "revision": prepared_revision,
            "base_revision": "a8af395df2c2b83b627f5a71337b67d209daf5f3",
            "environment": "staging-disposable-emulator",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-root", required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--prepared-revision", required=True)
    parser.add_argument("--prepared-run", required=True, type=int)
    parser.add_argument("--attempt", required=True, type=int)
    args = parser.parse_args()
    sys.path.insert(0, str(args.canonical_root.resolve()))
    from control.validate_records import validate_transition_authorization
    record = build(args.source, args.prepared_revision, args.prepared_run, args.attempt)
    validate_transition_authorization(record)
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
