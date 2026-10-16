"""Exact-source binary and authorization controls for PINK 2026-10-16 APK signing."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.request
import zipfile

REPO = "martaxi-boss/pink-iptv"
SOURCE_MAIN = "d48126cb8b95da3ea76646fbb8bf3de033216167"
UPSTREAM = "1efcc1b4ab3468db04aedd1c466228c52ef001b7"
BUILDER = "523f9d4cfe09ccc196c4dd4be09b8b29bf5fdee7"
RUN = 38911733123
ARTIFACT = 12050624216
ARCHIVE_SHA = "839283368e47a21a58679ef469b352b0f00098e480179710cfb63a5e1eb46caf"
UNSIGNED_SHA = "517702ff380edfc6c4b51177ecc04f6bb4379f7abb5ec5c3c299e6b7a58c603a"
UNSIGNED_BYTES = 47331714
TARGET = "com.pinkiptv.extreme"
AUTH = Path(".project-leader/transitions/PINK-IPTV-FINAL-SIGNING-20261016.authorization.json")
ROOT = Path(os.environ.get("RUNNER_TEMP", "/dev/null"))


def digest(path):
    d = hashlib.sha256()
    with open(path,"rb") as fd:
        for chunk in iter(lambda:fd.read(1024*1024),b""):d.update(chunk)
    return d.hexdigest()


def api(path):
    token = os.environ["GH_TOKEN"]
    if not token:
        raise RuntimeError("No GitHub read-only access token")
    headers={"Authorization":"Bearer "+token,
             "Accept":"application/vnd.github+json",
             "X-GitHub-Api-Version":"2022-11-28"}
    req=urllib.request.Request("https://api.github.com/repos/"+REPO+"/"+path,headers=headers)
    with urllib.request.urlopen(req,timeout=30) as response:
        return json.load(response)


def verify_manifest():
    assert os.environ["GITHUB_REPOSITORY"] == "martaxi-boss/VPS"
    assert os.environ["GITHUB_REF"] == "refs/heads/release/pink-signing-readiness-20261016"
    assert subprocess.check_output(["git","merge-base","--is-ancestor",
          "c516f3df8af5c82829bf6b75f2adc62cecd7b480","HEAD"]) == b""
    allowed = {
        ".github/workflows/pink-android-signing-readiness-20261016.yml",
        ".github/workflows/pink-android-signing-20261016.yml",
        "ops/pink_release_signer_20261016.py",
        "ops/pink_release_artifact_20261016.py",
        str(AUTH)
    }
    observed = set(subprocess.check_output(["git","diff","--name-only",
        "c516f3df8af5c82829bf6b75f2adc62cecd7b480","HEAD"],text=True).splitlines())
    assert observed==allowed, "Unexpected files in signer task branch"
    a=json.loads(AUTH.read_text())
    assert a["repository"]=="martaxi-boss/VPS"
    assert a["authority"]["source"]=="CURRENT_OWNER_INSTRUCTION"
    assert a["authority"]["binding_mode"]=="EXACT_REVISION_BOUND"
    assert a["action"]=="create_permanent_signing_identity_and_sign_exact_approved_pink_apk"
    t=a["target"]
    assert (t["pink_main_sha"],t["pink_builder_sha"],t["artifact_run_id"]) == (SOURCE_MAIN,BUILDER,RUN)
    assert (t["artifact_id"],t["artifact_zip_sha256"]) == (ARTIFACT,ARCHIVE_SHA)
    assert t["apk_unsigned_sha256"]==UNSIGNED_SHA
    assert t["preserve_original_android_and_vpn"] is True
    assert t["keep_signer_root_only"] is True
    info=api("actions/artifacts/"+str(ARTIFACT))
    assert info["id"]==ARTIFACT and not info["expired"]
    assert info["digest"]=="sha256:"+ARCHIVE_SHA
    assert info["name"]=="PINK-IPTV-RELEASE-UNSIGNED-INPUT-20261016"
    assert info["workflow_run"]["id"]==RUN
    builder=api("actions/runs/"+str(RUN))
    assert builder["head_sha"]==BUILDER and builder["conclusion"]=="success"
    assert api("git/ref/heads/main")["object"]["sha"]==SOURCE_MAIN
    print("PINK_RELEASE_MANIFEST_ARTIFACT_AND_MAIN_VERIFIED=PASS")


def verify_unsigned():
    packed=ROOT/"pink-signing-input.zip"
    assert packed.stat().st_size < 100000000
    assert digest(packed)==ARCHIVE_SHA
    folder=ROOT/"pink-release-input"
    folder.mkdir(parents=True,exist_ok=True)
    names={"PINK-IPTV-RELEASE-UNSIGNED.apk","SHA256SUMS","apksigner.jar",
           "location.txt","package-check.txt","provenance.json"}
    with zipfile.ZipFile(packed) as f:
        info=f.infolist()
        assert len(info)==len(names)
        assert set(x.filename for x in info)==names
        for x in info:
            assert x.filename in names and x.file_size<100000000
            assert not x.is_dir() and ((x.external_attr>>16)&0o170000)!=stat.S_IFLNK
        f.extractall(folder)
    meta=json.loads((folder/"provenance.json").read_text())
    assert meta["approved_main"]==SOURCE_MAIN
    assert meta["upstream"]==UPSTREAM
    assert meta["builder_workflow_sha"]==BUILDER
    assert meta["package"]==TARGET
    assert meta["stage"]=="unsigned-not-installable"
    assert meta["release_signed"] is False
    apk=folder/"PINK-IPTV-RELEASE-UNSIGNED.apk"
    assert apk.stat().st_size==UNSIGNED_BYTES and digest(apk)==UNSIGNED_SHA
    with zipfile.ZipFile(apk) as pkg:
        entries=pkg.namelist()
        assert any(x.endswith("/libwg-go.so") for x in entries)
        assert not any(x.endswith("/libwg.so") or x.endswith("/libwg-quick.so") for x in entries)
    print("PINK_EXACT_UNSIGNED_APK_AND_WIREGUARD=PASS")


def verify_remote():
    result=ROOT/"pink-signer-remote-report.txt"
    payload=[x.split("=",1)[1] for x in result.read_text().splitlines()
             if x.startswith("PINK_RELEASE_SIGNING=")]
    assert len(payload)==1
    info=json.loads(payload[0])
    assert info["status"]=="SIGNED_AND_VERIFIED"
    assert info["application_id"]==TARGET
    assert info["unsigned_sha256"]==UNSIGNED_SHA
    assert re.fullmatch(r"[0-9a-f]{64}", info["signed_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", info["certificate_sha256"])
    assert info["permanent_signer_preserved_on_vps"] is True
    assert info["protected_local_backup_preserved"] is True
    assert info["vpn_leases_modified"] is False
    assert info["secrets_disclosed"] is False
    out=ROOT/"pink-release-output"
    out.mkdir(parents=True,exist_ok=True)
    (out/"signing-report.json").write_text(json.dumps(info,indent=2,sort_keys=True)+"\n")
    print("PINK_ROOT_SIGNER_PERMANENT_NO_SECRET_EXFILTRATION=PASS")


def verify_signed():
    out=ROOT/"pink-release-output"
    apk=out/"PINK-IPTV-FINAL.apk"
    remote=json.loads((out/"signing-report.json").read_text())
    assert 10000000<apk.stat().st_size<100000000
    assert apk.stat().st_size==remote["signed_bytes"]
    signed_hash=digest(apk)
    assert signed_hash==remote["signed_sha256"]
    checked=(out/"apksigner-check.txt").read_text()
    fingerprints=re.findall(r"Signer #1 certificate SHA-256 digest:\s*([a-fA-F0-9]{64})",checked)
    assert len(fingerprints)==1 and fingerprints[0].lower()==remote["certificate_sha256"]
    assert "Verified using v2 scheme (APK Signature Scheme v2): true" in checked
    badging=(out/"package-check.txt").read_text()
    assert "package: name='com.pinkiptv.extreme'" in badging
    assert "application-label:'PINK IPTV'" in badging
    assert "application-debuggable" not in badging
    with zipfile.ZipFile(apk) as z:
        names=z.namelist()
        assert any(x.endswith("/libwg-go.so") for x in names)
        assert not any(x.endswith("/libwg.so") or x.endswith("/libwg-quick.so") for x in names)
    result={
        "kind":"PINK_IPTV_FINAL_ANDROID_RELEASE_SIGNED",
        "package":TARGET,
        "approved_main_sha":SOURCE_MAIN,
        "accepted_qa5_sha256":"787631d6ac171857157ff93138abdf99652b6cbce7b004bbde47acf9a5799871",
        "builder_sha":BUILDER,
        "unsigned_apk_sha256":UNSIGNED_SHA,
        "signed_sha256":signed_hash,
        "signed_size_bytes":apk.stat().st_size,
        "signing_certificate_sha256":fingerprints[0].lower(),
        "root_only_vps_keystore":True,
        "local_protected_backup":True,
        "release_signed":True,
        "debuggable":False,
        "original_debug_signed_application_replaceable":False,
        "vpn_and_customer_data_unchanged":True,
    }
    (out/"PINK-IPTV-FINAL-PROVENANCE.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("PINK_FINAL_SIGNED_APK_SHA256="+signed_hash)
    print("PINK_FINAL_SIGNER_FINGERPRINT="+fingerprints[0].lower())
    print("PINK_SIGNED_RELEASE_ACCEPTANCE=PASS")


if __name__=="__main__":
    commands={"manifest":verify_manifest,"unsigned":verify_unsigned,"remote":verify_remote,"signed":verify_signed}
    if len(sys.argv)!=2 or sys.argv[1] not in commands:
        raise SystemExit("Use manifest, unsigned, remote, or signed")
    commands[sys.argv[1]]()
