#!/usr/bin/env python3
"""Remove stale paths only in FINAL-owned vendor/config copies, then validate.

Does not touch source engine, original provider packages, system dirs, user-local
original optional tools, services, credentials or legacy REA. Uses pinned GitHub SSH.
"""
import json,os,pwd,subprocess,sys,time
from pathlib import Path

PIN="160d821ac9a0310afcb8d1fc427862dd6508add5"
ROOT=Path("/home/ubuntu/rea-original-upstream-680")
BASE=Path("/home/ubuntu/rea-final-runtime")
PROOF=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029/strict-normalize-20261029.json")
STAGED=Path("/home/ubuntu/rea-original-upstream-680-evidence/isolation-20261029/strict-copy-20261029.json")
OLD="/opt/rea-reversa"
REPLACEMENTS={
  b"/opt/rea-reversa/providers/":b"/home/ubuntu/rea-final-runtime/vendors/providers/",
  b"/opt/rea-reversa/tools/":b"/home/ubuntu/rea-final-runtime/vendors/tools/",
  b"/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0":b"/home/ubuntu/rea-final-runtime/optional/rea-optional-ilspycmd-11.2.0",
  b"/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15":b"/home/ubuntu/rea-final-runtime/optional/rea-optional-pwndbg-2026.09.15",
  b"/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0":b"/home/ubuntu/rea-final-runtime/optional/rea-optional-pwntools-4.15.0",
}

# Escalation is only for copy-owned files created in /home/ubuntu/rea-final-runtime.
# All paths are constants, and symlinks are not traversed.
ROOT_FIX="\nimport json,os,stat\nfrom pathlib import Path\nBASE=Path(\"/home/ubuntu/rea-final-runtime\")\nOLD=b\"/opt/rea-reversa/\"\nLOCAL=b\"/home/ubuntu/.local/share/rea-optional-\"\nPREF={\nb\"/opt/rea-reversa/providers/\":b\"/home/ubuntu/rea-final-runtime/vendors/providers/\",\nb\"/opt/rea-reversa/tools/\":b\"/home/ubuntu/rea-final-runtime/vendors/tools/\",\nb\"/home/ubuntu/.local/share/rea-optional-ilspycmd-11.2.0\":b\"/home/ubuntu/rea-final-runtime/optional/rea-optional-ilspycmd-11.2.0\",\nb\"/home/ubuntu/.local/share/rea-optional-pwndbg-2026.09.15\":b\"/home/ubuntu/rea-final-runtime/optional/rea-optional-pwndbg-2026.09.15\",\nb\"/home/ubuntu/.local/share/rea-optional-pwntools-4.15.0\":b\"/home/ubuntu/rea-final-runtime/optional/rea-optional-pwntools-4.15.0\"}\nroots=[BASE/\"vendors\",BASE/\"optional\"]\nsuffixes={\".pth\",\".cfg\",\".ini\",\".sh\",\".py\",\".toml\",\".conf\",\".txt\",\".json\"}\ndef candidates():\n for root in roots:\n  assert root.is_dir() and not root.is_symlink()\n  for dr,dirs,files in os.walk(root,followlinks=False):\n   for name in files:\n    p=Path(dr)/name\n    if p.is_symlink() or not p.is_file():continue\n    if p.suffix.lower() not in suffixes and p.parent.name!=\"bin\" and name!=\"pyvenv.cfg\":continue\n    if p.stat().st_size>262144:continue\n    yield p\ndef replace_one(p):\n initial=p.read_bytes()\n if b\"\\0\" in initial[:1500] or initial[:4]==b\"\\x7fELF\":return False\n updated=initial\n for before,after in PREF.items():\n  if before in updated:updated=updated.replace(before,after)\n if updated==initial:return False\n st=p.stat()\n tmp=p.with_name(p.name+\".rea-final-path-update.tmp\")\n if tmp.exists() or tmp.is_symlink():raise RuntimeError(\"TEMP_ALREADY_EXISTS:\"+p.name)\n with tmp.open(\"xb\") as f:f.write(updated)\n os.chown(tmp,st.st_uid,st.st_gid)\n os.chmod(tmp,stat.S_IMODE(st.st_mode))\n os.replace(tmp,p)\n return True\nchanged=[]\nfor p in candidates():\n if replace_one(p):changed.append(str(p.relative_to(BASE))[:160])\nold=[];local=[];scanned=0\nfor p in candidates():\n scanned+=1\n data=p.read_bytes()\n if OLD in data:\n  if len(old)<20:old.append(str(p.relative_to(BASE))[:160])\n if LOCAL in data:\n  if len(local)<20:local.append(str(p.relative_to(BASE))[:160])\nprint(json.dumps({\"changed\":changed[:120],\"count_changed\":len(changed),\"scan_count\":scanned,\n \"old_path_refs_left\":len(old),\"source_local_refs_left\":len(local),\n \"old_examples\":old,\"local_examples\":local},sort_keys=True))\n"

def check(ok,what):
 if not ok:raise RuntimeError(what)
def cmd(args,timeout=45):
 p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
  stderr=subprocess.PIPE,text=True,errors="replace",timeout=timeout,check=False)
 return p.returncode,p.stdout.strip(),p.stderr[:200]
def run():
 check(pwd.getpwuid(os.geteuid()).pw_name=="ubuntu","WRONG_USER")
 check(ROOT.is_dir() and not ROOT.is_symlink(),"ENGINE_MISSING")
 check(cmd(["git","-C",str(ROOT),"rev-parse","HEAD"],timeout=12)[1]==PIN,"SOURCE_COMMIT_CHANGED")
 check((ROOT/"node_modules").resolve(strict=False)==BASE/"node_modules","NPM_NOT_ISOLATED")
 check(not BASE.is_symlink() and BASE.is_dir(),"FINAL_RUNTIME_MISSING")
 check(not PROOF.exists(),"ALREADY_NORMALIZED")
 staged=json.loads(STAGED.read_text(encoding="utf8"))
 check(staged.get("status")=="PASS_COPIED_INDEPENDENT_OPTIONAL_PROVIDER_FILES",
       "INDEPENDENT_COPY_NOT_VERIFIED")
 for path in (
  BASE/"vendors/providers/chromium-playwright-1.58.2",
  BASE/"optional/rea-optional-ilspycmd-11.2.0",
  BASE/"optional/rea-optional-pwndbg-2026.09.15",
  BASE/"optional/rea-optional-pwntools-4.15.0"):
  check(path.is_dir() and not path.is_symlink(),"MISSING_INDEPENDENT_OPTIONAL_COPY:"+path.name)
 check(cmd(["sudo","-n","true"],timeout=7)[0]==0,"NO_PRIVILEGE")
 code=ROOT_FIX
 rc,stdout,stderr=cmd(["sudo","-n","python3","-c",code],timeout=240)
 check(rc==0,"OWNED_CONFIG_RELOCATION_FAILED:"+stderr[:90])
 audit=json.loads(stdout)
 check(audit["old_path_refs_left"]==0 and audit["source_local_refs_left"]==0,
       "UNRELOCATED_TEXT_REFERENCES")
 # Smoke tests are target-free; no browser window, no debugged process, no new service.
 paths={
  "mitmdump":BASE/"vendors/providers/mitmproxy-12.2.3/bin/mitmdump",
  "binwalk":BASE/"vendors/providers/binwalk-3.1.0/bin/binwalk",
  "chromium":BASE/"vendors/providers/chromium-playwright-1.58.2/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell",
  "ilspy":BASE/"optional/rea-optional-ilspycmd-11.2.0/ilspycmd",
 }
 probes={}
 for name,p in paths.items():
  opt=["--version"]
  rc,out,err=cmd([str(p),*opt],timeout=35)
  probes[name]={"exit":rc,"first_line":out.splitlines()[0][:125] if out else (err.splitlines()[0][:125] if err else "")}
  # Binwalk -v may legitimately have a nonzero code for invalid usage; retry --version.
  if name=="binwalk" and rc!=0:
   rc,out,err=cmd([str(p),"--version"],timeout=35)
   probes[name]={"exit":rc,"first_line":out.splitlines()[0][:125] if out else ""}
  check(probes[name]["exit"]==0,"OPTIONAL_PROVIDER_VERSION_REGRESSION:"+name)
 check("Mitmproxy" in probes["mitmdump"]["first_line"],"WRONG_MITMDUMP")
 check("binwalk" in probes["binwalk"]["first_line"].lower(),"WRONG_BINWALK")
 check("Chrome" in probes["chromium"]["first_line"],"WRONG_CHROMIUM")
 result={"status":"PASS_NO_OLD_REFERENCES_IN_FINAL_CONFIG",
         "source_commit":PIN,"changed":audit["changed"],"scan":audit,
         "probes":probes,"original_and_legacy_files_untouched":True,
         "timestamp_unix":int(time.time())}
 PROOF.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
 return result
if __name__=="__main__":
 try:
  print("REA_STRICT_NORMALIZE_RESULT="+json.dumps(run(),sort_keys=True,separators=(",",":")),flush=True)
 except (RuntimeError,ValueError,OSError,subprocess.TimeoutExpired) as e:
  print("REA_STRICT_NORMALIZE_BLOCKED="+type(e).__name__+":"+str(e)[:170],flush=True)
  sys.exit(2)
