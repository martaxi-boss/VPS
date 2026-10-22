#!/usr/bin/env python3
"""One-shot read-only MCP smoke against localhost, without a persistent service."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HOME = Path.home()
ROOT = HOME / ".local/share/rea-chatgpt-trial"
CLI = ROOT / "repository/rea/scripts/rea.mjs"
JADX = ROOT / "tools/jadx-headless-mcp-0.7.1-all.jar"
JDK = ROOT / "tools/jdk-21"
GHIDRA = ROOT / "tools/ghidra_12.1.4_PUBLIC"
PORT = 8765
URL = "http://127.0.0.1:8765/mcp"

def require(cond, why):
    if not cond:
        raise RuntimeError(why)

def parse_mcp(data):
    text = data.decode("utf-8",errors="replace").strip()
    if text.startswith("{"):
        return json.loads(text)
    for line in text.splitlines():
        if line.startswith("data:"):
            candidate = line[5:].strip()
            if candidate.startswith("{"):
                return json.loads(candidate)
    raise ValueError("Unexpected MCP response payload prefix: "+repr(text[:250]))

def rpc(obj, session=None, protocol=None):
    headers = {
        "Content-Type":"application/json",
        "Accept":"application/json, text/event-stream"
    }
    if session:
        headers["Mcp-Session-Id"]=session
    if protocol:
        headers["MCP-Protocol-Version"]=protocol
    request=urllib.request.Request(
        URL, data=json.dumps(obj).encode("utf-8"),headers=headers,method="POST")
    with urllib.request.urlopen(request,timeout=25) as resp:
        return resp.status,resp.headers,resp.read(5_000_000)

def main():
    require(os.geteuid() != 0, "Refuse MCP smoke as root")
    require(CLI.is_file() and JADX.is_file() and (JDK/"bin/java").is_file() and
            (GHIDRA/"support/analyzeHeadless").is_file(), "Incomplete trial toolchain")
    env=os.environ.copy()
    env.update({
        "REA_JADX_MCP_JAR":str(JADX),
        "REA_JADX_HEAP_MIB":"1024",
        "JAVA_HOME":str(JDK),
        "GHIDRA_INSTALL_DIR":str(GHIDRA),
        "GHIDRA_HEADLESS_MAXMEM":"1024M",
        "NODE_OPTIONS":"--max-old-space-size=1024",
    })
    for provider in ("jadx","ghidra"):
        cmd=["node",str(CLI),"doctor","--provider",provider,"--json"]
        p=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=50,check=False)
        require(p.returncode == 0, "REA doctor failed for "+provider)
        data=json.loads(p.stdout)
        print("REA_PROVIDER_DOCTOR="+json.dumps({
          "provider":provider,"returncode":p.returncode,"keys":sorted(data.keys()),
          "status":data.get("status"),"summary":str(data.get("summary",""))[:170],
        },sort_keys=True))

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect(("127.0.0.1",PORT))
        except OSError:
            pass
        else:
            raise RuntimeError("MCP port already in use; refuse to disturb existing service")

    log=open(os.devnull,"wb")
    server=subprocess.Popen(
        ["node",str(CLI),"mcp","--http","--host","127.0.0.1","--port",str(PORT)],
        env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    try:
        start=time.monotonic()
        while True:
            if server.poll() is not None:
                raise RuntimeError("REA MCP HTTP terminated before startup")
            try:
                with socket.create_connection(("127.0.0.1",PORT),timeout=1):
                    break
            except OSError:
                if time.monotonic()-start>25:
                    raise TimeoutError("REA MCP HTTP did not listen locally")
                time.sleep(0.25)
        print("REA_MCP_LOOPBACK_LISTEN=PASS")
        init={
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},
                      "clientInfo":{"name":"rea-vps-local-smoke","version":"0.1.0"}}
        }
        code,headers,content=rpc(init)
        response=parse_mcp(content)
        require("result" in response and "serverInfo" in response["result"],"MCP initialization failed")
        protocol=response["result"].get("protocolVersion")
        session=headers.get("Mcp-Session-Id")
        print("REA_MCP_INITIALIZE=PASS "+str(protocol))
        rpc({"jsonrpc":"2.0","method":"notifications/initialized"},session,protocol)
        code,headers,content=rpc(
            {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},session,protocol)
        response=parse_mcp(content)
        tools=response.get("result",{}).get("tools")
        require(isinstance(tools,list) and len(tools)>0, "MCP tools/list returned no tools")
        print("REA_MCP_TOOLS_LIST=PASS")
        print("REA_MCP_TOOLS_COUNT="+str(len(tools)))
        print("REA_MCP_TOOL_EXAMPLES="+json.dumps([tool.get("name") for tool in tools[:6]]))
    except urllib.error.HTTPError as e:
        raise RuntimeError("MCP transport returned HTTP "+str(e.code)+": "+
                           e.read(300).decode("utf-8",errors="replace"))
    finally:
        server.terminate()
        try:
            server.wait(timeout=12)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        log.close()
        print("REA_MCP_TEMP_SERVER_STOPPED=PASS")

if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print("REA_MCP_SMOKE=FAILED "+type(exc).__name__+": "+str(exc)[:450])
        sys.exit(1)
