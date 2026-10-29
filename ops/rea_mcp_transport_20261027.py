#!/usr/bin/env python3
"""One REA 6.8 MCP engine; GitHub -> pinned SSH -> localhost MCP.

This file is TRANSPORT, not an access-policy engine. No per-tool grants,
owner signatures, classification lists or extra confirmation prompts.
The GitHub repository is public: publish only encrypted call payloads.
Authentication is GitHub actor + SSH; encryption protects private data.
"""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request

MCP = "http://127.0.0.1:8765/mcp"
ALG = "RSA-OAEP-SHA256+A256GCM"
ROOT = Path.home() / ".local/share/rea-github-transport"
MAX_BODY = 750000
MAX_OUTPUT = 5000000
MAX_CALLS = 32

# Local 6.8.0 compiled fixes. A rebuild may overwrite dist/ while leaving the
# original upstream Git tree intact. This verifies only the existing runtime;
# it never writes modules, restarts services or bypasses provider permissions.
OVERLAY_ROOT = Path("/opt/rea-reversa/rea/dist/process")
OVERLAY_SHA256 = {
    "ProcessOwnershipObservation.js": "05426e8e3f3c1b42a9ccaafee64ef562e5e587e3e15f8f68387d29b8b7237a06",
    "ProcessOwnership.js": "896032442deb6ee3aad314d5778e7310ff5598127a03d667387724085984cec6",
}

def verify_compiled_overlays(root=OVERLAY_ROOT, expected=OVERLAY_SHA256):
    """Fail closed before MCP calls if either native Linux runtime fix changed.

    Hash the opened regular inode with O_NOFOLLOW. This never follows a
    replacement symlink, modifies a runtime file or auto-replays an operation.
    """
    for name, wanted in expected.items():
        path = root / name
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError("REA_OVERLAY_INTEGRITY=INVALID_TYPE")
                digest = hashlib.sha256()
                for block in iter(lambda: os.read(fd, 65536), b""):
                    digest.update(block)
            finally:
                os.close(fd)
        except (OSError, ValueError) as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError("REA_OVERLAY_INTEGRITY=UNAVAILABLE") from None
        if not secrets.compare_digest(digest.hexdigest(), wanted):
            raise ValueError("REA_OVERLAY_INTEGRITY=DRIFT")
    print("REA_OVERLAY_INTEGRITY=PASS;modules=" + str(len(expected)),
          file=sys.stderr)

def test_overlay_integrity():
    """Positive, tampered, missing, non-regular and symlink rejection cases."""
    from contextlib import redirect_stderr
    from unittest import mock
    import io
    with tempfile.TemporaryDirectory(prefix="rea-overlay-selftest-") as directory:
        root = Path(directory)
        fixtures = {"one.js": b"patched-first\n", "two.js": b"patched-second\n"}
        expected = {name: hashlib.sha256(data).hexdigest()
                    for name, data in fixtures.items()}
        for name, data in fixtures.items():
            (root / name).write_bytes(data)
        with redirect_stderr(io.StringIO()) as log:
            verify_compiled_overlays(root, expected)
        assert "REA_OVERLAY_INTEGRITY=PASS;modules=2" in log.getvalue()
        def rejects(marker):
            try:
                with redirect_stderr(io.StringIO()):
                    verify_compiled_overlays(root, expected)
            except ValueError as exc:
                assert str(exc) == marker, (str(exc), marker)
            else:
                raise AssertionError("Incorrect runtime overlay was accepted")
        (root / "two.js").write_bytes(b"upstream rebuild\n")
        rejects("REA_OVERLAY_INTEGRITY=DRIFT")
        (root / "two.js").unlink()
        rejects("REA_OVERLAY_INTEGRITY=UNAVAILABLE")
        (root / "two.js").symlink_to(root / "one.js")
        rejects("REA_OVERLAY_INTEGRITY=UNAVAILABLE")
        (root / "two.js").unlink()
        (root / "two.js").mkdir()
        rejects("REA_OVERLAY_INTEGRITY=INVALID_TYPE")
        (root / "two.js").rmdir()
        (root / "two.js").write_bytes(fixtures["two.js"])
        with redirect_stderr(io.StringIO()):
            verify_compiled_overlays(root, expected)
    # A compromised module blocks before any MCP handshake or tool call.
    with (mock.patch(__name__ + ".verify_compiled_overlays",
                     side_effect=ValueError("REA_OVERLAY_INTEGRITY=DRIFT")) as guard,
          mock.patch.object(Client, "start",
                            side_effect=AssertionError("MCP called")) as startup):
        try:
            remote_run({"version": 1, "action": "catalog"})
        except ValueError as exc:
            assert str(exc) == "REA_OVERLAY_INTEGRITY=DRIFT"
        else:
            raise AssertionError("MCP reached despite compromised module")
    guard.assert_called_once_with()
    startup.assert_not_called()


def compact(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def b64(data):
    return base64.b64encode(data).decode("ascii")

def unb64(data):
    return base64.b64decode(data, validate=True)

def fresh_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def public64(private):
    from cryptography.hazmat.primitives import serialization
    return b64(private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))

def key_from_public64(encoded):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = serialization.load_der_public_key(unb64(encoded))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise ValueError("Transport public key must be 3072-bit RSA")
    return key

def save_key(private, directory):
    from cryptography.hazmat.primitives import serialization
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    path = directory / "reply-private.pem"
    if path.exists():
        raise ValueError("Reply private key already exists; use a fresh directory")
    raw = private.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    (directory / "reply-public.b64").write_text(public64(private), encoding="ascii")
    os.chmod(directory / "reply-public.b64", 0o600)

def load_private(path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(path.read_bytes(), password=None)

def server_key():
    from cryptography.hazmat.primitives import serialization
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid != os.geteuid():
        raise ValueError("Invalid transport-key directory")
    if stat.S_IMODE(ROOT.stat().st_mode) != 0o700:
        raise ValueError("Invalid transport-key permissions")
    path = ROOT / "request-private.pem"
    if not path.exists():
        key = fresh_key()
        raw = key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        return key
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("Invalid transport-key file")
    return load_private(path)

def seal(payload, public, aad):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = compact(payload)
    if len(raw) > MAX_OUTPUT:
        raise ValueError("Encrypted payload too large")
    aes = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    recipient = key_from_public64(public)
    wrapped = recipient.encrypt(aes, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    return {"algorithm": ALG, "nonce": b64(nonce), "wrapped_key": b64(wrapped),
            "ciphertext": b64(AESGCM(aes).encrypt(nonce, raw, aad))}

def open_seal(wrapped, private, aad, limit=MAX_BODY):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not isinstance(wrapped, dict) or set(wrapped) != {
            "algorithm", "nonce", "wrapped_key", "ciphertext"} or wrapped["algorithm"] != ALG:
        raise ValueError("Malformed encrypted transport envelope")
    if len(wrapped["ciphertext"]) > ((limit + 32) * 4 // 3 + 8):
        raise ValueError("Envelope exceeds size limit")
    aes = private.decrypt(unb64(wrapped["wrapped_key"]), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    raw = AESGCM(aes).decrypt(unb64(wrapped["nonce"]), unb64(wrapped["ciphertext"]), aad)
    if len(raw) > limit:
        raise ValueError("Decoded transport payload exceeds limit")
    return json.loads(raw)

def check_request(request):
    if not isinstance(request, dict) or request.get("version") != 1:
        raise ValueError("Invalid request version")
    if request.get("action") in ("catalog", "smoke"):
        if set(request) != {"version", "action"}:
            raise ValueError("Unexpected catalog/smoke request fields")
        return
    if request.get("action") != "sealed" or set(request) != {
            "version", "action", "sealed", "reply_public"}:
        raise ValueError("Expected sealed request, catalog or smoke")
    key_from_public64(request["reply_public"])
    if not isinstance(request["sealed"], dict):
        raise ValueError("Malformed encrypted request")
    if len(compact(request)) > MAX_BODY * 2:
        raise ValueError("Oversized encrypted request")
    if set(request["sealed"]) != {"algorithm", "nonce", "wrapped_key", "ciphertext"}:
        raise ValueError("Malformed transport envelope")

class Client:
    def __init__(self):
        self.session = None
        self.protocol = None
        self.counter = 0

    def rpc(self, method, params=None, timeout=90):
        self.counter += 1
        message = {"jsonrpc": "2.0", "method": method}
        if not method.startswith("notifications/"):
            message["id"] = self.counter
        if params is not None:
            message["params"] = params
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        req = urllib.request.Request(MCP, data=compact(message), method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(MAX_OUTPUT + 1)
                if len(raw) > MAX_OUTPUT:
                    raise ValueError("MCP result too large")
                if resp.headers.get("Mcp-Session-Id"):
                    self.session = resp.headers["Mcp-Session-Id"]
        except urllib.error.HTTPError as exc:
            raise ValueError("REA MCP HTTP status " + str(exc.code)) from None
        if not raw.strip():
            return {}
        text = raw.decode("utf-8")
        if not text.lstrip().startswith("{"):
            rows = [line.removeprefix("data:").strip() for line in text.splitlines()
                    if line.startswith("data:") and line.removeprefix("data:").strip().startswith("{")]
            if not rows:
                raise ValueError("Unexpected MCP response encoding")
            text = rows[-1]
        payload = json.loads(text)
        if "error" in payload:
            raise ValueError("REA MCP returned a protocol error")
        return payload.get("result", {})

    def start(self):
        # Retry only the non-mutating MCP handshake and catalog discovery.
        # Never retry tools/call: its outcome can be ambiguous on network failure.
        deadline = time.monotonic() + 30.0
        for attempt in range(1, 9):
            self.session = None
            self.protocol = None
            try:
                def readiness_timeout(cap):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise urllib.error.URLError("MCP readiness deadline reached")
                    return min(cap, remaining)

                init = self.rpc("initialize", {"protocolVersion": "2025-06-18",
                    "capabilities": {}, "clientInfo": {"name": "rea-github-transport", "version": "1.0"}},
                    timeout=readiness_timeout(10.0))
                self.protocol = init.get("protocolVersion")
                if not self.protocol:
                    raise ValueError("MCP initialization failed")
                self.rpc("notifications/initialized", timeout=readiness_timeout(10.0))
                tools = self.rpc("tools/list", timeout=readiness_timeout(15.0)).get("tools")
                if not isinstance(tools, list) or not tools:
                    raise ValueError("MCP catalog unavailable")
                print("REA_MCP_READINESS=PASS;attempts=" + str(attempt), file=sys.stderr)
                return {item["name"]: item for item in tools
                        if isinstance(item, dict) and "name" in item}
            except urllib.error.URLError:
                if attempt == 8 or time.monotonic() >= deadline:
                    print("REA_MCP_READINESS=FAIL;attempts=" + str(attempt), file=sys.stderr)
                    raise ValueError("REA MCP unavailable after bounded readiness attempts") from None
                time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))

    def call_tool(self, descriptor, arguments):
        from jsonschema.validators import validator_for
        schema = descriptor.get("inputSchema")
        if not isinstance(schema, dict) or not isinstance(arguments, dict):
            raise ValueError("Invalid tool argument object or schema")
        validator = validator_for(schema)
        validator.check_schema(schema)
        validator(schema).validate(arguments)
        return self.rpc("tools/call", {"name": descriptor["name"],
                      "arguments": arguments}, timeout=180)

def check_body(body):
    if not isinstance(body, dict) or set(body) != {"calls", "nonce", "expires_at"}:
        raise ValueError("Invalid call batch")
    if not isinstance(body["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", body["nonce"]):
        raise ValueError("Invalid request nonce")
    if not isinstance(body["calls"], list) or not 1 <= len(body["calls"]) <= MAX_CALLS:
        raise ValueError("Invalid call count")
    for item in body["calls"]:
        if not isinstance(item, dict) or set(item) != {"tool", "arguments"} or \
                not isinstance(item["tool"], str) or not isinstance(item["arguments"], dict):
            raise ValueError("Invalid tool call; expected tool and arguments")
    expiry = datetime.datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    age = (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    if not (0 < age <= 86400):
        raise ValueError("Expired transport request")

def one_use(nonce):
    directory = ROOT / "consumed"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / nonce
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("used\n")

def remote_run(request):
    check_request(request)
    verify_compiled_overlays()
    client = Client()
    registry = client.start()
    public = public64(server_key())
    if request["action"] == "catalog":
        from jsonschema.validators import validator_for
        for t in registry.values():
            validator_for(t["inputSchema"]).check_schema(t["inputSchema"])
        meta = {"status": "PASS", "tool_count": len(registry),
                "schema_count": len(registry), "transport_public_key": public}
        print("REA_TRANSPORT_META=" + json.dumps(meta, sort_keys=True))
        return
    if request["action"] == "smoke":
        name = "inspect_with_objdump"
        if name not in registry:
            raise ValueError("Expected objdump tool not advertised")
        results = []
        for op in ("file_headers", "section_headers"):
            value = client.call_tool(registry[name], {"path": "/usr/bin/true", "operation": op})
            results.append(value.get("isError") is not True)
        if not all(results):
            raise ValueError("REA tool returned an error in public smoke")
        print("REA_TRANSPORT_META=" + json.dumps({"status":"PASS",
            "tool_count":len(registry),"smoke":"inspect_with_objdump",
            "operations":["file_headers","section_headers"],"results":results}))
        return
    aad = hashlib.sha256(unb64(request["reply_public"])).digest()
    body = open_seal(request["sealed"], server_key(), aad)
    check_body(body)
    one_use(body["nonce"])
    results = []
    for item in body["calls"]:
        name = item["tool"]
        if name not in registry:
            results.append({"tool":name,"isError":True,"message":"Tool not advertised"})
            break
        # Pass straight to the ORIGINAL REA MCP. No per-tool authorization layer.
        value = client.call_tool(registry[name], item["arguments"])
        results.append({"tool":name, "result":value})
        if value.get("isError") is True:
            break
    reply = {"protocol":1, "calls":results}
    request_sha = hashlib.sha256(compact(request)).hexdigest()
    envelope = {"version":1,"request_sha256":request_sha,
                "sealed":seal(reply,request["reply_public"],request_sha.encode("ascii"))}
    print("REA_TRANSPORT_META=" + json.dumps({"status":"PASS","tool_count":len(registry),
          "calls_executed":len(results),"result_encrypted":True}))
    print("REA_TRANSPORT_ENVELOPE_B64=" + b64(compact(envelope)))


def test_readiness():
    """Bounded startup retries, strict protocol errors, and no replay of real tools."""
    from contextlib import redirect_stderr
    from unittest import mock
    import io

    client = Client()
    client.session = "stale-session"
    client.protocol = "stale-protocol"
    calls = []

    def fake_rpc(method, params=None, timeout=90):
        calls.append(method)
        if method == "initialize":
            assert client.session is None and client.protocol is None
            if calls.count("initialize") <= 2:
                raise urllib.error.URLError("connection refused")
            return {"protocolVersion": "2025-11-25"}
        if method == "notifications/initialized":
            return {}
        if method == "tools/list":
            return {"tools": [{"name": "list_unknowns", "inputSchema": {}}]}
        raise AssertionError("Unexpected MCP call during readiness")

    with (mock.patch.object(client, "rpc", side_effect=fake_rpc),
          mock.patch.object(time, "sleep") as sleeps,
          redirect_stderr(io.StringIO()) as messages):
        tools = client.start()
    assert list(tools) == ["list_unknowns"]
    assert calls == ["initialize", "initialize", "initialize",
                     "notifications/initialized", "tools/list"]
    assert sleeps.call_count == 2
    assert "REA_MCP_READINESS=PASS;attempts=3" in messages.getvalue()

    client = Client()
    with (mock.patch.object(client, "rpc",
                            side_effect=urllib.error.URLError("connection refused")) as rpc,
          mock.patch.object(time, "sleep") as sleeps,
          redirect_stderr(io.StringIO()) as messages):
        try:
            client.start()
        except ValueError as exc:
            assert "bounded readiness" in str(exc)
        else:
            raise AssertionError("Readiness outage accepted")
    assert rpc.call_count == 8 and sleeps.call_count == 7
    assert "REA_MCP_READINESS=FAIL;attempts=8" in messages.getvalue()

    client = Client()
    with (mock.patch.object(client, "rpc", return_value={}) as rpc,
          mock.patch.object(time, "sleep") as sleeps):
        try:
            client.start()
        except ValueError as exc:
            assert "initialization" in str(exc)
        else:
            raise AssertionError("Invalid MCP protocol accepted")
    assert rpc.call_count == 1
    sleeps.assert_not_called()

    client = Client()
    with mock.patch.object(client, "rpc",
                           side_effect=urllib.error.URLError("connection reset")) as rpc:
        try:
            client.call_tool({"name": "list_unknowns",
                              "inputSchema": {"type": "object"}}, {})
        except urllib.error.URLError:
            pass
        else:
            raise AssertionError("Ambiguous tools/call was retried or swallowed")
    assert rpc.call_count == 1
    assert rpc.call_args.args[0] == "tools/call"


def test_local():
    key = fresh_key()
    pub = public64(key)
    body = {"calls":[{"tool":"list_unknowns","arguments":{}}],
            "nonce": secrets.token_hex(16),
            "expires_at": (datetime.datetime.now(datetime.timezone.utc) +
                           datetime.timedelta(hours=1)).isoformat().replace("+00:00","Z")}
    req = {"version":1, "action":"sealed","reply_public":pub,
           "sealed":seal(body,pub,hashlib.sha256(unb64(pub)).digest())}
    check_request(req)
    assert open_seal(req["sealed"], key, hashlib.sha256(unb64(pub)).digest()) == body
    assert not any("authorization" in call for call in body["calls"])
    altered=dict(req["sealed"])
    altered["ciphertext"]="AAAA"
    try:
        open_seal(altered,key,hashlib.sha256(unb64(pub)).digest())
    except Exception:
        pass
    else:
        raise AssertionError("Tamper acceptance")
    test_readiness()
    test_overlay_integrity()
    print("REA_TRANSPORT_SELFTEST=PASS")

def cli(args):
    if len(args)==1 and args[0]=="--selftest":
        test_local()
    elif len(args)==2 and args[0]=="--validate":
        check_request(json.loads(Path(args[1]).read_text()))
        print("REA_TRANSPORT_REQUEST_VALID=PASS")
    elif len(args)==1 and args[0]=="--run":
        encoded=os.environ.pop("REA_TRANSPORT_JOB_B64","")
        request=json.loads(unb64(encoded))
        remote_run(request)
    elif len(args)==2 and args[0]=="--new-client":
        directory=Path(args[1])
        save_key(fresh_key(), directory)
        print("REA_TRANSPORT_CLIENT_KEY=CREATED")
    elif len(args)==8 and args[0]=="--seal" and args[2]=="--recipient" and \
            args[4]=="--reply" and args[6]=="--output":
        body=json.loads(Path(args[1]).read_text())
        if set(body) != {"calls"}:
            raise ValueError("Call input must have calls only")
        body["nonce"]=secrets.token_hex(16)
        body["expires_at"]=(datetime.datetime.now(datetime.timezone.utc) +
            datetime.timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00","Z")
        check_body(body)
        reply_pub=Path(args[5]).read_text().strip()
        recipient=Path(args[3]).read_text().strip()
        output={"version":1, "action":"sealed","reply_public":reply_pub,
                "sealed":seal(body,recipient,hashlib.sha256(unb64(reply_pub)).digest())}
        check_request(output)
        Path(args[7]).write_text(json.dumps(output,separators=(",",":"))+"\n")
        print("REA_TRANSPORT_REQUEST_SEALED=PASS")
    elif len(args)==8 and args[0]=="--decrypt" and args[2]=="--private" and \
            args[4]=="--request" and args[6]=="--output":
        artifact=json.loads(Path(args[1]).read_text())
        request=json.loads(Path(args[5]).read_text())
        digest=hashlib.sha256(compact(request)).hexdigest()
        if artifact["request_sha256"]!=digest:
            raise ValueError("Response request digest mismatch")
        body=open_seal(artifact["sealed"],load_private(Path(args[3])),digest.encode("ascii"),MAX_OUTPUT)
        Path(args[7]).write_text(json.dumps(body,indent=2)+"\n")
        print("REA_TRANSPORT_RESULT_DECRYPTED=PASS")
    else:
        raise ValueError("Usage: --selftest | --validate FILE | --run | --new-client DIR | --seal CALLS --recipient FILE --reply FILE --output FILE | --decrypt ARTIFACT --private FILE --request FILE --output FILE")

if __name__=="__main__":
    try:
        cli(sys.argv[1:])
    except Exception as exc:
        print("REA_TRANSPORT_FAIL="+type(exc).__name__,file=sys.stderr)
        sys.exit(1)
