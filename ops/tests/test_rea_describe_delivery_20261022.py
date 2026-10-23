"""Regression: large MCP schema stays complete and private over existing Actions envelope."""
import base64
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BRIDGE = Path(__file__).resolve().parents[1] / "rea_mobile_mcp_bridge_20261022.py"


class ReadOnlySchemaDeliveryTests(unittest.TestCase):
    def test_public_and_private_describe_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = {"version": 1, "action": "describe", "tool": "analyze_web_bundle"}
            path = root / "describe.json"
            path.write_text(json.dumps(good))
            checked = subprocess.run([sys.executable, str(BRIDGE), "--validate",
                                      str(path)], capture_output=True, text=True)
            self.assertEqual(0, checked.returncode, checked.stderr)
            self.assertIn("REA_MOBILE_REQUEST_VALID=PASS", checked.stdout)
            bad = {**good, "response_key": "private-or-malformed"}
            path.write_text(json.dumps(bad))
            denied = subprocess.run([sys.executable, str(BRIDGE), "--validate",
                                     str(path)], capture_output=True, text=True)
            self.assertNotEqual(0, denied.returncode)
            owner = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            valid = base64.b64encode(owner.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")
            path.write_text(json.dumps({**good, "response_key": valid}))
            confirmed = subprocess.run([sys.executable, str(BRIDGE), "--validate",
                                        str(path)], capture_output=True, text=True)
            self.assertEqual(0, confirmed.returncode, confirmed.stderr)
            # A syntactically valid, RSA-sized base64 string is not an RSA key.
            invalid_der = base64.b64encode(b"\x00" * 294).decode("ascii")
            self.assertEqual(len(invalid_der), len(valid))
            path.write_text(json.dumps({**good, "response_key": invalid_der}))
            blocked = subprocess.run([sys.executable, str(BRIDGE), "--validate",
                                      str(path)], capture_output=True, text=True)
            self.assertNotEqual(0, blocked.returncode)

    def test_full_large_descriptor_authenticates_and_encrypts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            reply = base64.b64encode(private.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")
            request = root / "request.json"
            request.write_bytes((json.dumps({
                "version": 1, "action": "describe", "tool": "analyze_web_bundle",
                "response_key": reply,
            }, separators=(",", ":")) + "\n").encode())
            accepted = subprocess.run([sys.executable, str(BRIDGE), "--validate",
                                       str(request)], capture_output=True, text=True)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            huge = {"name": "analyze_web_bundle", "inputSchema": {
                "type": "object", "$defs": {"complete": {"const": "A" * 32000}}},
                "annotations": {"readOnlyHint": False}}
            raw = json.dumps(huge, sort_keys=True).encode()
            self.assertGreater(len(base64.b64encode(raw)), 24000)
            transcript = root / "raw-private.log"
            transcript.write_text(
                "REA_MOBILE_PRIVATE_RESULT_B64=" +
                base64.b64encode(raw).decode() + "\n" +
                "REA_MOBILE_TOOL_DESCRIPTOR_SHA256=" +
                hashlib.sha256(raw).hexdigest() + "\n",
                encoding="ascii",
            )
            envelope = root / "encrypted.json"
            produced = subprocess.run([
                sys.executable, str(BRIDGE), "--envelope", str(transcript),
                str(request), str(envelope),
            ], capture_output=True, text=True)
            self.assertEqual(0, produced.returncode, produced.stderr)
            self.assertNotIn("A" * 60, produced.stdout)
            self.assertIn("REA_MOBILE_ENCRYPTED_RESULT=PASS", produced.stdout)
            sealed = json.loads(envelope.read_text())
            expected = hashlib.sha256(request.read_bytes()).hexdigest()
            self.assertEqual(expected, sealed["request_sha256"])
            secret = private.decrypt(base64.b64decode(sealed["wrapped_key"]),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
            decoded = AESGCM(secret).decrypt(
                base64.b64decode(sealed["nonce"]),
                base64.b64decode(sealed["ciphertext"]), expected.encode())
            recovered = json.loads(gzip.decompress(decoded))
            self.assertEqual("describe", recovered["action"])
            self.assertEqual(huge, recovered["result"])


if __name__ == "__main__":
    unittest.main()
