#!/usr/bin/env python3
"""REA GitHub-to-VPS MCP bridge: v1 inspected calls and v2 sealed batches.

This script runs on the VPS as ubuntu, talking ONLY to the existing loopback
REA MCP service. It neither deploys services nor changes the desktop plugin.
Public GitHub requests and logs must never contain credentials/private data.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
import rea_secure_protocol_20261022 as secure

URL = "http://127.0.0.1:8765/mcp"
MAX_REQUEST = 750000
MAX_RESPONSE = 5000000
NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,119}$")
DANGEROUS_NAME_RE = re.compile(
    r"(?:^|[_./:-])(delete|remove|write|modify|patch|exec|shell|spawn|"
    r"install|uninstall|commit|push|upload|deploy|kill|shutdown|reset|"
    r"create|edit|update|set|run_script)(?:$|[_./:-])", re.I
)
SENSITIVE_RE = re.compile(r"token|password|passwd|secret|api.?key|"
                          r"authorization|bearer|private.?key|cookie", re.I)
# Explicitly reviewed names of static inspection operations. Never treat the
# entire advertised 208-tool catalogue as a permission grant.
STATIC_INSPECT_TOOLS = frozenset({
    "analyze_javascript_application", "analyze_web_bundle",
    "binary_overview", "compare_artifacts", "compare_bundles",
    "compare_javascript_export_shapes", "compare_managed_members",
    "compare_source_to_bundle", "compare_wasm_interfaces",
    "decode_android_resources", "identify_flutter_build",
    "inspect_android_class", "inspect_android_method",
    "inspect_android_package", "inspect_artifact", "inspect_binary_layout",
    "inspect_dart_aot", "inspect_desktop_application",
    "inspect_electron_fuses", "inspect_evm_interface",
    "inspect_go_binary", "inspect_macho", "inspect_managed_artifact",
    "inspect_managed_members", "inspect_managed_native_boundaries",
    "inspect_pe_resources", "inspect_plist", "inspect_rust_binary",
    "inspect_wasm_artifact", "search_android_classes",
    "trace_android_references",
})


# Additional explicitly reviewed metadata and navigation queries. No generic
# filesystem access, command execution, device modification or write operations.
SAFE_QUERY_TOOLS = frozenset({
    "address_name", "address_to_file_offset", "current_address",
    "current_document", "current_procedure", "find_xrefs_to_name",
    "get_call_graph", "get_navigation_context", "list_architectures",
    "list_bookmarks", "list_documents", "list_names", "list_procedures",
    "list_segments", "list_strings", "procedure_address",
    "procedure_assembly", "procedure_callees", "procedure_callers",
    "procedure_info", "procedure_pseudo_code", "procedure_references",
    "search_procedures", "search_strings", "frida_session_status",
    "rizin_debug_session_status", "list_cutter_sessions",
    "list_frida_devices", "list_jeb_units", "list_browser_targets",
    "list_electron_targets",
})


def error(msg):
    raise ValueError(msg)


# P268: Retention defect repaired in original REA (P265), and a real
# owner-signed Ghidra open/close proved 11/1 Evidence preserved (P267).
# The existing bridge still fail-closes for all non-sealed fixture/direct paths.
# These TWO tools are released only within a batch already verified by
# secure.validate_inner (workspace open, owner Ed25519 sensitive close).
P232_BLOCKED_MCP_TOOLS = frozenset(("open_binary", "close_binary"))


def p232_guard_live_call(payload, lifecycle_grants=None):
    """Block binary lifecycle unless the current validated sealed batch granted exact args."""
    if not isinstance(payload, dict):
        raise ValueError("REA_RETENTION_GATE: malformed MCP payload")
    if payload.get("method") != "tools/call":
        return
    params = payload.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        raise ValueError("REA_RETENTION_GATE: malformed tools/call")
    name = params["name"]
    if name in P232_BLOCKED_MCP_TOOLS:
        args = params.get("arguments")
        expected = lifecycle_grants.get(name) if isinstance(lifecycle_grants, dict) else None
        if (not isinstance(args, dict) or not isinstance(expected, str) or
                secure.arguments_sha256(args) != expected):
            raise ValueError("REA_RETENTION_GATE: exact signed session admission required")


def p232_guard_inner_batch(body):
    """Admission after validate_inner already checked owner Ed25519 and every schema.

    An opened target must have exactly one later signed close inside the SAME
    one-use sealed batch. Even emergency finally cleanup uses that validated
    close authorization; never implicitly close an unsigned session.
    """
    if not isinstance(body, dict) or not isinstance(body.get("steps"), list):
        raise ValueError("REA_RETENTION_GATE: malformed sealed batch")
    steps = body["steps"]
    for step in steps:
        if (not isinstance(step, dict) or not isinstance(step.get("tool"), str)
                or not isinstance(step.get("arguments"), dict)):
            raise ValueError("REA_RETENTION_GATE: malformed sealed tool")
    opens = [i for i, step in enumerate(steps) if step["tool"] == "open_binary"]
    closes = [i for i, step in enumerate(steps) if step["tool"] == "close_binary"]
    if len(opens) > 1 or len(closes) > 1:
        raise ValueError("REA_RETENTION_GATE: one binary open/close maximum")
    if opens and (len(closes) != 1 or closes[0] <= opens[0]):
        raise ValueError("REA_RETENTION_GATE: signed close must follow binary open")
    if opens and steps[closes[0]]["arguments"] != {}:
        # Emergency cleanup has an already-signed no-snapshot close. A
        # close_with_snapshot requires a separate, explicit signed batch.
        raise ValueError("REA_RETENTION_GATE: paired close must not write a snapshot")
    grants = {}
    for step in steps:
        name = step["tool"]
        if name not in P232_BLOCKED_MCP_TOOLS:
            continue
        auth = step.get("authorization")
        expected_scope = "sensitive" if name == "close_binary" else "workspace"
        if (not isinstance(auth, dict) or auth.get("scope") != expected_scope or
                auth.get("tool") != name or
                auth.get("arguments_sha256") != secure.arguments_sha256(step["arguments"])
                or auth.get("confirmed_by_owner") is not True or
                (name == "close_binary" and not isinstance(auth.get("owner_signature"), str))):
            raise ValueError("REA_RETENTION_GATE: exact individual authorization missing")
        grants[name] = secure.arguments_sha256(step["arguments"])
    return grants


def require_rsa_response_key(encoded):
    """Fail fast before SSH: validate full RSA DER, not just base64 shape."""
    if (not isinstance(encoded, str) or len(encoded) > 1800 or
            not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}", encoded)):
        error("Invalid RSA response key encoding")
    try:
        der = base64.b64decode(encoded, validate=True)
        command = subprocess.run(
            ["openssl", "rsa", "-pubin", "-inform", "DER", "-noout", "-text"],
            input=der, capture_output=True, timeout=6, check=False
        )
        found = re.search(rb"Public-Key: \((\d+) bit\)", command.stdout)
        if (command.returncode != 0 or found is None or
                int(found.group(1)) < 2048):
            error("Invalid RSA response public key")
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ValueError("Invalid RSA response public key") from exc


def validate(data):
    if not isinstance(data, dict) or set(data) - {
        "version", "action", "tool", "arguments", "response_key", "sealed"
    }:
        error("Unknown request fields")
    if data.get("version") != 1:
        error("Unsupported request version")
    action = data.get("action")
    if action in ("catalog", "health", "capability_audit", "fixture_ghidra", "fixture_ghidra_depth", "fixture_objdump",
                  "secure_public_key", "stage_dependencies", "fixture_linux_read5_regression", "fixture_linux_gdb_conformance", "fixture_linux_read5_mcp_boundaries", "fixture_linux_gdb_read_status_states", "fixture_linux_gdb_provider_probe", "fixture_linux_gdb_real_provider", "fixture_linux_install_inventory", "fixture_linux_doctor_readiness", "fixture_linux_service_install_preflight", "fixture_linux_provider_install_simulate", "fixture_linux_provider_install_apply", "fixture_linux_service_runtime_doctor", "fixture_linux_rizin_persistent", "fixture_linux_unblob_persistent", "fixture_linux_service_config_preflight", "fixture_linux_service_provider_activate", "fixture_linux_service_unit_diagnose"):
        if set(data) != {"version", "action"}:
            error("Catalog requests cannot have extra fields")
    elif action in ("fixture_ghidra_metadata", "fixture_ghidra_additional", "runtime_contracts", "fixture_isolated_suppliers", "fixture_isolated_pwntools", "fixture_static_files", "fixture_static_files_v2", "fixture_managed_inputs", "fixture_managed_inputs_v2", "fixture_linux_objdump"):
        # Named system-owned ELF only; never an arbitrary caller-selected path.
        if set(data) != {"version", "action", "response_key"}:
            error("Ghidra inspection fixture accepts only a public reply key")
        if (not isinstance(data["response_key"], str)
                or not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}",
                                    data["response_key"])):
            error("Ghidra fixture requires RSA public response key")
    elif action == "fixture_portable_formats":
        if set(data) != {"version", "action", "response_key"}:
            error("Format fixture accepts only a public reply key")
        if (not isinstance(data["response_key"], str)
                or not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}",
                                    data["response_key"])):
            error("Format fixture requires an RSA reply public key")
    elif action == "fixture_apkdemos":
        # Fixed, Apache-2.0 public Appium APK. Only a public response key is accepted.
        if set(data) != {"version", "action", "response_key"}:
            error("Android fixture request must not contain caller paths or commands")
        if (not isinstance(data["response_key"], str)
                or not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}",
                                    data["response_key"])):
            error("Android fixture requires a public RSA reply key")
    elif action == "fixture_linux_rea_680_session_gate":
        if set(data) not in ({"version","action"}, {"version","action","response_key"}):
            error("Session review accepts optional public encrypted reply key only")
    elif action == "fixture_linux_rea_680_owner_signature_preflight":
        if set(data) != {"version", "action", "sealed", "response_key"}:
            error("Encrypted owner authorization preflight requires sealed payload and public reply key")
        secure.validate_public_envelope(data["sealed"])
    elif action == "sealed_batch":
        if set(data) != {"version", "action", "sealed", "response_key"}:
            error("Sealed batch must carry a public reply key and sealed request")
        secure.validate_public_envelope(data["sealed"])
        key = data["response_key"]
        if (not isinstance(key, str) or len(key) > 1800 or
                not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}", key)):
            error("Invalid encrypted reply public key")
    elif action == "describe":
        if set(data) not in (
            {"version", "action", "tool"},
            {"version", "action", "tool", "response_key"},
        ):
            error("A description request requires one tool name and optional public reply key")
        if not isinstance(data["tool"], str) or not NAME_RE.fullmatch(data["tool"]):
            error("Invalid tool name")
        if "response_key" in data:
            key = data["response_key"]
            if (not isinstance(key, str) or len(key) > 1800 or
                    not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}", key)):
                error("Description reply key must be a public RSA key")
    elif action == "call":
        if set(data) not in (
            {"version", "action", "tool", "arguments"},
            {"version", "action", "tool", "arguments", "response_key"}
        ):
            error("A call requires tool name and arguments")
        if not isinstance(data["tool"], str) or not NAME_RE.fullmatch(data["tool"]):
            error("Invalid tool name")
        if DANGEROUS_NAME_RE.search(data["tool"]):
            error("Tool is not allowed by the read-only adapter")
        if not isinstance(data["arguments"], dict):
            error("Tool arguments must be an object")
        if SENSITIVE_RE.search(json.dumps(data["arguments"], ensure_ascii=True)):
            error("Secret-like request fields are forbidden in a public repository")
        if "response_key" in data:
            key = data["response_key"]
            if (not isinstance(key, str) or len(key) > 1800
                    or not re.fullmatch(r"[A-Za-z0-9+/=]{340,1800}", key)):
                error("response_key must be a public RSA SubjectPublicKeyInfo DER")
    else:
        error("Unsupported action")
    if "response_key" in data:
        require_rsa_response_key(data["response_key"])
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_REQUEST:
        error("Request exceeds size limit")
    return data


def parse_mcp(raw):
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("{"):
        return json.loads(text)
    for line in text.splitlines():
        if line.startswith("data:"):
            body = line[5:].strip()
            if body.startswith("{"):
                return json.loads(body)
    raise RuntimeError("Unexpected MCP response type")


def request_mcp(payload, session=None, protocol=None, timeout=55, lifecycle_grants=None):
    p232_guard_live_call(payload, lifecycle_grants=lifecycle_grants)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    if protocol:
        headers["MCP-Protocol-Version"] = protocol
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode(), method="POST", headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise RuntimeError("MCP response too large")
            return resp.headers, parse_mcp(data) if data.strip() else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError("REA loopback MCP HTTP status " + str(e.code))


def encrypt_result(raw_path, request_path, envelope_path):
    """On GitHub runner ONLY: encrypt private MCP output before emitting any logs."""
    import gzip
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    request_raw = Path(request_path).read_bytes()
    request = validate(json.loads(request_raw))
    private = None
    allowed_markers = {
        "REA_MOBILE_LOOPBACK_MCP", "REA_MOBILE_MCP_TOOL_COUNT",
        "REA_MOBILE_READONLY_HINT_COUNT", "REA_MOBILE_STATIC_INSPECT_COUNT",
        "REA_MOBILE_SAFE_QUERY_COUNT", "REA_MOBILE_SAFE_CALLABLE_COUNT",
        "REA_MOBILE_LEGACY_NAME_COUNT", "REA_MOBILE_WORKSPACE_CALLABLE_COUNT",
        "REA_MOBILE_SIGNATURE_REQUIRED_COUNT", "REA_MOBILE_VALIDATED_SCHEMA_COUNT",
        "REA_MOBILE_AUDITED_SCHEMA_MATCH_COUNT",
        "REA_MOBILE_TOOL_CALL", "REA_MOBILE_TOOL_NAME",
        "REA_MOBILE_OUTPUT_BYTES", "REA_MOBILE_OUTPUT_SHA256",
        "REA_MOBILE_TOOL_ERROR", "REA_MOBILE_HEALTH",
        "REA_MOBILE_PROVIDER_DOCTOR_GHIDRA",
        "REA_MOBILE_PROVIDER_DOCTOR_JADX", "REA_MOBILE_CATALOG",
        "REA_MOBILE_DESCRIBE_TOOL", "REA_MOBILE_TOOL_DESCRIPTOR_B64",
        "REA_MOBILE_TOOL_SCHEMA_SUMMARY", "REA_MOBILE_TOOL_DESCRIPTOR_SHA256",
        "REA_MOBILE_TOOL_DESCRIPTOR_BYTES", "REA_MOBILE_TOOL_DESCRIPTOR_TRUNCATED",
        "REA_FIXTURE_OBJDUMP_HEADERS", "REA_FIXTURE_OBJDUMP_HEADERS_SHA256",
        "REA_FIXTURE_OBJDUMP_SECTIONS", "REA_FIXTURE_OBJDUMP_SECTIONS_SHA256",
        "REA_AUDIT_STATUS", "REA_AUDIT_CLI_STATUS",
        "REA_AUDIT_PROVIDER_KEYS", "REA_AUDIT_DEPENDENCIES",
        "REA_AUDIT_PROVIDER_SECTIONS", "REA_AUDIT_OPERATION_PROVIDERS",
        "REA_AUDIT_PROVIDER_NAMES", "REA_AUDIT_TOOL_CONTRACTS",
        "REA_AUDIT_REQUIRED_ARGUMENTS", "REA_AUDIT_PLATFORM_RUNTIME",
        "REA_FIXTURE_PROVIDER", "REA_FIXTURE_OPEN",
        "REA_FIXTURE_DOCUMENTS", "REA_FIXTURE_CLEANUP",
        "REA_FIXTURE_PROCEDURES", "REA_FIXTURE_STRINGS",
        "REA_SECURE_REQUEST_PUBLIC_KEY_B64", "REA_SEALED_STEPS_TOTAL",
        "REA_SEALED_STEPS_EXECUTED", "REA_SEALED_POLICY",
        "REA_SEALED_CLEANUP", "REA_FIXTURE_ANDROID_DOWNLOAD",
        "REA_FIXTURE_ANDROID_SHA256", "REA_FIXTURE_ANDROID_JADX",
        "REA_FIXTURE_ANDROID_CLEANUP",
        "REA_FIXTURE_MANAGED_PE", "REA_FIXTURE_PE_RESOURCES",
        "REA_FIXTURE_MANAGED_MEMBERS", "REA_FIXTURE_MANAGED_BOUNDARIES",
        "REA_FIXTURE_MACHO_FUSES", "REA_FIXTURE_FORMAT_CLEANUP",
        "REA_FIXTURE_WASM", "REA_FIXTURE_SQLITE",
        "REA_FIXTURE_GHIDRA_METADATA", "REA_FIXTURE_GHIDRA_METADATA_CLEANUP",
        "REA_FIXTURE_GHIDRA_ADDITIONAL", "REA_FIXTURE_GHIDRA_ADDITIONAL_CLEANUP",
        "REA_FIXTURE_ANDROID_CLASSES", "REA_FIXTURE_ANDROID_CLASS",
        "REA_FIXTURE_ANDROID_METHOD", "REA_FIXTURE_ANDROID_XREFS",
        "REA_STAGE_NODE", "REA_STAGE_WABT", "REA_STAGE_NO_SERVICE_CHANGES",
        "REA_LINUX_READ5_SOURCE_PRESENT", "REA_LINUX_READ5_VITEST_PRESENT",
        "REA_LINUX_READ5_NODE_PRESENT", "REA_LINUX_READ5_REGRESSION",
        "REA_LINUX_READ5_EXIT_CODE", "REA_LINUX_READ5_TEST_OUTPUT_SHA256",
        "REA_LINUX_READ5_TEST_NAME", "REA_LINUX_READ5_TEST_DIAGNOSTIC",
        "REA_LINUX_GDB_CONFORMANCE_SOURCE", "REA_LINUX_GDB_CONFORMANCE_COUNT",
        "REA_LINUX_GDB_CONFORMANCE_STATUS", "REA_LINUX_GDB_CONFORMANCE_WORKTREE",
        "REA_LINUX_GDB_MANAGER_EXIT", "REA_LINUX_GDB_MANAGER_RESULT",
        "REA_LINUX_GDB_MANAGER_SHA256", "REA_LINUX_GDB_MCP_EXIT",
        "REA_LINUX_GDB_MCP_RESULT", "REA_LINUX_GDB_MCP_SHA256",
        "REA_LINUX_READ5_SOURCE_REVISION",
        "REA_LINUX_READ5_LIST_NONEMPTY",
        "REA_LINUX_READ5_LIST_NONEMPTY_EXIT",
        "REA_LINUX_READ5_LIST_NONEMPTY_SHA256",
        "REA_LINUX_READ5_LIST_NONEMPTY_DIAGNOSTIC",
        "REA_LINUX_READ5_EVIDENCE_BUNDLE",
        "REA_LINUX_READ5_EVIDENCE_BUNDLE_EXIT",
        "REA_LINUX_READ5_EVIDENCE_BUNDLE_SHA256",
        "REA_LINUX_READ5_EVIDENCE_BUNDLE_DIAGNOSTIC",
        "REA_LINUX_READ5_COVERAGE",
        "REA_LINUX_READ5_COVERAGE_EXIT",
        "REA_LINUX_READ5_COVERAGE_SHA256",
        "REA_LINUX_READ5_COVERAGE_DIAGNOSTIC",
        "REA_LINUX_READ5_RESOLUTION_MCP",
        "REA_LINUX_READ5_RESOLUTION_MCP_EXIT",
        "REA_LINUX_READ5_RESOLUTION_MCP_SHA256",
        "REA_LINUX_READ5_RESOLUTION_MCP_DIAGNOSTIC",
        "REA_LINUX_READ5_MCP_WORKTREE",
        "REA_LINUX_READ5_MCP_PASS_COUNT",
        "REA_LINUX_READ5_MCP_BOUNDARIES",
        "REA_LINUX_GDB_STATES_SOURCE",
        "REA_LINUX_GDB_STATES_READY",
        "REA_LINUX_GDB_STATES_READY_EXIT",
        "REA_LINUX_GDB_STATES_READY_SHA256",
        "REA_LINUX_GDB_STATES_READY_DIAGNOSTIC",
        "REA_LINUX_GDB_STATES_LOSSY",
        "REA_LINUX_GDB_STATES_LOSSY_EXIT",
        "REA_LINUX_GDB_STATES_LOSSY_SHA256",
        "REA_LINUX_GDB_STATES_LOSSY_DIAGNOSTIC",
        "REA_LINUX_GDB_STATES_WORKTREE",
        "REA_LINUX_GDB_STATES_BINARY_IN_PATH",
        "REA_LINUX_GDB_STATUS_STATES",
        "REA_LINUX_GDB_PROBE_PLATFORM",
        "REA_LINUX_GDB_PROBE_ARCH",
        "REA_LINUX_GDB_PROBE_DISTRO",
        "REA_LINUX_GDB_PROBE_PATH",
        "REA_LINUX_GDB_PROBE_FIXED_FILES",
        "REA_LINUX_GDB_PROBE_MANAGERS",
        "REA_LINUX_GDB_PROBE_REPO",
        "REA_LINUX_GDB_PROBE_AUDIT",
        "REA_LINUX_GDB_REAL_STATUS",
        "REA_LINUX_GDB_REAL_REA_SOURCE",
        "REA_LINUX_GDB_REAL_DOWNLOAD",
        "REA_LINUX_GDB_REAL_DIAGNOSTIC",
        "REA_LINUX_GDB_REAL_PACKAGE_SHA256",
        "REA_LINUX_GDB_REAL_EXTRACT",
        "REA_LINUX_GDB_REAL_BINARY_SHA256",
        "REA_LINUX_GDB_REAL_BINARY_CHECK",
        "REA_LINUX_GDB_REAL_VERSION",
        "REA_LINUX_GDB_REAL_TEST_EXIT",
        "REA_LINUX_GDB_REAL_TEST_SHA256",
        "REA_LINUX_GDB_REAL_TEST",
        "REA_LINUX_GDB_REAL_SOURCE_UNCHANGED",
        "REA_LINUX_GDB_REAL_MISSING_LIBS",
        "REA_LINUX_GDB_REAL_STAGED_DEPS",
        "REA_LINUX_GDB_REAL_DEP_ERROR",
        "REA_INSTALL_AUDIT_OS",
        "REA_INSTALL_AUDIT_ARCH",
        "REA_INSTALL_AUDIT_RELEASE",
        "REA_INSTALL_AUDIT_BIN_CORE",
        "REA_INSTALL_AUDIT_BIN_NATIVE",
        "REA_INSTALL_AUDIT_BIN_APPLICATION",
        "REA_INSTALL_AUDIT_BIN_FIRMWARE",
        "REA_INSTALL_AUDIT_BIN_CAPTURE",
        "REA_INSTALL_AUDIT_VENDOR",
        "REA_INSTALL_AUDIT_PROVIDERS_CLI",
        "REA_INSTALL_AUDIT_PROVIDERS_TOP_KEYS",
        "REA_INSTALL_AUDIT_PROVIDER_CANDIDATES",
        "REA_INSTALL_AUDIT_PROVIDERS_JSON",
        "REA_INSTALL_AUDIT_MCP_TOOL_COUNT",
        "REA_INSTALL_AUDIT_COMPLETED",
        "REA_DOCTOR_LINUX_STATUS",
        "REA_DOCTOR_LINUX_EXIT",
        "REA_DOCTOR_LINUX_JSON_SHA256",
        "REA_DOCTOR_LINUX_KEYS",
        "REA_DOCTOR_LINUX_SAFE_SUMMARY",
        "REA_DOCTOR_LINUX_CHECKS",
        "REA_DOCTOR_LINUX_PROVIDERS",
        "REA_DOCTOR_LINUX_HEALTH",
        "REA_DOCTOR_LINUX_CHECK_GROUP1",
        "REA_DOCTOR_LINUX_CHECK_GROUP2",
        "REA_DOCTOR_LINUX_CHECK_GROUP3",
        "REA_DOCTOR_LINUX_CHECK_GROUP4",
        "REA_DOCTOR_LINUX_PROVIDER1",
        "REA_DOCTOR_LINUX_PROVIDER2",
        "REA_DOCTOR_LINUX_PROVIDER3",
        "REA_DOCTOR_LINUX_PROVIDER4",
        "REA_DOCTOR_LINUX_PROVIDER5",
        "REA_DOCTOR_LINUX_PROVIDER6",
        "REA_DOCTOR_LINUX_PROVIDER7",
        "REA_DOCTOR_LINUX_PROVIDER8",
        "REA_DOCTOR_LINUX_PROVIDER9",
        "REA_DOCTOR_LINUX_PROVIDER10",
        "REA_DOCTOR_LINUX_PROVIDER11",
        "REA_DOCTOR_LINUX_PROVIDER12",
        "REA_PREFLIGHT_OS",
        "REA_PREFLIGHT_UID",
        "REA_PREFLIGHT_ADMIN_NONINTERACTIVE",
        "REA_PREFLIGHT_ENGINE_OWNER",
        "REA_PREFLIGHT_ENGINE_WRITE",
        "REA_PREFLIGHT_DISK_GIB",
        "REA_PREFLIGHT_HOME",
        "REA_PREFLIGHT_CMD_DPKG_QUERY",
        "REA_PREFLIGHT_CMD_APT_GET",
        "REA_PREFLIGHT_CMD_APT_CACHE",
        "REA_PREFLIGHT_CMD_SYSTEMCTL",
        "REA_PREFLIGHT_CMD_PGREP",
        "REA_PREFLIGHT_CMD_SUDO",
        "REA_PREFLIGHT_CMD_LDCONFIG",
        "REA_PREFLIGHT_CANDIDATE_GDB",
        "REA_PREFLIGHT_CANDIDATE_RIZIN",
        "REA_PREFLIGHT_CANDIDATE_RADARE2",
        "REA_PREFLIGHT_CANDIDATE_BINWALK",
        "REA_PREFLIGHT_CANDIDATE_TSHARK",
        "REA_PREFLIGHT_CANDIDATE_ADB",
        "REA_PREFLIGHT_CANDIDATE_APKTOOL",
        "REA_PREFLIGHT_CANDIDATE_CHROMIUM",
        "REA_PREFLIGHT_UNITS",
        "REA_PREFLIGHT_NODE_PROC_COUNT",
        "REA_PREFLIGHT_COMPLETE",
        "REA_SIM_APT_AVAILABLE",
        "REA_SIM_APT_UNAVAILABLE",
        "REA_SIM_APT_EXIT",
        "REA_SIM_APT_INSTALL_COUNT",
        "REA_SIM_APT_REMOVE_COUNT",
        "REA_SIM_APT_FIRST_PACKAGES",
        "REA_SIM_APT_PLAN_SHA256",
        "REA_SIM_APT_SAFE",
        "REA_SIM_APT_FAILURE",
        "REA_SIM_SERVICE_USER",
        "REA_SIM_SERVICE_ACTIVE",
        "REA_SIM_SERVICE_PID_PRESENT",
        "REA_SIM_SERVICE_DROPIN",
        "REA_SIM_COMPLETED",
        "REA_SIM_SERVICE_ENV_GHIDRA_INSTALL_DIR",
        "REA_SIM_SERVICE_ENV_JAVA_HOME",
        "REA_SIM_SERVICE_ENV_REA_JADX_MCP_JAR",
        "REA_SIM_SERVICE_ENV_REA_GDB_COMMAND",
        "REA_SIM_SERVICE_ENV_REA_BINWALK_COMMAND",
        "REA_SIM_SERVICE_ENV_REA_UNBLOB_COMMAND",
        "REA_APPLY_SIM_PACKAGES",
        "REA_APPLY_SIM_SHA256",
        "REA_APPLY_REQUESTED",
        "REA_APPLY_BEFORE_SHA256",
        "REA_APPLY_APT_EXIT",
        "REA_APPLY_OUTPUT_SHA256",
        "REA_APPLY_INSTALLED",
        "REA_APPLY_SERVICE_ACTIVE",
        "REA_APPLY_STATE_SAVED",
        "REA_APPLY_FAILURE",
        "REA_APPLY_RESULT",
        "REA_SERVICE_DOCTOR_STATUS",
        "REA_SERVICE_DOCTOR_UNIT_USER",
        "REA_SERVICE_DOCTOR_CONFIG_KEYS",
        "REA_SERVICE_DOCTOR_CONFIG_GHIDRA_INSTALL_DIR",
        "REA_SERVICE_DOCTOR_CONFIG_JAVA_HOME",
        "REA_SERVICE_DOCTOR_CONFIG_REA_JADX_MCP_JAR",
        "REA_SERVICE_DOCTOR_CONFIG_REA_GDB_COMMAND",
        "REA_SERVICE_DOCTOR_CONFIG_REA_BINWALK_COMMAND",
        "REA_SERVICE_DOCTOR_CONFIG_REA_UNBLOB_COMMAND",
        "REA_SERVICE_DOCTOR_CONFIG_REA_RIZIN_COMMAND",
        "REA_SERVICE_DOCTOR_EXIT",
        "REA_SERVICE_DOCTOR_HEALTH",
        "REA_SERVICE_DOCTOR_PROVIDERS",
        "REA_SERVICE_DOCTOR_BINARY_CHECK",
        "REA_RIZIN_STATUS",
        "REA_RIZIN_ALREADY_PRESENT",
        "REA_RIZIN_VERSION_EXIT",
        "REA_RIZIN_ARCHIVE_BYTES",
        "REA_RIZIN_ARCHIVE_SHA256",
        "REA_RIZIN_BINARIES",
        "REA_RIZIN_VERIFIED_EXIT",
        "REA_RIZIN_INSTALLED",
        "REA_RIZIN_VERSION",
        "REA_UNBLOB_ALREADY_INSTALLED",
        "REA_UNBLOB_STATUS",
        "REA_UNBLOB_WHEEL_SHA256",
        "REA_UNBLOB_PIP_EXIT",
        "REA_UNBLOB_PIP_SHA256",
        "REA_UNBLOB_EXEC_EXIT",
        "REA_PCONFIG_SERVICE_USER_OK",
        "REA_PCONFIG_SERVICE_PID_OK",
        "REA_PCONFIG_DROPIN_PRESENT",
        "REA_PCONFIG_ENVFILE_PRESENT",
        "REA_PCONFIG_UNIT_CUSTOM",
        "REA_PCONFIG_SERVICE_PATH_RIZIN",
        "REA_PCONFIG_REA_BINWALK_COMMAND",
        "REA_PCONFIG_REA_UNBLOB_COMMAND",
        "REA_PCONFIG_REA_GDB_COMMAND",
        "REA_PCONFIG_PROVIDER_GDB",
        "REA_PCONFIG_PROVIDER_BINWALK",
        "REA_PCONFIG_PROVIDER_RIZIN",
        "REA_PCONFIG_PROVIDER_UNBLOB",
        "REA_PCONFIG_STATUS",
        "REA_PACT_PROVIDER_ACCESS",
        "REA_PACT_STATUS",
        "REA_PACT_ACTIVE_ENV",
        "REA_PACT_MCP_TOOL_COUNT",
        "REA_PACT_RESULT",
        "REA_PACT_ERROR_CLASS",
        "REA_PACT_ROLLBACK",
        "REA_PACT_SYSTEMD_DROPIN_LOADED",
        "REA_PACT_SYSTEMD_ENV_KEYS",
        "REA_PACT_PID_REPLACED",
        "REA_PACT_PROC_ENV_READ",
        "REA_PACT_POST_SYSTEMD_ENV_KEYS",
        "REA_PACT_MCP_ATTEMPTS",
        "REA_PACT_POST_READY_ENV",
        "REA_PACT_POST_READY_CHECKS",
        "REA_SDIAG_IDENTITY",
        "REA_SDIAG_TYPE",
        "REA_SDIAG_DROPIN",
        "REA_SDIAG_ENVFILE",
        "REA_SDIAG_PASSENV",
        "REA_SDIAG_UNSETENV",
        "REA_SDIAG_ENV_KEY_COUNT",
        "REA_SDIAG_PROVIDER_ENV_KEYS",
        "REA_SDIAG_EXEC_SH",
        "REA_SDIAG_EXEC_ENV_RESET",
        "REA_SDIAG_EXEC_NODE",
        "REA_SDIAG_EXEC_SUDO",
        "REA_SDIAG_PROC_EXE_KIND",
        "REA_SDIAG_PID_ENV_READ",
        "REA_SDIAG_PID_ENV_SIZE",
        "REA_SDIAG_PID_PROVIDER_KEYS",
        "REA_SDIAG_STATUS",
        "REA_U680_OWNER_SIGNATURE_VERIFIED", "REA_U680_OWNER_SIGNED_PROFILES",
        "REA_U680_OWNER_REPLAY_CHECK", "REA_U680_OWNER_RESTORE_READY",
        "REA_U680_SESSION_LIST_DOCUMENTS", "REA_U680_SESSION_LIST_DOCUMENTS_REQUIRED",
        "REA_U680_SESSION_LIST_DOCUMENTS_STRUCTURE", "REA_U680_SESSION_LIST_DOCUMENTS_TEXTCOUNT",
        "REA_U680_SESSION_LIST_DOCUMENTS_COUNTS",
        "REA_U680_SESSION_LIST_CUTTER_SESSIONS", "REA_U680_SESSION_LIST_CUTTER_SESSIONS_REQUIRED",
        "REA_U680_SESSION_LIST_CUTTER_SESSIONS_STRUCTURE",
        "REA_U680_SESSION_LIST_CUTTER_SESSIONS_TEXTCOUNT",
        "REA_U680_SESSION_LIST_CUTTER_SESSIONS_COUNTS"
    }
    markers = {}
    for line in Path(raw_path).read_text(encoding="utf-8").splitlines():
        if line.startswith("REA_MOBILE_PRIVATE_RESULT_B64="):
            if private is not None:
                error("Duplicate private payload")
            private = base64.b64decode(line.split("=", 1)[1], validate=True)
        elif "=" in line:
            k, value = line.split("=", 1)
            if k in allowed_markers:
                markers[k] = value[:1500] if k == "REA_SECURE_REQUEST_PUBLIC_KEY_B64" else value[:24000] if k == "REA_MOBILE_TOOL_DESCRIPTOR_B64" else (value[:1200] if k in ("REA_AUDIT_PROVIDER_SECTIONS", "REA_AUDIT_PROVIDER_NAMES") else value[:300])
                print(k + "=" + markers[k])
    if "response_key" not in request:
        if private is not None:
            error("Unexpected private response")
        return
    if request["action"] not in ("call", "sealed_batch", "fixture_apkdemos", "fixture_portable_formats", "fixture_ghidra_metadata", "fixture_ghidra_additional", "describe", "runtime_contracts", "fixture_isolated_suppliers", "fixture_isolated_pwntools", "fixture_static_files", "fixture_static_files_v2", "fixture_managed_inputs", "fixture_managed_inputs_v2", "fixture_linux_objdump", "fixture_linux_rea_680_owner_signature_preflight", "fixture_linux_rea_680_session_gate") or private is None:
        error("Missing encrypted-return payload from REA")
    public = serialization.load_der_public_key(
        base64.b64decode(request["response_key"], validate=True)
    )
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
        error("RSA public key too short or invalid")
    result = json.loads(private)
    sealed = gzip.compress(json.dumps({
        "version": 1, "action": request["action"],
        "tool": request.get("tool", "<sealed_batch>"),
        "result": result, "markers": markers,
    }, sort_keys=True, ensure_ascii=True).encode(), compresslevel=6)
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aad = hashlib.sha256(request_raw).hexdigest().encode()
    ciphertext = AESGCM(aes_key).encrypt(nonce, sealed, aad)
    wrapped = public.encrypt(aes_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    envelope = {
        "version": 1, "algorithm": "RSA-OAEP-SHA256+A256GCM",
        "request_sha256": aad.decode(), "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    out = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    Path(envelope_path).write_bytes(out)
    print("REA_MOBILE_ENCRYPTED_RESULT=PASS")
    print("REA_MOBILE_ENCRYPTED_RESULT_BYTES=" + str(len(out)))
    log64 = base64.b64encode(out).decode()
    # Full 208-tool catalog is ~3.5MB before gzip; its authenticated envelope
    # fits below 1MB. Keep the existing log return usable by GitHub connectors
    # whose artifact file references cannot be opened by the Cloud sandbox.
    if len(log64) <= 1000000:
        parts = [log64[i:i+2600] for i in range(0, len(log64), 2600)]
        for i, part in enumerate(parts, start=1):
            print("REA_MOBILE_ENVELOPE_PART_%04d_OF_%04d=%s" %
                  (i, len(parts), part))
        print("REA_MOBILE_ENVELOPE_IN_LOG=PASS")
    else:
        print("REA_MOBILE_ENVELOPE_IN_LOG=TOO_LARGE_USE_ARTIFACT")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--envelope":
        encrypt_result(sys.argv[2], sys.argv[3], sys.argv[4])
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--validate":
        path = Path(sys.argv[2])
        if not re.fullmatch(r"[a-zA-Z0-9_.\/-]+", str(path)):
            error("Invalid request path")
        if path.stat().st_size > MAX_REQUEST:
            error("Request file too large")
        data = json.loads(path.read_text(encoding="utf-8"))
        validate(data)
        print("REA_MOBILE_REQUEST_VALID=PASS")
        print("REA_MOBILE_REQUEST_ACTION=" + data["action"])
        return
    if len(sys.argv) != 1:
        error("Unknown CLI arguments")
    # Consume before any subprocess: a large ciphertext must never be inherited
    # as one OS environment entry by openssl or a supplier probe.
    encoded = os.environ.pop("REA_MOBILE_JOB_B64", "")
    if not encoded or len(encoded) > MAX_REQUEST * 2:
        error("Missing or oversized job")
    data = json.loads(base64.b64decode(encoded, validate=True))
    validate(data)
    if os.geteuid() == 0:
        error("Never execute MCP client as root")
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "rea-android-github-bridge", "version": "0.1"},
        }
    }
    headers, initialized = request_mcp(init)
    if "result" not in initialized:
        error("MCP initialize failed")
    session = headers.get("Mcp-Session-Id")
    protocol = initialized["result"].get("protocolVersion")
    request_mcp(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session, protocol
    )
    _, catalog = request_mcp(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        session, protocol
    )
    tools = catalog.get("result", {}).get("tools")
    if not isinstance(tools, list) or not tools:
        error("MCP tool catalogue empty")
    tool_by_name = {t.get("name"): t for t in tools}
    readonly = sorted(
        name for name, t in tool_by_name.items()
        if isinstance(name, str)
        and NAME_RE.fullmatch(name)
        and not DANGEROUS_NAME_RE.search(name)
        and (t.get("annotations") or {}).get("readOnlyHint") is True
        and (t.get("annotations") or {}).get("destructiveHint") is not True
    )
    print("REA_MOBILE_LOOPBACK_MCP=PASS")
    print("REA_MOBILE_MCP_TOOL_COUNT=" + str(len(tools)))
    print("REA_MOBILE_READONLY_HINT_COUNT=" + str(len(readonly)))
    permitted_static = sorted(STATIC_INSPECT_TOOLS.intersection(tool_by_name))
    print("REA_MOBILE_STATIC_INSPECT_COUNT=" + str(len(permitted_static)))
    permitted_query = sorted(SAFE_QUERY_TOOLS.intersection(tool_by_name))
    safe_callable = sorted(set(readonly) | set(permitted_static) | set(permitted_query))
    print("REA_MOBILE_SAFE_QUERY_COUNT=" + str(len(permitted_query)))
    print("REA_MOBILE_LEGACY_NAME_COUNT=" + str(len(safe_callable)))
    safe_callable = sorted(name for name, descriptor in tool_by_name.items()
                           if secure.classify(name, descriptor, ()) == "read")
    print("REA_MOBILE_SAFE_CALLABLE_COUNT=" + str(len(safe_callable)))
    print("REA_MOBILE_WORKSPACE_CALLABLE_COUNT=" + str(sum(
        secure.classify(name, descriptor, ()) == "workspace"
        for name, descriptor in tool_by_name.items())))
    print("REA_MOBILE_SIGNATURE_REQUIRED_COUNT=" + str(sum(
        secure.classify(name, descriptor, ()) == "sensitive"
        for name, descriptor in tool_by_name.items())))
    print("REA_MOBILE_CATALOG_SAMPLE=" + json.dumps(
        list(tool_by_name)[:14], ensure_ascii=True
    ))
    if data["action"] == "fixture_linux_rea_680_owner_signature_preflight":
        # One-use, read-only preflight. Signed payload remains encrypted,
        # no nonce claimed, no import, no service restart or filesystem writes.
        if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            raise RuntimeError("Encrypted result capture required")
        body = secure.unseal(data["sealed"], data["response_key"])
        if (len(body.get("steps", [])) != 3 or
              [x.get("tool") for x in body["steps"]] !=
              ["import_evidence_bundle","get_evidence_bundle","list_unknowns"] or
              body["steps"][0].get("arguments") !=
              {"path":"/opt/rea-reversa/rea/.rea-migration/evidence-restore.json"} or
              body["steps"][1].get("arguments") != {"detail":"complete"} or
              body["steps"][2].get("arguments") != {}):
            raise RuntimeError("Signed request is not the exact 6.8.0 evidence transfer")
        profiles = secure.validate_inner(body, tool_by_name, set(safe_callable))
        if profiles != ["sensitive","read","read"]:
            raise RuntimeError("Owner signed import must remain sensitive and both verifications read-only")
        p232_guard_inner_batch(body)
        consumed = secure.key_directory() / "consumed" / body["nonce"]
        if consumed.exists() or consumed.is_symlink():
            raise RuntimeError("Owner approval nonce previously used")
        stage = Path("/opt/rea-reversa/upgrades/rea-6.8.0-160d821ac9a0")
        restore = stage / ".rea-migration/evidence-restore.json"
        backup = Path.home() / ".local/share/rea-chatgpt-trial/upgrade-backups/rea-6.7.0-retained-evidence-before-6.8.0-20261026.json"
        if (stage.is_symlink() or not (stage/"dist/mcp/main.js").is_file()
              or not backup.is_file() or backup.is_symlink()
              or hashlib.sha256(backup.read_bytes()).hexdigest() !=
              "baa448b25c2f1f2a5c76589b0a1eb4f586e20d733335eef76a9f5ed29f76b936"):
            raise RuntimeError("Pinned official staging or owner backup not ready")
        check = subprocess.run(["sudo","-n","-u","rea-reversa","sha256sum",str(restore)],
                                capture_output=True,text=True,timeout=20,check=False)
        if check.returncode or not check.stdout.startswith("f8178b2c3db0d093fa65864d9c12be9a1afe3c6d66fc93603769761bd9400f3b "):
            raise RuntimeError("Service-owned restoration checksum failed")
        print("REA_U680_OWNER_SIGNATURE_VERIFIED=PASS")
        print("REA_U680_OWNER_SIGNED_PROFILES=SIGNED_IMPORT_READ_READ")
        print("REA_U680_OWNER_REPLAY_CHECK=UNUSED")
        print("REA_U680_OWNER_RESTORE_READY=PASS")
        safe = {"owner_cryptographic_signature_verified":True,
                "profiles":profiles,"restore_sha256_verified":True,
                "one_use_nonce_unconsumed":True,"changes_applied":False}
        print("REA_MOBILE_PRIVATE_RESULT_B64="+
              base64.b64encode(json.dumps(safe,sort_keys=True).encode()).decode())
        return
    if data["action"] == "fixture_linux_rea_680_session_gate":
        # Read-only bounded check before replacing a running service.
        private_session_results={}
        names=("list_documents","list_cutter_sessions")
        for name in names:
            if name not in tool_by_name:
                print("REA_U680_SESSION_"+name.upper()+"=UNAVAILABLE")
                continue
            descriptor=tool_by_name[name]
            print("REA_U680_SESSION_"+name.upper()+"_REQUIRED="+
                  json.dumps((descriptor.get("inputSchema") or {}).get("required",[]))[:400])
            try:
                _,r=request_mcp({"jsonrpc":"2.0","id":6688,"method":"tools/call",
                   "params":{"name":name,"arguments":{}}},session,protocol,timeout=32)
                value=r.get("result",{})
                private_session_results[name]=r
                if "error" in r or value.get("isError") is True:
                    print("REA_U680_SESSION_"+name.upper()+"=MCP_ERROR")
                else:
                    sc=value.get("structuredContent")
                    print("REA_U680_SESSION_"+name.upper()+"_STRUCTURE="+
                          json.dumps(sorted(sc) if isinstance(sc,dict) else
                          type(sc).__name__)[:400])
                    lines=value.get("content",[])
                    print("REA_U680_SESSION_"+name.upper()+"_TEXTCOUNT="+str(len(lines) if isinstance(lines,list) else -1))
                    if isinstance(sc,dict):
                        print("REA_U680_SESSION_"+name.upper()+"_COUNTS="+json.dumps(
                          {k:len(v) for k,v in sc.items() if isinstance(v,list)})[:400])
                    print("REA_U680_SESSION_"+name.upper()+"=PASS_READ_ONLY")
            except (OSError,RuntimeError,ValueError,TypeError,subprocess.TimeoutExpired) as e:
                print("REA_U680_SESSION_"+name.upper()+"=PROBE_FAILED")
        if "response_key" in data:
            if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
                raise RuntimeError("Session responses require authenticated encryption")
            output=json.dumps(private_session_results,ensure_ascii=True,sort_keys=True).encode()
            if len(output)>100000:
                raise RuntimeError("Session response exceeds sealed size")
            print("REA_MOBILE_PRIVATE_RESULT_B64="+base64.b64encode(output).decode())
        return
    if data["action"] == "secure_public_key":
        print("REA_SECURE_REQUEST_PUBLIC_KEY_B64=" +
              secure.request_public_key_b64(create=True))
        return
    if data["action"] in ("fixture_managed_inputs", "fixture_managed_inputs_v2"):
        # Real Evidence prerequisites for managed graph/comparison workflows;
        # generated from the same existing source fixture as earlier PE tests.
        import tempfile
        root = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        generator = root / "scripts/fixtures/managed/pe.mjs"
        records = []
        with tempfile.TemporaryDirectory(prefix="rea-public-managed-", dir="/dev/shm") as directory:
            workspace = Path(directory)
            workspace.chmod(0o755)
            managed = workspace / "public.dll"
            script = ("import{writeFileSync}from'node:fs';"
                      "const m=await import(process.argv[1]);"
                      "writeFileSync(process.argv[2],m.buildManagedPeFixture(" + (
                          "{mvid:m.alternateMvid,methodName:'MainV2'}"
                          if data["action"] == "fixture_managed_inputs_v2" else "{}") + "));" )
            created = subprocess.run(["node", "--input-type=module", "-e", script,
                generator.as_uri(), str(managed)], capture_output=True, text=True,
                timeout=30, check=False)
            if created.returncode or not managed.is_file():
                error("Existing public managed generator failed")
            managed.chmod(0o644)
            before = hashlib.sha256(managed.read_bytes()).hexdigest()
            names = ("inspect_managed_members",) if data["action"] == "fixture_managed_inputs_v2" else (
                "inspect_managed_artifact", "inspect_managed_members", "inspect_managed_native_boundaries")
            for index, name in enumerate(names, start=710):
                args = {"path": str(managed)}
                secure.validate_arguments(tool_by_name[name], args)
                secure._authorized_target_paths(args, additional_roots=(workspace,))
                if secure.classify(name, tool_by_name[name], ()) != "workspace":
                    error("Managed static source audit mismatch")
                _, reply = request_mcp({"jsonrpc": "2.0", "id": index, "method": "tools/call",
                    "params": {"name": name, "arguments": args}}, session, protocol, timeout=90)
                result = reply.get("result")
                records.append({"tool": name, "result": result, "protocol_error": reply.get("error"),
                    "arguments_sha256": secure.arguments_sha256(args),
                    "status": "PASS" if isinstance(result, dict) and
                    result.get("isError") is not True and "error" not in reply else "ERROR"})
            unchanged = before == hashlib.sha256(managed.read_bytes()).hexdigest()
        raw = json.dumps({"records": records, "input_sha256": before, "input_unchanged": unchanged,
            "cleanup": "PASS" if not workspace.exists() else "FAIL"},
            ensure_ascii=True, sort_keys=True).encode()
        if len(raw) > MAX_RESPONSE or os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Managed Evidence requires bounded encrypted result capture")
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_TOOL_ERROR=" + str(any(r["status"] != "PASS" for r in records)).lower())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
        return
    if data["action"] in ("fixture_static_files", "fixture_static_files_v2"):
        # Fixed source-owned inputs; never a caller-selected path, URL or code.
        import tempfile
        import plistlib
        import zipfile
        records = []
        # These fixtures contain ONLY the public source literals below. The
        # system REA account cannot traverse the SSH user's private home.
        with tempfile.TemporaryDirectory(prefix="rea-public-static-", dir="/dev/shm") as directory:
            workspace = Path(directory)
            workspace.chmod(0o755)
            application = workspace / "public-js"
            application.mkdir()
            (application / "package.json").write_text(json.dumps({
                "name": "rea-public-static", "version": (
                    "1.1.0" if data["action"] == "fixture_static_files_v2" else "1.0.0"), "type": "module",
                "main": "main.js"}))
            (application / "main.js").write_text(
                "import {label} from './labels.js'; export function greet(name){return label+name;}\n")
            (application / "labels.js").write_text(
                "export const label='REA version two ';\n" if data["action"] == "fixture_static_files_v2"
                else "export const label='REA public ';\n")
            plist = workspace / "Info.plist"
            plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "org.rea.public",
                "CFBundleName": "REA controlled fixture", "CFBundleVersion": "1"}))
            evm = workspace / "public-evm.hex"
            evm.write_text("0x60003560e01c8063a9059cbb14601b57600080fd5b00\n")
            firmware = workspace / "public-firmware.bin"
            with zipfile.ZipFile(firmware, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("README.txt", "REA public controlled firmware container\n")
            tasks = (
                ("inspect_desktop_application", {"path": str(application), "detail": "complete"}),
                ("analyze_javascript_application", {"input_path": str(application), "detail": "complete"}),
                ("inspect_evm_interface", {"path": str(evm), "encoding": "hex"}),
                ("inspect_firmware_regions", {"path": str(firmware)}),
                ("open_binary", {"path": str(plist)}),
                ("inspect_plist", {}),
                ("get_evidence_bundle", {"detail": "summary"}),
            )
            if data["action"] == "fixture_static_files_v2":
                tasks = tuple(task for task in tasks if task[0] == "analyze_javascript_application")
            for path in workspace.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            hashes = {str(p.relative_to(workspace)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in workspace.rglob("*") if p.is_file()}
            open_attempted = False
            session_cleanup = "NOT_OPENED"
            try:
                for index, (name, args) in enumerate(tasks, start=600):
                    secure.validate_arguments(tool_by_name[name], args)
                    secure._authorized_target_paths(args, additional_roots=(workspace,))
                    if secure.classify(name, tool_by_name[name], safe_callable) == "sensitive":
                        error("Static fixture tool unexpectedly needs independent signature")
                    if name == "open_binary":
                        open_attempted = True
                    _, reply = request_mcp({"jsonrpc": "2.0", "id": index,
                        "method": "tools/call", "params": {"name": name, "arguments": args}},
                        session, protocol, timeout=110)
                    result = reply.get("result")
                    records.append({"tool": name, "arguments": args, "result": result,
                        "protocol_error": reply.get("error"),
                        "status": "PASS" if isinstance(result, dict) and
                        result.get("isError") is not True and "error" not in reply else "ERROR"})
            finally:
                if open_attempted:
                    _, closed = request_mcp({"jsonrpc": "2.0", "id": 699,
                        "method": "tools/call", "params": {"name": "close_binary", "arguments": {}}},
                        session, protocol, timeout=90)
                    session_cleanup = "PASS" if ("error" not in closed and
                        isinstance(closed.get("result"), dict) and
                        closed["result"].get("isError") is not True) else "FAIL"
                    if session_cleanup != "PASS":
                        error("Owned static fixture session cleanup failed")
            unchanged = all(hashlib.sha256((workspace / p).read_bytes()).hexdigest() == h
                            for p, h in hashes.items())
        payload = {"records": records, "input_sha256": hashes, "inputs_unchanged": unchanged,
                   "session_cleanup": session_cleanup,
                   "cleanup": "PASS" if not workspace.exists() else "FAIL",
                   "source": "fixed source-owned public fixtures; no target execution"}
        raw = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode()
        if len(raw) > MAX_RESPONSE or os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Static fixture requires bounded encrypted result capture")
        print("REA_MOBILE_TOOL_ERROR=" + str(any(r["status"] != "PASS" for r in records)).lower())
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
        return
    if data["action"] == "fixture_isolated_pwntools":
        # Coordinator-owned isolated dependency preparation. The engine neither
        # installs packages nor changes the system interpreter or REA service.
        import tempfile
        root = Path.home() / ".local/share/rea-chatgpt-trial"
        tools_root = root / "tools"
        final = tools_root / "pwntools-4.15.0"
        expected = {"pwntools": "4.15.0", "pyelftools": "0.33", "unicorn": "2.1.2"}
        probe_code = "import json,importlib.metadata as m;print(json.dumps({n:m.version(n) for n in ['pwntools','pyelftools','unicorn']}))"
        if final.is_symlink():
            error("Untrusted pwntools stage")
        created = False
        if not final.exists():
            with tempfile.TemporaryDirectory(prefix="pwntools-build-", dir=tools_root) as directory:
                staging = Path(directory)
                environment = staging / "environment"
                made = subprocess.run(["python3", "-m", "venv", "--without-pip", str(environment)],
                    capture_output=True, text=True, timeout=30, check=False)
                if made.returncode:
                    error("Isolated Python venv creation unavailable")
                wheel = staging / "pip-25.3-py3-none-any.whl"
                url = ("https://files.pythonhosted.org/packages/44/3c/"
                       "d717024885424591d5376220b5e836c2d5293ce2011523c9de23ff7bf068/"
                       "pip-25.3-py3-none-any.whl")
                with urllib.request.urlopen(url, timeout=45) as response:
                    raw = response.read(2000001)
                if hashlib.sha256(raw).hexdigest() != "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd":
                    error("Pinned pip wheel integrity mismatch")
                wheel.write_bytes(raw)
                python = environment / "bin/python"
                bootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
                installed = subprocess.run([str(python), "-c", bootstrap, str(wheel),
                    "install", "--disable-pip-version-check", "--no-cache-dir",
                    "--index-url", "https://pypi.org/simple", "--only-binary=:all:",
                    "pwntools==4.15.0", "pyelftools==0.33", "unicorn==2.1.2"],
                    capture_output=True, text=True, timeout=300, check=False)
                if installed.returncode:
                    # Diagnostics are fixed public package names, retained only
                    # inside the encrypted result on an installation failure.
                    raw = json.dumps({"stage": "pip_install", "returncode": installed.returncode,
                                      "stderr": installed.stderr[-12000:]}).encode()
                    print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
                    return
                probe = subprocess.run([str(python), "-c", probe_code],
                    capture_output=True, text=True, timeout=15, check=False)
                if probe.returncode or json.loads(probe.stdout) != expected:
                    error("Isolated pwntools profile mismatch")
                packages = subprocess.run([str(python), "-c", bootstrap, str(wheel), "freeze"],
                    capture_output=True, text=True, timeout=15, check=True)
                (environment / "REA-PACKAGES.txt").write_text(packages.stdout)
                environment.rename(final)
                created = True
        python = final / "bin/python"
        probe = subprocess.run([str(python), "-c", probe_code],
            capture_output=True, text=True, timeout=15, check=False)
        if probe.returncode or json.loads(probe.stdout) != expected:
            error("Existing isolated pwntools profile does not match")
        cli = Path("/opt/rea-reversa/rea/scripts/rea.mjs")
        node = root / "tools/node-24.15.0/bin/node"
        env = os.environ.copy()
        env.update({"REA_PWNTOOLS_PYTHON": str(python), "TERM": "xterm",
                    "NODE_OPTIONS": "--max-old-space-size=1024"})
        target = Path("/usr/bin/true")
        before = hashlib.sha256(target.read_bytes()).hexdigest()
        outcome = subprocess.run([str(node), str(cli), "inspect-binary-layout", str(target), "--json"],
            capture_output=True, text=True, timeout=100, check=False, env=env)
        try:
            result = json.loads(outcome.stdout)
        except ValueError:
            result = {"unparsed_stdout": outcome.stdout}
        payload = {"tool": "inspect_binary_layout", "adapter": "CLI_ISOLATED_NOT_MCP",
                   "profile": expected, "created_stage": created, "python": str(python),
                   "packages": (final / "REA-PACKAGES.txt").read_text(),
                   "returncode": outcome.returncode, "result": result, "stderr": outcome.stderr,
                   "input_sha256": before,
                   "input_unchanged": before == hashlib.sha256(target.read_bytes()).hexdigest(),
                   "production_modified": False}
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()
        if len(raw) > MAX_RESPONSE or os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Isolated binary supplier evidence needs bounded encrypted return")
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
        return
    if data["action"] == "fixture_isolated_suppliers":
        # Same installed REA CLI, short lived commands only. No new MCP,
        # listener, repository, engine installation or daemon configuration.
        import tempfile
        import sqlite3
        root = Path.home() / ".local/share/rea-chatgpt-trial"
        cli = Path("/opt/rea-reversa/rea/scripts/rea.mjs")
        node = root / "tools/node-24.15.0/bin/node"
        wabt = root / "tools/wabt-1.0.42/bin"
        if not cli.is_file() or not node.is_file():
            error("Existing REA or staged Node unavailable")
        env = os.environ.copy()
        env.update({"PATH": str(node.parent) + os.pathsep + env.get("PATH", ""),
                    "REA_WABT_BIN_DIRECTORY": str(wabt),
                    "REA_PWNTOOLS_PYTHON": str(root / "tools/pwntools-4.15.0/bin/python"),
                    "TERM": "xterm",
                    "NODE_OPTIONS": "--max-old-space-size=1024"})
        observations = []
        artifacts = root / "artifacts"
        artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supplier-fixture-", dir=artifacts) as directory:
            workspace = Path(directory)
            wasm = workspace / "public.wasm"
            wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
            database = workspace / "public.sqlite"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE fixture_items (id INTEGER PRIMARY KEY, title TEXT)")
                connection.execute("INSERT INTO fixture_items VALUES (1, 'rea-public')")
            for name, command, target, options in (
                ("inspect_wasm_artifact", "inspect-wasm-artifact", wasm, []),
                ("inspect_sqlite_database", "inspect-sqlite-database", database,
                 ["--table", "fixture_items", "--row-limit", "1"]),
                ("inspect_binary_layout", "inspect-binary-layout", Path("/usr/bin/true"), []),
            ):
                before = hashlib.sha256(target.read_bytes()).hexdigest()
                outcome = subprocess.run([str(node), str(cli), command, str(target),
                                          *options, "--json"], env=env,
                    capture_output=True, text=True, timeout=110, check=False)
                if len(outcome.stdout) + len(outcome.stderr) > MAX_RESPONSE:
                    error("Isolated supplier evidence exceeds return budget")
                try:
                    result = json.loads(outcome.stdout)
                except ValueError:
                    result = {"unparsed_stdout": outcome.stdout}
                observations.append({"tool": name, "adapter": "CLI_ISOLATED_NOT_MCP",
                    "returncode": outcome.returncode, "result": result,
                    "stderr": outcome.stderr, "input_sha256": before,
                    "input_unchanged": before == hashlib.sha256(target.read_bytes()).hexdigest()})
        payload = {"records": observations, "cleanup": "PASS" if not workspace.exists() else "FAIL",
                   "engine_cli": str(cli), "engine_cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
                   "production_modified": False}
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()
        if len(raw) > MAX_RESPONSE or os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Isolated supplier evidence needs bounded encrypted return")
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
        return
    if data["action"] == "runtime_contracts":
        # No installation or service configuration. Full live contracts and
        # bounded observations return only through the existing sealed reply.
        import importlib.util
        import shutil
        root = Path.home() / ".local/share/rea-chatgpt-trial"
        observations = {"jsonschema_available": importlib.util.find_spec("jsonschema") is not None,
                        "suppliers": {}, "executables": {}}
        for name in ("node", "python3", "adb", "frida", "gdb", "rizin",
                     "r2", "objdump", "tshark", "tcpdump", "xcrun"):
            observations["executables"][name] = shutil.which(name)
        for label, folder, binaries in (
            ("node", "node-24.15.0", ("node",)),
            ("wabt", "wabt-1.0.42", ("wasm-validate", "wasm2wat", "wasm-objdump")),
        ):
            stage = root / "tools" / folder
            entries = {}
            for name in binaries:
                executable = stage / "bin" / name
                entry = {"path": str(executable), "exists": executable.is_file(),
                         "symlink": executable.is_symlink()}
                if executable.is_file() and not executable.is_symlink():
                    entry["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
                    probe = subprocess.run([str(executable), "--version"],
                        capture_output=True, text=True, timeout=12, check=False)
                    entry.update(returncode=probe.returncode, version=probe.stdout.strip()[:100])
                entries[name] = entry
            manifest = stage / "SOURCE-SHA256.txt"
            observations["suppliers"][label] = {"binaries": entries,
                "archive_sha256": manifest.read_text().strip() if manifest.is_file() else None}
        approval = secure.key_directory() / "owner-approval-public.pem"
        observations["owner_verifier_file_present"] = approval.is_file()
        observations["owner_verifier_validated"] = False
        payload = {"tools": tools, "risk": {name: secure.classify(name, desc, safe_callable)
                   for name, desc in tool_by_name.items()}, "observations": observations,
                   "request_public_key": secure.request_public_key_b64(create=False)}
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()
        if len(raw) > MAX_RESPONSE:
            error("Full catalog exceeds encrypted return budget")
        if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Runtime contracts require encrypted result capture")
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode())
        return
    if data["action"] == "stage_dependencies":
        # Owner-approved, bounded staging only: do not alter PATH, systemd,
        # the REA daemon, or another application's installed dependencies.
        import platform
        import tempfile
        import tarfile
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
            error("Supplier staging supports only Linux x86-64")
        root = Path.home() / ".local/share/rea-chatgpt-trial/tools"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink():
            error("Untrusted supplier staging directory")
        suppliers = (
            ("NODE", "node-24.15.0",
             "https://nodejs.org/dist/v24.15.0/node-v24.15.0-linux-x64.tar.xz",
             "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6",
             36 * 1024 * 1024),
            ("WABT", "wabt-1.0.42",
             "https://github.com/WebAssembly/wabt/releases/download/"
             "1.0.42/wabt-1.0.42-linux-x64.tar.gz",
             "84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131",
             7 * 1024 * 1024),
        )
        for provider, folder, url, expected, download_limit in suppliers:
            final = root / folder
            manifest = final / "SOURCE-SHA256.txt"
            if final.exists():
                if final.is_symlink() or not manifest.is_file() or (
                    manifest.read_text(encoding="ascii").strip() != expected
                ):
                    error("Pre-existing supplier files are not a matching pinned stage")
                outcome = "ALREADY_STAGED"
            else:
                with tempfile.TemporaryDirectory(
                    prefix="rea-vendor-temp-", dir=str(root)
                ) as tempdir:
                    tmp = Path(tempdir)
                    archive = tmp / "verified-archive"
                    digest = hashlib.sha256()
                    received = 0
                    with urllib.request.urlopen(
                        urllib.request.Request(
                            url, headers={"User-Agent": "REA-fixed-supplier-staging/1"}),
                        timeout=80
                    ) as remote:
                        with archive.open("xb") as out:
                            while True:
                                chunk = remote.read(131072)
                                if not chunk:
                                    break
                                received += len(chunk)
                                if received > download_limit:
                                    error("Supplier download is larger than the fixed limit")
                                digest.update(chunk)
                                out.write(chunk)
                    if digest.hexdigest() != expected:
                        error("Supplier archive SHA-256 mismatch")
                    payload = tmp / "payload"
                    bindir = payload / "bin"
                    bindir.mkdir(mode=0o700, parents=True)
                    mandatory = (
                        {"node"} if provider == "NODE"
                        else {"wasm-validate", "wasm2wat", "wasm-objdump"}
                    )
                    extracted = set()
                    with tarfile.open(archive, "r:*") as package:
                        for entry in package:
                            parts = Path(entry.name).parts
                            if len(parts) < 3 or parts[-2] != "bin":
                                continue
                            filename = parts[-1]
                            if provider == "NODE" and filename != "node":
                                continue
                            if provider == "WABT" and (
                                not filename.startswith("wasm-") and
                                filename not in ("wasm2wat", "wat2wasm", "spectest-interp")
                            ):
                                continue
                            if (not entry.isfile() or filename in extracted or
                                    entry.size > 180 * 1024 * 1024):
                                error("Supplier archive contains invalid executable entry")
                            handle = package.extractfile(entry)
                            if handle is None:
                                error("Supplier archive contains unreadable executable")
                            target = bindir / filename
                            with target.open("xb") as output:
                                remaining = entry.size
                                while remaining:
                                    piece = handle.read(min(131072, remaining))
                                    if not piece:
                                        error("Incomplete verified supplier executable")
                                    output.write(piece)
                                    remaining -= len(piece)
                            target.chmod(0o755)
                            extracted.add(filename)
                    if not mandatory.issubset(extracted):
                        error("Pinned archive lacks required supplier tools")
                    (payload / "SOURCE-SHA256.txt").write_text(
                        expected + "\n", encoding="ascii")
                    if final.exists():
                        error("Refusing to overwrite concurrently staged supplier")
                    payload.rename(final)
                    outcome = "STAGED"
            if provider == "NODE":
                probe = subprocess.run(
                    [str(final / "bin/node"), "-e",
                     "const {DatabaseSync}=require('node:sqlite');"
                     "const db=new DatabaseSync(':memory:');"
                     "if(!db.limits||typeof db.limits!=='object'||" 
                     "typeof db.limits.length!=='number'||" 
                     "typeof db.limits.sqlLength!=='number')process.exit(3);" 
                     "db.limits.sqlLength=16384;" 
                     "if(db.limits.sqlLength!==16384)process.exit(4);"
                     "db.close();"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=14)
                if probe.returncode != 0:
                    error("Staged Node does not provide required SQLite limits API")
            else:
                probe = subprocess.run(
                    [str(final / "bin/wasm-validate"), "--version"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=14)
                if probe.returncode != 0:
                    error("Staged WABT validator did not start")
            print("REA_STAGE_" + provider + "=" + outcome)
        print("REA_STAGE_NO_SERVICE_CHANGES=PASS")
        return
    if data["action"] == "fixture_linux_read5_mcp_boundaries":
        # Run original REA real MCP tool methods against private in-memory
        # sessions with controlled evidence. No production MCP state writes.
        import shutil
        source = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        vitest = source / "node_modules/vitest/vitest.mjs"
        node = shutil.which("node")
        if not source.is_dir() or not vitest.is_file() or not node:
            print("REA_LINUX_READ5_MCP_BOUNDARIES=UNAVAILABLE_DEPENDENCIES")
            return
        git_before = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                    capture_output=True, text=True, timeout=15, check=False)
        source_rev = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                    capture_output=True, text=True, timeout=15, check=False)
        if git_before.returncode != 0 or source_rev.returncode != 0:
            error("Original staged REA source integrity check failed")
        print("REA_LINUX_READ5_SOURCE_REVISION=" + source_rev.stdout.strip()[:40])
        temporary = source / "tests/boundary/mcp/reaLinuxReadFiveFixture.test.ts"
        if temporary.exists():
            error("Isolated temporary read-5 test already exists")
        checks = (
            ("LIST_NONEMPTY", "tests/boundary/mcp/serverUnknownsMcp.test.ts",
             "pages filtered unknown heads through the public MCP contract"),
            ("EVIDENCE_BUNDLE", "tests/boundary/mcp/serverUnknownsMcp.test.ts",
             "records capture disagreement as a contradicted unknown"),
            ("COVERAGE", "tests/boundary/mcp/reconstructionCoverageMcp.test.ts",
             "evaluates inline fail-closed coverage without session retention"),
            ("RESOLUTION_MCP", "tests/boundary/mcp/reaLinuxReadFiveFixture.test.ts",
             "verifies a genuinely recorded unknown through original MCP with observed evidence"),
        )
        pass_count = 0
        try:
            temporary.write_text("import { Client, InMemoryTransport } from \"@modelcontextprotocol/client\";\nimport { expect, it } from \"vitest\";\nimport { createTestBinarySession } from \"../../fixtures/binarySession.js\";\nimport { createServer } from \"../../../src/server/createServer.js\";\nimport { createEvidence } from \"../../../src/domain/evidence.js\";\nimport { observed } from \"../../fixtures/analysisExecution.js\";\nimport { ok as resultOk } from \"../../../src/domain/result.js\";\n\nit(\"verifies a genuinely recorded unknown through original MCP with observed evidence\", async () => {\n  const session = createTestBinarySession(() => ({\n    execute: () => Promise.resolve(observed(null)),\n    close: () => Promise.resolve(resultOk(null)),\n  }));\n  const server = createServer({ kind: \"session\", session });\n  const client = new Client({ name: \"rea-linux-read5-fixture\", version: \"1\" });\n  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();\n  try {\n    await server.connect(serverTransport);\n    await client.connect(clientTransport);\n    const provider = { id: \"fixture\", name: \"Fixture\", version: \"1\" };\n    const environment = {\n      id: \"fixture-linux\", platform: \"linux\",\n      architecture: \"x86_64\", isolation: \"process\",\n    } as const;\n    const evidence = (label: string, confidence: \"observed\" | \"inferred\") =>\n      createEvidence(undefined, provider, {\n        operation: label, parameters: {}, result: { label },\n        authority: confidence === \"observed\" ? \"controlled-replay\" : \"analyst-inference\",\n        confidence, environment: confidence === \"observed\" ? environment : null,\n      });\n    const inferred = evidence(\"read-five-inferred\", \"inferred\");\n    expect(session.recordEvidence(inferred).ok).toBe(true);\n    const created = session.recordUnknown({\n      question: \"Was controlled Linux replay observed?\",\n      severity: \"high\", domain: \"read-five-certification\",\n      required_authority: \"controlled-replay\",\n      required_confidence: \"observed\",\n      required_environment: environment,\n      recommended_probes: [], relationships: [],\n      supporting_evidence_ids: [inferred.evidence_id],\n      contradicting_evidence_ids: [],\n    });\n    expect(created.ok).toBe(true);\n    if (!created.ok) throw created.error;\n    const id = created.value.unknown_id;\n    const pending = await client.callTool({\n      name: \"verify_unknown_resolution\", arguments: { unknown_id: id },\n    });\n    expect(pending.isError).not.toBe(true);\n    expect(pending.structuredContent).toMatchObject({\n      result: { valid: false, truthVerified: false },\n    });\n    const observedEvidence = evidence(\"read-five-controlled-replay\", \"observed\");\n    expect(session.recordEvidence(observedEvidence).ok).toBe(true);\n    const updated = session.updateUnknown({\n      unknown_id: id, expected_revision: created.value.revision,\n      status: \"resolved\", severity: created.value.severity,\n      supporting_evidence_ids: [inferred.evidence_id, observedEvidence.evidence_id],\n      contradicting_evidence_ids: [],\n      required_authority: \"controlled-replay\",\n      required_confidence: \"observed\",\n      required_environment: environment,\n      recommended_probes: [], relationships: [],\n      resolution: {\n        disposition: \"verified\", rationale: \"Controlled replay observed in Linux test\",\n        evidence_ids: [observedEvidence.evidence_id],\n      },\n    });\n    expect(updated.ok).toBe(true);\n    if (!updated.ok) throw updated.error;\n    const verified = await client.callTool({\n      name: \"verify_unknown_resolution\", arguments: { unknown_id: id },\n    });\n    expect(verified.isError).not.toBe(true);\n    expect(verified.structuredContent).toMatchObject({\n      result: { valid: true, truthVerified: true, unknown: { status: \"resolved\" } },\n    });\n    const absent = await client.callTool({\n      name: \"verify_unknown_resolution\", arguments: { unknown_id: \"unk_\" + \"0\".repeat(64) },\n    });\n    expect(absent.isError).toBe(true);\n    const filtered = await client.callTool({\n      name: \"list_unknowns\", arguments: { status: \"resolved\", domain: \"read-five-certification\" },\n    });\n    expect(filtered.structuredContent).toMatchObject({ result: { total: 1 } });\n  } finally {\n    await Promise.allSettled([client.close(), server.close()]);\n  }\n});\n", encoding="utf-8")
            for name, rel, title in checks:
                proc = subprocess.run(
                    [node, str(vitest), "run", rel, "-t", title,
                     "--no-file-parallelism", "--maxWorkers=1"],
                    cwd=str(source), capture_output=True, text=True, timeout=125,
                    check=False, env={**os.environ, "CI":"true", "NO_COLOR":"1",
                                      "NODE_OPTIONS":"--max-old-space-size=1024"})
                raw = proc.stdout + "\n" + proc.stderr
                clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
                ok = proc.returncode == 0 and bool(re.search(r"\b1 passed\b", clean))
                pass_count += int(ok)
                print("REA_LINUX_READ5_" + name + "=" + ("PASS" if ok else "FAIL"))
                print("REA_LINUX_READ5_" + name + "_EXIT=" + str(proc.returncode))
                print("REA_LINUX_READ5_" + name + "_SHA256=" +
                      hashlib.sha256(raw.encode()).hexdigest())
                if not ok:
                    print("REA_LINUX_READ5_" + name + "_DIAGNOSTIC=" +
                          re.sub(r"[^A-Za-z0-9 .,=_:;()\[\]/#-]", " ", clean[-1500:]))
        finally:
            temporary.unlink(missing_ok=True)
        git_after = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                   capture_output=True, text=True, timeout=15, check=False)
        intact = git_after.returncode == 0 and git_after.stdout == git_before.stdout
        print("REA_LINUX_READ5_MCP_WORKTREE=" + ("PASS" if intact else "FAIL"))
        print("REA_LINUX_READ5_MCP_PASS_COUNT=" + str(pass_count))
        print("REA_LINUX_READ5_MCP_BOUNDARIES=" +
              ("PASS_ISOLATED_MCP_NOT_PRODUCTION" if pass_count == 4 and intact else "INCOMPLETE"))
        return
    if data["action"] == "fixture_linux_read5_regression":
        # Run existing original REA test using an isolated in-memory ledger,
        # never the production server's retained Evidence or GDB sessions.
        import shutil
        source = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        test = source / "src/application/investigation/EvidenceLedger.residualUnknown.test.ts"
        runner = source / "node_modules/vitest/vitest.mjs"
        node = shutil.which("node")
        print("REA_LINUX_READ5_SOURCE_PRESENT=" + str(test.is_file()).lower())
        print("REA_LINUX_READ5_VITEST_PRESENT=" + str(runner.is_file()).lower())
        print("REA_LINUX_READ5_NODE_PRESENT=" + str(node is not None).lower())
        if not test.is_file() or not runner.is_file() or node is None:
            print("REA_LINUX_READ5_REGRESSION=UNAVAILABLE_DEPENDENCIES")
            return
        target = "rejects inference for observed resolution, then accepts matching live evidence"
        proc = subprocess.run(
            [node, str(runner), "run", str(test.relative_to(source)),
             "-t", target, "--no-file-parallelism", "--maxWorkers=1"],
            cwd=str(source), capture_output=True, text=True, timeout=140,
            env={**os.environ, "CI":"true", "NODE_OPTIONS":"--max-old-space-size=1024"},
            check=False,
        )
        combined = (proc.stdout + "\n" + proc.stderr)[-16000:]
        plain = re.sub(r"\x1b\[[0-9;]*m", "", combined)
        # The exact -t filter above selects one original REA test. Under
        # Vitest v5, its name is not necessarily echoed in the summary.
        selected = ("10 tests" in plain and "9 skipped" in plain)
        passed = (proc.returncode == 0 and
                  (bool(re.search(r"\b1 passed\b", plain)) or selected))
        print("REA_LINUX_READ5_REGRESSION=" + ("PASS" if passed else "FAIL"))
        print("REA_LINUX_READ5_EXIT_CODE=" + str(proc.returncode))
        print("REA_LINUX_READ5_TEST_OUTPUT_SHA256=" +
              hashlib.sha256(combined.encode()).hexdigest())
        print("REA_LINUX_READ5_TEST_NAME=" + target)
        print("REA_LINUX_READ5_TEST_DIAGNOSTIC=" +
              re.sub(r"[^A-Za-z0-9 .,_:;=/()\[\]#-]", " ", plain[-1200:]))
        return
    if data["action"] == "fixture_linux_gdb_read_status_states":
        # Genuine original MCP API calls via in-memory test harness using
        # an emulated GDB/MI subprocess. This is NOT a live gdb binary test.
        import shutil
        source = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        vitest = source / "node_modules/vitest/vitest.mjs"
        node = shutil.which("node")
        if not source.is_dir() or not vitest.is_file() or node is None:
            print("REA_LINUX_GDB_STATUS_STATES=UNAVAILABLE_DEPENDENCIES")
            return
        tests = (
            ("READY", "accepts caller-selected inferior_tty and exposes verified sink status through MCP"),
            ("LOSSY", "exposes lossy GDB MI decoding through the strict status MCP contract"),
        )
        revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=12, check=False)
        before = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=12, check=False)
        if revision.returncode != 0 or before.returncode != 0:
            error("Original staged REA source unavailable")
        print("REA_LINUX_GDB_STATES_SOURCE=" + revision.stdout.strip()[:40])
        passed = 0
        for name, title in tests:
            p = subprocess.run(
                [node, str(vitest), "run", "tests/boundary/mcp/gdbCancellationMcp.test.ts",
                 "-t", title, "--no-file-parallelism", "--maxWorkers=1"],
                cwd=str(source), capture_output=True, text=True,
                timeout=125, check=False, env={**os.environ, "CI":"true",
                "NO_COLOR":"1", "NODE_OPTIONS":"--max-old-space-size=1024"})
            raw = p.stdout + "\n" + p.stderr
            plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
            ok = p.returncode == 0 and bool(re.search(r"\b1 passed\b", plain))
            passed += int(ok)
            print("REA_LINUX_GDB_STATES_" + name + "=" + ("PASS" if ok else "FAIL"))
            print("REA_LINUX_GDB_STATES_" + name + "_EXIT=" + str(p.returncode))
            print("REA_LINUX_GDB_STATES_" + name + "_SHA256=" +
                  hashlib.sha256(raw.encode()).hexdigest())
            if not ok:
                print("REA_LINUX_GDB_STATES_" + name + "_DIAGNOSTIC=" +
                      re.sub(r"[^A-Za-z0-9 .,=_:;()\[\]/#-]", " ", plain[-1100:]))
        after = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=12, check=False)
        intact = after.returncode == 0 and after.stdout == before.stdout
        print("REA_LINUX_GDB_STATES_WORKTREE=" + ("PASS" if intact else "FAIL"))
        print("REA_LINUX_GDB_STATES_BINARY_IN_PATH=" + str(shutil.which("gdb") is not None).lower())
        print("REA_LINUX_GDB_STATUS_STATES=" +
              ("PASS_EMULATED_GDB_MI_ONLY" if passed == 2 and intact else "INCOMPLETE"))
        return
    if data["action"] == "fixture_linux_gdb_real_provider":
        # Rootless GDB from the distro's configured verified apt package list.
        # Extract and test inside a temporary owner-controlled path ONLY.
        # Original MCP daemon and installed OS libraries remain unchanged.
        import shutil
        import tempfile
        if not (shutil.which("apt-get") and shutil.which("dpkg-deb")):
            print("REA_LINUX_GDB_REAL_STATUS=UNAVAILABLE_LOCAL_PACKAGE_TOOLS")
            return
        root = Path.home() / ".local/share/rea-chatgpt-trial"
        source = root / "repository/rea"
        vitest = source / "node_modules/vitest/vitest.mjs"
        node = shutil.which("node")
        if not source.is_dir() or not vitest.is_file() or not node:
            print("REA_LINUX_GDB_REAL_STATUS=UNAVAILABLE_SOURCE_DEPS")
            return
        before = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=12, check=False)
        revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=12, check=False)
        if before.returncode != 0 or revision.returncode != 0:
            error("Original REA source provenance verification failed")
        print("REA_LINUX_GDB_REAL_REA_SOURCE=" + revision.stdout.strip()[:40])
        staging = root / "artifacts"
        staging.mkdir(parents=True, mode=0o700, exist_ok=True)
        fixed_test = source / "tests/boundary/mcp/reaLinuxRealGdbReadStatus.test.ts"
        if fixed_test.exists():
            error("Refusing to overwrite existing staged REA test source")
        result = "INCOMPLETE"
        try:
            with tempfile.TemporaryDirectory(prefix="rea-real-gdb-", dir=str(staging)) as dirname:
                temp = Path(dirname)
                dl = subprocess.run(["apt-get", "download", "gdb"], cwd=str(temp),
                                    capture_output=True, text=True, timeout=115, check=False,
                                    env={**os.environ, "DEBIAN_FRONTEND":"noninteractive"})
                packages = list(temp.glob("gdb_*.deb"))
                if dl.returncode != 0 or len(packages) != 1 or packages[0].stat().st_size > 30*1024*1024:
                    print("REA_LINUX_GDB_REAL_DOWNLOAD=FAIL")
                    print("REA_LINUX_GDB_REAL_DIAGNOSTIC=" +
                          re.sub(r"[^A-Za-z0-9 .,=_:;()/\\#-]", " ",
                                 (dl.stdout+" "+dl.stderr)[-450:]))
                    result = "UNAVAILABLE_PACKAGE_DOWNLOAD"
                else:
                    package = packages[0]
                    print("REA_LINUX_GDB_REAL_PACKAGE_SHA256=" + hashlib.sha256(package.read_bytes()).hexdigest())
                    unpack = temp / "unpacked"
                    p = subprocess.run(["dpkg-deb", "-x", str(package), str(unpack)],
                                       capture_output=True, text=True, timeout=30, check=False)
                    gdb = unpack / "usr/bin/gdb"
                    print("REA_LINUX_GDB_REAL_EXTRACT=" + ("PASS" if p.returncode == 0 and gdb.is_file() else "FAIL"))
                    if p.returncode == 0 and gdb.is_file():
                        # Resolve only missing shared libraries from the
                        # host distro's signed, configured package metadata.
                        # dpkg-deb extracts into this temporary directory only.
                        local_env = os.environ.copy()
                        dl_map = {
                            "libbabeltrace.so.1":"libbabeltrace1",
                            "libbabeltrace-ctf.so.1":"libbabeltrace1",
                            "libdebuginfod.so.1":"libdebuginfod1t64",
                            "libipt.so.2":"libipt2",
                            "libsource-highlight.so.4":"libsource-highlight4t64",
                            "libboost_regex.so.1.83.0":"libboost-regex1.83.0",
                            "libpython3.12.so.1.0":"libpython3.12",
                            "libpopt.so.0":"libpopt0",
                            "libunistring.so.5":"libunistring5",
                            "libdw.so.1":"libdw1",
                            "libelf.so.1":"libelf1",
                        }
                        staged_packages = set()
                        staged_path = unpack / "usr/lib/x86_64-linux-gnu"
                        local_env["LD_LIBRARY_PATH"] = str(staged_path) + os.pathsep + local_env.get("LD_LIBRARY_PATH", "")
                        for _ in range(4):
                            scan = subprocess.run(["ldd", str(gdb)], capture_output=True,
                                                  text=True, timeout=20, check=False, env=local_env)
                            missing = sorted(set(re.findall(
                                r"^\s*([^\s]+)\s*=>\s*not found",
                                scan.stdout, flags=re.MULTILINE)))
                            if not missing:
                                break
                            unknown = [lib for lib in missing if lib not in dl_map]
                            if unknown:
                                print("REA_LINUX_GDB_REAL_MISSING_LIBS=" + json.dumps(unknown[:10]))
                                break
                            needed = sorted({dl_map[lib] for lib in missing} - staged_packages)
                            if not needed or len(staged_packages) + len(needed) > 12:
                                break
                            for pkg_name in needed:
                                dl_dep = subprocess.run(["apt-get", "download", pkg_name],
                                                       cwd=str(temp), capture_output=True,
                                                       text=True, timeout=85, check=False)
                                matches = sorted(temp.glob(pkg_name + "_*.deb"))
                                if (dl_dep.returncode != 0 or len(matches) != 1 or
                                        matches[0].stat().st_size > 20*1024*1024):
                                    print("REA_LINUX_GDB_REAL_DEP_ERROR=" + pkg_name)
                                    break
                                dep_extract = subprocess.run(
                                    ["dpkg-deb", "-x", str(matches[0]), str(unpack)],
                                    capture_output=True, text=True, timeout=25, check=False)
                                if dep_extract.returncode != 0:
                                    print("REA_LINUX_GDB_REAL_DEP_ERROR=" + pkg_name)
                                    break
                                staged_packages.add(pkg_name)
                        print("REA_LINUX_GDB_REAL_STAGED_DEPS=" +
                              json.dumps(sorted(staged_packages)))
                        g = subprocess.run([str(gdb), "--version"], capture_output=True, text=True,
                                           timeout=30, check=False, env=local_env)
                        print("REA_LINUX_GDB_REAL_BINARY_SHA256=" + hashlib.sha256(gdb.read_bytes()).hexdigest())
                        if g.returncode != 0 or "GNU gdb" not in g.stdout:
                            print("REA_LINUX_GDB_REAL_BINARY_CHECK=UNAVAILABLE")
                            print("REA_LINUX_GDB_REAL_DIAGNOSTIC=" +
                                  re.sub(r"[^A-Za-z0-9 .,=_:;()/\\#-]", " ", g.stderr[-700:]))
                            result = "UNAVAILABLE_RUNTIME_LIBRARIES"
                        else:
                            print("REA_LINUX_GDB_REAL_BINARY_CHECK=PASS")
                            print("REA_LINUX_GDB_REAL_VERSION=" +
                                  re.sub(r"[^A-Za-z0-9 .()/-]", " ", g.stdout.splitlines()[0])[:120])
                            fixed_test.write_text("import { Client, InMemoryTransport } from \"@modelcontextprotocol/client\";\nimport { McpServer } from \"@modelcontextprotocol/server\";\nimport { expect, it } from \"vitest\";\nimport { GdbSessionManager } from \"../../../src/gdb/GdbSessionManager.js\";\nimport { registerGdbTools } from \"../../../src/server/registerGdbTools.js\";\nimport { createToolResultDelivery } from \"../../../src/server/toolResult.js\";\nimport { silentLogger } from \"../../../src/logger.js\";\n\nit(\"observes a genuine Linux GDB session state via the original MCP contract\", async () => {\n  const binary = process.env.REA_GDB_REAL_FIXTURE_BINARY;\n  expect(binary).toBeTruthy();\n  const manager = new GdbSessionManager({\n    platform: \"linux\",\n    environment: { ...process.env, REA_GDB_COMMAND: binary },\n    startupTimeoutMs: 25000, commandTimeoutMs: 25000,\n  });\n  const server = new McpServer({ name: \"rea-linux-real-gdb\", version: \"1\" });\n  registerGdbTools(server, manager, silentLogger, createToolResultDelivery(undefined));\n  const client = new Client({ name: \"rea-linux-real-gdb-client\", version: \"1\" });\n  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();\n  try {\n    await server.connect(serverTransport);\n    await client.connect(clientTransport);\n    const started = await client.callTool({ name: \"start_gdb_session\", arguments: {} });\n    expect(started.isError, JSON.stringify(started)).not.toBe(true);\n    const id = (started.structuredContent as { session_id?: string }).session_id;\n    expect(id).toMatch(/^[0-9a-f-]{36}$/);\n    if (!id) throw new Error(\"No genuine GDB session ID\");\n    const status = await client.callTool({ name: \"gdb_session_status\", arguments: { session_id: id } });\n    expect(status.isError, JSON.stringify(status)).not.toBe(true);\n    expect(status.structuredContent).toMatchObject({\n      session_id: id,\n      state: \"ready\",\n      mi_invalid_utf8: false,\n      inferior_tty: null,\n      inferior_tty_verified: false,\n    });\n    const content = status.structuredContent as Record<string, unknown>;\n    expect([\"mi3\", \"mi2\"]).toContain(content.mi_version);\n    expect(Array.isArray(content.recent_mi_records)).toBe(true);\n    expect(typeof content.stderr).toBe(\"string\");\n    expect(content.diagnostics_truncated).toBe(false);\n    const closed = await client.callTool({ name: \"close_gdb_session\", arguments: { session_id: id } });\n    expect(closed.isError, JSON.stringify(closed)).not.toBe(true);\n    const absent = await client.callTool({ name: \"gdb_session_status\", arguments: { session_id: id } });\n    expect(absent.isError).toBe(true);\n  } finally {\n    await Promise.allSettled([client.close(), server.close()]);\n    await manager.closeAll().catch(() => undefined);\n  }\n});\n", encoding="utf-8")
                            q = subprocess.run(
                              [node, str(vitest), "run", str(fixed_test.relative_to(source)),
                               "-t", "observes a genuine Linux GDB session state via the original MCP contract",
                               "--no-file-parallelism", "--maxWorkers=1"],
                              cwd=str(source), capture_output=True, text=True, timeout=125,
                              check=False, env={**os.environ, "CI":"true", "NO_COLOR":"1",
                                "REA_GDB_REAL_FIXTURE_BINARY":str(gdb),
                                "LD_LIBRARY_PATH":local_env["LD_LIBRARY_PATH"],
                                "NODE_OPTIONS":"--max-old-space-size=1024"})
                            out = q.stdout + "\n" + q.stderr
                            plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out)
                            passed = q.returncode == 0 and bool(re.search(r"\b1 passed\b", plain))
                            print("REA_LINUX_GDB_REAL_TEST_EXIT=" + str(q.returncode))
                            print("REA_LINUX_GDB_REAL_TEST_SHA256=" + hashlib.sha256(out.encode()).hexdigest())
                            print("REA_LINUX_GDB_REAL_TEST=" + ("PASS" if passed else "FAIL"))
                            if not passed:
                                print("REA_LINUX_GDB_REAL_DIAGNOSTIC=" +
                                      re.sub(r"[^A-Za-z0-9 .,=_:;()/\\#-]", " ", plain[-900:]))
                            result = "PASS_REAL_GDB_ISOLATED_MCP" if passed else "FAIL_REAL_GDB_TEST"
        finally:
            fixed_test.unlink(missing_ok=True)
        after = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=12, check=False)
        print("REA_LINUX_GDB_REAL_SOURCE_UNCHANGED=" + str(
            after.returncode == 0 and after.stdout == before.stdout).lower())
        print("REA_LINUX_GDB_REAL_STATUS=" + result)
        return
    if data["action"] == "fixture_linux_gdb_provider_probe":
        # Query OS-native GDB availability without system package writes.
        import shutil
        import platform
        import glob
        print("REA_LINUX_GDB_PROBE_PLATFORM=" + str(platform.system()))
        print("REA_LINUX_GDB_PROBE_ARCH=" + str(platform.machine()))
        release = {}
        os_release = Path("/etc/os-release")
        if os_release.is_file():
            for line in os_release.read_text(errors="replace").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k in ("ID", "VERSION_ID", "ID_LIKE"):
                        release[k] = v.strip('"').strip("'")
        print("REA_LINUX_GDB_PROBE_DISTRO=" + json.dumps(release, sort_keys=True))
        print("REA_LINUX_GDB_PROBE_PATH=" + str(shutil.which("gdb") or "NOT_FOUND"))
        print("REA_LINUX_GDB_PROBE_FIXED_FILES=" + json.dumps(
            {p: Path(p).is_file() for p in
             ("/usr/bin/gdb", "/bin/gdb", "/usr/local/bin/gdb",
              "/usr/bin/gdb-multiarch", "/usr/bin/lldb")}, sort_keys=True))
        print("REA_LINUX_GDB_PROBE_MANAGERS=" + json.dumps(
            {p: bool(shutil.which(p)) for p in
             ("apt-cache", "apt-get", "dpkg-deb", "rpm", "dnf", "pacman", "tar", "ldd")},
            sort_keys=True))
        if shutil.which("apt-cache"):
            result = subprocess.run(["apt-cache", "policy", "gdb"],
                                    capture_output=True, text=True, timeout=18, check=False)
            text = result.stdout.strip()
            # Only show bounded package version info; no private local sources.
            sanitized = [line.strip() for line in text.splitlines()
                         if "Installed:" in line or "Candidate:" in line]
            print("REA_LINUX_GDB_PROBE_REPO=" + json.dumps(sanitized[:4]))
        print("REA_LINUX_GDB_PROBE_AUDIT=PASS_READ_ONLY")
        return
    if data["action"] == "fixture_linux_gdb_conformance":
        # Run source-owned REA GDB tests in isolated Linux processes only.
        # The test uses an explicit emulated MI provider, not the real gdb
        # executable or a production MCP session. No production writes.
        import shutil
        source = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        vitest = source / "node_modules/vitest/vitest.mjs"
        node = shutil.which("node")
        if not source.is_dir() or not vitest.is_file() or not node:
            print("REA_LINUX_GDB_CONFORMANCE_STATUS=UNAVAILABLE_DEPENDENCIES")
            return
        revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False)
        initial = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, check=False)
        if revision.returncode != 0 or initial.returncode != 0:
            error("Original REA staged source provenance unavailable")
        print("REA_LINUX_GDB_CONFORMANCE_SOURCE=" + revision.stdout.strip()[:40])
        tests = (
            ("MANAGER", "tests/boundary/providers/GdbSessionManagers.test.ts",
             "runs a correlated GDB MI command, reports status, and closes its owned process"),
            ("MCP", "tests/boundary/mcp/gdbCancellationMcp.test.ts",
             "propagates MCP cancellation into a running GDB command"),
        )
        passed_all = True
        for name, file, selected in tests:
            if not (source / file).is_file():
                error("Original REA GDB source test missing")
            proc = subprocess.run(
                [node, str(vitest), "run", file, "-t", selected,
                 "--no-file-parallelism", "--maxWorkers=1"],
                cwd=str(source), capture_output=True, text=True,
                timeout=110, check=False, env={**os.environ,
                    "CI":"true", "NO_COLOR":"1", "NODE_OPTIONS":"--max-old-space-size=1024"})
            raw = proc.stdout + "\n" + proc.stderr
            plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
            ok = proc.returncode == 0 and bool(re.search(r"\b1 passed\b", plain))
            passed_all = passed_all and ok
            print("REA_LINUX_GDB_" + name + "_EXIT=" + str(proc.returncode))
            print("REA_LINUX_GDB_" + name + "_RESULT=" + ("PASS" if ok else "FAIL"))
            print("REA_LINUX_GDB_" + name + "_SHA256=" +
                  hashlib.sha256(raw.encode()).hexdigest())
        final = subprocess.run(["git", "-C", str(source), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, check=False)
        unchanged = final.returncode == 0 and final.stdout == initial.stdout
        print("REA_LINUX_GDB_CONFORMANCE_WORKTREE=" +
              ("PASS" if unchanged else "FAIL"))
        print("REA_LINUX_GDB_CONFORMANCE_COUNT=2")
        print("REA_LINUX_GDB_CONFORMANCE_STATUS=" +
              ("PASS_MOCKED_PROVIDER_ONLY" if passed_all and unchanged
               else "FAIL"))
        return
    if data["action"] == "fixture_linux_doctor_readiness":
        # Read-only original REA doctor. Only bounded metadata/status, not
        # local paths, usernames, credentials, commands, or captured content.
        import shutil
        cli = Path("/opt/rea-reversa/rea/scripts/rea.mjs")
        node = shutil.which("node")
        if not cli.is_file() or not node:
            print("REA_DOCTOR_LINUX_STATUS=UNAVAILABLE_CORE")
            return
        proc=subprocess.run(
            [node, str(cli), "doctor", "--json"],
            capture_output=True,text=True,timeout=110,check=False,
            env={**os.environ,"NO_COLOR":"1","NODE_OPTIONS":"--max-old-space-size=1024"})
        print("REA_DOCTOR_LINUX_EXIT=" + str(proc.returncode))
        if not proc.stdout or len(proc.stdout)>500000:
            print("REA_DOCTOR_LINUX_STATUS=UNAVAILABLE_RESULT")
            return
        try:
            val=json.loads(proc.stdout)
        except ValueError:
            print("REA_DOCTOR_LINUX_STATUS=INVALID_JSON")
            return
        print("REA_DOCTOR_LINUX_JSON_SHA256=" +
              hashlib.sha256(proc.stdout.encode()).hexdigest())
        if isinstance(val,dict):
            print("REA_DOCTOR_LINUX_KEYS=" +
                  json.dumps(sorted(str(k) for k in val.keys())[:35]))
            checks=val.get("checks")
            if isinstance(checks,list):
                summary=[{"name":str(z.get("name",""))[:90],
                          "ok":z.get("ok") is True,
                          "classification":str(z.get("classification","unknown"))[:45]}
                         for z in checks[:40] if isinstance(z,dict)]
                print("REA_DOCTOR_LINUX_CHECKS="+json.dumps(summary,separators=(",",":")))
                for i in range(0,len(summary),3):
                    print("REA_DOCTOR_LINUX_CHECK_GROUP"+str(i//3+1)+"="+json.dumps(summary[i:i+3],separators=(",",":")))
            providers=val.get("providerInspections")
            if isinstance(providers,list):
                summary=[]
                for entry in providers[:20]:
                    if not isinstance(entry,dict):
                        continue
                    summary.append({
                        "id":str(entry.get("id",""))[:45],
                        "configured":entry.get("configured") is True,
                        "available":entry.get("available") is True,
                        "checks":[{"name":str(c.get("name",""))[:60],
                                   "ok":c.get("ok") is True,
                                   "classification":str(c.get("classification",""))[:35]}
                                  for c in entry.get("checks",[])[:12]
                                  if isinstance(c,dict)]
                    })
                print("REA_DOCTOR_LINUX_PROVIDERS="+json.dumps(summary,separators=(",",":")))
                for i,entry in enumerate(summary[:12]):
                    print("REA_DOCTOR_LINUX_PROVIDER"+str(i+1)+"="+json.dumps({"id":entry["id"],"configured":entry["configured"],"available":entry["available"],"failed_checks":sum(1 for c in entry["checks"] if not c["ok"])},separators=(",",":")))
            print("REA_DOCTOR_LINUX_HEALTH="+json.dumps({
                "healthy":val.get("healthy"),"environment_healthy":val.get("environment_healthy")}))
            def safe_statuses(v,depth=0):
                if depth>3:
                    return "nested"
                if isinstance(v,dict):
                    filtered={}
                    for k,z in v.items():
                        name=str(k)
                        if len(filtered)>=35:
                            break
                        if re.search(r"token|secret|key|path|environment|command|user|host|uri|url", name,re.I):
                            continue
                        if isinstance(z,bool):
                            filtered[name]=z
                        elif isinstance(z,str) and name in ("status","state","healthy","availability"):
                            filtered[name]=z[:80]
                        elif isinstance(z,(dict,list)):
                            filtered[name]=safe_statuses(z,depth+1)
                    return filtered
                if isinstance(v,list):
                    return {"count":len(v),"sample":[safe_statuses(z,depth+1) for z in v[:8]]}
                return type(v).__name__
            print("REA_DOCTOR_LINUX_SAFE_SUMMARY=" +
                  json.dumps(safe_statuses(val),sort_keys=True)[:9000])
        print("REA_DOCTOR_LINUX_STATUS=" +
              ("PASS_READ_ONLY" if proc.returncode==0 else "DOCTOR_FOUND_READINESS_ISSUES"))
        return
    if data["action"] == "fixture_linux_unblob_persistent":
        # Official SHA-pinned unblob wheel in dedicated Linux service-owned venv.
        # No global Python changes and no other REA/process restarts.
        import pwd
        import grp
        import shutil
        import tempfile
        installed=Path("/opt/rea-reversa/providers/unblob-26.6.4")
        entry=installed/"bin/unblob"
        # Provider directory is 0750 and belongs to the REA service user:
        # the SSH transport account MUST NOT inspect it directly.
        existing=subprocess.run(["sudo","-n","-u","rea-reversa",
                                 "test","-f",str(entry)],
                                capture_output=True,timeout=12,check=False)
        if existing.returncode==0:
            p=subprocess.run(["sudo","-n","-u","rea-reversa",
                              str(entry),"--version"],capture_output=True,
                             text=True,timeout=25,check=False)
            print("REA_UNBLOB_ALREADY_INSTALLED="+str(p.returncode==0).lower())
            print("REA_UNBLOB_STATUS="+("PASS_PERSISTENT_LINUX"
                  if p.returncode==0 else "EXISTING_EXECUTABLE_UNHEALTHY"))
            return
        try:
            account=pwd.getpwnam("rea-reversa")
        except KeyError:
            error("Original REA systemd service account missing")
        group=grp.getgrgid(account.pw_gid).gr_name
        parent=Path("/opt/rea-reversa/providers")
        if parent.is_symlink() or installed.is_symlink():
            error("Untrusted REA service provider path")
        for folder,perms in ((parent,"0755"),(installed,"0750")):
            mk=subprocess.run(["sudo","-n","install","-d","-m",perms,
                              "-o","rea-reversa","-g",group,str(folder)],
                              capture_output=True,text=True,timeout=15,check=False)
            if mk.returncode:
                error("Cannot create dedicated REA provider directory")
        venv=subprocess.run(["sudo","-n","-u","rea-reversa","/usr/bin/python3",
                            "-m","venv",str(installed)],capture_output=True,
                            text=True,timeout=65,check=False)
        if venv.returncode:
            print("REA_UNBLOB_STATUS=VENV_CREATION_FAILED")
            return
        url=("https://github.com/onekey-sec/unblob/releases/download/26.6.4/"
             "unblob-26.6.4-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
        digest="0fc16e9c7dc92fcf86b8b61475700c9dd16e1dddacf34467574ea965a5d3584e"
        local=installed/"unblob-official.whl"
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"REA-Linux-provider-verification/1"})
            with urllib.request.urlopen(req,timeout=65) as source:
                chunks=[];size=0
                while True:
                    data=source.read(65536)
                    if not data: break
                    size+=len(data)
                    if size>3*1024*1024:
                        error("Pinned unblob wheel unexpectedly large")
                    chunks.append(data)
            wheel=b"".join(chunks)
            sha=hashlib.sha256(wheel).hexdigest()
            print("REA_UNBLOB_WHEEL_SHA256="+sha)
            if sha!=digest:
                error("Pinned unblob official wheel checksum mismatched")
            # pip requires valid wheel naming; do not add/modify arbitrary files.
            wheelname="unblob-26.6.4-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
            target=installed/wheelname
            # Copy wheel into directory accessible only to REA service identity.
            temp=Path.home()/".local/share/rea-chatgpt-trial/artifacts"
            temp.mkdir(mode=0o700,parents=True,exist_ok=True)
            staging=temp/wheelname
            if staging.exists():
                error("Fixed wheel staging path unexpectedly occupied")
            staging.write_bytes(wheel)
            try:
                cp=subprocess.run(["sudo","-n","install","-m","0640",
                    "-o","rea-reversa","-g",group,str(staging),str(target)],
                    capture_output=True,text=True,timeout=20,check=False)
                if cp.returncode:
                    error("Failed to stage wheel in private REA service directory")
            finally:
                staging.unlink(missing_ok=True)
            cmd=["sudo","-n","-u","rea-reversa","env","PIP_NO_CACHE_DIR=1",
                 "PIP_DISABLE_PIP_VERSION_CHECK=1","PIP_NO_INPUT=1",
                 str(installed/"bin/python"),"-m","pip","install",
                 "--no-input","--disable-pip-version-check",str(target)]
            pip=subprocess.run(cmd,capture_output=True,text=True,timeout=380,
                               check=False)
            print("REA_UNBLOB_PIP_EXIT="+str(pip.returncode))
            print("REA_UNBLOB_PIP_SHA256="+hashlib.sha256(
                (pip.stdout+"\n"+pip.stderr).encode()).hexdigest())
            if pip.returncode:
                print("REA_UNBLOB_STATUS=PIP_DEPENDENCIES_FAILED")
                return
            check=subprocess.run(["sudo","-n","-u","rea-reversa",str(entry),
                                  "--version"],capture_output=True,
                                  text=True,timeout=32,check=False)
            print("REA_UNBLOB_EXEC_EXIT="+str(check.returncode))
            print("REA_UNBLOB_STATUS="+(
                "PASS_PERSISTENT_LINUX" if check.returncode==0 else
                "UNAVAILABLE_AFTER_INSTALL"))
        finally:
            # The service-owned provider directory is 0750. Only sudo may
            # traverse it. Remove this exact transient wheel without probing
            # via the unprivileged SSH account (previously raised EACCES).
            target=installed/"unblob-26.6.4-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
            cleanup=subprocess.run(["sudo","-n","rm","-f","--",str(target)],
                capture_output=True,timeout=15,check=False)
            print("REA_UNBLOB_TRANSIENT_CLEANUP="+
                  ("PASS" if cleanup.returncode==0 else "FAIL"))
        return
    if data["action"] == "fixture_linux_rizin_persistent":
        # Official checksum-pinned Rizin Linux static binary, under existing
        # REA prefix. No apt changes, systemd reloads or other projects.
        import shutil
        import tempfile
        import tarfile
        import platform
        import os as operating_system
        if platform.system()!="Linux" or platform.machine()!="x86_64":
            error("Unsupported host for pinned Rizin x86_64 asset")
        final=Path("/opt/rea-reversa/providers/rizin-v0.9.1")
        asset="https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz"
        expected="9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf"
        if final.exists():
            q=final/"bin/rizin"
            print("REA_RIZIN_ALREADY_PRESENT="+str(q.is_file()).lower())
            if q.is_file():
                version=subprocess.run([str(q),"-v"],capture_output=True,
                    text=True,timeout=18,check=False)
                print("REA_RIZIN_VERSION_EXIT="+str(version.returncode))
            print("REA_RIZIN_STATUS=EXISTING_NO_OVERWRITE")
            return
        base=Path.home()/".local/share/rea-chatgpt-trial/artifacts"
        base.mkdir(parents=True,mode=0o700,exist_ok=True)
        if base.is_symlink():
            error("Unsafe vendor staging path")
        names={"rizin","rz-bin","rz-asm","rz-diff","rz-find",
               "rz-hash","rz-pm","rz-run"}
        with tempfile.TemporaryDirectory(dir=str(base),prefix="rizin-release-") as td:
            p=Path(td);archive=p/"release.tar.xz"
            sha=hashlib.sha256()
            received=0
            req=urllib.request.Request(asset,headers={"User-Agent":"REA-Linux-provider-certification/1"})
            with urllib.request.urlopen(req,timeout=85) as source:
                with archive.open("xb") as out:
                    while True:
                        data=source.read(256*1024)
                        if not data:
                            break
                        received+=len(data)
                        if received>155*1024*1024:
                            error("Rizin official asset exceeds size cap")
                        out.write(data);sha.update(data)
            print("REA_RIZIN_ARCHIVE_BYTES="+str(received))
            print("REA_RIZIN_ARCHIVE_SHA256="+sha.hexdigest())
            if sha.hexdigest()!=expected:
                error("Official Rizin checksum validation failed")
            stage=p/"bin";stage.mkdir(mode=0o700)
            extracted=[]
            with tarfile.open(archive,"r:xz") as pkg:
                for member in pkg:
                    parts=Path(member.name).parts
                    if (".." in parts or len(parts)<2 or
                        parts[-1] not in names or not member.isfile() or
                        "bin" not in parts[:-1]):
                        continue
                    if member.size>160*1024*1024:
                        error("Pinned Rizin archive contains oversized executable")
                    source=pkg.extractfile(member)
                    if source is None or parts[-1] in extracted:
                        error("Unexpected Rizin archive member")
                    target=stage/parts[-1]
                    with target.open("xb") as dest:
                        shutil.copyfileobj(source,dest,length=256*1024)
                    target.chmod(0o755)
                    extracted.append(parts[-1])
            print("REA_RIZIN_BINARIES="+json.dumps(sorted(extracted)))
            if "rizin" not in extracted:
                print("REA_RIZIN_STATUS=UNRECOGNIZED_ARCHIVE_LAYOUT")
                return
            check=subprocess.run([str(stage/"rizin"),"-v"],
                 capture_output=True,text=True,timeout=22,check=False)
            print("REA_RIZIN_VERIFIED_EXIT="+str(check.returncode))
            if check.returncode!=0:
                print("REA_RIZIN_STATUS=UNRUNNABLE_PINNED_BINARY")
                return
            # Only deploy verified executables beneath REA's dedicated prefix.
            for folder in ("/opt/rea-reversa/providers",str(final),str(final/"bin")):
                mk=subprocess.run(["sudo","-n","install","-d","-m","0755",
                    "-o","root","-g","root",folder],capture_output=True,
                    text=True,timeout=12,check=False)
                if mk.returncode!=0:
                    error("Cannot install in original REA provider-only directory")
            for name in extracted:
                copy=subprocess.run(["sudo","-n","install","-m","0755",
                    "-o","root","-g","root",str(stage/name),str(final/"bin"/name)],
                    capture_output=True,text=True,timeout=25,check=False)
                if copy.returncode!=0:
                    error("Rizin binary install failed")
            installed=subprocess.run([str(final/"bin/rizin"),"-v"],
                    capture_output=True,text=True,timeout=15,check=False)
            print("REA_RIZIN_INSTALLED="+str(installed.returncode==0).lower())
            print("REA_RIZIN_VERSION="+
                  (installed.stdout or installed.stderr).splitlines()[0][:110])
            print("REA_RIZIN_STATUS="+(
                "PASS_PINNED_PERSISTENT" if installed.returncode==0 else "INCOMPLETE"))
        return
    if data["action"] == "fixture_linux_service_unit_diagnose":
        # Read-only, classify original service wiring without printing secrets.
        import re as regex
        unit="rea-reversa-mcp.service"
        keys=("User","Type","MainPID","FragmentPath","DropInPaths",
              "EnvironmentFiles","PassEnvironment","UnsetEnvironment","Environment","ExecStart")
        values={}
        for name in keys:
            p=subprocess.run(["systemctl","show",unit,"-p",name,"--value"],
                             capture_output=True,text=True,timeout=12,check=False)
            values[name]=p.stdout.strip() if p.returncode==0 else ""
        command=values["ExecStart"]
        config=values["Environment"]
        keys_present=sorted(set(regex.findall(r"(?:^| )([A-Za-z_][A-Za-z0-9_]*)=",config)))
        print("REA_SDIAG_IDENTITY="+str(values["User"]=="rea-reversa").lower())
        print("REA_SDIAG_TYPE="+values["Type"][:30])
        print("REA_SDIAG_DROPIN="+str(bool(values["DropInPaths"])).lower())
        print("REA_SDIAG_ENVFILE="+str(bool(values["EnvironmentFiles"])).lower())
        print("REA_SDIAG_PASSENV="+str(bool(values["PassEnvironment"])).lower())
        print("REA_SDIAG_UNSETENV="+str(bool(values["UnsetEnvironment"])).lower())
        print("REA_SDIAG_ENV_KEY_COUNT="+str(len(keys_present)))
        print("REA_SDIAG_PROVIDER_ENV_KEYS="+json.dumps({
            key:key in keys_present for key in (
                "REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND",
                "REA_RIZIN_COMMAND","REA_GDB_COMMAND")},sort_keys=True))
        print("REA_SDIAG_EXEC_SH="+str(
            any(x in command for x in ("/bin/bash","/bin/sh","/usr/bin/bash"))).lower())
        print("REA_SDIAG_EXEC_ENV_RESET="+str(
            any(x in command for x in ("env -i","env --ignore-environment","--unset"))).lower())
        print("REA_SDIAG_EXEC_NODE="+str("node" in command).lower())
        print("REA_SDIAG_EXEC_SUDO="+str("sudo" in command or "runuser" in command).lower())
        pid=values["MainPID"]
        if pid.isdecimal() and int(pid)>0:
            ex=subprocess.run(["sudo","-n","readlink","-f",f"/proc/{int(pid)}/exe"],
                              capture_output=True,text=True,timeout=12,check=False)
            print("REA_SDIAG_PROC_EXE_KIND="+(
                Path(ex.stdout.strip()).name[:70] if ex.returncode==0 else "UNAVAILABLE"))
            env=subprocess.run(["sudo","-n","cat",f"/proc/{int(pid)}/environ"],
                              capture_output=True,timeout=12,check=False)
            names=set()
            if env.returncode==0:
                names={row.split(b"=",1)[0].decode("ascii",errors="ignore")
                       for row in env.stdout.split(bytes([0])) if b"=" in row}
            print("REA_SDIAG_PID_ENV_READ="+str(env.returncode==0).lower())
            print("REA_SDIAG_PID_ENV_SIZE="+str(len(names)))
            print("REA_SDIAG_PID_PROVIDER_KEYS="+json.dumps({
                key:key in names for key in (
                    "REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND",
                    "REA_RIZIN_COMMAND","REA_GDB_COMMAND")},sort_keys=True))
        print("REA_SDIAG_STATUS=PASS_READ_ONLY")
        return
    if data["action"] == "fixture_linux_service_provider_activate":
        # Owner-requested REA ONLY integration, with rollback on any
        # activation failure. Other Linux projects/services stay untouched.
        import tempfile
        import time
        unit="rea-reversa-mcp.service"
        paths={
            "REA_GDB_COMMAND":"/usr/bin/gdb",
            "REA_BINWALK_COMMAND":"/usr/bin/binwalk",
            "REA_RIZIN_COMMAND":"/opt/rea-reversa/providers/rizin-v0.9.1/bin/rizin",
            "REA_UNBLOB_COMMAND":"/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob",
        }
        target=Path("/etc/systemd/system/rea-reversa-mcp.service.d/70-rea-linux-providers.conf")
        folder=target.parent
        def sudo(*args, timeout=35):
            return subprocess.run(["sudo","-n",*args],capture_output=True,
                                  timeout=timeout,check=False)
        def prop(name):
            p=subprocess.run(["systemctl","show",unit,"-p",name,"--value"],
                             capture_output=True,text=True,timeout=12,check=False)
            return p.stdout.strip() if p.returncode==0 else ""
        if prop("User")!="rea-reversa" or prop("ActiveState")!="active":
            print("REA_PACT_STATUS=BLOCKED_ORIGINAL_REA_INACTIVE")
            return
        if prop("DropInPaths") or prop("EnvironmentFiles"):
            print("REA_PACT_STATUS=BLOCKED_EXISTING_SERVICE_OVERRIDES")
            return
        check=sudo("test","!","-e",str(target),timeout=10)
        if check.returncode:
            print("REA_PACT_STATUS=BLOCKED_PREEXISTING_FILE")
            return
        if not Path("/opt/rea-reversa/rea/package.json").is_file():
            print("REA_PACT_STATUS=BLOCKED_MISSING_ORIGINAL_ENGINE")
            return
        good={}
        for key,p in paths.items():
            chk=sudo("-u","rea-reversa","test","-x",p,timeout=12)
            good[key]=(chk.returncode==0)
        print("REA_PACT_PROVIDER_ACCESS="+json.dumps(good,sort_keys=True))
        if not all(good.values()):
            print("REA_PACT_STATUS=BLOCKED_MISSING_PROVIDER")
            return
        cfg=("[Service]"+chr(10)+"".join(
            f'Environment="{key}={value}"'+chr(10)
            for key,value in paths.items()))
        # Only four fixed executable paths; never copy external environment
        # or user secrets to public GitHub logs or service configuration.
        user_stage=Path.home()/".local/share/rea-chatgpt-trial/artifacts"
        user_stage.mkdir(mode=0o700,parents=True,exist_ok=True)
        cfgfile=None
        applied=False
        verified=False
        try:
            with tempfile.NamedTemporaryFile(prefix="rea-unit-env-",suffix=".conf",
                 dir=str(user_stage),mode="w",encoding="utf-8",delete=False) as tmp:
                tmp.write(cfg)
                cfgfile=Path(tmp.name)
            cfgfile.chmod(0o600)
            mk=sudo("install","-d","-m","0755","-o","root","-g","root",
                    str(folder),timeout=18)
            if mk.returncode:
                print("REA_PACT_STATUS=BLOCKED_DIRECTORY_CREATION")
                return
            put=sudo("install","-m","0644","-o","root","-g","root",
                     str(cfgfile),str(target),timeout=18)
            if put.returncode:
                print("REA_PACT_STATUS=BLOCKED_DROPIN_WRITE")
                return
            applied=True
            reload=sudo("systemctl","daemon-reload",timeout=35)
            if reload.returncode:
                print("REA_PACT_STATUS=FAILED_SYSTEMD_RELOAD")
                return
            loaded=prop("DropInPaths")
            environment=prop("Environment")
            observed={key:(key+"=" in environment) for key in paths}
            print("REA_PACT_SYSTEMD_DROPIN_LOADED="+str(str(target) in loaded).lower())
            print("REA_PACT_SYSTEMD_ENV_KEYS="+json.dumps(observed,sort_keys=True))
            if str(target) not in loaded or not all(observed.values()):
                print("REA_PACT_STATUS=FAILED_SYSTEMD_ENV_NOT_LOADED")
                return
            previous_pid=prop("MainPID")
            restart=sudo("systemctl","restart",unit,timeout=105)
            if restart.returncode:
                print("REA_PACT_STATUS=FAILED_REA_RESTART")
                return
            for _ in range(25):
                pid=prop("MainPID")
                if prop("ActiveState")=="active" and pid.isdecimal() and int(pid)>0:
                    break
                time.sleep(1)
            else:
                print("REA_PACT_STATUS=FAILED_REA_NOT_ACTIVE")
                return
            actual=sudo("cat",f"/proc/{int(pid)}/environ",timeout=15)
            print("REA_PACT_PID_REPLACED="+str(pid!=previous_pid).lower())
            print("REA_PACT_PROC_ENV_READ="+str(actual.returncode==0).lower())
            print("REA_PACT_POST_SYSTEMD_ENV_KEYS="+json.dumps(
                {key:(key+"=" in prop("Environment")) for key in paths},
                sort_keys=True))
            env_values={}
            if actual.returncode==0:
                for row in actual.stdout.split(bytes([0])):
                    if b"=" in row:
                        k,v=row.split(b"=",1)
                        key=k.decode("ascii",errors="ignore")
                        if key in paths:
                            env_values[key]=v.decode("utf-8",errors="replace")
            matches={k:env_values.get(k)==value for k,value in paths.items()}
            print("REA_PACT_ACTIVE_ENV="+json.dumps(matches,sort_keys=True))
            # A service can pass through a short exec/ready transition.
            # Do not reject provider env until the new MCP is fully serving.
            # Independent *new* MCP session after REA restart.
            init={"jsonrpc":"2.0","id":9401,"method":"initialize",
                  "params":{"protocolVersion":"2025-06-18",
                            "capabilities":{},
                            "clientInfo":{"name":"rea-linux-provider-activation",
                                          "version":"1"}}}
            # systemd can report "active" before Node binds loopback.
            # Retry fresh read-only MCP initialization until startup settles.
            count=0
            attempts=0
            for i in range(1,21):
                attempts=i
                try:
                    headers,info=request_mcp(init,timeout=12)
                    if "result" not in info:
                        raise RuntimeError("MCP initialize not ready")
                    active_session=headers.get("Mcp-Session-Id")
                    protocol=info["result"].get("protocolVersion")
                    request_mcp({"jsonrpc":"2.0","method":"notifications/initialized"},
                                active_session,protocol,timeout=12)
                    _,data=request_mcp({"jsonrpc":"2.0","id":9402,"method":"tools/list",
                                        "params":{}},active_session,protocol,timeout=15)
                    advertised=data.get("result",{}).get("tools")
                    count=len(advertised) if isinstance(advertised,list) else 0
                    if count==208:
                        break
                except (OSError,RuntimeError,ValueError):
                    pass
                time.sleep(2)
            print("REA_PACT_MCP_ATTEMPTS="+str(attempts))
            print("REA_PACT_MCP_TOOL_COUNT="+str(count))
            if count!=208:
                print("REA_PACT_STATUS=FAILED_MCP_NOT_READY")
                return
            stable={}
            for env_attempt in range(1,11):
                final_pid=prop("MainPID")
                if not final_pid.isdecimal() or int(final_pid)<1:
                    time.sleep(1)
                    continue
                proc=sudo("cat",f"/proc/{int(final_pid)}/environ",timeout=14)
                current={}
                if proc.returncode==0:
                    for item in proc.stdout.split(bytes([0])):
                        if b"=" not in item:
                            continue
                        name,value=item.split(b"=",1)
                        key=name.decode("ascii",errors="ignore")
                        if key in paths:
                            current[key]=value.decode("utf-8",errors="replace")
                stable={key:current.get(key)==value for key,value in paths.items()}
                if all(stable.values()):
                    break
                time.sleep(1)
            print("REA_PACT_POST_READY_ENV="+json.dumps(stable,sort_keys=True))
            print("REA_PACT_POST_READY_CHECKS="+str(env_attempt))
            if not all(stable.values()):
                print("REA_PACT_STATUS=FAILED_PROVIDER_ENV_AFTER_MCP_READY")
                return
            verified=True
            print("REA_PACT_RESULT=PASS_PERSISTENT_4_PROVIDERS")
        except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
            print("REA_PACT_STATUS=FAILED_RUNTIME_VERIFICATION")
            print("REA_PACT_ERROR_CLASS="+type(exc).__name__)
        finally:
            if cfgfile is not None:
                cfgfile.unlink(missing_ok=True)
            if applied and not verified:
                rm=sudo("rm","-f","--",str(target),timeout=20)
                reload=sudo("systemctl","daemon-reload",timeout=35)
                restart=sudo("systemctl","restart",unit,timeout=100)
                restored=(rm.returncode==0 and reload.returncode==0
                          and restart.returncode==0
                          and prop("ActiveState")=="active")
                print("REA_PACT_ROLLBACK="+
                      ("RESTORED" if restored else "INCOMPLETE_CHECK_SERVICE"))
            elif verified:
                print("REA_PACT_ROLLBACK=NOT_NEEDED")
        return
    if data["action"] == "fixture_linux_service_config_preflight":
        # Only original REA service, never disclose environment values.
        unit="rea-reversa-mcp.service"
        def prop(key):
            p=subprocess.run(["systemctl","show",unit,"-p",key,"--value"],
                capture_output=True,text=True,timeout=10,check=False)
            return p.stdout.strip() if p.returncode==0 else ""
        user=prop("User")
        pid=prop("MainPID")
        print("REA_PCONFIG_SERVICE_USER_OK="+str(user=="rea-reversa").lower())
        print("REA_PCONFIG_SERVICE_PID_OK="+str(pid.isdecimal() and int(pid)>0).lower())
        print("REA_PCONFIG_DROPIN_PRESENT="+str(bool(prop("DropInPaths"))).lower())
        print("REA_PCONFIG_ENVFILE_PRESENT="+str(bool(prop("EnvironmentFiles"))).lower())
        print("REA_PCONFIG_UNIT_CUSTOM="+str(
            prop("FragmentPath").startswith("/etc/systemd/system/")).lower())
        if user!="rea-reversa" or not pid.isdecimal() or int(pid)<=0:
            print("REA_PCONFIG_STATUS=INVALID_SERVICE_IDENTITY")
            return
        run=subprocess.run(["sudo","-n","cat",f"/proc/{int(pid)}/environ"],
            capture_output=True,timeout=12,check=False)
        if run.returncode:
            print("REA_PCONFIG_STATUS=UNREADABLE_SERVICE_ENV")
            return
        data={}
        for entry in run.stdout.split(bytes([0])):
            if b"=" in entry:
                key,val=entry.split(b"=",1)
                if key in (b"PATH",b"REA_BINWALK_COMMAND",b"REA_UNBLOB_COMMAND",
                    b"REA_GDB_COMMAND",b"GHIDRA_INSTALL_DIR",
                    b"REA_JADX_MCP_JAR",b"JAVA_HOME"):
                    data[key.decode("ascii")]=val.decode("utf-8",errors="replace")
        path=data.get("PATH","")
        print("REA_PCONFIG_SERVICE_PATH_RIZIN="+str(
             "/opt/rea-reversa/providers/rizin-v0.9.1/bin" in path.split(":")).lower())
        for key in ("REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND","REA_GDB_COMMAND"):
            val=data.get(key,"")
            print("REA_PCONFIG_"+key+"="+(
                "EXECUTABLE" if val.startswith("/") and Path(val).is_file()
                else "UNSET" if not val else "MISSING"))
        checks={
            "gdb":"/usr/bin/gdb",
            "binwalk":"/usr/bin/binwalk",
            "rizin":"/opt/rea-reversa/providers/rizin-v0.9.1/bin/rizin",
            "unblob":"/opt/rea-reversa/providers/unblob-26.6.4/bin/unblob",
        }
        for name,executable in checks.items():
            test=subprocess.run(["sudo","-n","-u",user,"test","-x",executable],
                capture_output=True,timeout=10,check=False)
            print("REA_PCONFIG_PROVIDER_"+name.upper()+"="+(
                "PASS" if test.returncode==0 else "NOT_ACCESSIBLE"))
        print("REA_PCONFIG_STATUS=PASS_READ_ONLY")
        return
    if data["action"] == "fixture_linux_service_runtime_doctor":
        # Run original REA doctor under the actual systemd service identity
        # and selected live service environment; never print env values.
        import shutil
        unit="rea-reversa-mcp.service"
        def systemctl_value(key):
            p=subprocess.run(["systemctl","show",unit,"-p",key,"--value"],
                   capture_output=True,text=True,timeout=12,check=False)
            return p.stdout.strip() if p.returncode==0 else ""
        user=systemctl_value("User")
        pidstr=systemctl_value("MainPID")
        if not user or not pidstr.isdigit() or int(pidstr)<1:
            print("REA_SERVICE_DOCTOR_STATUS=NO_SERVICE_PROCESS")
            return
        procenv=subprocess.run(["sudo","-n","cat",f"/proc/{int(pidstr)}/environ"],
                         capture_output=True,timeout=18,check=False)
        if procenv.returncode!=0:
            print("REA_SERVICE_DOCTOR_STATUS=ENV_NOT_READABLE")
            return
        d={}
        for item in procenv.stdout.split(b"\x00"):
            if b"=" in item:
                k,v=item.split(b"=",1)
                try:
                    d[k.decode("utf-8")]=v.decode("utf-8")
                except UnicodeDecodeError:
                    pass
        allow=("PATH","HOME","NODE_OPTIONS","JAVA_HOME","GHIDRA_INSTALL_DIR",
               "REA_JADX_MCP_JAR","REA_JADX_HEAP_MIB",
               "REA_JADX_ACTIVE_PROCESSOR_COUNT","REA_GDB_COMMAND",
               "REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND",
               "REA_RIZIN_COMMAND","REA_KUNA_COMMAND","REA_KUNA_CACHE_DIR",
               "REA_SIGROK_COMMAND","REA_TSHARK_COMMAND",
               "REA_WABT_BIN_DIRECTORY","REA_PWNTOOLS_PYTHON",
               "REA_IDA_MCP_CONFIG")
        supplied={k:v for k,v in d.items() if k in allow and len(v)<3000}
        print("REA_SERVICE_DOCTOR_UNIT_USER="+user[:45])
        print("REA_SERVICE_DOCTOR_CONFIG_KEYS="+json.dumps(
              sorted(k for k in allow if k in supplied)))
        for name in ("GHIDRA_INSTALL_DIR","JAVA_HOME","REA_JADX_MCP_JAR",
                     "REA_GDB_COMMAND","REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND",
                     "REA_RIZIN_COMMAND","REA_KUNA_COMMAND","REA_KUNA_CACHE_DIR",
                     "REA_SIGROK_COMMAND","REA_TSHARK_COMMAND",
                     "REA_WABT_BIN_DIRECTORY","REA_PWNTOOLS_PYTHON"):
            val=supplied.get(name)
            # unblob is 0750 owned by REA service: the SSH ubuntu account
            # cannot stat it; test through service identity instead.
            isfile=False
            isdir=False
            if val and val.startswith("/"):
                file_check=subprocess.run(["sudo","-n","-u",user,"test","-f",val],
                     capture_output=True,timeout=10,check=False)
                dir_check=subprocess.run(["sudo","-n","-u",user,"test","-d",val],
                     capture_output=True,timeout=10,check=False)
                isfile=file_check.returncode==0
                isdir=dir_check.returncode==0
            print("REA_SERVICE_DOCTOR_CONFIG_"+name+"="+
                  ("FILE" if isfile else "DIR" if isdir else "MISSING" if val else "UNSET"))
        original=Path("/opt/rea-reversa/rea/scripts/rea.mjs")
        if not original.is_file():
            print("REA_SERVICE_DOCTOR_STATUS=ORIGINAL_CLI_MISSING")
            return
        envargs=[f"{k}={v}" for k,v in supplied.items()]
        if "PATH" not in supplied:
            envargs.append("PATH=/usr/local/bin:/usr/bin:/bin")
        cmd=["sudo","-n","-u",user,"env",*envargs,
             "node",str(original),"doctor","--json"]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=120,
                 cwd="/opt/rea-reversa/rea",check=False)
        print("REA_SERVICE_DOCTOR_EXIT="+str(result.returncode))
        try:
            doc=json.loads(result.stdout)
        except ValueError:
            print("REA_SERVICE_DOCTOR_STATUS=INVALID_RESULT")
            return
        if not isinstance(doc,dict):
            print("REA_SERVICE_DOCTOR_STATUS=INVALID_SHAPE")
            return
        print("REA_SERVICE_DOCTOR_HEALTH="+json.dumps(
            {"healthy":doc.get("healthy"),"environment_healthy":doc.get("environment_healthy")},
            sort_keys=True))
        providers=doc.get("providerInspections",[])
        if isinstance(providers,list):
            print("REA_SERVICE_DOCTOR_PROVIDERS="+json.dumps([
              {"id":str(v.get("id",""))[:45],
               "configured":v.get("configured") is True,
               "available":v.get("available") is True}
              for v in providers[:15] if isinstance(v,dict)],sort_keys=True))
        print("REA_SERVICE_DOCTOR_BINARY_CHECK="+json.dumps({
            name:Path("/usr/bin/"+name).is_file()
            for name in ("gdb","r2","binwalk","tshark","adb","apktool","sigrok-cli")},
            sort_keys=True))
        print("REA_SERVICE_DOCTOR_STATUS=PASS_READ_ONLY_CHECKED")
        return
    if data["action"] == "fixture_linux_provider_install_apply":
        # Owner-initiated: signed distro packages, no upgrades or removals.
        import re as regex
        pkgs=("gdb","radare2","binwalk","tshark","adb","apktool",
              "sigrok-cli","python3-venv","python3-pip",
              "llvm","unzip","p7zip-full")
        if not Path("/opt/rea-reversa/rea/package.json").is_file():
            error("Original REA engine missing; refuse installation")
        if subprocess.run(["systemctl","is-active","--quiet","rea-reversa-mcp.service"],
                          timeout=10,check=False).returncode:
            error("Original REA daemon is inactive")
        if subprocess.run(["sudo","-n","true"],capture_output=True,
                          timeout=10,check=False).returncode:
            error("No safe noninteractive system installation permission")
        simulation=subprocess.run(["apt-get","-s","--no-install-recommends",
                                  "--no-remove","--no-upgrade","install",*pkgs],
                                  capture_output=True,text=True,timeout=60,check=False)
        planned=[line for line in simulation.stdout.splitlines() if line.startswith("Inst ")]
        removed=[line for line in simulation.stdout.splitlines() if line.startswith("Remv ")]
        if simulation.returncode or removed:
            error("Package-manager safety simulation failed, no changes")
        print("REA_APPLY_SIM_PACKAGES="+str(len(planned)))
        print("REA_APPLY_SIM_SHA256="+hashlib.sha256(
            (simulation.stdout+"\n"+simulation.stderr).encode()).hexdigest())
        print("REA_APPLY_REQUESTED="+json.dumps(pkgs))
        state_dir=Path.home()/".local/share/rea-chatgpt-trial/install"
        state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        if state_dir.is_symlink():
            error("Untrusted state directory")
        before=subprocess.run(["dpkg-query","-W","-f=${binary:Package}=${Version}\\n"],
                capture_output=True,text=True,timeout=25,check=False)
        print("REA_APPLY_BEFORE_SHA256="+hashlib.sha256(before.stdout.encode()).hexdigest())
        cmd=["sudo","-n","env","DEBIAN_FRONTEND=noninteractive",
             "NEEDRESTART_MODE=l","APT_LISTCHANGES_FRONTEND=none",
             "apt-get","-y","--no-install-recommends","--no-remove",
             "--no-upgrade","-o","Dpkg::Options::=--force-confold",
             "install",*pkgs]
        try:
            p=subprocess.run(cmd,capture_output=True,text=True,
                             timeout=650,check=False)
            exit_code=p.returncode
            output=p.stdout+"\n"+p.stderr
        except subprocess.TimeoutExpired:
            exit_code=124
            output="INSTALL_TIMEOUT"
        print("REA_APPLY_APT_EXIT="+str(exit_code))
        print("REA_APPLY_OUTPUT_SHA256="+hashlib.sha256(output.encode()).hexdigest())
        status={}
        for name in pkgs:
            found=subprocess.run(["dpkg-query","-W","-f=${Status}",name],
                capture_output=True,text=True,timeout=12,check=False)
            status[name]=found.returncode==0 and found.stdout.strip()=="install ok installed"
        print("REA_APPLY_INSTALLED="+json.dumps(status,sort_keys=True))
        active=subprocess.run(["systemctl","is-active","--quiet","rea-reversa-mcp.service"],
                    timeout=12,check=False).returncode==0
        print("REA_APPLY_SERVICE_ACTIVE="+str(active).lower())
        outcome="PASS_INSTALLED" if exit_code==0 and all(status.values()) and active else "INCOMPLETE"
        report={"packages":pkgs,"installed":status,"apt_exit":exit_code,
                "apt_output_sha256":hashlib.sha256(output.encode()).hexdigest(),
                "service_active":active,"status":outcome}
        snapshot=state_dir/"linux-distro-provider-packages-20261023.json"
        snapshot.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        snapshot.chmod(0o600)
        print("REA_APPLY_STATE_SAVED="+str(snapshot.is_file()).lower())
        if exit_code!=0:
            print("REA_APPLY_FAILURE="+regex.sub(r"[^A-Za-z0-9 .,:;=/()+~-]",
                                    " ",output[-700:]))
        print("REA_APPLY_RESULT="+outcome)
        return
    if data["action"] == "fixture_linux_provider_install_simulate":
        # Simulation only; never apt-get update/install, no restart/edits.
        import shutil
        import re as regex
        approved=("gdb","radare2","binwalk","tshark","adb","apktool",
                  "sigrok-cli","python3-venv","python3-pip",
                  "llvm","unzip","p7zip-full")
        available=[]
        unavailable=[]
        for name in approved:
            p=subprocess.run(["apt-cache","policy",name],capture_output=True,
                             text=True,timeout=12,check=False)
            values=[l.split(":",1)[1].strip() for l in p.stdout.splitlines()
                    if l.strip().startswith("Candidate:")]
            if len(values)==1 and values[0] not in ("(none)","none"):
                available.append(name)
            else:
                unavailable.append(name)
        print("REA_SIM_APT_AVAILABLE="+json.dumps(available))
        print("REA_SIM_APT_UNAVAILABLE="+json.dumps(unavailable))
        cmd=["apt-get","-s","--no-install-recommends","--no-remove",
             "--no-upgrade","install",*available]
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=55,check=False,
                         env={**os.environ,"DEBIAN_FRONTEND":"noninteractive"})
        output=p.stdout+"\n"+p.stderr
        install=[l.split()[1] for l in output.splitlines()
                 if l.startswith("Inst ") and len(l.split())>=2]
        removed=[l.split()[1] for l in output.splitlines()
                 if l.startswith("Remv ") and len(l.split())>=2]
        # A dry-run must not introduce removals; exit code alone insufficient.
        print("REA_SIM_APT_EXIT="+str(p.returncode))
        print("REA_SIM_APT_INSTALL_COUNT="+str(len(install)))
        print("REA_SIM_APT_REMOVE_COUNT="+str(len(removed)))
        print("REA_SIM_APT_FIRST_PACKAGES="+json.dumps(install[:20]))
        print("REA_SIM_APT_PLAN_SHA256="+hashlib.sha256(output.encode()).hexdigest())
        print("REA_SIM_APT_SAFE="+str(p.returncode==0 and not removed).lower())
        if p.returncode!=0:
            print("REA_SIM_APT_FAILURE="+regex.sub(
                r"[^A-Za-z0-9 .,:;=/()+~-]"," ",output[-500:]))
        # Host service current root path and effective provider keys.
        if shutil.which("systemctl"):
            unit="rea-reversa-mcp.service"
            values={}
            for key in ("User","Group","MainPID","ActiveState","SubState","WorkingDirectory",
                        "ExecStart","Environment","EnvironmentFiles"):
                proc=subprocess.run(["systemctl","show",unit,"-p",key,"--value"],
                   capture_output=True,text=True,timeout=12,check=False)
                values[key]=proc.stdout.strip() if proc.returncode==0 else ""
            print("REA_SIM_SERVICE_USER="+values["User"][:50])
            print("REA_SIM_SERVICE_ACTIVE="+values["ActiveState"][:35])
            print("REA_SIM_SERVICE_PID_PRESENT="+str(values["MainPID"].isdigit()
                  and int(values["MainPID"])>0).lower())
            for k in ("GHIDRA_INSTALL_DIR","JAVA_HOME","REA_JADX_MCP_JAR",
                      "REA_GDB_COMMAND","REA_BINWALK_COMMAND","REA_UNBLOB_COMMAND"):
                print("REA_SIM_SERVICE_ENV_"+k+"="+str(k+"=" in values["Environment"]).lower())
            print("REA_SIM_SERVICE_DROPIN="+str("rea-reversa-mcp" in values["EnvironmentFiles"]).lower())
        print("REA_SIM_COMPLETED=PASS_READ_ONLY")
        return
    if data["action"] == "fixture_linux_service_install_preflight":
        # Strictly read-only: verify ownership, service environment, admin
        # capability and safe package-manager simulation, never install.
        import shutil
        import stat
        import platform
        import pwd
        import re as regex
        import tempfile
        print("REA_PREFLIGHT_OS="+platform.system())
        print("REA_PREFLIGHT_UID="+str(os.geteuid()))
        print("REA_PREFLIGHT_ADMIN_NONINTERACTIVE="+str(subprocess.run(
            ["sudo","-n","true"],capture_output=True,text=True,timeout=10,
            check=False).returncode==0).lower() if shutil.which("sudo") else "false")
        root=Path("/opt/rea-reversa/rea")
        print("REA_PREFLIGHT_ENGINE_OWNER="+(
            str(root.stat().st_uid) if root.is_dir() else "MISSING"))
        print("REA_PREFLIGHT_ENGINE_WRITE="+str(os.access(root,os.W_OK)).lower())
        disk=shutil.disk_usage(str(Path.home()))
        print("REA_PREFLIGHT_DISK_GIB="+str(disk.free//(1024**3)))
        print("REA_PREFLIGHT_HOME="+json.dumps({"write":os.access(Path.home(),os.W_OK),
            "real":not Path.home().is_symlink()},sort_keys=True))
        for tool in ("dpkg-query","apt-get","apt-cache","systemctl","pgrep","sudo","ldconfig"):
            print("REA_PREFLIGHT_CMD_"+tool.upper().replace("-","_")+"="+
                  str(bool(shutil.which(tool))).lower())
        for name in ("gdb","rizin","radare2","binwalk","tshark","adb","apktool","chromium"):
            result=subprocess.run(["apt-cache","policy",name],
                capture_output=True,text=True,timeout=12,check=False)
            version="NONE"
            for line in result.stdout.splitlines():
                if line.strip().startswith("Candidate:"):
                    version=line.split(":",1)[1].strip()[:80]
            print("REA_PREFLIGHT_CANDIDATE_"+name.upper()+"="+
                  regex.sub(r"[^A-Za-z0-9.+:~_-]","",version))
        # Only list REA-related service unit names and status, no full process
        # command lines or process environments.
        if shutil.which("systemctl"):
            r=subprocess.run(["systemctl","list-units","--all","--type=service",
               "--no-legend","--plain","--no-pager"],capture_output=True,text=True,
               timeout=18,check=False)
            found=[]
            for line in r.stdout.splitlines():
                unit=line.split()[0] if line.strip() else ""
                if "rea" in unit.lower() and len(unit)<105:
                    found.append(unit)
            print("REA_PREFLIGHT_UNITS="+json.dumps(sorted(set(found))[:15]))
        result=subprocess.run(["ps","-eo","pid=,comm="],capture_output=True,
                              text=True,timeout=12,check=False)
        print("REA_PREFLIGHT_NODE_PROC_COUNT="+str(sum(
            1 for line in result.stdout.splitlines() if line.split()[-1:] in
            (["node"],["nodejs"]))))
        print("REA_PREFLIGHT_COMPLETE=PASS_READ_ONLY")
        return
    if data["action"] == "fixture_linux_install_inventory":
        # Audit original Linux REA installation; no installation, no restart.
        import shutil
        import platform
        import re as regex
        base = Path.home() / ".local/share/rea-chatgpt-trial/tools"
        groups = {
            "core": ("node","npm","python3","java","javac","ps","git","curl"),
            "native": ("gdb","gdb-multiarch","rizin","rz-bin","r2","radare2",
                       "objdump","readelf","strings","llvm-objdump","nm"),
            "application": ("adb","frida","apktool","dotnet","mono","ffmpeg",
                            "chrome","chromium","google-chrome","firefox"),
            "firmware": ("binwalk","unblob","prlimit","wasm2wat","wasm-objdump","wasm-validate"),
            "capture": ("tshark","tcpdump","sigrok-cli","wireshark","strace"),
        }
        print("REA_INSTALL_AUDIT_OS=" + str(platform.system()))
        print("REA_INSTALL_AUDIT_ARCH=" + str(platform.machine()))
        release = {}
        os_release = Path("/etc/os-release")
        if os_release.is_file():
            for line in os_release.read_text(errors="replace").splitlines():
                if "=" in line:
                    k, v = line.split("=",1)
                    if k in ("ID", "ID_LIKE", "VERSION_ID"):
                        release[k]=v.strip('"').strip("'")
        print("REA_INSTALL_AUDIT_RELEASE=" + json.dumps(release, sort_keys=True))
        for name, commands in groups.items():
            print("REA_INSTALL_AUDIT_BIN_" + name.upper() + "=" +
                  json.dumps({cmd: bool(shutil.which(cmd)) for cmd in commands},
                  sort_keys=True))
        vendor = {
          "original_motor":Path("/opt/rea-reversa/rea/scripts/rea.mjs"),
          "original_package":Path("/opt/rea-reversa/rea/package.json"),
          "ghidra":base/"ghidra_12.1.4_PUBLIC/support/analyzeHeadless",
          "jdk21":base/"jdk-21/bin/java",
          "jadx":base/"jadx-headless-mcp-0.7.1-all.jar",
          "node24":base/"node-24.15.0/bin/node",
          "wabt":base/"wabt-1.0.42/bin/wasm-objdump",
          "pwntools":base/"pwntools-4.15.0/bin/python",
        }
        print("REA_INSTALL_AUDIT_VENDOR="+
              json.dumps({name:path.is_file() and not path.is_symlink()
                         for name,path in vendor.items()},sort_keys=True))
        cli=vendor["original_motor"]
        node=shutil.which("node")
        if node and cli.is_file():
            probe=subprocess.run([node,str(cli),"providers","--json"],
                capture_output=True,text=True,timeout=60,check=False,
                env={**os.environ,"NO_COLOR":"1","NODE_OPTIONS":"--max-old-space-size=1024"})
            print("REA_INSTALL_AUDIT_PROVIDERS_CLI=" +
                  ("PASS" if probe.returncode==0 else "FAIL"))
            if probe.returncode==0:
                try:
                    data=json.loads(probe.stdout)
                    print("REA_INSTALL_AUDIT_PROVIDERS_TOP_KEYS="+json.dumps(
                        sorted(str(k) for k in data)[:30] if isinstance(data,dict) else []))
                    if isinstance(data,dict):
                        candidates=data.get("analysis_provider_candidates")
                        if isinstance(candidates,list):
                            print("REA_INSTALL_AUDIT_PROVIDER_CANDIDATES="+str(len(candidates)))
                except ValueError:
                    print("REA_INSTALL_AUDIT_PROVIDERS_JSON=INVALID")
        print("REA_INSTALL_AUDIT_MCP_TOOL_COUNT="+str(len(tools)))
        print("REA_INSTALL_AUDIT_COMPLETED=PASS_READ_ONLY")
        return
    if data["action"] == "capability_audit":
        import shutil
        from collections import Counter
        import platform
        contract = {
            "declared": len(tools),
            "unique_names": len(tool_by_name),
            "valid_names": sum(bool(isinstance(t.get("name"), str) and
                NAME_RE.fullmatch(t["name"])) for t in tools),
            "json_input_schemas": sum(isinstance(t.get("inputSchema"), dict)
                and t["inputSchema"].get("type") == "object" for t in tools),
            "read_only_hints": sum((t.get("annotations") or {}).get("readOnlyHint")
                is True for t in tools),
            "destructive_hints": sum((t.get("annotations") or {}).get("destructiveHint")
                is True for t in tools),
            "safe_call_allowlist": len(safe_callable),
        }
        print("REA_AUDIT_TOOL_CONTRACTS=" + json.dumps(contract, sort_keys=True))
        required = Counter()
        for tool in tools:
            schema = tool.get("inputSchema")
            if isinstance(schema, dict) and isinstance(schema.get("required"), list):
                for key in schema["required"]:
                    if isinstance(key, str) and NAME_RE.fullmatch(key):
                        required[key] += 1
        print("REA_AUDIT_REQUIRED_ARGUMENTS=" + json.dumps(
            {name: count for name, count in sorted(required.items(),
                key=lambda v: (-v[1], v[0]))[:16]}, sort_keys=True))
        print("REA_AUDIT_PLATFORM_RUNTIME=" + json.dumps({
            "system": platform.system(), "machine": platform.machine(),
            "procps_ps": bool(shutil.which("ps")),
        }, sort_keys=True))
        root = Path.home() / ".local/share/rea-chatgpt-trial"
        cli = root / "repository/rea/scripts/rea.mjs"
        paths = {
            "bundled_jdk21": root / "tools/jdk-21/bin/java",
            "bundled_jadx": root / "tools/jadx-headless-mcp-0.7.1-all.jar",
            "bundled_ghidra": root / "tools/ghidra_12.1.4_PUBLIC/support/analyzeHeadless",
        }
        status = {name: bool(shutil.which(name)) for name in (
            "node", "python3", "java", "adb", "frida", "gdb",
            "rizin", "r2", "objdump", "tshark", "tcpdump", "ffmpeg",
            "xcrun", "powershell")}
        status.update({k: value.is_file() for k, value in paths.items()})
        print("REA_AUDIT_DEPENDENCIES=" + json.dumps(status, sort_keys=True))
        if cli.is_file() and shutil.which("node"):
            p = subprocess.run(
                ["node", str(cli), "providers", "--json"],
                capture_output=True, text=True, timeout=55, check=False
            )
            print("REA_AUDIT_CLI_STATUS=" + ("PASS" if p.returncode == 0 else "FAIL"))
            if p.returncode == 0 and len(p.stdout) <= 200000:
                result = json.loads(p.stdout)
                if isinstance(result, dict):
                    print("REA_AUDIT_PROVIDER_KEYS=" + json.dumps(
                        sorted(str(k) for k in result.keys())[:30]))
                    shapes = {}
                    for key, val in result.items():
                        if isinstance(val, dict):
                            shapes[key] = {"type": "object", "count": len(val)}
                        elif isinstance(val, list):
                            shapes[key] = {"type": "array", "count": len(val)}
                        else:
                            shapes[key] = {"type": type(val).__name__}
                    print("REA_AUDIT_PROVIDER_SECTIONS=" + json.dumps(
                        shapes, sort_keys=True))
                    names = {}
                    for section_name in ("analysis_provider_candidates", "capabilities"):
                        section = result.get(section_name)
                        if isinstance(section, list):
                            selected = []
                            for val in section[:120]:
                                if isinstance(val, str) and NAME_RE.fullmatch(val):
                                    selected.append(val)
                                elif isinstance(val, dict):
                                    for key in ("provider", "name", "provider_id", "id", "capability"):
                                        candidate = val.get(key)
                                        if isinstance(candidate, str) and NAME_RE.fullmatch(candidate):
                                            selected.append(candidate)
                                            break
                            names[section_name] = sorted(set(selected))
                    print("REA_AUDIT_PROVIDER_NAMES=" + json.dumps(names, sort_keys=True))
                    section = result.get("provider_operation_health")
                    if isinstance(section, dict):
                        names = [k for k in section.keys()
                                 if isinstance(k, str) and NAME_RE.fullmatch(k)]
                        print("REA_AUDIT_OPERATION_PROVIDERS=" + json.dumps(
                            sorted(names)[:100]))

        else:
            print("REA_AUDIT_CLI_STATUS=UNAVAILABLE")
        print("REA_AUDIT_STATUS=PASS")
        return

    if data["action"] in ("fixture_ghidra_metadata", "fixture_ghidra_additional"):
        # Expand actual static Ghidra inspection coverage without touching
        # another VPS service, user data or external tooling. This fixture
        # uses the existing REA MCP and unmodified /usr/bin/true.
        if not Path("/usr/bin/true").is_file():
            error("Public Ghidra metadata target is unavailable")
        if "open_binary" not in tool_by_name or "close_binary" not in tool_by_name:
            error("Ghidra session contracts are missing")
        opened = False
        cleaned = False
        records = []
        try:
            _, started = request_mcp(
                {"jsonrpc":"2.0","id":210,"method":"tools/call",
                 "params":{"name":"open_binary","arguments":{
                     "path":"/usr/bin/true","provider_id":"ghidra"}}},
                session,protocol,timeout=130
            )
            if "error" in started or not isinstance(started.get("result"), dict) or (
                started["result"].get("isError") is True
            ):
                error("Controlled Ghidra metadata session could not open")
            opened = True
            basic_queries = (
                "binary_overview", "list_segments", "list_names", "list_bookmarks",
                "current_document", "current_address", "search_procedures",
                "search_strings",
            ) if data["action"] == "fixture_ghidra_metadata" else ()
            for idx, name in enumerate(basic_queries, start=211):
                if name not in tool_by_name:
                    records.append({"tool":name,"status":"NOT_ADVERTISED"})
                    continue
                arguments = {"pattern":"main"} if name == "search_procedures" else (
                    {"pattern":"libc"} if name == "search_strings" else {}
                )
                try:
                    _, response = request_mcp(
                        {"jsonrpc":"2.0","id":idx,"method":"tools/call",
                         "params":{"name":name,"arguments":arguments}},
                        session,protocol,timeout=75
                    )
                    result = response.get("result")
                    ok = ("error" not in response and isinstance(result,dict)
                          and result.get("isError") is not True)
                    records.append({"tool":name,"status":"PASS" if ok else "ERROR",
                                    "result":result if isinstance(result,dict)
                                    else {"error":"MCP response unavailable"}})
                except Exception:
                    records.append({"tool":name,"status":"ERROR",
                                    "result":{"error":"MCP operation unavailable"}})
            # Fixed, read-only procedure investigations based on the 'entry'
            # symbol observed in the same public /usr/bin/true ELF target.
            # They never accept an external address or command in the request.
            procedure_queries = (
                ("procedure_address", {"procedure":"entry"}),
                ("procedure_info", {"procedure":"entry"}),
                ("procedure_assembly", {"procedure":"entry"}),
                ("procedure_pseudo_code", {"procedure":"entry"}),
                ("procedure_callees", {"procedure":"entry"}),
                ("procedure_callers", {"procedure":"entry"}),
                ("procedure_references", {"procedure":"entry", "direction":"outgoing"}),
                ("address_name", {"address":"0x1019f0"}),
                ("comment", {"address":"0x1019f0"}),
            ) if data["action"] == "fixture_ghidra_metadata" else (
                ("read_bytes", {"address":"0x1019f0", "length":16}),
                ("address_to_file_offset", {"address":"0x1019f0"}),
                ("resolve_containing_procedure", {"address":"0x1019f0"}),
                ("inspect_native_instruction", {"address":"0x1019f0"}),
                ("read_function_instructions", {"procedure":"entry"}),
                ("xrefs", {"address":"0x1019f0"}),
                ("find_xrefs_to_name", {"name":"entry"}),
                ("get_call_graph", {"address":"entry","direction":"forward"}),
                ("analyze_function", {"procedure":"entry"}),
            )
            for idx, (name, arguments) in enumerate(procedure_queries, start=230):
                if name not in tool_by_name:
                    records.append({"tool":name,"status":"NOT_ADVERTISED"})
                    continue
                try:
                    _, response = request_mcp(
                        {"jsonrpc":"2.0","id":idx,"method":"tools/call",
                         "params":{"name":name,"arguments":arguments}},
                        session,protocol,timeout=80
                    )
                    result = response.get("result")
                    ok = ("error" not in response and isinstance(result,dict)
                          and result.get("isError") is not True)
                    records.append({"tool":name,"status":"PASS" if ok else "ERROR",
                                    "result":result if isinstance(result,dict)
                                    else {"error":"MCP response unavailable"}})
                except Exception:
                    records.append({"tool":name,"status":"ERROR",
                                    "result":{"error":"MCP operation unavailable"}})
        finally:
            if opened:
                try:
                    _, closed = request_mcp(
                        {"jsonrpc":"2.0","id":299,"method":"tools/call",
                         "params":{"name":"close_binary","arguments":{}}},
                        session,protocol,timeout=95
                    )
                    cleaned=("error" not in closed and isinstance(
                        closed.get("result"),dict) and
                        closed["result"].get("isError") is not True)
                except Exception:
                    cleaned=False
                print(("REA_FIXTURE_GHIDRA_ADDITIONAL_CLEANUP" if
                    data["action"] == "fixture_ghidra_additional" else
                    "REA_FIXTURE_GHIDRA_METADATA_CLEANUP") + "="+(
                    "PASS" if cleaned else "FAIL"))
            if not cleaned:
                error("Controlled Ghidra metadata cleanup failed")
        data_bytes = json.dumps(
            {"source":"/usr/bin/true","provider":"ghidra","records":records},
            ensure_ascii=True, sort_keys=True
        ).encode()
        if len(data_bytes)>MAX_RESPONSE:
            error("Ghidra metadata exceeds encrypted response size")
        print(("REA_FIXTURE_GHIDRA_ADDITIONAL" if
            data["action"] == "fixture_ghidra_additional" else
            "REA_FIXTURE_GHIDRA_METADATA") + "=" + str(
            sum(x["status"]=="PASS" for x in records)) + "/" + str(len(records)))
        print("REA_MOBILE_TOOL_CALL=PASS")
        print("REA_MOBILE_TOOL_ERROR=" + str(
            any(x["status"]!="PASS" for x in records)).lower())
        print("REA_MOBILE_OUTPUT_BYTES="+str(len(data_bytes)))
        print("REA_MOBILE_OUTPUT_SHA256="+hashlib.sha256(data_bytes).hexdigest())
        if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE")!="1":
            error("Controlled Ghidra requires encrypted result capture")
        print("REA_MOBILE_PRIVATE_RESULT_B64="+base64.b64encode(data_bytes).decode())
        return
    if data["action"] in ("fixture_ghidra", "fixture_ghidra_depth"):
        # Fixed, non-confidential, system-provided ELF fixture only.
        # No user-supplied paths or arbitrary commands cross public GitHub.
        if not Path("/usr/bin/true").is_file():
            error("Public native fixture is unavailable")
        if not all(name in tool_by_name for name in (
                "open_binary", "list_documents", "close_binary")):
            error("Required REA native session tools are not advertised")
        print("REA_FIXTURE_PROVIDER=ghidra")
        was_opened = False
        try:
            _, opened = request_mcp(
                {"jsonrpc": "2.0", "id": 31, "method": "tools/call",
                 "params": {"name": "open_binary", "arguments": {
                     "path": "/usr/bin/true", "provider_id": "ghidra"
                 }}},
                session, protocol, timeout=125
            )
            if "error" in opened or (
                    opened.get("result") or {}).get("isError") is True:
                error("Controlled Ghidra fixture failed to open")
            was_opened = True
            print("REA_FIXTURE_OPEN=PASS")
            _, documents = request_mcp(
                {"jsonrpc": "2.0", "id": 32, "method": "tools/call",
                 "params": {"name": "list_documents", "arguments": {}}},
                session, protocol, timeout=65
            )
            if "error" in documents or (
                    documents.get("result") or {}).get("isError") is True:
                error("Controlled Ghidra fixture could not list documents")
            print("REA_FIXTURE_DOCUMENTS=PASS")
            if data["action"] == "fixture_ghidra_depth":
                for tool, marker, call_id in (
                    ("list_procedures", "REA_FIXTURE_PROCEDURES", 34),
                    ("list_strings", "REA_FIXTURE_STRINGS", 35)
                ):
                    if tool not in tool_by_name:
                        error("Controlled native fixture query tool unavailable")
                    _, queried = request_mcp(
                        {"jsonrpc": "2.0", "id": call_id,
                         "method": "tools/call",
                         "params": {"name": tool, "arguments": {}}},
                        session, protocol, timeout=85
                    )
                    if "error" in queried or (
                            queried.get("result") or {}).get("isError") is True:
                        error("Controlled native fixture query failed: " + tool)
                    print(marker + "=PASS")
        finally:
            if was_opened:
                try:
                    _, closed = request_mcp(
                        {"jsonrpc": "2.0", "id": 33, "method": "tools/call",
                         "params": {"name": "close_binary", "arguments": {}}},
                        session, protocol, timeout=80
                    )
                    ok = "error" not in closed and (
                        closed.get("result") or {}).get("isError") is not True
                    print("REA_FIXTURE_CLEANUP=" + ("PASS" if ok else "FAIL"))
                    if not ok:
                        error("Controlled Ghidra fixture cleanup failed")
                except (OSError, RuntimeError, ValueError):
                    print("REA_FIXTURE_CLEANUP=FAIL")
                    raise
        return
    if data["action"] == "fixture_linux_objdump":
        # Source-owned, fixed Linux fixture on the original local REA MCP.
        target = Path("/usr/bin/true")
        if not target.is_file() or target.read_bytes()[:4] != b"\x7fELF":
            error("Fixed Linux ELF input is unavailable")
        target_hash_before = hashlib.sha256(target.read_bytes()).hexdigest()
        if "inspect_with_objdump" not in tool_by_name:
            error("GNU objdump MCP tool is not advertised")
        records = []
        for idx, operation in enumerate(("file_headers", "section_headers", "disassemble"), start=701):
            arguments = {"operation": operation, "path": str(target),
                         "follow_debug_links": False}
            secure.validate_arguments(tool_by_name["inspect_with_objdump"], arguments)
            _, reply = request_mcp(
                {"jsonrpc": "2.0", "id": idx, "method": "tools/call",
                 "params": {"name": "inspect_with_objdump", "arguments": arguments}},
                session, protocol, timeout=95)
            result = reply.get("result")
            accepted = ("error" not in reply and isinstance(result, dict)
                        and result.get("isError") is not True)
            records.append({"tool": "inspect_with_objdump", "operation": operation,
                            "arguments_sha256": secure.arguments_sha256(arguments),
                            "isError": result.get("isError") if isinstance(result, dict) else None,
                            "status": "MCP_OK" if accepted else "MCP_ERROR",
                            "result": result if isinstance(result, dict) else None,
                            "protocol_error": reply.get("error")})
        unchanged = target_hash_before == hashlib.sha256(target.read_bytes()).hexdigest()
        payload = {"host_family": "Linux", "source": "/usr/bin/true",
                   "source_sha256": target_hash_before, "source_unchanged": unchanged,
                   "records": records, "method": "original MCP tools/call on Linux"}
        raw = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode()
        if len(raw) > MAX_RESPONSE or os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            error("Linux objdump fixture requires bounded encrypted evidence")
        print("REA_MOBILE_TOOL_CALL=PASS")
        print("REA_MOBILE_TOOL_ERROR=" + str(
            not unchanged or any(r["status"] != "MCP_OK" for r in records)).lower())
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(raw)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode("ascii"))
        return
    if data["action"] == "fixture_objdump":
        # Deterministic system-owned ELF; no caller path, source, shell or flags.
        if "inspect_with_objdump" not in tool_by_name:
            error("System objdump inspection is not in live REA catalogue")
        for operation, marker, req_id in (
            ("file_headers", "REA_FIXTURE_OBJDUMP_HEADERS", 71),
            ("section_headers", "REA_FIXTURE_OBJDUMP_SECTIONS", 72)
        ):
            _, response = request_mcp(
                {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                 "params": {"name": "inspect_with_objdump", "arguments": {
                    "operation": operation, "path": "/usr/bin/true",
                    "follow_debug_links": False
                }}}, session, protocol, timeout=55
            )
            if "error" in response or not isinstance(response.get("result"), dict):
                error("REA objdump fixture returned a protocol error")
            if response["result"].get("isError") is True:
                error("REA objdump fixture inspection reported a tool error")
            data_bytes = json.dumps(response["result"], ensure_ascii=True,
                                     sort_keys=True).encode()
            print(marker + "=PASS")
            print(marker + "_SHA256=" + hashlib.sha256(data_bytes).hexdigest())
        return
    if data["action"] == "fixture_portable_formats":
        # Fixed source-owned fixtures, never fetched from private customers.
        # .NET PE/CLI comes from the existing REA test fixture generator.
        # Apple Mach-O uses the format tested in REA's own Electron suite.
        import tempfile
        import struct
        root = Path.home() / ".local/share/rea-chatgpt-trial/repository/rea"
        generator = root / "scripts/fixtures/managed/pe.mjs"
        if not generator.is_file():
            error("Source-owned managed PE fixture generator is unavailable")
        targets = []
        cleanup_ok = True
        try:
            fd, filename = tempfile.mkstemp(prefix="rea-managed-public-",
                                             suffix=".dll", dir="/dev/shm")
            os.close(fd)
            managed = Path(filename)
            targets.append(managed)
            script = (
                "import{writeFileSync}from'node:fs';"
                "const m=await import(process.argv[1]);"
                "writeFileSync(process.argv[2],m.buildManagedPeFixture());"
            )
            generated = subprocess.run(
                ["node", "--input-type=module", "-e", script,
                 generator.as_uri(), str(managed)],
                capture_output=True, text=True, timeout=30, check=False
            )
            if generated.returncode != 0:
                error("Existing PE/CLI fixture generator failed")
            raw = managed.read_bytes()
            if len(raw) > 1048576 or raw[:2] != b"MZ":
                error("Unexpected managed PE fixture bytes")
            os.chmod(managed, 0o644)
            fd, filename = tempfile.mkstemp(prefix="rea-macho-fuse-public-",
                                             suffix=".dylib", dir="/dev/shm")
            os.close(fd)
            macho = Path(filename)
            targets.append(macho)
            header = struct.pack("<IiiIIIII",
                                 0xfeedfacf, 0x0100000c, 0, 2, 0, 0, 0, 0)
            sentinel = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
            wire = bytes([1, 8, 0x30, 0x31, 0x30, 0x30,
                          0x30, 0x30, 0x30, 0x31])
            macho.write_bytes(header + sentinel + wire)
            os.chmod(macho, 0o644)
            # Fixed, non-executable files. Inspect unavailable suppliers
            # without installing dependencies or altering other VPS services.
            fd, filename = tempfile.mkstemp(
                prefix="rea-wasm-public-", suffix=".wasm", dir="/dev/shm")
            os.close(fd)
            wasm = Path(filename)
            targets.append(wasm)
            wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
            os.chmod(wasm, 0o644)
            fd, filename = tempfile.mkstemp(
                prefix="rea-sqlite-public-", suffix=".sqlite", dir="/dev/shm")
            os.close(fd)
            database = Path(filename)
            targets.append(database)
            import sqlite3
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "CREATE TABLE fixture_items (item_id INTEGER PRIMARY KEY, title TEXT)")
                connection.execute(
                    "INSERT INTO fixture_items (item_id, title) VALUES (1, 'rea-public')")
                connection.commit()
            finally:
                connection.close()
            os.chmod(database, 0o644)
            tasks = (
                ("inspect_managed_artifact", {"path": str(managed), "detail": "summary"},
                 "REA_FIXTURE_MANAGED_PE"),
                ("inspect_managed_members",
                 {"path": str(managed), "detail": "summary"},
                 "REA_FIXTURE_MANAGED_MEMBERS"),
                ("inspect_managed_native_boundaries",
                 {"path": str(managed)},
                 "REA_FIXTURE_MANAGED_BOUNDARIES"),
                ("inspect_pe_resources", {"path": str(managed)},
                 "REA_FIXTURE_PE_RESOURCES"),
                ("inspect_electron_fuses", {"path": str(macho)},
                 "REA_FIXTURE_MACHO_FUSES"),
                ("inspect_wasm_artifact", {"path": str(wasm), "detail": "summary"},
                 "REA_FIXTURE_WASM"),
                ("inspect_sqlite_database", {"path": str(database)},
                 "REA_FIXTURE_SQLITE"),
            )
            records = []
            for i, (tool, args, marker) in enumerate(tasks):
                if tool not in tool_by_name:
                    records.append({"tool": tool, "status": "NOT_ADVERTISED"})
                    print(marker + "=NOT_ADVERTISED")
                    continue
                try:
                    _, reply = request_mcp(
                        {"jsonrpc": "2.0", "id": 91 + i, "method": "tools/call",
                         "params": {"name": tool, "arguments": args}},
                        session, protocol, timeout=105
                    )
                    result = reply.get("result")
                    ok = "error" not in reply and isinstance(result, dict) and (
                        result.get("isError") is not True)
                    records.append({"tool": tool, "status": "PASS" if ok else "ERROR",
                                    "response": result if isinstance(result, dict)
                                    else {"error": "MCP returned protocol error"}})
                    print(marker + "=" + ("PASS" if ok else "ERROR"))
                except Exception:
                    records.append({"tool": tool, "status": "ERROR",
                                    "response": {"error": "MCP call unavailable"}})
                    print(marker + "=ERROR")
            result = {"target_family": ["Windows PE/CLI", "Apple Mach-O Electron", "WASM", "SQLite"],
                      "source": "REA existing fixtures; no untrusted code run",
                      "fixtures_sha256": {
                          "managed_pe": hashlib.sha256(raw).hexdigest(),
                          "macho": hashlib.sha256(macho.read_bytes()).hexdigest(),
                          "wasm": hashlib.sha256(wasm.read_bytes()).hexdigest(),
                          "sqlite": hashlib.sha256(database.read_bytes()).hexdigest()
                      }, "records": records}
            data_bytes = json.dumps(result, ensure_ascii=True,
                                    sort_keys=True).encode()
            if len(data_bytes) > MAX_RESPONSE:
                error("Public format evidence exceeded encrypted-return budget")
            print("REA_MOBILE_TOOL_CALL=PASS")
            print("REA_MOBILE_TOOL_ERROR=" + str(
                any(r["status"] != "PASS" for r in records)).lower())
            print("REA_MOBILE_OUTPUT_BYTES=" + str(len(data_bytes)))
            print("REA_MOBILE_OUTPUT_SHA256=" +
                  hashlib.sha256(data_bytes).hexdigest())
            if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
                error("Public format fixture requires encrypted result capture")
            print("REA_MOBILE_PRIVATE_RESULT_B64=" +
                  base64.b64encode(data_bytes).decode("ascii"))
        finally:
            for file in targets:
                file.unlink(missing_ok=True)
                if file.exists():
                    cleanup_ok = False
            print("REA_FIXTURE_FORMAT_CLEANUP=" +
                  ("PASS" if cleanup_ok else "FAIL"))
            if not cleanup_ok:
                error("Public format fixture staging was not cleaned")
        return
    if data["action"] == "fixture_apkdemos":
        # Public source and sha256 are pinned to the checked-in REA fixture
        # rea/scripts/fixtures/android/apidemos.json. No caller-controlled URL,
        # path, script, APK, or install is admitted by this action.
        import tempfile
        url = ("https://github.com/appium/android-apidemos/releases/"
               "download/v6.0.18/ApiDemos-debug.apk")
        expected = "a9eecf37b26cd084855c530db81c2bb1b91f4c1b095a04f47aa7c20e2791f686"
        path = None
        cleanup = False
        try:
            fd, name = tempfile.mkstemp(
                prefix="rea-apidemos-public-", suffix=".apk", dir="/dev/shm")
            path = Path(name)
            sha = hashlib.sha256()
            total = 0
            with os.fdopen(fd, "wb") as output:
                with urllib.request.urlopen(
                    urllib.request.Request(
                        url, headers={"User-Agent": "REA-public-fixture-smoke"}),
                    timeout=55
                ) as incoming:
                    while True:
                        block = incoming.read(65536)
                        if not block:
                            break
                        total += len(block)
                        if total > 30 * 1024 * 1024:
                            error("Public Android fixture exceeds fixed size budget")
                        sha.update(block)
                        output.write(block)
            if sha.hexdigest() != expected:
                error("Public Android fixture hash mismatch")
            # The REA service is isolated from the SSH user's private home
            # and from /tmp (PrivateTmp). /dev/shm is staging only; it contains
            # one VERIFIED and NONCONFIDENTIAL fixture for this request.
            os.chmod(path, 0o644)
            print("REA_FIXTURE_ANDROID_DOWNLOAD=PASS")
            print("REA_FIXTURE_ANDROID_SHA256=" + sha.hexdigest())
            public_apk = {"path": str(path)}
            class_name = "io.appium.android.apis.ApiDemos"
            fixed_operations = (
                ("inspect_android_package", public_apk,
                 "REA_FIXTURE_ANDROID_JADX"),
                ("search_android_classes", {**public_apk, "query": "ApiDemos"},
                 "REA_FIXTURE_ANDROID_CLASSES"),
                ("inspect_android_class", {**public_apk, "class_name": class_name},
                 "REA_FIXTURE_ANDROID_CLASS"),
                ("inspect_android_method",
                 {**public_apk, "class_name": class_name, "method_name": "onCreate"},
                 "REA_FIXTURE_ANDROID_METHOD"),
                ("trace_android_references", {**public_apk, "class_name": class_name},
                 "REA_FIXTURE_ANDROID_XREFS"),
            )
            observations = []
            for pos, (tool, args, marker) in enumerate(fixed_operations):
                if tool not in tool_by_name:
                    print(marker + "=NOT_ADVERTISED")
                    observations.append({"tool": tool, "status": "NOT_ADVERTISED"})
                    continue
                try:
                    _, reply = request_mcp(
                        {"jsonrpc": "2.0", "id": 82 + pos, "method": "tools/call",
                         "params": {"name": tool, "arguments": args}},
                        session, protocol, timeout=155
                    )
                    result = reply.get("result")
                    ok = "error" not in reply and isinstance(result, dict) and (
                        result.get("isError") is not True)
                    print(marker + "=" + ("PASS" if ok else "ERROR"))
                    observations.append({
                        "tool": tool, "status": "PASS" if ok else "ERROR",
                        "response": result if isinstance(result, dict) else {
                            "error": "MCP protocol response unavailable"},
                    })
                except Exception:
                    print(marker + "=ERROR")
                    observations.append({
                        "tool": tool, "status": "ERROR",
                        "response": {"error": "MCP operation unavailable"}
                    })
            body = json.dumps(
                {"artifact": "Appium ApiDemos 6.0.18", "sha256": expected,
                 "records": observations}, sort_keys=True, ensure_ascii=True
            ).encode()
            if len(body) > MAX_RESPONSE:
                error("REA Android fixture results exceed encrypted-return budget")
            print("REA_MOBILE_TOOL_CALL=PASS")
            print("REA_MOBILE_TOOL_ERROR=" + str(
                any(row["status"] != "PASS" for row in observations)).lower())
            print("REA_MOBILE_OUTPUT_BYTES=" + str(len(body)))
            print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(body).hexdigest())
            if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
                error("Public fixture requires encrypted result capture")
            print("REA_MOBILE_PRIVATE_RESULT_B64=" +
                  base64.b64encode(body).decode("ascii"))
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
                cleanup = not path.exists()
                print("REA_FIXTURE_ANDROID_CLEANUP=" +
                      ("PASS" if cleanup else "FAIL"))
            if not cleanup:
                error("Public Android fixture staging was not cleaned")
        return
    if data["action"] == "health":
        toolroot = Path.home() / ".local/share/rea-chatgpt-trial"
        cli = toolroot / "repository/rea/scripts/rea.mjs"
        jdk = toolroot / "tools/jdk-21"
        jadx = toolroot / "tools/jadx-headless-mcp-0.7.1-all.jar"
        ghidra = toolroot / "tools/ghidra_12.1.4_PUBLIC"
        if not all([cli.is_file(), (jdk / "bin/java").is_file(),
                    jadx.is_file(), (ghidra / "support/analyzeHeadless").is_file()]):
            error("Known REA health toolchain incomplete")
        env = os.environ.copy()
        env.update({
            "JAVA_HOME": str(jdk),
            "REA_JADX_MCP_JAR": str(jadx),
            "GHIDRA_INSTALL_DIR": str(ghidra),
            "GHIDRA_HEADLESS_MAXMEM": "1024M",
            "REA_JADX_HEAP_MIB": "1024",
            "NODE_OPTIONS": "--max-old-space-size=1024",
        })
        for provider in ("jadx", "ghidra"):
            result = subprocess.run(
                ["node", str(cli), "doctor", "--provider", provider, "--json"],
                text=True, capture_output=True, timeout=55,
                check=False, env=env
            )
            if result.returncode:
                raise RuntimeError("REA doctor failed for " + provider)
            try:
                json.loads(result.stdout)
            except ValueError:
                raise RuntimeError("REA doctor response not JSON for " + provider)
            print("REA_MOBILE_PROVIDER_DOCTOR_" + provider.upper() + "=PASS")
        print("REA_MOBILE_HEALTH=PASS")
        return
    if data["action"] == "catalog":
        from jsonschema.validators import validator_for
        for descriptor in tools:
            validator_for(descriptor["inputSchema"]).check_schema(descriptor["inputSchema"])
        print("REA_MOBILE_VALIDATED_SCHEMA_COUNT=" + str(len(tools)))
        print("REA_MOBILE_AUDITED_SCHEMA_MATCH_COUNT=" + str(sum(
            secure.arguments_sha256(descriptor.get("inputSchema")) ==
            secure.AUDITED_SCHEMA_SHA256.get(name)
            for name, descriptor in tool_by_name.items())))
        print("REA_MOBILE_CATALOG=PASS")
        print("REA_MOBILE_READONLY_NAMES=" + json.dumps(readonly[:40]))
        print("REA_MOBILE_STATIC_INSPECT_NAMES=" + json.dumps(permitted_static))
        print("REA_MOBILE_SAFE_QUERY_NAMES=" + json.dumps(permitted_query))
        print("REA_MOBILE_ALL_NAMES=" + json.dumps(sorted(tool_by_name)))
        return
    if data["action"] == "describe":
        name = data["tool"]
        if name not in tool_by_name:
            error("Tool not advertised by REA")
        descriptor = tool_by_name[name]
        raw = json.dumps(descriptor, sort_keys=True, ensure_ascii=True).encode()
        if len(raw) > MAX_RESPONSE:
            error("MCP tool descriptor exceeds encrypted return budget")
        schema = descriptor.get("inputSchema") or {}
        properties = schema.get("properties") or {}
        summary = {
            "tool": name,
            "required": schema.get("required") if isinstance(
                schema.get("required"), list) else [],
            "properties": sorted(properties)[:24] if isinstance(properties, dict) else [],
            "schema_type": schema.get("type"),
            "annotations": descriptor.get("annotations") or {},
        }
        print("REA_MOBILE_DESCRIBE_TOOL=" + name)
        print("REA_MOBILE_TOOL_DESCRIPTOR_SHA256=" + hashlib.sha256(raw).hexdigest())
        print("REA_MOBILE_TOOL_DESCRIPTOR_BYTES=" + str(len(raw)))
        print("REA_MOBILE_TOOL_SCHEMA_SUMMARY=" + json.dumps(
            summary, sort_keys=True, separators=(",", ":")))
        if "response_key" in data:
            if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
                error("Full tool descriptors require encrypted result capture")
            print("REA_MOBILE_PRIVATE_RESULT_B64=" + base64.b64encode(raw).decode("ascii"))
            print("REA_MOBILE_TOOL_DESCRIPTOR_TRUNCATED=NO_ENCRYPTED")
        else:
            public_b64 = base64.b64encode(raw).decode("ascii")
            if len(public_b64) <= 18000:
                print("REA_MOBILE_TOOL_DESCRIPTOR_B64=" + public_b64)
                print("REA_MOBILE_TOOL_DESCRIPTOR_TRUNCATED=NO")
            else:
                print("REA_MOBILE_TOOL_DESCRIPTOR_TRUNCATED=NEEDS_ENCRYPTED_REPLY")
        return
    if data["action"] == "sealed_batch":
        # All 208 advertised names can be routed, but each operation is
        # individually classified and must pass its risk-specific grant.
        # No plaintext request parameters/results are printed to public logs.
        body = secure.unseal(data["sealed"], data["response_key"])
        profiles = secure.validate_inner(body, tool_by_name, set(safe_callable))
        # Individual workspace and owner-Ed25519 sensitive approvals have
        # already been verified before releasing either lifecycle tool.
        lifecycle_grants = p232_guard_inner_batch(body)
        secure.claim_one_use_nonce(body["nonce"])
        print("REA_SEALED_POLICY=PASS")
        print("REA_SEALED_STEPS_TOTAL=" + str(len(body["steps"])))
        records = []
        binary_open = False
        cleanup_ok = True
        signed_close_attempted = False
        try:
            for idx, (step, risk) in enumerate(zip(body["steps"], profiles), start=1):
                name = step["tool"]
                if name == "close_binary" and "close_binary" in lifecycle_grants:
                    signed_close_attempted = True
                _, reply = request_mcp(
                    {"jsonrpc": "2.0", "id": idx + 100, "method": "tools/call",
                     "params": {"name": name, "arguments": step["arguments"]}},
                    session, protocol, timeout=100,
                    lifecycle_grants=lifecycle_grants
                )
                if "error" in reply or not isinstance(reply.get("result"), dict):
                    raise RuntimeError("REA returned a protocol error for an authorized step")
                item = reply["result"]
                ok = item.get("isError") is not True
                records.append({"tool": name, "risk": risk, "result": item})
                if name == "open_binary" and ok:
                    binary_open = True
                elif name == "close_binary" and ok:
                    binary_open = False
                if not ok:
                    break
        finally:
            if binary_open:
                if signed_close_attempted or "close_binary" not in lifecycle_grants:
                    # Do not replay an ambiguous signed close. A missing
                    # signed close is a hard error, never implicit permission.
                    cleanup_ok = False
                else:
                    try:
                        _, closed = request_mcp(
                            {"jsonrpc": "2.0", "id": 199, "method": "tools/call",
                             "params": {"name": "close_binary", "arguments": {}}},
                            session, protocol, timeout=85,
                            lifecycle_grants=lifecycle_grants
                        )
                        cleanup_ok = ("error" not in closed and
                                      (closed.get("result") or {}).get("isError") is not True)
                    except Exception:
                        cleanup_ok = False
                print("REA_SEALED_CLEANUP=" + ("PASS" if cleanup_ok else "FAIL"))
        if not cleanup_ok:
            raise RuntimeError("REA binary session cleanup failed")
        output = json.dumps({"protocol": 1, "steps": records},
                            ensure_ascii=True, sort_keys=True).encode()
        if len(output) > MAX_RESPONSE:
            raise RuntimeError("REA secure result exceeds encrypted response limit")
        print("REA_SEALED_STEPS_EXECUTED=" + str(len(records)))
        print("REA_MOBILE_TOOL_CALL=PASS")
        print("REA_MOBILE_OUTPUT_BYTES=" + str(len(output)))
        print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(output).hexdigest())
        print("REA_MOBILE_TOOL_ERROR=" + str(
            any(x["result"].get("isError") is True for x in records)).lower())
        if os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") != "1":
            raise RuntimeError("Secure calls require encrypted result capture")
        print("REA_MOBILE_PRIVATE_RESULT_B64=" +
              base64.b64encode(output).decode("ascii"))
        return
    name = data["tool"]
    if name not in safe_callable:
        error("Requested tool is not in the explicit query/inspection allowlist")
    if (tool_by_name[name].get("annotations") or {}).get("destructiveHint") is True:
        error("Tool descriptor declares destructive side effects")
    if secure.classify(name, tool_by_name[name], safe_callable) != "read":
        error("This operation requires the sealed per-operation authorization path")
    secure.validate_arguments(tool_by_name[name], data["arguments"])
    secure._authorized_target_paths(data["arguments"])
    _, result = request_mcp(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": name, "arguments": data["arguments"]}},
        session, protocol
    )
    if "error" in result:
        error("MCP tool call returned an error")
    body = json.dumps(result.get("result"), ensure_ascii=True,
                      sort_keys=True).encode()
    # Public GitHub Actions logs must not disclose analysis data or private paths.
    print("REA_MOBILE_TOOL_CALL=PASS")
    print("REA_MOBILE_TOOL_NAME=" + name)
    print("REA_MOBILE_OUTPUT_BYTES=" + str(len(body)))
    print("REA_MOBILE_OUTPUT_SHA256=" + hashlib.sha256(body).hexdigest())
    print("REA_MOBILE_TOOL_ERROR=" + str(bool(
        result.get("result", {}).get("isError", False))).lower())
    if "response_key" in data and os.environ.get("REA_MOBILE_ENVELOPE_CAPTURE") == "1":
        print("REA_MOBILE_PRIVATE_RESULT_B64=" +
              base64.b64encode(body).decode())


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("REA_MOBILE_BRIDGE=FAIL " + type(exc).__name__ + ": " +
              str(exc)[:250], file=sys.stderr)
        sys.exit(1)

