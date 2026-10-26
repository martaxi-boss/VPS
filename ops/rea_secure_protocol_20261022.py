#!/usr/bin/env python3
"""Private, one-use request envelopes for the existing REA GitHub->SSH bridge.

No new listener, MCP server or network transport. Never log decoded requests.
The GitHub repository is public: it may contain only ciphertext and public keys.
"""
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ALGORITHM = "RSA-OAEP-SHA256+A256GCM"
AAD_PREFIX = b"REA-MCP-SEALED-REQUEST-v1\x00"
MAX_PLAINTEXT = 512000
MAX_CIPHERTEXT_B64 = ((MAX_PLAINTEXT + 16 + 2) // 3) * 4
MAX_STEPS = 12
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,119}$")
HIGH_RISK_PREFIXES = (
    "install_", "uninstall_", "push_adb_", "start_adb_", "stop_adb_",
    "pull_adb_", "capture_", "observe_", "instrument_", "load_frida_",
    "unload_frida_", "resume_frida_", "start_frida_", "start_gdb_",
    "start_rizin_", "gdb_console", "rizin_debug_command",
    "execute_rizin_command", "cutter_command", "import_",
    "set_", "unset_", "annotate_", "record_", "update_",
)
HIGH_RISK_NAMES = frozenset({
    "goto_address", "read_adb_logcat", "read_adb_setting",
    "list_adb_processes", "list_adb_packages", "list_adb_directory",
    "list_adb_services", "list_adb_devices", "inspect_adb_device",
    "inspect_adb_package", "inspect_adb_window", "inspect_adb_display",
    "inspect_adb_client", "export_evidence_bundle",
    "extract_artifact", "extract_firmware", "inspect_web_page",
    "inspect_web_network_capture", "inspect_web_event_listeners",
    "list_frida_processes", "list_browser_targets", "list_electron_targets",
    "inspect_electron_page", "observe_javascript_runtime",
    "recover_javascript_sources", "reconcile_javascript_runtime",
    "open_jeb_project", "close_frida_session", "close_gdb_session",
    "close_rizin_debug_session",
})
# Source-audited REA ToolEffects = session evidence only (no target write,
# process/device mutation, foreign execution or network access).
REVIEWED_SESSION_READ_TOOLS = frozenset({
    'inspect_native_load_image',
    'inspect_native_data_type',
    'resolve_native_call_targets',
    'search_bytes',
    'inspect_native_dispatch_metadata',
    'get_objc_classes',
    'get_objc_protocols',
    'batch_decompile',
    'inspect_native_api',
    'trace_feature',
    'trace_call_path',
    'inspect_address_context',
    'get_navigation_context',
    'binary_overview',
    'list_segments',
    'list_names',
    'list_procedures',
    'list_strings',
    'procedure_address',
    'procedure_assembly',
    'procedure_callees',
    'procedure_callers',
    'procedure_info',
    'procedure_pseudo_code',
    'procedure_references',
    'address_name',
    'address_to_file_offset',
    'find_xrefs_to_name',
    'get_call_graph',
    'search_procedures',
    'search_strings',
    'inspect_artifact',
    'inspect_macho',
    'inspect_signature',
    'decode_interface_builder',
    'inspect_keyed_archive',
    'inspect_asset_catalog',
    'trace_dylib_resolution',
    'analyze_swift_types',
    'current_document',
    'current_address',
    'current_procedure',
    'list_bookmarks',

    "read_bytes", "resolve_containing_procedure", "inspect_native_instruction",
    "read_function_instructions", "xrefs", "analyze_function",
})

# P286: explicit source-effects review of passive provider queries and bounded
# workspace artifact analyses. These use the SAME per-request authenticated SSH,
# exact MCP schema, path confinement and exact workspace authorization; they
# cannot write a target, discard Evidence or execute foreign code according to
# the source-audited REA ToolEffects contract. No 'read' class is granted.
# Mutating/device/process-control/Evidence ledger actions remain owner-signed.
REVIEWED_SCOPED_WORKSPACE_OPERATIONS = frozenset({
    "analyze_web_bundle",
    "capture_adb_screen",
    "capture_web_screenshot",
    "collect_adb_bugreport",
    "decompile_jeb_item",
    "discover_webmcp_tools",
    "extract_artifact",
    "extract_firmware",
    "inspect_adb_client",
    "inspect_adb_device",
    "inspect_adb_display",
    "inspect_adb_package",
    "inspect_adb_window",
    "inspect_electron_page",
    "inspect_jeb_client",
    "inspect_web_event_listeners",
    "inspect_web_network_capture",
    "inspect_web_page",
    "list_adb_devices",
    "list_adb_directory",
    "list_adb_features",
    "list_adb_packages",
    "list_adb_processes",
    "list_adb_services",
    "list_browser_targets",
    "list_cutter_sessions",
    "list_electron_targets",
    "list_frida_devices",
    "list_frida_processes",
    "list_javascript_runtime_targets",
    "list_jeb_units",
    "observe_web_session",
    "read_adb_logcat",
    "read_adb_setting",
    "reconcile_javascript_runtime",
    "resolve_adb_packages",
})
OWNER_SIGNATURE_EFFECTS = frozenset({
    "mutatesTarget", "mayDiscardData", "changesUiState",
    "executesForeignCode", "mutatesDevice",
})

# Canonical effect audit: Engenheira-reversa a29937e6, rea/src/contracts/toolEffects.ts.
# All 208 names were matched to the complete live catalog on 2026-10-22.
# Unknown names and incompatible live annotations remain sensitive.
AUDITED_EFFECTS = {
    'address_name': frozenset('mutatesSession'.split()),
    'address_to_file_offset': frozenset('mutatesSession'.split()),
    'analyze_function': frozenset('mutatesSession'.split()),
    'analyze_javascript_application': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'analyze_swift_types': frozenset('mutatesSession'.split()),
    'analyze_web_bundle': frozenset('mutatesSession accessesNetwork'.split()),
    'annotate_native_function': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess mayDiscardData'.split()),
    'batch_decompile': frozenset('mutatesSession'.split()),
    'binary_overview': frozenset('mutatesSession'.split()),
    'binary_session': frozenset('launchesProcess'.split()),
    'build_call_path': frozenset('mutatesSession'.split()),
    'build_reconstruction_obligation_ledger': frozenset('mutatesSession'.split()),
    'capture_adb_screen': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork'.split()),
    'capture_browser_scenario': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState mayDiscardData executesForeignCode'.split()),
    'capture_electron_scenario': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState mayDiscardData executesForeignCode'.split()),
    'capture_native_ui_scenario': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState mayDiscardData executesForeignCode'.split()),
    'capture_process_scenario': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork executesForeignCode'.split()),
    'capture_web_screenshot': frozenset('mutatesSession accessesNetwork'.split()),
    'close_binary': frozenset('mutatesSession writesFilesystem mayDiscardData'.split()),
    'close_frida_session': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork'.split()),
    'close_gdb_session': frozenset('mutatesTarget mutatesSession launchesProcess executesForeignCode'.split()),
    'close_rizin_debug_session': frozenset('mutatesTarget mutatesSession launchesProcess executesForeignCode'.split()),
    'collect_adb_bugreport': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork'.split()),
    'comment': frozenset('mutatesSession'.split()),
    'compare_application_versions': frozenset('mutatesSession'.split()),
    'compare_artifacts': frozenset('mutatesSession'.split()),
    'compare_bundles': frozenset('mutatesSession'.split()),
    'compare_functions': frozenset('mutatesSession'.split()),
    'compare_javascript_export_shapes': frozenset('mutatesSession'.split()),
    'compare_managed_members': frozenset('mutatesSession'.split()),
    'compare_process_captures': frozenset('mutatesSession'.split()),
    'compare_source_to_bundle': frozenset('mutatesSession'.split()),
    'compare_wasm_interfaces': frozenset('mutatesSession'.split()),
    'compare_web_captures': frozenset('mutatesSession'.split()),
    'compare_web_screenshots': frozenset('mutatesSession'.split()),
    'correlate_static_and_runtime': frozenset('mutatesSession'.split()),
    'current_address': frozenset('mutatesSession'.split()),
    'current_document': frozenset('mutatesSession'.split()),
    'current_procedure': frozenset('mutatesSession'.split()),
    'cutter_command': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState executesForeignCode'.split()),
    'decode_android_resources': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'decode_interface_builder': frozenset('mutatesSession'.split()),
    'decode_signal_recording': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'decompile_jeb_item': frozenset('mutatesSession accessesNetwork'.split()),
    'demangle_swift': frozenset('mutatesSession launchesProcess'.split()),
    'discover_webmcp_tools': frozenset('mutatesSession accessesNetwork'.split()),
    'evaluate_reconstruction_coverage': frozenset(''.split()),
    'execute_rizin_command': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork mayDiscardData executesForeignCode'.split()),
    'export_evidence_bundle': frozenset('writesFilesystem mayDiscardData'.split()),
    'export_web_scripts': frozenset('mutatesSession writesFilesystem'.split()),
    'extract_artifact': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'extract_firmware': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'find_changed_behavior': frozenset('mutatesSession'.split()),
    'find_xrefs_to_name': frozenset('mutatesSession'.split()),
    'frida_session_status': frozenset('mutatesSession'.split()),
    'gdb_console': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork executesForeignCode'.split()),
    'gdb_session_status': frozenset(''.split()),
    'get_call_graph': frozenset('mutatesSession'.split()),
    'get_evidence_bundle': frozenset(''.split()),
    'get_navigation_context': frozenset('mutatesSession'.split()),
    'get_objc_classes': frozenset('mutatesSession'.split()),
    'get_objc_protocols': frozenset('mutatesSession'.split()),
    'goto_address': frozenset('mutatesSession changesUiState'.split()),
    'identify_flutter_build': frozenset('mutatesSession writesFilesystem'.split()),
    'import_evidence_bundle': frozenset('mutatesSession'.split()),
    'import_managed_reconstruction': frozenset('mutatesSession'.split()),
    'inline_comment': frozenset('mutatesSession'.split()),
    'inspect_adb_client': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_adb_device': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'inspect_adb_display': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'inspect_adb_package': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'inspect_adb_window': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'inspect_address_context': frozenset('mutatesSession'.split()),
    'inspect_analysis_view': frozenset('mutatesSession'.split()),
    'inspect_android_class': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_android_method': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_android_package': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_apktool_client': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_artifact': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_asset_catalog': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_binary_layout': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_dart_aot': frozenset('mutatesSession writesFilesystem'.split()),
    'inspect_desktop_application': frozenset('mutatesSession'.split()),
    'inspect_electron_fuses': frozenset('mutatesSession'.split()),
    'inspect_electron_page': frozenset('mutatesSession accessesNetwork'.split()),
    'inspect_evm_interface': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_firmware_regions': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_go_binary': frozenset('mutatesSession'.split()),
    'inspect_jeb_client': frozenset('mutatesSession accessesNetwork'.split()),
    'inspect_keyed_archive': frozenset('mutatesSession'.split()),
    'inspect_macho': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_managed_artifact': frozenset('mutatesSession'.split()),
    'inspect_managed_members': frozenset('mutatesSession'.split()),
    'inspect_managed_native_boundaries': frozenset('mutatesSession'.split()),
    'inspect_native_api': frozenset('mutatesSession'.split()),
    'inspect_native_data_type': frozenset('mutatesSession'.split()),
    'inspect_native_dispatch_metadata': frozenset('mutatesSession'.split()),
    'inspect_native_instruction': frozenset('mutatesSession'.split()),
    'inspect_native_load_image': frozenset('mutatesSession'.split()),
    'inspect_packet_capture': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_packet_fields': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_pcap_capture': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_pcap_client': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_pe_resources': frozenset('mutatesSession'.split()),
    'inspect_plist': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_recorded_crash': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_rust_binary': frozenset('mutatesSession'.split()),
    'inspect_signal_decoders': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_signature': frozenset('mutatesSession launchesProcess'.split()),
    'inspect_sqlite_database': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_wasm_artifact': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_web_event_listeners': frozenset('mutatesSession accessesNetwork'.split()),
    'inspect_web_network_capture': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'inspect_web_page': frozenset('mutatesSession accessesNetwork'.split()),
    'inspect_with_objdump': frozenset('mutatesSession launchesProcess'.split()),
    'install_adb_package': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork mutatesDevice'.split()),
    'instrument_with_frida': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork executesForeignCode'.split()),
    'list_adb_devices': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_adb_directory': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_adb_features': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_adb_packages': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_adb_processes': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_adb_services': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'list_architectures': frozenset('mutatesSession launchesProcess'.split()),
    'list_bookmarks': frozenset('mutatesSession'.split()),
    'list_browser_targets': frozenset('mutatesSession accessesNetwork'.split()),
    'list_cutter_sessions': frozenset('accessesNetwork'.split()),
    'list_documents': frozenset('mutatesSession'.split()),
    'list_electron_targets': frozenset('mutatesSession accessesNetwork'.split()),
    'list_frida_devices': frozenset('launchesProcess accessesNetwork'.split()),
    'list_frida_processes': frozenset('launchesProcess accessesNetwork'.split()),
    'list_javascript_runtime_targets': frozenset('mutatesSession accessesNetwork'.split()),
    'list_jeb_units': frozenset('mutatesSession accessesNetwork'.split()),
    'list_names': frozenset('mutatesSession'.split()),
    'list_procedures': frozenset('mutatesSession'.split()),
    'list_segments': frozenset('mutatesSession'.split()),
    'list_strings': frozenset('mutatesSession'.split()),
    'list_unknowns': frozenset(''.split()),
    'load_frida_script': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork executesForeignCode'.split()),
    'next_address': frozenset('mutatesSession'.split()),
    'observe_javascript_runtime': frozenset('mutatesSession accessesNetwork'.split()),
    'observe_native_calls': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState executesForeignCode'.split()),
    'observe_native_ui': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'observe_web_execution': frozenset('mutatesTarget mutatesSession accessesNetwork mayDiscardData'.split()),
    'observe_web_session': frozenset('mutatesSession accessesNetwork'.split()),
    'open_binary': frozenset('mutatesSession launchesProcess'.split()),
    'open_jeb_project': frozenset('mutatesSession accessesNetwork'.split()),
    'prev_address': frozenset('mutatesSession'.split()),
    'procedure_address': frozenset('mutatesSession'.split()),
    'procedure_assembly': frozenset('mutatesSession'.split()),
    'procedure_callees': frozenset('mutatesSession'.split()),
    'procedure_callers': frozenset('mutatesSession'.split()),
    'procedure_info': frozenset('mutatesSession'.split()),
    'procedure_pseudo_code': frozenset('mutatesSession'.split()),
    'procedure_references': frozenset('mutatesSession'.split()),
    'project_android_application_graph': frozenset('mutatesSession'.split()),
    'project_apple_application_graph': frozenset('mutatesSession'.split()),
    'project_harmony_application_graph': frozenset('mutatesSession'.split()),
    'project_managed_application_graph': frozenset('mutatesSession'.split()),
    'pull_adb_file': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork'.split()),
    'pull_adb_package': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork'.split()),
    'push_adb_file': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork mutatesDevice'.split()),
    'read_adb_logcat': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'read_adb_setting': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'read_bytes': frozenset('mutatesSession'.split()),
    'read_function_instructions': frozenset('mutatesSession'.split()),
    'reconcile_javascript_runtime': frozenset('mutatesSession'.split()),
    'record_unknown': frozenset('mutatesSession'.split()),
    'recover_javascript_sources': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'resolve_adb_packages': frozenset('mutatesSession launchesProcess accessesNetwork'.split()),
    'resolve_containing_procedure': frozenset('mutatesSession'.split()),
    'resolve_native_call_targets': frozenset('mutatesSession'.split()),
    'resume_frida_session': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork executesForeignCode'.split()),
    'rizin_debug_command': frozenset('mutatesTarget mutatesSession writesFilesystem launchesProcess accessesNetwork changesUiState mayDiscardData executesForeignCode'.split()),
    'rizin_debug_session_status': frozenset('mutatesSession'.split()),
    'search_android_classes': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'search_bytes': frozenset('mutatesSession'.split()),
    'search_procedures': frozenset('mutatesSession'.split()),
    'search_strings': frozenset('mutatesSession'.split()),
    'set_address_name': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'set_addresses_names': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'set_bookmark': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'set_comment': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'set_inline_comment': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'start_adb_activity': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork mutatesDevice'.split()),
    'start_adb_app': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork mutatesDevice'.split()),
    'start_frida_session': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork'.split()),
    'start_gdb_session': frozenset('mutatesSession launchesProcess'.split()),
    'start_rizin_debug_session': frozenset('mutatesTarget mutatesSession launchesProcess executesForeignCode'.split()),
    'stop_adb_app': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork mutatesDevice'.split()),
    'trace_android_references': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'trace_application_feature': frozenset('mutatesSession'.split()),
    'trace_call_path': frozenset('mutatesSession'.split()),
    'trace_dylib_resolution': frozenset('mutatesSession'.split()),
    'trace_feature': frozenset('mutatesSession'.split()),
    'trace_javascript_semantics': frozenset('mutatesSession'.split()),
    'trace_native_ui_action': frozenset('mutatesSession'.split()),
    'trace_native_values': frozenset('mutatesSession'.split()),
    'trace_web_module_imports': frozenset('mutatesSession writesFilesystem launchesProcess accessesNetwork'.split()),
    'trace_web_source_location': frozenset('mutatesSession writesFilesystem launchesProcess'.split()),
    'uninstall_adb_package': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork mutatesDevice'.split()),
    'unload_frida_script': frozenset('mutatesTarget mutatesSession launchesProcess accessesNetwork'.split()),
    'unset_bookmark': frozenset('mutatesTarget mutatesSession mayDiscardData'.split()),
    'update_unknown': frozenset('mutatesSession'.split()),
    'verify_managed_native_boundaries': frozenset('mutatesSession'.split()),
    'verify_reconstruction': frozenset('mutatesSession'.split()),
    'verify_unknown_resolution': frozenset(''.split()),
    'xrefs': frozenset('mutatesSession'.split()),
}

# Exact live schema fingerprints: drift cannot silently inherit local grants.
AUDITED_SCHEMA_SHA256 = {
    'address_name': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'address_to_file_offset': 'dbeefa8be34d7fbbd00062b41dbe24c309938eb6eb441463b7c703b50af9d6e5',
    'analyze_function': '755ceb4f86ba55426eb7c4406f6f14cf3dc7fd1c96a79d12fd2d99207ef8a2a1',
    'analyze_javascript_application': '8aa7d0a27631f963ffa6da5bba74af0f36548d735927a29d37c185ebd1e654ac',
    'analyze_swift_types': '72b14233021dc4cb8715f218a5ef9f5eae566accc66d603edc49aa3bb26e3ec4',
    'analyze_web_bundle': 'f0f8a978841e9efc9bf84d9dd9482fa2c66ab895764e67c10ef452cc158a709b',
    'annotate_native_function': '3e23e3ec4210d82a31ce783b90302ebebe4c67c95f43d2ccab8e7bcc1ec9f89b',
    'batch_decompile': '5b9f882697018a836fa9958ae100a169248beab637e12bf6cbd0b328c854b6b7',
    'binary_overview': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'binary_session': '9bcf14242613cb5ae228338531db6d614c88c27edac11a8218a2327cbb3834f6',
    'build_call_path': '1fef275dffd590e5c779c8c5c8e072695a4b101e70b44d12d103cda88e55f0a8',
    'build_reconstruction_obligation_ledger': '070cc416d24cbbd6e076d678d6f761ea63e881521909430ca955ae2a9c1cc286',
    'capture_adb_screen': 'fa693bd87be92715bc3802adc65bacfd2e5f18df00fe078863a7041382996a9e',
    'capture_browser_scenario': '4c6ba6d9c1fdee7012a0d1ed02597d97d26147d6d69611951331cbdb98402281',
    'capture_electron_scenario': '4430605d7b881dce7aee8d1510c3f875bd61b91533eeac27656f73e2905c5934',
    'capture_native_ui_scenario': 'd4079b64fcbab79a6fde23efbe2ba5efc5c677316a443a23a1d024b783b24cfc',
    'capture_process_scenario': '52ab748f5d680c62cd40fd2825a1aece9d64e67334a7cbe27a65f8dbe0c726d9',
    'capture_web_screenshot': 'b3b19f72c8a47770e81d22345df0401e7690662856b3b45fc48823350e6e0af1',
    'close_binary': '7c3ec5b8da0b299cb07225898da552ae08d3beab891728da751e6e6210ab784d',
    'close_frida_session': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'close_gdb_session': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'close_rizin_debug_session': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'collect_adb_bugreport': '937ca33fac6c28f93cb111301973376ed5cbffbbff7d1f1f6a91d998bf01dca2',
    'comment': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'compare_application_versions': '72517c88e8f579f16573154c20d1b87fb92f9c9bdd75962cfd546cd34da04bd7',
    'compare_artifacts': '7537317439d04b57c2012426c572999b3c709bbf5794d188e810ab125debd186',
    'compare_bundles': '70fb57a6be8bb6ac4d9ed85cc685db6dd3243437cd5f74fe20d1445bce3f7afd',
    'compare_functions': '7537317439d04b57c2012426c572999b3c709bbf5794d188e810ab125debd186',
    'compare_javascript_export_shapes': '468646dc87ac1ebf629c679f4cf54edacd5f6692bd7b79edbb9000ae488a4b3f',
    'compare_managed_members': '7537317439d04b57c2012426c572999b3c709bbf5794d188e810ab125debd186',
    'compare_process_captures': '2b35444395d5bbc54a7fad1f4c7cda731b7e54cc4383e0727aade81ddc783fc7',
    'compare_source_to_bundle': '27a5b3f3360216920339ae101c9ece5e6077842a8c1d10e2a1a7ab4fa01d5d52',
    'compare_wasm_interfaces': '5eb3fda1790cc98246f84e90bc08025e8aac19da60dcf2730f80b5cf7fe8f3bd',
    'compare_web_captures': '928d5b50987741f49f917287aba94eb3ccb186921ba641d52a8c0602e4813de5',
    'compare_web_screenshots': 'a97bf84871059cc48e9fcec0b83fa173f93ca529fd89a9c2f39a91a53698fb5a',
    'correlate_static_and_runtime': '8587966dab4cc175ab8f0b1bd4ef216fe108cec00b401f0c16cc9d2219d23691',
    'current_address': '194cae8cbc22a3dc0077c8622279bea472d11e42032efa3a19e347929383739c',
    'current_document': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'current_procedure': '194cae8cbc22a3dc0077c8622279bea472d11e42032efa3a19e347929383739c',
    'cutter_command': 'ac65a80467beb9a82de6a4316b36f954411b199edc809e3f77b93153ce6aab99',
    'decode_android_resources': '1e28b6bdf046a256357c102d6a0ac3db4ab1646ea311567376cb754525fe0850',
    'decode_interface_builder': '94f8a6a278c88ebb25703aba6b191c627e98eae4413c6e01d7b1f10366a260ff',
    'decode_signal_recording': 'aaa1e1cab4a1ec3190e45a97bcd7b5fcd72a71c4c5d224414eb42f8e83f6509f',
    'decompile_jeb_item': 'd5fe01c01e13185dad0610f932b58285a80f8a104fc8bf9e7ba571f152406f87',
    'demangle_swift': '90e5a249e97d1544cd92a04f9c4e15dcd9ca07c28a95226bea7eaca4b4fded56',
    'discover_webmcp_tools': '524e457055e70fde32d14d7c5410a0719dd75a8883ade632d51eb67407a8b44d',
    'evaluate_reconstruction_coverage': '41eca249aa61423589cd786a946d8b438f0dc4fea3a43dbf492e0d8fd450eb15',
    'execute_rizin_command': '7fbb8cb5ef8c4f043a63f24cda0b6008c47e9faa12dc2260d3a3b338b175793b',
    'export_evidence_bundle': 'cdf9f45f18877cec2bf365f19349664d01cb31a75d5a3dc6555f2027756da0f2',
    'export_web_scripts': '04dde143462803c76d05cd5117c79654689af2131166b747d461400eb2f31226',
    'extract_artifact': '144995ec4835eb26a5f0bbf3783a18edc6a9740e1c97b474e8b24d59dd7132c3',
    'extract_firmware': 'd29bddcfcfb743d26980a08a3d822a613a43249e32fd1261210148da427020d8',
    'find_changed_behavior': '426a106f5c743065cdcd69b38862327c800e702e32741f7ae9ddb33c4e9941d7',
    'find_xrefs_to_name': 'fc4705f399c9e5fd1c8ba97cc811bdfaceeabe9013971121736526d4da18f7be',
    'frida_session_status': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'gdb_console': '4bf2fd8d741c4a68a2f535e2737c44a6d366bdb968353ecdca6243d115608f06',
    'gdb_session_status': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'get_call_graph': '6065ba127d9fd11ea6cb7f65dda46db640170132e40b746b42da3c8ac2f288c2',
    'get_evidence_bundle': '855be8c8fef6c10a0122b1ad598eec12b3d806c3595eda2d338a119712af4798',
    'get_navigation_context': '08c2fe755b828dfe3e12ca7fda73a2f7bc83e280b9432f71a21638dde766a974',
    'get_objc_classes': 'b8bf4caac08bf0a381aeb456376f3a64bb945c911dbac7ff8ba4f2610891445b',
    'get_objc_protocols': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'goto_address': 'dbeefa8be34d7fbbd00062b41dbe24c309938eb6eb441463b7c703b50af9d6e5',
    'identify_flutter_build': 'c87db48c2461f6307eda666dc83cace5cc9c14b881a6d863fa3d33cdccd5e330',
    'import_evidence_bundle': '6d888471c6101d9ceab38d1e71bff65b2cdcf6a18093cacdd51e7d11bbcb8dc1',
    'import_managed_reconstruction': 'aee134fdd7f754ef688320cee44600f5cb3a020b526383c210303fd73b18bdca',
    'inline_comment': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'inspect_adb_client': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_adb_device': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'inspect_adb_display': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'inspect_adb_package': '4259240e348208d1ac74ee396b167375127412d03c03b21d9d80e605dffc36ae',
    'inspect_adb_window': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'inspect_address_context': '1090f63caabbccead14319b7cbe8ff2695286f6c4ea361856b343ba215788c0c',
    'inspect_analysis_view': '61582e68a5fae401f2249df2d31d175aec0f34f6ad055cf4f697f618fd1829ef',
    'inspect_android_class': '5d0a06f55caca616a2e7165dbd8c4e85a327d896b19942add6102ab98712947f',
    'inspect_android_method': '6a3cc9665f0047a5e4f76d6462bdab8ee04cbf15253172a5bbd44818ccfc8a4b',
    'inspect_android_package': '7ca64518f71bf38698773e8e7bb73d9127c1aa3c40fe8e9e5138390d1d69b498',
    'inspect_apktool_client': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_artifact': '4d993f3da45d0286ada5cdd69f1e6ecc666b79099c916fcb4ca25c53b150cb6d',
    'inspect_asset_catalog': '10e3a8de5ebaf966d3091ae3f95be1f189c6db14f13c59f288a8f02bb7b06e6b',
    'inspect_binary_layout': 'db85e69fe2a7c899c77c23ae4f0878fe3c3c298f442c79021ae77b85ece1dba4',
    'inspect_dart_aot': '52dfbca3fbd32fd065309aaf5e4e90eb154dcba341fad581579e866c9dbbba6d',
    'inspect_desktop_application': 'da5a5a7a7f0d20dcf64d37d71b35de788f01b0f66904a7f787ee793c4b6dedda',
    'inspect_electron_fuses': 'ca2851be6b74f3fab37ee2ee9c39eb828231f7b102bfad9471f54fb2aced22f6',
    'inspect_electron_page': 'c3e09dfc4fc8a7a9ebdbc0ad35ba3e1e9df699a8786824e960803b66f7febfe0',
    'inspect_evm_interface': 'ccb2ebd42443c571d5cd8abccd535bbe0c7749b7cda2c67cf4e3570af2ce7743',
    'inspect_firmware_regions': '5d6a48065b720f4a769b7433ae6393a7137bc89eb3a2edc2bc7f4972467188e4',
    'inspect_go_binary': '05cd7e679cbbbcb9c207421e6f9863d9e1961472584112aad31b78c54cb1436f',
    'inspect_jeb_client': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_keyed_archive': 'cefbaca332901097fd338fec219e70d541a40091df824d45459dd4812f2a2da7',
    'inspect_macho': '3fdb6b8c5bf8a46ce9301eca7374173cba2c9c525355e2b25a5e53b462af1a08',
    'inspect_managed_artifact': '7fd3b3346b39856552ca833a59fcf5a86ec455b46161d2b466097d22924e7447',
    'inspect_managed_members': '42d90fb9fa4b69e4d188160647d263d4606556d5d091321ee14b6ade4ca43af7',
    'inspect_managed_native_boundaries': '333fc1075b7a7ed454cc5f37eade7ea4af99b37ad2a942573566f08d3d8f56b0',
    'inspect_native_api': '755ceb4f86ba55426eb7c4406f6f14cf3dc7fd1c96a79d12fd2d99207ef8a2a1',
    'inspect_native_data_type': '91469ea564c77e63b3202e6669731fec650e21e5f7094833a72e084dfe23b2c8',
    'inspect_native_dispatch_metadata': '31a2b0b479bec438efc3e2aad8c7e6e2f2ca348c8e89f89e4794314880ac44e0',
    'inspect_native_instruction': '324cd72f21b8405cffa47b5e9ac76107657f326d71f42b3db793ad15560dc46e',
    'inspect_native_load_image': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_packet_capture': 'df218deaa4533e214712134a140753c8afa2704ad137196645905e641509e614',
    'inspect_packet_fields': 'a2cd00dc48818456fd3ae1d1ec7a4a6f01bd7b263411e62a8615edf5745032a2',
    'inspect_pcap_capture': 'c9b56f67b91f41b0094033a7ae68163b8ac3e944179076713b8960c68c08bd7d',
    'inspect_pcap_client': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_pe_resources': 'fbb3d6670d90b7033cdd55b8a2a5352bdca061cc4dcf341d6df534f143954e7c',
    'inspect_plist': '47e9e23f83e25ec425fdb00e011ef47ed6f9514b1b5dfca289866600d6c4fefd',
    'inspect_recorded_crash': 'a8c3fe06d3ab929c85299a3c38b95f2cb837b015ca00201c348a174922526a99',
    'inspect_rust_binary': '05cd7e679cbbbcb9c207421e6f9863d9e1961472584112aad31b78c54cb1436f',
    'inspect_signal_decoders': '26cd84b22ecab7ab56b2adaf5bacb2ec9585b3819cee20bf974d41a0aad13f2b',
    'inspect_signature': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'inspect_sqlite_database': '72056994977d184f16a232ed053548e4bf415a0d0c8c9603cb9dee01e411a36b',
    'inspect_wasm_artifact': '91f67a175e9f021539b1205752d6a8d481c78e78b31c93abd6f5499b94bc35ff',
    'inspect_web_event_listeners': 'da4c867a88c3734e77bf83d2c12255827e07aeeaefa25185b7ca342e7bb5d38c',
    'inspect_web_network_capture': 'ffebd8f096b8dac798fb30e91778a09bad87dae25a984f72eaf5e079ed323336',
    'inspect_web_page': 'cc7fba713e576e4f593e9b666b91ed456fe8d9c16335dcd27751107c061656f8',
    'inspect_with_objdump': '2abf642bdb721ffd8fd29b6526bce2aa888306eeee47096270cb7c2f61f2d01c',
    'install_adb_package': '8024346ea52304ef4284b18bada22713b94aee09b40d00e89a7ee2b8fb9dd8e4',
    'instrument_with_frida': 'af7d59d37aa753f91b86d968d61f9e7fbc7aed111e1c57cf2818eaa4509e82e3',
    'list_adb_devices': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'list_adb_directory': '17b44ef1bd94b7164800d6a6e6f0297853ba7062f13c3b4b6ef09ff785d0bd1f',
    'list_adb_features': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'list_adb_packages': 'e765f5a3a3b086ce67df270906aa4971e95d35d50554eef0b3f17c0578c32478',
    'list_adb_processes': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'list_adb_services': '4d4c7a6f87aec3c9511b9d31ae60b2e75abf4537332cc7c0d3f9158a226919ff',
    'list_architectures': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'list_bookmarks': '194cae8cbc22a3dc0077c8622279bea472d11e42032efa3a19e347929383739c',
    'list_browser_targets': '1712bb1f3e255d34389012ed6b9b9b4c3548f755bd7a3e5984237f75fb443881',
    'list_cutter_sessions': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'list_documents': 'c0cd46452db6c33ae1672c165c78e593f6bc472932b6b0370130b9d1d3e57fe5',
    'list_electron_targets': '0cca9b812bfaf745d43e5a94ccb8165cf61d4d984be4aae7848a97db7f1a99be',
    'list_frida_devices': '58a88fe2ff2f1df54198a3d96c44f7c8a96b13695a46b415d24d404e3aece3ab',
    'list_frida_processes': 'a50b8de6947a3381bb64ae2c782a1947e8d2dc220b3996ddabe9e2db7382e7ef',
    'list_javascript_runtime_targets': '8b9cc299f78560e170f4a9d48a9a8d3a4eed8cd78a2238f5a4d1deb0dfd6e09b',
    'list_jeb_units': 'd8027a9e10501e46833eab429dcc4bd7ea78ac1a6f599a3fb350d33222eab6c4',
    'list_names': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'list_procedures': '194cae8cbc22a3dc0077c8622279bea472d11e42032efa3a19e347929383739c',
    'list_segments': '194cae8cbc22a3dc0077c8622279bea472d11e42032efa3a19e347929383739c',
    'list_strings': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'list_unknowns': 'e5cb22568c104e8a8c5ca6740cd7c2605d677a54c5b14e635c2d3089c4690810',
    'load_frida_script': '740655868d1dce0d7734f295cb655ac6c53dd22a14282873fc58be95f491689d',
    'next_address': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'observe_javascript_runtime': 'c34cf031856d7213a17dd9fee6c304e64ccf46bbfc719e773aca506f4fd0a1a3',
    'observe_native_calls': '8336111949551086b4ae5f56209e84678911a9f9621082920971fc9ccd3d1bcc',
    'observe_native_ui': 'd2c7477ad4f64c87c51ce79f1b8aea87636680eddf8852a4b8cac2d3c03529aa',
    'observe_web_execution': '7da523fa54a6162c3f97df4889cc256f1e9d374bd53ecc269e3e816d21452bb5',
    'observe_web_session': 'ea0806bc3649c5fa3dbb8f71d3cda3633bce13fe010b9845ba157a2a683a006c',
    'open_binary': 'c538a6afb901c0cee249dffb68b916c3fed8b77ebd3df9ac4a7841156e4ff88f',
    'open_jeb_project': '5fe2eceda149eecaa43dfdf72ad7b9df0463053432c840321b0a95afa505a235',
    'prev_address': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
    'procedure_address': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_assembly': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_callees': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_callers': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_info': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_pseudo_code': 'be1d9beb75a9c5ea9a84287bed46b2a33113c13b8ca16ee1cbc9b2b8ff0ed543',
    'procedure_references': '1942dca73f6fd92356ce25e7051d7834eaaa32d6bd0d29b2bcc273338a022a00',
    'project_android_application_graph': '3bb7edfb8451f2c6a1b02d23cda0052cb4988f6c229b4f7ab537295a58933f9e',
    'project_apple_application_graph': '3bb7edfb8451f2c6a1b02d23cda0052cb4988f6c229b4f7ab537295a58933f9e',
    'project_harmony_application_graph': '3bb7edfb8451f2c6a1b02d23cda0052cb4988f6c229b4f7ab537295a58933f9e',
    'project_managed_application_graph': 'cc96bf4850469bb0fec8e7ef4daf6f8db42dd788c7d478bdeab32326d4d6898d',
    'pull_adb_file': '573f6c59a57b46ef955a496fa83343ef00c1a2b20ff4538c78d08364e8f75a40',
    'pull_adb_package': '58442651c390da8ede0ff75d4e62dd94e1ab4453a81cf4015cf1c086253d9d78',
    'push_adb_file': '1d5f09c443afe30a4b0fab1d79be5576b5e9e02dad0c6202d662cd46c3d87443',
    'read_adb_logcat': 'e9967b95c1511cade6ff8f90a2add6bf39eb768f88f1bdef04c1d2404e28f31e',
    'read_adb_setting': 'c1d26a9459ce7ecef478a9efb898e277691920abc21c441b4f52f4b8504b8bd7',
    'read_bytes': '1034000676f58d84594299b03d0f40a8baa2f403e3ace6be62a6b89b489d574d',
    'read_function_instructions': 'c7b1bfbb8cb8bfbc0bcf705ccf6688642be258f2f9c90e13a479b275c26dc230',
    'reconcile_javascript_runtime': '891992026c7f977411259442adbfbbf15bd6276a3e2c1001db73f1adab7f43a3',
    'record_unknown': 'e2fe92156281831efc18bc384b91eddaffde3119df04dc34b1cc0ad76a5f740e',
    'recover_javascript_sources': '07d89af24ff731f7ac85dd411a497988d3f40a840bd7299ebc3aac3159a49be2',
    'resolve_adb_packages': 'bd54a8d55d1726a0caf20058b884acc6e344aea521b492ac33cda5128feae91c',
    'resolve_containing_procedure': 'dbeefa8be34d7fbbd00062b41dbe24c309938eb6eb441463b7c703b50af9d6e5',
    'resolve_native_call_targets': '324cd72f21b8405cffa47b5e9ac76107657f326d71f42b3db793ad15560dc46e',
    'resume_frida_session': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'rizin_debug_command': '73a8e4af94ed72247f8fb59196c6a87c524a4cdde63c09fa3064c04ca298db96',
    'rizin_debug_session_status': 'a00f83b4677653238dfd6ecd99877d1a51e505c0703e42db40901f9d78054b6a',
    'search_android_classes': 'a442ea84e24fa78e5c0889386a3981e4190f0fad18240a700b2a97489904ebd3',
    'search_bytes': '0268019b838c44659f4ef3b7e110573e4073f682cdeeb4a438e8a29b1c71b009',
    'search_procedures': 'd9112387f55b0451aa25ed604d0ee0b955381a207c41e980bb0de8a7a197e059',
    'search_strings': '62663821fc0b39da8069526f51deb33e08fc19f79dd17600ab3ba5f81ecccf1b',
    'set_address_name': 'bae239e4f75b997e8bef838aa52b039dad28c58a86bf2f80705365be98ebec2f',
    'set_addresses_names': '63b38f6dc97e0a8da59895a96afa4cc13b2631ad269845b588edd9d93e80ab13',
    'set_bookmark': '6133b8c4c653f8d1b472d6019b11e9778bb3eac640b7f70dbea53cffcedda901',
    'set_comment': 'fac961568e5fe0006376c67f462c79ba375299cbef52f8c52a740a0e21200f21',
    'set_inline_comment': '9f7f582544d8b537e6831b8ec7acff6cd64c6249bbc255fa7aeae9e9d3ea816e',
    'start_adb_activity': 'da5fa654f586b62b85a3b0171536bcede43afe21a76a9b9642b6d8e4d0950675',
    'start_adb_app': 'ff66055d3cdc46a0a3f2a7440d3de065dc24cf51dd0e95a37d708d3644ef04c1',
    'start_frida_session': '961d770c3a60309ff7270d5517753f627308e448a59ea83f03ec1f37180b2a6c',
    'start_gdb_session': 'f570af50a7ecefac605e90e7da081ca041e2047557212671c875293841e35213',
    'start_rizin_debug_session': '14e45c27cca2b361326bdeedf41243d4fbee9b2711fef503208b99498b735913',
    'stop_adb_app': 'f3c8c5b7a77e9a96ce18302a4fa1b44e13418c1edf7dc622d89db2407ddfccd9',
    'trace_android_references': '47ada94a67216d8e12146c59bce8b63a34c2d3bee5ebbd00260c4d353abbbf69',
    'trace_application_feature': '625471088ed2b59acba49a536b57d112f84de153e6981aac09cbfc6defb5f3af',
    'trace_call_path': '101aae9c44766471d6b0645ff570c8daef9c78d33029a672b43940cc0eda9768',
    'trace_dylib_resolution': 'fab94d6ef1f91cae9b7763455cfeb53db4c664b9d76bc7bd22f20c074a19be79',
    'trace_feature': 'c462eeb5e8335d27dbd86331641e9db9d42a089fa215d92dad18ecc36c62231b',
    'trace_javascript_semantics': '30ef1c458e81fb81c8b01efc6feb8ff13d7d2177d05a96f2ce0867e8c91eb9ab',
    'trace_native_ui_action': 'cb7bb7b38d38bf8ee80bc88de29a376d24f54b8c6e935221e20bd6d629ceb251',
    'trace_native_values': '89a3cc48cc594b6ce09f9432fa2bdc6dee68f19b5eb8243aa9b66ad18a715c3d',
    'trace_web_module_imports': '3e73cc74c53abdca504d9d8bdfcbd802e21dfb354d6440fdf05bd840fe2d36b6',
    'trace_web_source_location': '0047ce89d40b082e2139622266424de3a7a58d703a3c6f2c8169d8a593ac12dc',
    'uninstall_adb_package': '3bcb639c20177dcedf63cd62d7f64e4f5098074bde002b5bc0d07b0364de900b',
    'unload_frida_script': '5630216b79d5ac3b8d2c0a3521d472e8099bacfb715fd543a27e2dd238353aca',
    'unset_bookmark': 'dbeefa8be34d7fbbd00062b41dbe24c309938eb6eb441463b7c703b50af9d6e5',
    'update_unknown': 'bfa34a46f0aa89a029de918d8ba9b85d7860e3efb0d89d3df4f8e0afb99320f6',
    'verify_managed_native_boundaries': '4a73bbab5dc144c75064acc2d3161ce3ba233b6e73de17e8ff24b607877279b4',
    'verify_reconstruction': 'a8a8737b8fbcbd116e4e41c6ebc73ea273571636aa21c87426e41592171e1c75',
    'verify_unknown_resolution': '16dae7e4cece2310ea287284f09ff8996146a5956c6d4ac1de59953a98d1b45e',
    'xrefs': '31c3eed9474f1aecb410a0582aa15bc95ef79f77be99f23c7549fa311fa2b44f',
}

PATH_KEYS = frozenset({
    "path", "file_path", "input_path", "output_path", "artifact_path",
    "binary_path", "apk_path", "directory", "root", "source_path",
    "target_path", "archive_path", "bundle_path", "project_path",
    "out_dir", "output_dir", "source_map_path",
})


class SecureBridgeError(ValueError):
    """Expected rejected request; do not include request bytes in messages."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def arguments_sha256(arguments):
    return hashlib.sha256(canonical_json(arguments)).hexdigest()


def validate_arguments(descriptor, arguments):
    """Validate the live MCP schema without fetching remote schema resources.

    Messages intentionally omit argument values, which may be confidential.
    All validation happens before the first tools/call in a sealed batch.
    """
    try:
        from jsonschema.validators import validator_for
        schema = descriptor.get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise SecureBridgeError("Missing MCP object argument schema")
        def local_references(value):
            if isinstance(value, dict):
                for key in ("$ref", "$dynamicRef", "$recursiveRef"):
                    ref = value.get(key)
                    if ref is not None and (not isinstance(ref, str) or
                                            not ref.startswith("#")):
                        raise SecureBridgeError("External schema references are forbidden")
                for child in value.values():
                    local_references(child)
            elif isinstance(value, list):
                for child in value:
                    local_references(child)
        local_references(schema)
        validator = validator_for(schema)
        validator.check_schema(schema)
        validator(schema).validate(arguments)
    except SecureBridgeError:
        raise
    except ImportError as exc:
        raise SecureBridgeError("MCP schema validator dependency unavailable") from exc
    except Exception as exc:
        raise SecureBridgeError("MCP argument schema validation failed") from exc


def key_directory():
    return Path.home() / ".local" / "share" / "rea-chatgpt-trial" / "sealed-bridge"


def _private_directory():
    directory = key_directory()
    if directory.is_symlink():
        raise SecureBridgeError("Untrusted request-state directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink():
        raise SecureBridgeError("Untrusted request-state directory")
    meta = directory.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o700:
        raise SecureBridgeError("Request-state directory ownership/mode mismatch")
    return directory


def private_key(create=False):
    """Persistent private key only in the SSH user's private existing home."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    directory = _private_directory()
    path = directory / "request-private.pem"
    if path.is_symlink():
        raise SecureBridgeError("Untrusted private-key path")
    if not path.exists():
        if not create:
            raise SecureBridgeError("Secure request key is not provisioned")
        generated = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        raw = generated.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass  # Concurrent provisioning: load the winning key.
        else:
            with os.fdopen(fd, "wb") as writer:
                writer.write(raw)
    meta = path.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) != 0o600:
        raise SecureBridgeError("Private-key ownership/mode mismatch")
    obj = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(obj, rsa.RSAPrivateKey) or obj.key_size < 3072:
        raise SecureBridgeError("Invalid secure request private key")
    return obj


def request_public_key_b64(create=False):
    from cryptography.hazmat.primitives import serialization
    raw = private_key(create=create).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(raw).decode("ascii")


def _decode_b64(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        raise SecureBridgeError("Invalid sealed field size")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecureBridgeError("Invalid sealed field encoding") from exc


def validate_public_envelope(sealed):
    if not isinstance(sealed, dict) or set(sealed) != {
        "algorithm", "nonce", "wrapped_key", "ciphertext"
    }:
        raise SecureBridgeError("Invalid sealed envelope structure")
    if sealed["algorithm"] != ALGORITHM:
        raise SecureBridgeError("Unsupported sealed algorithm")
    if len(_decode_b64(sealed["nonce"], 40)) != 12:
        raise SecureBridgeError("Invalid AES-GCM nonce")
    if len(_decode_b64(sealed["wrapped_key"], 1024)) != 384:
        raise SecureBridgeError("Invalid wrapped key length")
    if not (16 <= len(_decode_b64(sealed["ciphertext"], MAX_CIPHERTEXT_B64)) <=
            MAX_PLAINTEXT + 16):
        raise SecureBridgeError("Invalid ciphertext size")


def _aad(response_key):
    decoded = _decode_b64(response_key, 1800)
    if len(decoded) < 256:
        raise SecureBridgeError("Invalid response public key")
    return AAD_PREFIX + hashlib.sha256(decoded).digest()


def unseal(sealed, response_key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    validate_public_envelope(sealed)
    wrapped = _decode_b64(sealed["wrapped_key"], 1024)
    try:
        session_key = private_key(create=False).decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        if len(session_key) != 32:
            raise SecureBridgeError("Invalid session key")
        raw = AESGCM(session_key).decrypt(
            _decode_b64(sealed["nonce"], 40),
            _decode_b64(sealed["ciphertext"], MAX_CIPHERTEXT_B64),
            _aad(response_key))
    except Exception as exc:
        raise SecureBridgeError("Sealed request authentication failed") from exc
    if len(raw) > MAX_PLAINTEXT:
        raise SecureBridgeError("Sealed request exceeds plaintext limit")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise SecureBridgeError("Invalid decoded request") from exc


def seal_for_client(request, recipient_key_b64, response_key_b64):
    """Client-side helper; requires only recipient and response PUBLIC keys."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    recipient = serialization.load_der_public_key(
        _decode_b64(recipient_key_b64, 1800))
    if not isinstance(recipient, rsa.RSAPublicKey) or recipient.key_size != 3072:
        raise SecureBridgeError("Recipient key must be 3072-bit RSA")
    raw = canonical_json(request)
    if len(raw) > MAX_PLAINTEXT:
        raise SecureBridgeError("Request too large")
    aes_key, nonce = os.urandom(32), os.urandom(12)
    return {
        "algorithm": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_key": base64.b64encode(recipient.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))).decode("ascii"),
        "ciphertext": base64.b64encode(
            AESGCM(aes_key).encrypt(nonce, raw, _aad(response_key_b64))
        ).decode("ascii"),
    }


def effect_category(name):
    flags = AUDITED_EFFECTS.get(name)
    if flags is None:
        return "data_change_or_unreviewed"
    if ("mutatesDevice" in flags or "executesForeignCode" in flags or
            name.startswith(("start_gdb_", "close_gdb_", "gdb_console",
                             "start_rizin_", "close_rizin_", "rizin_debug_"))):
        return "process_or_device_control"
    if flags.intersection({"mutatesTarget", "mayDiscardData", "changesUiState"}):
        return "data_change_or_unreviewed"
    if flags:
        return "analysis_or_temporary_session"
    return "read"


RELEASE_680_MANIFEST_SHA256 = (
    "4aca2ddc92fc2d7dfc99a5097d5bf60cff0098d1c4ef64243117587fdfb8b713"
)
RELEASE_680_MANIFEST_PATH = (
    Path.home() / ".local/share/rea-chatgpt-trial/upgrade-backups/"
    "rea-6.8.0-mcp-contract-manifest.json"
)
REVIEWED_680_SCOPED_SETTINGS = frozenset({"update_analysis_settings"})


def _release680_verified_policy(registry):
    """The exact new release policy comes only from SHA-pinned official source.

    Original 208-tool requests remain on the proven original policy. New
    229-tool requests fail closed if the private independently checked source
    manifest is missing, tampered with, or has drifted from live tools/list.
    """
    if len(registry) != 229:
        return None
    path = RELEASE_680_MANIFEST_PATH
    if path.is_symlink() or not path.is_file():
        raise SecureBridgeError("Official REA 6.8.0 policy manifest missing")
    state = path.stat()
    if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o077:
        raise SecureBridgeError("Official release manifest permissions unsafe")
    blob = path.read_bytes()
    if (len(blob) > 140000 or
            hashlib.sha256(blob).hexdigest() != RELEASE_680_MANIFEST_SHA256):
        raise SecureBridgeError("Official release tool metadata SHA mismatch")
    manifest = json.loads(blob)
    if (manifest.get("release") != "rea-agents-6.8.0"
            or manifest.get("commit") != "160d821ac9a0310afcb8d1fc427862dd6508add5"
            or manifest.get("tree") != "15e6fec513dcce08cefdbcf441200986397e2793"):
        raise SecureBridgeError("Unexpected REA 6.8.0 release identity")
    catalogue = manifest.get("tools")
    if not isinstance(catalogue, dict) or set(catalogue) != set(registry):
        raise SecureBridgeError("Unexpected REA 6.8.0 live tool inventory")
    allowed_effects = frozenset((
        "mutatesTarget", "mutatesSession", "writesFilesystem",
        "launchesProcess", "accessesNetwork", "changesUiState",
        "mayDiscardData", "executesForeignCode", "mutatesDevice",
    ))
    flags = {}
    schemas = {}
    for name, data in catalogue.items():
        effects = data.get("effects")
        digest = data.get("input_schema_sha256")
        if (not isinstance(effects, list) or
                any(not isinstance(e, str) or e not in allowed_effects
                    for e in effects) or
                not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise SecureBridgeError("Invalid source-attested tool policy")
        flags[name] = frozenset(effects)
        schemas[name] = digest
    return flags, schemas


def classify(name, descriptor, safe_callable, verified_policy=None):
    """Use the explicit canonical effects audit, never catalog hints as grants."""
    annotations = descriptor.get("annotations") or {}
    audit_effects = AUDITED_EFFECTS if verified_policy is None else verified_policy[0]
    audit_schemas = AUDITED_SCHEMA_SHA256 if verified_policy is None else verified_policy[1]
    flags = audit_effects.get(name)
    if (flags is None or annotations.get("destructiveHint") is True or
            arguments_sha256(descriptor.get("inputSchema")) != audit_schemas.get(name)):
        return "sensitive"
    expected_hints = {
        "readOnlyHint": not bool(flags),
        "destructiveHint": bool(flags.intersection({"mayDiscardData", "executesForeignCode", "mutatesDevice"})),
        "openWorldHint": bool(flags.intersection({"launchesProcess", "accessesNetwork"})),
    }
    if any(annotations.get(key) is not expected for key, expected in expected_hints.items()):
        return "sensitive"
    # Never reduce owner protection for modifications, destructive effects,
    # device mutation, foreign execution or GUI-side changes.
    if flags.intersection(OWNER_SIGNATURE_EFFECTS):
        return "sensitive"
    # These individually reviewed, schema-bound commands are permitted only
    # as workspace calls, NEVER unauthenticated reads. This also prevents an
    # accidental network/process-only flag from requiring an Ed25519 signature.
    if (name in REVIEWED_SCOPED_WORKSPACE_OPERATIONS or
            (verified_policy is not None and name in REVIEWED_680_SCOPED_SETTINGS)):
        return "workspace"
    if name in HIGH_RISK_NAMES or any(name.startswith(p) for p in HIGH_RISK_PREFIXES):
        return "sensitive"
    if "accessesNetwork" in flags:
        return "sensitive"
    return "workspace" if flags else "read"


def _authorized_target_paths(arguments, additional_roots=()):
    # Prevent requests addressed to confidential/shared-service paths on the VPS.
    # Staged authorized inputs should live in the private per-user artifact area.
    from pathlib import Path
    roots = [
        (Path.home() / ".local/share/rea-chatgpt-trial/artifacts").resolve(),
        Path("/opt/rea-reversa/rea").resolve(),
    ]
    exact = {Path("/usr/bin/true").resolve()}
    # Only source-owned fixture code may supply its freshly created root.
    # This parameter is never read from a public or sealed request.
    roots.extend(Path(root).resolve() for root in additional_roots)
    def walk(obj):
        if isinstance(obj, dict):
            # Complete authenticated Evidence is inert input to comparisons.
            # Its historical locations are provenance, not file acquisitions.
            # The actual MCP schema is validated before this path check.
            if (isinstance(obj.get("evidence_id"), str) and re.fullmatch(
                    r"ev_[a-f0-9]{64}", obj["evidence_id"]) and
                    {"operation", "provider", "normalized_result", "subject"}.issubset(obj)):
                return
            for key, value in obj.items():
                if (key in PATH_KEYS or key.endswith("_path")) and key not in {
                    "left_module_path", "right_module_path", "module_path"
                } and isinstance(value, str):
                    if not value.startswith("/"):
                        raise SecureBridgeError("Analysis target needs an absolute path")
                    target = Path(value).resolve()
                    if target not in exact and not any(
                        target == root or root in target.parents for root in roots
                    ):
                        raise SecureBridgeError("Target outside approved analysis roots")
                if key.endswith("_paths") and key not in {"source_paths", "logical_paths"} and isinstance(value, list):
                    for path in value:
                        walk({"path": path})
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)
    walk(arguments)


def _verify_sensitive_owner_authorization(body, position, name, args, auth):
    """Verify *independent owner signature*, not a self-asserted JSON boolean.

    This verifier has no default key. Sensitive calls remain forbidden until
    the owner explicitly provisions a trusted Ed25519 PUBLIC key in the existing
    private SSH-home policy directory, outside GitHub-controlled request data.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    path = _private_directory() / "owner-approval-public.pem"
    if path.is_symlink() or not path.is_file():
        raise SecureBridgeError("Owner approval verifier is not provisioned")
    state = path.stat()
    if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o022:
        raise SecureBridgeError("Unsafe owner approval verifier permissions")
    try:
        public = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(public, Ed25519PublicKey):
            raise ValueError("Unexpected public-key type")
        signature = _decode_b64(auth["owner_signature"], 128)
        if len(signature) != 64:
            raise ValueError("Bad signature size")
        public.verify(signature, canonical_json({
            "purpose": "REA_OWNER_APPROVAL_V1",
            "nonce": body["nonce"],
            "expires_at": body["expires_at"],
            "step_index": position,
            "tool": name,
            "arguments_sha256": arguments_sha256(args),
            "scope": auth["scope"],
            "reason": auth["reason"],
            "acknowledgement": auth["acknowledgement"],
        }))
    except (InvalidSignature, ValueError, TypeError, KeyError) as exc:
        raise SecureBridgeError("Invalid independent owner authorization") from exc


def propose_p311_task_from_live_catalog(registry, safe_callable, *,
                                      project, task_id, artifact_root,
                                      chosen_tools, now=None,
                                      lifetime_seconds=86400,
                                      grant_id=None):
    """Prepare a reviewable owner grant from ONLY the internally verified MCP.

    Never accept a source-effects table or schema hashes from GitHub requests
    or the task's model-generated metadata. They must come from this module's
    pinned audit (208) or the exact SHA-checked original REA 6.8.0 manifest.
    A result is an UNSIGNED proposal, not a permission to execute tools.
    """
    if not isinstance(registry, dict) or not isinstance(safe_callable, (set, frozenset, list, tuple)):
        raise SecureBridgeError("Invalid live MCP tool catalog")
    verified_policy = _release680_verified_policy(registry)
    effects = AUDITED_EFFECTS if verified_policy is None else verified_policy[0]
    pins = AUDITED_SCHEMA_SHA256 if verified_policy is None else verified_policy[1]
    if verified_policy is None and (
            len(registry) != 208 or set(registry) != set(AUDITED_EFFECTS)):
        # No user-supplied partial/fabricated catalog can yield a task grant.
        raise SecureBridgeError("Incomplete or unsupported live MCP catalog")
    try:
        from ops import rea_scoped_approval_20261026 as scoped
        return scoped.prepare_unsigned_task_grant(
            project, task_id, artifact_root, registry, effects, pins,
            chosen_tools=chosen_tools,
            schema_digest=arguments_sha256,
            classify_tool=lambda name, desc: classify(
                name, desc, safe_callable, verified_policy),
            now=now, lifetime_seconds=lifetime_seconds,
            grant_id=grant_id,
        )
    except (ImportError, ValueError, TypeError, KeyError) as exc:
        raise SecureBridgeError("Cannot derive an owner task grant from the live source-audited catalog") from exc


def _p311_owner_scoped_grant(scoped_task, name, args, risk, verified_policy, now):
    """Experimental signed task delegation. DISABLED unless server opts in.

    Caller-supplied booleans or GitHub text are NEVER accepted as approval.
    The owner public verifier is read only from the existing VPS private area.
    """
    if os.environ.get("REA_P311_SCOPED_TASKS") != "enabled":
        return False
    required = {
        "grant", "owner_signature", "project", "task_id", "origin",
        "artifact_root"
    }
    if not isinstance(scoped_task, dict) or set(scoped_task) != required:
        raise SecureBridgeError("Malformed scoped task approval")
    # The exact source-audited effects and SHA-pinned live schema must be used.
    effects = (AUDITED_EFFECTS if verified_policy is None
               else verified_policy[0]).get(name)
    if not isinstance(effects, frozenset):
        raise SecureBridgeError("Tool effects are not source-audited")
    path = _private_directory() / "owner-approval-public.pem"
    if path.is_symlink() or not path.is_file():
        raise SecureBridgeError("Owner public verifier is not configured")
    meta = path.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o022:
        raise SecureBridgeError("Unsafe owner verifier ownership/permissions")
    # The scoped approval helper is NOT injected into the deployed SSH bridge
    # yet: enabling before the authenticated integration fails CLOSED.
    try:
        from ops import rea_scoped_approval_20261026 as scoped
        scoped.verify_task_grant(
            scoped_task["grant"], scoped_task["owner_signature"],
            path.read_bytes(), project=scoped_task["project"],
            task_id=scoped_task["task_id"], origin=scoped_task["origin"],
            artifact_root=scoped_task["artifact_root"], tool=name,
            audited_effects=effects, current_risk=risk,
            arguments=args, now=now,
            revocation_dir=_private_directory() / "revoked-p311-grants",
        )
    except (ImportError, ValueError) as exc:
        raise SecureBridgeError("Invalid owner-signed scoped authorization") from exc
    return True


def _p311_load_registered_task(grant_id, registry, safe_callable,
                              verified_policy, now):
    """Resolve a PRIVATE owner-signed grant by opaque ID, with no new server.

    This path is disabled in the active bridge. IDs from encrypted requests
    never override original trusted REA schemas, effects or owner verifier.
    """
    if (os.environ.get("REA_P311_SCOPED_TASKS") != "enabled" or
            not isinstance(grant_id, str) or
            not re.fullmatch(r"[0-9a-f]{32}", grant_id)):
        raise SecureBridgeError("Registered owner task reference is not permitted")
    effects = AUDITED_EFFECTS if verified_policy is None else verified_policy[0]
    schemas = AUDITED_SCHEMA_SHA256 if verified_policy is None else verified_policy[1]
    if verified_policy is None and (len(registry) != 208 or
                                    set(registry) != set(AUDITED_EFFECTS)):
        raise SecureBridgeError("Registered grants require a full known MCP catalog")
    verifier = _private_directory() / "owner-approval-public.pem"
    if verifier.is_symlink() or not verifier.is_file():
        raise SecureBridgeError("Registered grants need owner public verifier")
    state = verifier.stat()
    if state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) != 0o600:
        raise SecureBridgeError("Unsafe registered-grant public verifier")
    try:
        from ops import rea_scoped_approval_20261026 as scoped
        eligible = scoped.propose_task_tools(
            registry, effects, schemas, schema_digest=arguments_sha256,
            classify_tool=lambda name, desc: classify(
                name, desc, safe_callable, verified_policy))
        contracts = {
            name: (effects[name], classify(
                name, registry[name], safe_callable, verified_policy))
            for name in eligible
        }
        directory = _private_directory()
        return scoped.read_registered_task_grant(
            grant_id, verifier.read_bytes(),
            private_registry_dir=directory / "approved-p311-tasks",
            revocation_dir=directory / "revoked-p311-grants",
            trusted_contracts=contracts, now=now)
    except (ImportError, ValueError, TypeError) as exc:
        raise SecureBridgeError("Invalid registered owner task") from exc


def validate_inner(body, registry, safe_callable, now=None, *, scoped_task=None):
    """Per-operation authorization, exact argument hash and expiration.

    P311 adds an *optional* encrypted owner-signed task grant; an absent grant
    follows the unchanged original admission path. Server opt-in is mandatory.
    """
    fields = {"protocol", "nonce", "expires_at", "steps"}
    if (not isinstance(body, dict) or set(body) not in (
            fields, fields | {"scoped_task"}, fields | {"scoped_task_id"}
        ) or body["protocol"] != 1):
        raise SecureBridgeError("Invalid secure request protocol")
    if "scoped_task" in body:
        if (scoped_task is not None or
                not isinstance(body["scoped_task"], dict) or
                os.environ.get("REA_P311_SCOPED_TASKS") != "enabled"):
            raise SecureBridgeError("Scoped task envelope is not allowed")
        scoped_task = body["scoped_task"]
    reference_id = body.get("scoped_task_id")
    if "scoped_task_id" in body and (
            scoped_task is not None or
            not isinstance(reference_id, str) or
            not re.fullmatch(r"[0-9a-f]{32}", reference_id) or
            os.environ.get("REA_P311_SCOPED_TASKS") != "enabled"):
        raise SecureBridgeError("Registered task reference is not permitted")
    if not isinstance(body["nonce"], str) or not NONCE_RE.fullmatch(body["nonce"]):
        raise SecureBridgeError("Invalid one-use nonce")
    if not isinstance(body["expires_at"], str) or not TIME_RE.fullmatch(body["expires_at"]):
        raise SecureBridgeError("Invalid request expiry")
    expiry = datetime.strptime(body["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    seconds = (expiry - now).total_seconds()
    if not 0 < seconds <= 86400:
        raise SecureBridgeError("Expired or overly long-lived request")
    steps = body["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise SecureBridgeError("Invalid secure step count")
    verified_policy = _release680_verified_policy(registry)
    if reference_id is not None:
        scoped_task = _p311_load_registered_task(
            reference_id, registry, safe_callable, verified_policy, now)
    profiles = []
    scoped_grant_was_verified = False
    opened_in_request = False
    for position, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) not in (
            {"tool", "arguments"}, {"tool", "arguments", "authorization"}
        ):
            raise SecureBridgeError("Invalid secure step fields")
        name, args = step.get("tool"), step.get("arguments")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name not in registry:
            raise SecureBridgeError("Unknown MCP tool")
        if not isinstance(args, dict) or len(canonical_json(args)) > 400000:
            raise SecureBridgeError("Invalid MCP argument object")
        validate_arguments(registry[name], args)
        risk = classify(name, registry[name], safe_callable, verified_policy)
        _authorized_target_paths(args)
        if name in REVIEWED_SESSION_READ_TOOLS:
            if not opened_in_request:
                raise SecureBridgeError(
                    "Reviewed session inspection requires open_binary in this request")
            if "document" in args:
                raise SecureBridgeError(
                    "Reviewed session inspections must use the newly opened document")
            required_field = "procedure" if name in (
                "read_function_instructions", "analyze_function"
            ) else "address" if name in (
                "read_bytes", "resolve_containing_procedure",
                "inspect_native_instruction", "xrefs"
            ) else None
            if required_field and (
                not isinstance(args.get(required_field), str) or
                not args[required_field].strip()
            ):
                raise SecureBridgeError(
                    "Session inspection requires explicit address or procedure")
            if name == "read_bytes":
                length = args.get("length", 256)
                if type(length) is not int or not 1 <= length <= 4096:
                    raise SecureBridgeError("Session byte read exceeds safe bound")
        if name == "open_binary":
            if opened_in_request:
                raise SecureBridgeError("Only one opened binary per sealed request")
            opened_in_request = True
        elif name == "close_binary":
            opened_in_request = False
        if name == "open_binary" and "snapshot_path" in args:
            raise SecureBridgeError("External binary snapshot writes need separate approval")
        auth = step.get("authorization")
        if risk == "read":
            if auth is not None:
                raise SecureBridgeError("Read-only operation must omit authorization")
        else:
            # Optional signed delegation is only allowed with an explicit
            # server-side opt-in, and only after all original schema/path/
            # session checks above have passed. Defaults to legacy behaviour.
            if auth is None and scoped_task is not None and _p311_owner_scoped_grant(
                    scoped_task, name, args, risk, verified_policy, now):
                scoped_grant_was_verified = True
                profiles.append(risk)
                continue
            required = {
                "tool", "arguments_sha256", "scope", "reason",
                "confirmed_by_owner", "acknowledgement"
            }
            if risk == "sensitive":
                required.add("owner_signature")
            if not isinstance(auth, dict) or set(auth) != required:
                raise SecureBridgeError("Individual authorization is required")
            if auth["tool"] != name or auth["scope"] != risk or (
                auth["arguments_sha256"] != arguments_sha256(args)
            ) or auth["confirmed_by_owner"] is not True:
                raise SecureBridgeError("Authorization does not match exact operation")
            reason = auth["reason"]
            if not isinstance(reason, str) or not 12 <= len(reason.strip()) <= 400:
                raise SecureBridgeError("Authorization needs a specific reason")
            expected = (
                "AUTORIZO_OPERACAO_SENSIVEL"
                if risk == "sensitive" else "AUTORIZO_ANALISE_LOCAL"
            )
            if auth["acknowledgement"] != expected:
                raise SecureBridgeError("Missing per-operation acknowledgement")
            if risk == "sensitive":
                _verify_sensitive_owner_authorization(body, position, name, args, auth)
        profiles.append(risk)
    if scoped_task is not None and not scoped_grant_was_verified:
        # A stray grant on read-only or individually authorized batches must
        # never masquerade as owner-verified task authorization.
        raise SecureBridgeError("Scoped task approval was not used or verified")
    return profiles


def claim_one_use_nonce(nonce):
    directory = _private_directory() / "consumed"
    if directory.is_symlink():
        raise SecureBridgeError("Untrusted replay-guard directory")
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise SecureBridgeError("Unsafe replay guard permissions")
    try:
        fd = os.open(directory / nonce,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SecureBridgeError("Already used one-time request") from exc
    with os.fdopen(fd, "w", encoding="ascii") as writer:
        writer.write("claimed\n")

