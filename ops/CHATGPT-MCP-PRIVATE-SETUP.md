# ChatGPT -> VPS: private selected-media MCP server

**Deployment state: not active.** This document accompanies a disabled, loopback-only implementation. No network listener or new coordinator is enabled by merging the PR.

## Exact responsibility

ChatGPT user selects photographs, videos, or other original files. The tool `stage_selected_owner_files` receives ChatGPT's native `_meta["openai/fileParams"]` `files[]`, downloads originals to the existing private `codex-bridge/.coordinator-inbox`, checks the manifest, file sizes and SHA-256, and yields a **single-use `bundle_id`**. The read-only `status_selected_owner_files` tool confirms successful completion. Neither tool creates a GitHub Issue, runs Codex, changes phases, decides worker count, or forwards files that the Owner has not explicitly selected.

The Owner can then choose **not** to send a work order, or submit the Owner-authenticated `[coordinator run]` Issue with `COORDINATOR_ATTACHMENTS_ID=<bundle_id>`; that Issue triggers the **existing** Coordinator. Never submit the Issue before the MCP status is `READY` with the expected file count and SHA-256.

## Capacity and operational limits

- Backend original-file allowance **1 GiB in aggregate**, maximum 16 selected originals, a single video can occupy this allowance. The ChatGPT client and connector may impose additional per-file or aggregate upload limits.
- Downloads, verification, and private copies use **1 MiB** chunks rather than buffering the full video. A separate background worker permits transfers longer than a single MCP request timeout.
- The VPS must have free space for the incoming originals, the private packaged copy, and any video preview files; provision significantly more than 1 GiB of available disk before testing a 1-GiB video. At most one active transfer and two ready unconsumed bundles; no silently discarded selected media.
- Pending transfer receipts contain **only** status, file name, size and SHA-256; never download URLs, access tokens, content, or plaintext. Receipts are stored private (0600) under a private `.mcp-jobs` folder (0700).
- A transfer interruption or missing file cannot authorize a text-only execution. Cleanup of orphaned/unconsumed receipts after a defined retention period must be configured before routine 1-GiB use; don't delete a bundle being consumed by the Coordinator.

## One-time platform connection (Owner-only Human Gate)

This endpoint should be reachable through a **Secure MCP Tunnel** that runs outbound from the existing VPS, not through a newly exposed public service. It binds only to `127.0.0.1` (by default port `8765`) and fails closed without a trusted, local Owner-only API key. ChatGPT custom MCP plugins support API-key authentication; the key must be provisioned **outside chat** and bound to the verified Owner's private ChatGPT plugin connection. No GitHub or VPS secret should be pasted in chat, Issue bodies, screenshots or logs.

- Privately provision the Owner key in a file owned by the `ubuntu` VPS user, permissions **0600**, with **at least 32 random printable characters**. Pass only its absolute pathname in `PROJECT_LEADER_MCP_OWNER_KEY_FILE`. Never commit the key or print it in logs; keep it in the existing credentials vault with restricted access.
- Reuse the **existing** `$HOME/codex-bridge/.coordinator-inbox` with owner-only permissions **0700**; do not chmod a suspicious or shared directory to force a pass.
- A private local process can be started with `python3 -m ops.chatgpt_media_mcp` in a reviewed VPS checkout with `$HOME` configured. Deploy a pinned systemd service and verify that listening addresses are loopback only. This PR does not install services.
- In OpenAI Platform create or reuse a suitable **Secure MCP Tunnel** with a restricted runtime credential; associate its Platform organization with the target ChatGPT workspace and use `tunnel-client` to forward to `http://127.0.0.1:8765/mcp` over outbound HTTPS. The API key belongs in the ChatGPT **connection credential** (`Authorization: Bearer`), never in a tool argument. For a Team/Business workspace verify whether tunnel and custom-plugin permissions are available; do not assume plan entitlements. Platform setup/consent is outside GitHub repository control.
- In ChatGPT Plugins, add a **private custom MCP server** via the tunnel and configure its API-key authentication. Check that `tools/list` exposes `stage_selected_owner_files` with `_meta["openai/fileParams"] == ["files"]`, and that `status_selected_owner_files` is present. Use the installed plugin from ChatGPT on Android after initial setup.
- Check the exact ChatGPT temporary file URL hostname presented by a real authorized `fileParams` call; the backend has a restrictive CDN host allowlist and forbids redirects. Update **only** the verified host if necessary; no `http:`, arbitrary URLs, localhost or private IP addresses.
- Prove end to end with three existing PINK IPTV photographs (or a small Owner-approved test package), comparing SHA-256 and file count with the VPS before any work order. Then prove a video. A 1-GiB live test is optional; no claims of throughput certification before evidence.

## Safety and fallback

This server is a **transport recipient**, not a new Coordinator. It has no Github issue permissions or GitHub token and cannot trigger models or jobs; the existing Owner-authenticated Issue remains mandatory to execute work. If the custom ChatGPT connection is unavailable, fail explicitly. Keep the already certified **16-MiB Git encrypted blob** route for small one-off media as a fallback; do **not** try to send 1 GiB via public Git blobs just to bypass platform consent.

Official references:
- https://developers.openai.com/plugins/reference#file-apis
- https://developers.openai.com/plugins/deploy/connect-chatgpt
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- https://developers.openai.com/plugins/build/auth