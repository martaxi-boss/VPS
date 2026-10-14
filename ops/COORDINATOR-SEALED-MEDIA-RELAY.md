# ChatGPT -> VPS Coordinator: sealed diagnostic file relay

**Scope:** an optional transport for Owner-selected ORIGINAL photographs and small files through the existing GitHub Actions -> pinned SSH -> existing Coordinator private inbox. It never creates or invokes another Coordinator, Worker, Telegram command route, or task by itself.

## Authenticated two-step handoff

1. Only the Owner `martaxi-boss` creates a GitHub Issue titled `[media key] <nonsecret label>` with body `MEDIA_SESSION=<32 lowercase hex>`. The workflow uses the existing VPS SSH credential and the independently pinned Ed25519 host fingerprint. It asks the VPS to create a single-use X25519 recipient key **locally** and posts only its public key as `MEDIA_PUBLIC_KEY_V1 session=<id> public=<base64>` to the Issue.
2. A trusted ChatGPT execution prepares only the Owner-selected originals in a private ZIP with an authenticated `manifest.json`, encrypts it locally using X25519 + HKDF SHA-256 + AES-256-GCM, and computes SHA-256 of the **ciphertext**. The private key stays on the VPS. The original ZIP, JPEGs, videos, and ChatGPT temporary URLs must **never** be put in a public GitHub object, Issue or log.
3. Only the ciphertext bytes are uploaded to a Git blob; the Owner creates a second Issue titled `[media stage] <nonsecret label>`, with exact body:

```text
MEDIA_SESSION=<same 32 hex>
MEDIA_BLOB=<40 lowercase hex blob SHA>
MEDIA_SHA256=<64 lowercase hex ciphertext SHA256>
```

4. The separate inbound workflow validates the Owner, fetches only that opaque blob, checks the digest, verifies pinned VPS SSH, transfers the ciphertext over SSH and invokes the same VPS's private stage routine. The VPS authenticates AES-GCM and verifies every declared original's SHA-256, size and name before atomically publishing a private bundle. The workflow posts `MEDIA_PRIVATE_STAGED_V1=<session>;count=<n>` only after successful verification. It does **not** send a coordinator task.
5. When explicitly ordered by the Owner, the normal authenticated Coordinator Issue uses `COORDINATOR_ATTACHMENTS_ID=<verified session>` and targets exactly the requested project. The existing Coordinator consumes this private bundle once, checks it before model use, and keeps all Worker/CI/Supervisor rules unchanged.

A failed upload or rejected hash is **not** evidence that originals were delivered. The receipt is a public identifier only, not the original data.

## Bounds, trust and current certification

- Backend capacity is **1 GiB of selected originals per transfer** and at most 16 originals. Inputs are streamed in 1-MiB blocks. A single large video may occupy the allowance. This is a receiver budget, not a claim that every client/network transport can carry one GiB.
- This initial Git **single-blob** relay intentionally accepts at most **16 MiB of ciphertext per request**; it is sufficient for the three PINK screenshots but not yet a one-GiB video. Larger remote transfers need a separately validated multi-blob or private MCP upload route. Never falsely claim a large remote transfer succeeded.
- Git objects in public repositories can retain the **encrypted ciphertext** for an extended period. AES-GCM and one-time VPS-held keys protect the original, but this is not cryptographic erasure of the ciphertext. Keep the object reference private except the Owner Issue's approved ciphertext SHA.
- This feature does not install the native ChatGPT MCP plugin. File selection comes from this chat when the Owner expressly requests it; files are not transferred automatically.
- The VPS needs Python `cryptography`; fail closed if missing. The authenticated workflow does not silently weaken encryption or send a plaintext fallback. Keep private keys on the VPS and delete them after staging.
- Verify the *real three-photo handoff* separately: receipt count=3, private files' hashes match the Owner originals, and then the Coordinator confirms it read three original images. Do not launch PINK repairs just from successful transport diagnostics.

**No deployment, production APK changes, or automatic PINK worker dispatch occur in this relay.**
