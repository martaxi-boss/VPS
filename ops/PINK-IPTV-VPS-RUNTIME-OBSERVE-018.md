# Runtime observation 018

Canonical control: martaxi-boss/Project-leader@80288f44a236c0ca4095bf4399492632e0152dbe (Project Leader 0.6.0).

FORCED_OPERATIONAL_ACCESS_DISCOVERY found the existing VPS GitHub Actions SSH bridge and historical successful SSH checks. ACCESS_PATH_REQUIRES_SEPARATE_TASK is resolved by this isolated operations task. Absence of direct SSH is not an access blocker.

Scope: fixed read-only script to ubuntu@146.59.145.3, hostname vps-32bea5b6. Existing secret name VPS_SSH_PASSWORD; no secret values in source, command arguments or evidence. Runner package installation does not modify the VPS. No checkout or arbitrary command input. SSH host authentication retains the established accept-new trust-on-first-use limitation; successful execution is not independent host-key attestation.

Reads: UTC, systemd service/process metadata excluding arguments/environment, trusted Git HEAD, loopback OpenAPI HTTP status, PostgreSQL readiness, WireGuard interface names/count, forwarding values and firewall policy/count summaries. No peer/configuration/provider secrets, service changes, network changes, installed source changes or backup changes. Service start timestamps are observations; no uptime or age-based deletion is authorized. Runtime revision may remain UNKNOWN if the installed tree has no readable Git metadata. API availability is not provider, playback, tunnel or restore proof.

Execution requires exact implementation revision authorization before creating the same-repository PR. New fixed workflow and inherited VPS SSH Access PR Check must pass on that revision. Record observations in task-local result/transition receipts and close PR unmerged; do not merge this one-off workflow or change existing workflows. Then return to the separate PINK repository task.
