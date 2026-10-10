#!/usr/bin/env bash
# Ubuntu 24.04 Codex CLI sandbox repair (system bubblewrap + narrow AppArmor profile).
# Run only by the owner-gated GitHub Actions workflow. No global sysctl changes.
set -Eeuo pipefail
export LC_ALL=C
mode="$1"
if [ "$mode" != inspect ] && [ "$mode" != apply ]; then
  echo "RESULT=INVALID_MODE"
  exit 2
fi
if [ "$(id -un)" != ubuntu ]; then
  echo "RESULT=WRONG_USER"
  exit 3
fi
. /etc/os-release
if [ "$ID" != ubuntu ] || [ "$VERSION_ID" != 24.04 ]; then
  echo "RESULT=UNSUPPORTED_OS"
  exit 4
fi

profile="/etc/apparmor.d/bwrap-userns-restrict"
source_profile="/usr/share/apparmor/extra-profiles/bwrap-userns-restrict"
codex="$HOME/codex-agent/node_modules/.bin/codex"
before="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo unknown)"
echo "UBUNTU_VERSION=$VERSION_ID"
echo "APPARMOR_USERNS_RESTRICTION=$before"
if [ -x "$codex" ]; then
  echo "CODEX_INSTALLED=yes"
else
  echo "CODEX_INSTALLED=no"
fi

bwrap_probe() {
  if ! command -v bwrap >/dev/null 2>&1; then
    echo "BWRAP_PROBE=NOT_INSTALLED"
    return 1
  fi
  echo "BWRAP_BINARY=$(command -v bwrap)"
  local output
  if output="$(timeout 15s bwrap --ro-bind / / --unshare-user --unshare-pid --unshare-net -- /usr/bin/true 2>&1)"; then
    echo "BWRAP_PROBE=PASS"
    return 0
  fi
  echo "BWRAP_PROBE=FAILED"
  printf '%s\n' "$output" | head -c 300 | tr -cd '[:print:]\n'
  echo
  return 1
}

echo "APPARMOR_PROFILE_PRESENT=$([ -f "$profile" ] && echo yes || echo no)"
echo "BWRAP_PROFILE_SOURCE_PRESENT=$([ -f "$source_profile" ] && echo yes || echo no)"
if bwrap_probe; then
  echo "RESULT=SANDBOX_READY"
  exit 0
fi

if [ "$mode" = inspect ]; then
  echo "RESULT=INSPECT_ONLY_REPAIR_REQUIRED"
  exit 0
fi

if ! sudo -n true >/dev/null 2>&1; then
  echo "RESULT=NO_PASSWORDLESS_SUDO"
  exit 5
fi

# Narrow, official Ubuntu package installation. Do not run full upgrades or
# disable any AppArmor / kernel protection; avoid automatic service restarts.
echo "ACTION=INSTALL_UBUNTU_SANDBOX_PACKAGES"
sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get update -qq
sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install \
  -y -qq --no-install-recommends bubblewrap apparmor-profiles apparmor-utils

# Some hosts need no additional profile once /usr/bin/bwrap is present.
if bwrap_probe; then
  echo "ACTION=NO_PROFILE_CHANGE_NEEDED"
  echo "RESULT=SANDBOX_READY"
  exit 0
fi

# An existing or third-party profile may have a conflicting name. Never
# overwrite or reload it automatically on the shared production VPS.
if [ -e "$profile" ] || [ -L "$profile" ]; then
  echo "RESULT=EXISTING_PROFILE_REQUIRES_REVIEW"
  exit 6
fi
if sudo -n aa-status 2>/dev/null | grep -Eiq '(^|[ /])bwrap([ /:]|$)|bwrap-userns-restrict'; then
  echo "RESULT=POSSIBLE_PROFILE_COLLISION_REQUIRES_REVIEW"
  exit 7
fi
if [ ! -f "$source_profile" ]; then
  echo "RESULT=DISTRIBUTION_PROFILE_MISSING"
  exit 8
fi

echo "ACTION=INSTALL_NARROW_APPARMOR_PROFILE"
sudo -n install -m 0644 "$source_profile" "$profile"
if ! sudo -n apparmor_parser -r "$profile"; then
  # Remove only the profile we just created, without touching other profiles.
  sudo -n apparmor_parser -R "$profile" >/dev/null 2>&1 || true
  sudo -n rm -f "$profile"
  echo "RESULT=PROFILE_LOAD_FAILED_ROLLED_BACK"
  exit 9
fi

if bwrap_probe; then
  echo "RESULT=SANDBOX_READY_WITH_PROFILE"
else
  sudo -n apparmor_parser -R "$profile" >/dev/null 2>&1 || true
  sudo -n rm -f "$profile"
  echo "RESULT=SANDBOX_FAILED_PROFILE_ROLLED_BACK"
  exit 10
fi

after="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo unknown)"
if [ "$before" != "$after" ]; then
  echo "RESULT=UNEXPECTED_KERNEL_SETTING_CHANGE"
  exit 11
fi
echo "APPARMOR_USERNS_RESTRICTION_UNCHANGED=yes"
