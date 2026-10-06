"""Bounded fixed public control DNS readiness; no account or host effects."""
import re
import subprocess
import time

TARGET = "pink-iptv.duckdns.org"


def classify(output):
    match = re.search(r"^PING\s+\S+\s+\(([^)]+)\)", output, re.M)
    if match:
        return "READY" if match.group(1) == "146.59.145.3" else "UNEXPECTED_TARGET"
    if "unknown host" in output.lower() or "bad address" in output.lower():
        return "DNS_UNRESOLVED"
    return "NO_RESOLVED_TARGET"


def main():
    deadline = time.monotonic() + 60
    for attempt in range(1, 13):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            result = subprocess.run(["adb", "shell", "ping", "-c", "1", "-W", "2", TARGET],
                capture_output=True, text=True, timeout=min(5, remaining), check=False)
            state = classify(result.stdout + result.stderr)
        except subprocess.TimeoutExpired:
            state = "QUERY_TIMEOUT"
        print("ANDROID13_FIXED_CONTROL_DNS_READINESS=" + state + ";attempt=" + str(attempt), flush=True)
        if state == "READY":
            print("ANDROID13_FIXED_CONTROL_DNS_EXPECTED_TARGET=PASS")
            return
        if state == "UNEXPECTED_TARGET":
            raise AssertionError("Fixed control DNS target is not accepted")
        time.sleep(max(0, min(5, deadline - time.monotonic())))
    raise AssertionError("Bounded fixed control DNS readiness exhausted")


if __name__ == "__main__":
    main()
