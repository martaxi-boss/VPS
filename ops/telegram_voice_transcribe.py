#!/usr/bin/env python3
"""Offline Portuguese voice transcription worker. Run without GitHub/Telegram secrets.

Faster-Whisper decodes Telegram OGG/Opus using PyAV, on CPU, without a paid
speech API. The caller captures stdout privately and never prints it in CI.
"""
import os
import sys
from pathlib import Path

MAX_TRANSCRIPT_CHARS = 3800


def transcribe(path: Path) -> str:
    from faster_whisper import WhisperModel

    model = WhisperModel("base", device="cpu", compute_type="int8", cpu_threads=2)
    segments, _info = model.transcribe(
        str(path), language="pt", beam_size=3, vad_filter=True,
        condition_on_previous_text=False,
    )
    result = " ".join(s.text.strip() for s in segments).strip()
    if not result or len(result) > MAX_TRANSCRIPT_CHARS:
        raise RuntimeError("Voice transcript empty or too long")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    try:
        print(transcribe(Path(sys.argv[1])))
    except Exception as exc:
        # Diagnostic mode is used only with synthetic speech and no credentials.
        if os.environ.get("VOICE_SMOKE_DIAGNOSTICS") == "1":
            print("VOICE_SMOKE_ERROR_CLASS=" + type(exc).__name__, file=sys.stderr)
            print("VOICE_SMOKE_ERROR_DETAIL=" + str(exc)[:500], file=sys.stderr)
        # Do not expose audio bytes, transcription or sensitive diagnostics on real jobs.
        raise SystemExit(3) from None
