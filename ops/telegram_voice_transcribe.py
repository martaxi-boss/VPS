#!/usr/bin/env python3
"""Offline Portuguese voice transcription worker. Run without GitHub/Telegram secrets.

Faster-Whisper decodes Telegram OGG/Opus using PyAV, on CPU, without a paid
speech API. The caller captures stdout privately and never prints it in CI.
"""
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
    except Exception:
        # Do not expose audio bytes, transcription, paths or model diagnostics.
        raise SystemExit(3) from None
