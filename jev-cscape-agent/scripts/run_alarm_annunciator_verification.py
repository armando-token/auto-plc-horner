"""Verification Runner for SCADA Alarm Annunciator & Multi-Tone Audio Synthesis.

Work Package: W056 (Gate G9 HMI / Gate G8 Alarming)
Executes ANSI/ISA-18.1 annunciator sequence verification, pure-Python 44.1kHz 16-bit
PCM WAV synthesis, and exports artifacts/HMI/alarm_annunciator_evidence.json and critical_alarm_sample.wav.
"""

import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))

from jev_cscape.hmi.alarm_annunciator import verify_alarm_annunciator_and_export_evidence


def main() -> int:
    out_dir = repo_root / "artifacts" / "HMI"
    print(f"[W056] Executing SCADA Alarm Annunciator & Audio Synthesis verification...")
    result = verify_alarm_annunciator_and_export_evidence(str(out_dir))
    print(f"[W056] Status: {result.get('status')}")
    print(f"[W056] Details: {result.get('details')}")

    if result.get("status") == "success":
        data = result.get("data", {})
        synth = data.get("audio_synthesis", {})
        ann = data.get("annunciator_sequences", {})
        print(f"[W056] WAV Generated: {synth.get('wav_artifact_path')} ({synth.get('wav_file_size_bytes')} bytes, 44.1kHz 16-bit mono)")
        print(f"[W056] Annunciator Points: {ann.get('total_points_configured')}, standards: {ann.get('standards_verified')}")
        print(f"[W056] Evidence written to: {out_dir / 'alarm_annunciator_evidence.json'}")
        return 0
    else:
        print(f"[W056] ERROR: Annunciator verification failed: {result.get('error_code')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
