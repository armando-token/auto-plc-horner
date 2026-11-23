"""Tests for SCADA Alarm Annunciator & Multi-Tone Audio Synthesis Engine.

Work Package: W056 (Gate G9 HMI / Gate G8 Alarming)
"""

import json
from pathlib import Path
import struct
import pytest

from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.hmi.alarm_annunciator import (
    AlarmAnnunciatorManager,
    AlarmPriority,
    AnnunciatorPoint,
    AnnunciatorSequence,
    AnnunciatorState,
    AudioSynthesizer,
    LampFlashMode,
    verify_alarm_annunciator_and_export_evidence,
)


def test_audio_synthesizer_riff_wave_header_exactness():
    """Verify that synthesized WAV produces valid 44-byte RIFF/WAVE header."""
    header = AudioSynthesizer.build_wav_header(num_samples=100)
    assert len(header) == 44

    chunk_id, chunk_size, format_id, sub1_id, sub1_sz, audio_fmt, num_ch, rate, byte_rate, align, bits, sub2_id, sub2_sz = (
        struct.unpack("<4sI4s4sIHHIIHH4sI", header)
    )
    assert chunk_id == b"RIFF"
    assert format_id == b"WAVE"
    assert sub1_id == b"fmt "
    assert sub1_sz == 16
    assert audio_fmt == 1  # Linear PCM
    assert num_ch == 1     # Mono
    assert rate == 44100
    assert byte_rate == 88200
    assert align == 2
    assert bits == 16
    assert sub2_id == b"data"
    assert sub2_sz == 200
    assert chunk_size == 36 + 200


def test_audio_synthesizer_all_priority_profiles():
    """Verify that all 4 alarm priority tone waveforms generate valid, non-empty byte streams."""
    wav_crit = AudioSynthesizer.generate_critical_klaxon(0.5)
    wav_high = AudioSynthesizer.generate_high_beep(0.5)
    wav_med = AudioSynthesizer.generate_medium_chime(0.70)
    wav_info = AudioSynthesizer.generate_info_ping(0.35)

    assert len(wav_crit) == 44 + int(44100 * 0.5) * 2
    assert len(wav_high) == 44 + int(44100 * 0.5) * 2
    assert len(wav_med) == 44 + int(44100 * 0.70) * 2
    assert len(wav_info) == 44 + int(44100 * 0.35) * 2

    # Check for non-zero PCM samples
    pcm_crit = wav_crit[44:]
    non_zero = any(b != 0 for b in pcm_crit)
    assert non_zero is True


def test_annunciator_sequence_a_automatic_reset():
    """Verify ANSI/ISA-18.1 Sequence A (Automatic Reset) lifecycle."""
    mgr = AlarmAnnunciatorManager()
    pt = AnnunciatorPoint(
        point_id="TEST_SEQ_A",
        tag_name="TAG_A",
        description="Auto reset test",
        priority=AlarmPriority.HIGH,
        sequence=AnnunciatorSequence.SEQUENCE_A,
    )
    mgr.register_point(pt)

    # 1. Normal state
    assert pt.state == AnnunciatorState.NORMAL
    assert pt.horn_sounding is False

    # 2. Trip condition
    mgr.set_process_condition("TEST_SEQ_A", True)
    assert pt.state == AnnunciatorState.UNACKNOWLEDGED
    assert pt.horn_sounding is True
    assert pt.lamp_mode == LampFlashMode.FAST_FLASH

    # 3. Silence
    mgr.silence()
    assert pt.state == AnnunciatorState.SILENCED
    assert pt.horn_sounding is False
    assert pt.lamp_mode == LampFlashMode.FAST_FLASH

    # 4. Acknowledge while abnormal
    mgr.acknowledge()
    assert pt.state == AnnunciatorState.ACKNOWLEDGED
    assert pt.lamp_mode == LampFlashMode.STEADY

    # 5. Return to normal condition -> should auto-reset to NORMAL
    mgr.set_process_condition("TEST_SEQ_A", False)
    assert pt.state == AnnunciatorState.NORMAL
    assert pt.lamp_mode == LampFlashMode.OFF


def test_annunciator_sequence_m_manual_reset():
    """Verify ANSI/ISA-18.1 Sequence M (Manual Reset) requires explicit Reset push."""
    mgr = AlarmAnnunciatorManager()
    pt = AnnunciatorPoint(
        point_id="TEST_SEQ_M",
        tag_name="TAG_M",
        description="Manual reset test",
        priority=AlarmPriority.CRITICAL,
        sequence=AnnunciatorSequence.SEQUENCE_M,
    )
    mgr.register_point(pt)

    # 1. Trip and Ack
    mgr.set_process_condition("TEST_SEQ_M", True)
    mgr.acknowledge()
    assert pt.state == AnnunciatorState.ACKNOWLEDGED
    assert pt.lamp_mode == LampFlashMode.STEADY

    # 2. Return to normal condition -> transitions to RETURNED_UNACKNOWLEDGED (slow flash)
    mgr.set_process_condition("TEST_SEQ_M", False)
    assert pt.state == AnnunciatorState.RETURNED_UNACKNOWLEDGED
    assert pt.lamp_mode == LampFlashMode.SLOW_FLASH

    # 3. Explicit Reset push -> transitions to NORMAL
    mgr.reset()
    assert pt.state == AnnunciatorState.NORMAL
    assert pt.lamp_mode == LampFlashMode.OFF


def test_annunciator_flash_state_timing():
    """Verify flash state on/off calculation for fast and slow flashing."""
    pt = AnnunciatorPoint(
        point_id="TEST_FLASH",
        tag_name="FLASH_TAG",
        description="Flash test",
        priority=AlarmPriority.MEDIUM,
        sequence=AnnunciatorSequence.SEQUENCE_A,
    )
    pt.lamp_mode = LampFlashMode.FAST_FLASH  # 250ms ON / 250ms OFF
    assert pt.evaluate_flash_state(0.10) is True
    assert pt.evaluate_flash_state(0.30) is False
    assert pt.evaluate_flash_state(0.60) is True

    pt.lamp_mode = LampFlashMode.SLOW_FLASH  # 1.0s ON / 1.0s OFF
    assert pt.evaluate_flash_state(0.5) is True
    assert pt.evaluate_flash_state(1.5) is False
    assert pt.evaluate_flash_state(2.2) is True


def test_annunciator_register_table_scan_cycle_sync():
    """Verify scan cycle step reads operator coils and outputs to %R220, %AQ3."""
    reg_table = RegisterTable()
    mgr = AlarmAnnunciatorManager(register_table=reg_table)

    # Trip high temp alarm
    mgr.set_process_condition("ALM_03", True)

    mgr.step(0.010)

    r220 = reg_table.read_word("%R220")
    aq3 = reg_table.read_word("%AQ3")

    assert (r220 & (1 << 0)) != 0  # Unack flag
    assert (r220 & (1 << 1)) != 0  # Horn sounding flag
    assert (r220 & (1 << 3)) != 0  # Critical active flag
    assert aq3 == 25000            # Horn volume commanded on

    # Send operator silence via register table coil %M30
    reg_table.write_bit("%M30", True, privilege=PrivilegeMode.SYSTEM)
    mgr.step(0.010)

    assert reg_table.read_bit("%M30") is False  # Auto-cleared by logic unit
    assert mgr.is_horn_sounding() is False
    assert reg_table.read_word("%AQ3") == 0


def test_annunciator_lamp_test():
    """Verify lamp test forces horn and lamp illumination."""
    reg_table = RegisterTable()
    mgr = AlarmAnnunciatorManager(register_table=reg_table)

    reg_table.write_bit("%M33", True, privilege=PrivilegeMode.SYSTEM)
    mgr.step(0.010)

    r220 = reg_table.read_word("%R220")
    assert (r220 & (1 << 2)) != 0  # Lamp test bit
    assert reg_table.read_word("%AQ3") == 25000  # Horn sounding on lamp test


def test_verify_and_export_evidence(tmp_path: Path):
    """Verify canonical export runner creates valid JSON and WAV deliverables."""
    result = verify_alarm_annunciator_and_export_evidence(str(tmp_path))

    assert result["status"] == "success"
    assert result["error_code"] is None

    json_path = tmp_path / "alarm_annunciator_evidence.json"
    wav_path = tmp_path / "critical_alarm_sample.wav"

    assert json_path.exists()
    assert wav_path.exists()
    assert wav_path.stat().st_size == 44 + (44100 * 2)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["status"] == "success"
    assert data["data"]["work_package"] == "W056"
    assert data["data"]["gate"] == "G9"
    assert len(data["data"]["audio_synthesis"]["profiles_synthesized"]) == 4
