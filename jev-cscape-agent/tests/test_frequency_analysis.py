"""Unit tests for FrequencySpectrumAnalyzer (Gate G7/G10)."""

import math
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.simulation.frequency_analysis import (
    FrequencySpectrumAnalyzer,
    SpectralDiagnosticState,
    _radix2_fft,
)
from jev_cscape.simulation.register_table import RegisterTable


def test_radix2_fft_single_tone():
    n = 64
    dt = 0.01  # fs = 100 Hz
    freq = 10.0  # 10 Hz tone
    signal = [complex(math.sin(2.0 * math.pi * freq * (i * dt)), 0.0) for i in range(n)]

    spectrum = _radix2_fft(signal)
    magnitudes = [abs(c) for c in spectrum[: n // 2]]

    # Expected peak bin: k = freq / (fs / N) = 10 / (100 / 64) = 6.4 -> bin 6 or 7
    peak_bin = magnitudes.index(max(magnitudes))
    assert peak_bin in (6, 7)


def test_spectrum_analyzer_normal_damped_signal():
    analyzer = FrequencySpectrumAnalyzer(dt_s=0.020, window_size=512)
    fs = analyzer.sampling_rate_hz  # 50 Hz

    # Generate well-damped broad-band error signal (low resonance)
    error = [0.1 * math.sin(2.0 * math.pi * 0.5 * (i * 0.020)) + 0.05 * math.sin(i * 0.1) for i in range(512)]
    actuator = [0.2 * math.cos(2.0 * math.pi * 0.2 * (i * 0.020)) for i in range(512)]

    res = analyzer.analyze_signals(error, actuator)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["diagnostic_state"] in ("NORMAL", "UNDERDAMPED_WARNING")
    assert res.data["nyquist_frequency_hz"] == 25.0


def test_spectrum_analyzer_severe_resonance():
    analyzer = FrequencySpectrumAnalyzer(dt_s=0.020, window_size=512)

    # Sharp resonant sine tone at 1.5 Hz with high amplitude
    target_freq = 1.50
    error = [5.0 * math.sin(2.0 * math.pi * target_freq * (i * 0.020)) + 0.02 * math.sin(i * 0.5) for i in range(512)]
    actuator = [1.0 * math.sin(2.0 * math.pi * target_freq * (i * 0.020)) for i in range(512)]

    res = analyzer.analyze_signals(error, actuator)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["diagnostic_state"] == "STABILITY_DEGRADED"
    assert res.data["resonance_peak_ratio"] > 2.0
    assert abs(res.data["dominant_frequency_hz"] - target_freq) < 0.15


def test_spectrum_analyzer_valve_hunting():
    analyzer = FrequencySpectrumAnalyzer(dt_s=0.020, window_size=512, hunting_threshold=0.60)

    # Actuator concentrated in hunting band 0.5 Hz, error modest
    error = [0.2 * math.sin(i * 0.05) for i in range(512)]
    actuator = [10.0 * math.sin(2.0 * math.pi * 0.50 * (i * 0.020)) for i in range(512)]

    res = analyzer.analyze_signals(error, actuator)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["actuator_hunting_index"] > 0.60
    assert res.data["diagnostic_state"] == "VALVE_HUNTING"


def test_register_synchronization():
    table = RegisterTable()
    analyzer = FrequencySpectrumAnalyzer(dt_s=0.020, window_size=512)

    target_freq = 2.0
    error = [8.0 * math.sin(2.0 * math.pi * target_freq * (i * 0.020)) for i in range(512)]
    actuator = [2.0 * math.sin(i * 0.1) for i in range(512)]

    res = analyzer.analyze_signals(error, actuator, register_table=table)
    assert res.status == AgentStatus.SUCCESS

    # Verify flags %M21..%M24
    assert table.read_bit("%M24") is True  # Data valid
    assert table.read_bit("%M23") is True  # Stability degraded due to severe resonance

    # Verify telemetry %R201..%R205
    f_dist_reg = table.read_word("%R201")
    assert abs(f_dist_reg - int(target_freq * 100)) < 25  # ~200 counts (2.00 Hz)


def test_insufficient_samples_rejection():
    analyzer = FrequencySpectrumAnalyzer(dt_s=0.020, window_size=512)
    res = analyzer.analyze_signals([1.0] * 100, [1.0] * 100)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_INSUFFICIENT_SAMPLES"


def test_runner_frequency_analysis_verification(tmp_path):
    from scripts.run_frequency_analysis_verification import run_frequency_analysis_verification
    out_file = tmp_path / "frequency_analysis_evidence.json"
    evidence = run_frequency_analysis_verification(repo_root=tmp_path, output_path=out_file)
    assert evidence["status"] == "success"
    assert out_file.exists()
    assert len(evidence["data"]["scenarios_evaluated"]) == 4
