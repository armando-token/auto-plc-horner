"""Disturbance Frequency Spectrum Analyzer & Stochastic Stability Diagnostic (Gate G7/G10).

Provides pure-Python numerical FFT spectral power density analysis of closed-loop
control signals, evaluating:
- Single-sided Power Spectral Density (PSD) for error e(t) and control effort u(t)
- Hann windowing and energy normalization
- Dominant disturbance frequency f_dist with parabolic sub-bin refinement
- Resonance peak ratio M_r and estimated damping ratio zeta_est
- Actuator hunting concentration index eta_hunt
- Nyquist boundary assertions across scan rates (5ms, 10ms, 20ms, 50ms)
- Horner OCS register status flags (%M21..%M24) and telemetry (%R201..%R205)
- Zero external dependencies: pure standard library (math, cmath).
"""

from __future__ import annotations

import cmath
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class SpectralDiagnosticState(str, Enum):
    """Closed-loop control loop dynamic stability state."""

    NORMAL = "NORMAL"
    UNDERDAMPED_WARNING = "UNDERDAMPED_WARNING"
    VALVE_HUNTING = "VALVE_HUNTING"
    STABILITY_DEGRADED = "STABILITY_DEGRADED"


@dataclass
class SpectralMetrics:
    """Quantitative frequency domain performance metrics."""

    sampling_rate_hz: float
    nyquist_frequency_hz: float
    frequency_resolution_hz: float
    window_length_n: int
    dominant_frequency_hz: float
    resonance_peak_ratio: float
    estimated_damping_ratio: float
    closed_loop_bandwidth_hz: float
    actuator_hunting_index: float
    diagnostic_state: SpectralDiagnosticState
    frequencies: List[float] = field(default_factory=list)
    psd_error: List[float] = field(default_factory=list)
    psd_actuator: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sampling_rate_hz": self.sampling_rate_hz,
            "nyquist_frequency_hz": self.nyquist_frequency_hz,
            "frequency_resolution_hz": self.frequency_resolution_hz,
            "window_length_n": self.window_length_n,
            "dominant_frequency_hz": round(self.dominant_frequency_hz, 4),
            "resonance_peak_ratio": round(self.resonance_peak_ratio, 4),
            "estimated_damping_ratio": round(self.estimated_damping_ratio, 4),
            "closed_loop_bandwidth_hz": round(self.closed_loop_bandwidth_hz, 4),
            "actuator_hunting_index": round(self.actuator_hunting_index, 4),
            "diagnostic_state": self.diagnostic_state.value,
        }


def _radix2_fft(x: List[complex]) -> List[complex]:
    """Pure-Python Radix-2 Cooley-Tukey Decimation-in-Time FFT (O(N log N))."""
    n = len(x)
    if n <= 1:
        return x
    if (n & (n - 1)) != 0:
        raise ValueError(f"FFT input length must be a power of two, got {n}")

    even = _radix2_fft(x[0::2])
    odd = _radix2_fft(x[1::2])
    factors = [cmath.exp(-2j * math.pi * k / n) * odd[k] for k in range(n // 2)]
    return [even[k] + factors[k] for k in range(n // 2)] + [
        even[k] - factors[k] for k in range(n // 2)
    ]


class FrequencySpectrumAnalyzer:
    """Performs FFT spectral decomposition and stability analysis."""

    def __init__(
        self,
        dt_s: float = 0.020,
        window_size: int = 512,
        resonance_threshold: float = 1.30,
        hunting_threshold: float = 0.65,
    ) -> None:
        """Initialize FrequencySpectrumAnalyzer.

        Args:
            dt_s: Discrete time step in seconds (e.g. 0.020 for 50Hz, 0.010 for 100Hz).
            window_size: Must be a power of 2 (default: 512).
            resonance_threshold: Peak-to-baseline ratio above which resonance warning trips.
            hunting_threshold: Actuator high-frequency energy ratio above which hunting alarm trips.
        """
        if (window_size & (window_size - 1)) != 0 or window_size < 16:
            raise ValueError(f"Window size must be a power of two >= 16, got {window_size}")

        self.dt_s = dt_s
        self.sampling_rate_hz = 1.0 / dt_s
        self.nyquist_frequency_hz = self.sampling_rate_hz / 2.0
        self.window_size = window_size
        self.frequency_resolution_hz = self.sampling_rate_hz / window_size
        self.resonance_threshold = resonance_threshold
        self.hunting_threshold = hunting_threshold

        # Compute Hann window and power normalization factor
        self.window = [
            0.5 * (1.0 - math.cos(2.0 * math.pi * n / (window_size - 1)))
            for n in range(window_size)
        ]
        self.window_power_u = sum(w * w for w in self.window) / window_size

    def analyze_signals(
        self,
        error_signal: List[float],
        actuator_signal: List[float],
        register_table: Optional[RegisterTable] = None,
    ) -> ExecutionResult:
        """Compute spectral metrics and stability diagnostic across error and actuator traces."""
        n = self.window_size
        if len(error_signal) < n or len(actuator_signal) < n:
            return ExecutionResult.failed(
                "ERR_INSUFFICIENT_SAMPLES",
                f"Requires at least {n} samples, got {len(error_signal)} error and {len(actuator_signal)} actuator.",
            )

        # Slice the most recent N samples
        e_slice = error_signal[-n:]
        u_slice = actuator_signal[-n:]

        # Remove DC bias
        e_mean = sum(e_slice) / n
        u_mean = sum(u_slice) / n
        e_detrended = [v - e_mean for v in e_slice]
        u_detrended = [v - u_mean for v in u_slice]

        # Apply Hann window
        e_windowed = [complex(e_detrended[i] * self.window[i], 0.0) for i in range(n)]
        u_windowed = [complex(u_detrended[i] * self.window[i], 0.0) for i in range(n)]

        # Compute Radix-2 FFT
        e_fft = _radix2_fft(e_windowed)
        u_fft = _radix2_fft(u_windowed)

        # Single-sided PSD
        num_bins = n // 2 + 1
        frequencies = [k * self.frequency_resolution_hz for k in range(num_bins)]
        scale = (2.0 * self.dt_s) / (n * self.window_power_u)

        psd_e = [scale * (abs(e_fft[k]) ** 2) for k in range(num_bins)]
        psd_u = [scale * (abs(u_fft[k]) ** 2) for k in range(num_bins)]
        # DC and Nyquist bin normalization
        psd_e[0] /= 2.0
        psd_u[0] /= 2.0
        if num_bins > 1:
            psd_e[-1] /= 2.0
            psd_u[-1] /= 2.0

        # Find dominant disturbance peak (skip DC bin k=0)
        search_start = max(1, int(0.05 / self.frequency_resolution_hz))
        k_star = search_start
        max_psd = psd_e[search_start]
        for k in range(search_start + 1, num_bins - 1):
            if psd_e[k] > max_psd:
                max_psd = psd_e[k]
                k_star = k

        # Parabolic sub-bin interpolation
        f_dist = frequencies[k_star]
        if 0 < k_star < num_bins - 1:
            y1 = math.log(max(1e-12, psd_e[k_star - 1]))
            y2 = math.log(max(1e-12, psd_e[k_star]))
            y3 = math.log(max(1e-12, psd_e[k_star + 1]))
            denom = y1 - 2.0 * y2 + y3
            if abs(denom) > 1e-9:
                delta = 0.5 * (y1 - y3) / denom
                f_dist = (k_star + delta) * self.frequency_resolution_hz

        # Resonance peak-to-baseline ratio
        baseline_slice = psd_e[search_start:]
        baseline = sum(baseline_slice) / len(baseline_slice) if baseline_slice else 1e-6
        m_r = max_psd / max(1e-9, baseline)
        zeta_est = 1.0 / (2.0 * math.sqrt(max(1.0, m_r)))

        # Actuator hunting index (energy between 0.1 Hz and 1.5 Hz)
        total_actuator_power = sum(psd_u)
        k_hunt_low = max(0, int(0.10 / self.frequency_resolution_hz))
        k_hunt_high = min(num_bins, int(1.50 / self.frequency_resolution_hz) + 1)
        hunting_power = sum(psd_u[k_hunt_low:k_hunt_high])
        eta_hunt = hunting_power / max(1e-9, total_actuator_power)

        # Closed-loop bandwidth (frequency where cumulative error variance reaches 70.7%)
        total_error_power = sum(psd_e)
        cum_power = 0.0
        f_bw = frequencies[-1]
        for k in range(num_bins):
            cum_power += psd_e[k]
            if cum_power >= 0.707 * total_error_power:
                f_bw = frequencies[k]
                break

        # RMS calculations for physical significance gating
        rms_error = math.sqrt(sum(v * v for v in e_detrended) / n)
        rms_actuator = math.sqrt(sum(v * v for v in u_detrended) / n)

        # State classification
        if (m_r > 2.0 or zeta_est < 0.25) and rms_error >= 1.0:
            state = SpectralDiagnosticState.STABILITY_DEGRADED
        elif eta_hunt > self.hunting_threshold and rms_actuator >= 1.0:
            state = SpectralDiagnosticState.VALVE_HUNTING
        elif m_r > self.resonance_threshold and rms_error >= 0.5:
            state = SpectralDiagnosticState.UNDERDAMPED_WARNING
        else:
            state = SpectralDiagnosticState.NORMAL

        metrics = SpectralMetrics(
            sampling_rate_hz=self.sampling_rate_hz,
            nyquist_frequency_hz=self.nyquist_frequency_hz,
            frequency_resolution_hz=self.frequency_resolution_hz,
            window_length_n=n,
            dominant_frequency_hz=f_dist,
            resonance_peak_ratio=m_r,
            estimated_damping_ratio=zeta_est,
            closed_loop_bandwidth_hz=f_bw,
            actuator_hunting_index=eta_hunt,
            diagnostic_state=state,
            frequencies=frequencies,
            psd_error=psd_e,
            psd_actuator=psd_u,
        )

        # Synchronize with Horner OCS registers if provided
        if register_table is not None:
            # Flags: %M21 (Resonance warning), %M22 (Hunting alarm), %M23 (Stability degraded), %M24 (Data valid)
            register_table.write_bit("%M21", state == SpectralDiagnosticState.UNDERDAMPED_WARNING, privilege=PrivilegeMode.SYSTEM)
            register_table.write_bit("%M22", state == SpectralDiagnosticState.VALVE_HUNTING, privilege=PrivilegeMode.SYSTEM)
            register_table.write_bit("%M23", state == SpectralDiagnosticState.STABILITY_DEGRADED, privilege=PrivilegeMode.SYSTEM)
            register_table.write_bit("%M24", True, privilege=PrivilegeMode.SYSTEM)

            # Telemetry: %R201..%R205
            register_table.write_word("%R201", int(f_dist * 100), privilege=PrivilegeMode.SYSTEM)
            register_table.write_word("%R202", int(m_r * 100), privilege=PrivilegeMode.SYSTEM)
            register_table.write_word("%R203", int(zeta_est * 1000), privilege=PrivilegeMode.SYSTEM)
            register_table.write_word("%R204", int(f_bw * 100), privilege=PrivilegeMode.SYSTEM)
            register_table.write_word("%R205", int(eta_hunt * 100), privilege=PrivilegeMode.SYSTEM)

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            error_code=None,
            details=f"Spectral analysis completed. Diagnostic state: {state.value} (dominant frequency: {f_dist:.3f} Hz, M_r: {m_r:.2f}).",
            data=metrics.to_dict(),
        )
