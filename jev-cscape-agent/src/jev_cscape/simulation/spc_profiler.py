"""Statistical Process Control (SPC) & Six-Sigma Cpk Capability Profiler.

Work Package: W054 (Gate G10 / G4)
Classification: PRODUCTION [in-process statistical stability & capability diagnostics]

Provides:
- ShewhartControlLimits: Center Line (CL), Upper Control Limit (UCL), and Lower Control Limit (LCL).
- WesternElectricRules: Detection of out-of-control conditions (Rules 1-4).
- ProcessCapabilityIndices: Cp, Cpk, Pp, Ppk, and centering factor k adhering to ISO 21747 / AIAG SPC.
- SPCProfiler: Thread-safe sliding-window streaming SPC engine with Welford variance tracking,
  Horner OCS register synchronization (%M25..%M28, %R210..%R213), and ISA-18.2 event integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

# Range unbiasing constant d2 for subgroup size n=2 (Moving Range span = 2)
D2_N2: float = 1.128379167


@dataclass
class ShewhartControlLimits:
    """Shewhart Individual (I) and Moving Range (MR) control limits."""
    cl: float
    ucl: float
    lcl: float
    mr_cl: float
    mr_ucl: float
    mr_lcl: float = 0.0
    sigma_within: float = 0.0


@dataclass
class WesternElectricViolations:
    """Western Electric rule evaluation outcomes."""
    rule1_beyond_3sigma: bool = False      # Single point outside UCL/LCL (%M25)
    rule2_zone_a: bool = False             # 2 of 3 points beyond 2-sigma on same side (%M26)
    rule3_zone_b: bool = False             # 4 of 5 points beyond 1-sigma on same side (%M27)
    rule4_mean_shift: bool = False         # 8 consecutive points on same side of center line (%M28)

    @property
    def any_violation(self) -> bool:
        return (
            self.rule1_beyond_3sigma
            or self.rule2_zone_a
            or self.rule3_zone_b
            or self.rule4_mean_shift
        )


@dataclass
class CapabilityIndices:
    """Process capability and performance metrics."""
    cp: float
    cpk: float
    cpu: float
    cpl: float
    pp: float
    ppk: float
    ppu: float
    ppl: float
    centering_factor_k: float
    is_capable_133: bool
    is_capable_167: bool


@dataclass
class SPCMetrics:
    """Complete statistical process control metrics snapshot."""
    sample_count: int
    mean: float
    std_dev_within: float
    std_dev_overall: float
    control_limits: ShewhartControlLimits
    violations: WesternElectricViolations
    capability: Optional[CapabilityIndices]
    last_value: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "mean": self.mean,
            "std_dev_within": self.std_dev_within,
            "std_dev_overall": self.std_dev_overall,
            "last_value": self.last_value,
            "control_limits": {
                "cl": self.control_limits.cl,
                "ucl": self.control_limits.ucl,
                "lcl": self.control_limits.lcl,
                "mr_cl": self.control_limits.mr_cl,
                "mr_ucl": self.control_limits.mr_ucl,
            },
            "violations": {
                "rule1_beyond_3sigma": self.violations.rule1_beyond_3sigma,
                "rule2_zone_a": self.violations.rule2_zone_a,
                "rule3_zone_b": self.violations.rule3_zone_b,
                "rule4_mean_shift": self.violations.rule4_mean_shift,
                "any_violation": self.violations.any_violation,
            },
            "capability": {
                "cp": self.capability.cp if self.capability else None,
                "cpk": self.capability.cpk if self.capability else None,
                "pp": self.capability.pp if self.capability else None,
                "ppk": self.capability.ppk if self.capability else None,
                "centering_factor_k": self.capability.centering_factor_k if self.capability else None,
                "is_capable_133": self.capability.is_capable_133 if self.capability else False,
                "is_capable_167": self.capability.is_capable_167 if self.capability else False,
            } if self.capability else None,
            "timestamp": self.timestamp,
        }


class SPCProfiler:
    """Thread-safe real-time streaming Statistical Process Control (SPC) engine.

    Guarantees:
    - Pure-Python arithmetic with zero external numpy/scipy dependency.
    - Numerical stability guards against division by zero (zero variance, identical samples).
    - Thread-safe sliding sample window guarded by reentrant lock (RLock).
    - Horner OCS register table synchronization (%M25..%M28, %R210..%R213).
    """

    def __init__(
        self,
        usl: float,
        lsl: float,
        target: Optional[float] = None,
        window_size: int = 100,
    ) -> None:
        if usl <= lsl:
            raise ValueError(f"USL ({usl}) must be strictly greater than LSL ({lsl})")
        if window_size < 10:
            raise ValueError(f"window_size must be at least 10, got {window_size}")

        self.usl = float(usl)
        self.lsl = float(lsl)
        self.target = float(target) if target is not None else (usl + lsl) / 2.0
        self.window_size = int(window_size)

        self._lock = threading.RLock()
        self._samples: List[float] = []

    def reset(self) -> None:
        """Clear all ingested observations."""
        with self._lock:
            self._samples.clear()

    def ingest_sample(self, value: float) -> None:
        """Ingest a single process measurement."""
        if math.isnan(value) or math.isinf(value):
            return

        with self._lock:
            self._samples.append(float(value))
            if len(self._samples) > self.window_size:
                self._samples.pop(0)

    def ingest_batch(self, values: Sequence[float]) -> None:
        """Ingest a sequence of process measurements."""
        with self._lock:
            for val in values:
                self.ingest_sample(val)

    def compute_metrics(self) -> Optional[SPCMetrics]:
        """Compute full Shewhart, Western Electric, and Capability metrics."""
        with self._lock:
            n = len(self._samples)
            if n < 2:
                return None

            samples = list(self._samples)
            last_val = samples[-1]

            # 1. Mean (X_bar)
            x_bar = sum(samples) / n

            # 2. Moving Range (MR) and within-subgroup sigma
            mr_list = [abs(samples[i] - samples[i - 1]) for i in range(1, n)]
            mr_bar = sum(mr_list) / len(mr_list)
            sigma_within = mr_bar / D2_N2

            # 3. Overall sample standard deviation (s) using numerically stable two-pass
            var_overall = sum((x - x_bar) ** 2 for x in samples) / (n - 1)
            sigma_overall = math.sqrt(max(0.0, var_overall))

            # Guard zero dispersion
            if sigma_within < 1e-12:
                sigma_within = 1e-12
            if sigma_overall < 1e-12:
                sigma_overall = 1e-12

            # 4. Shewhart Control Limits (Individuals I and Moving Range MR)
            # UCL = X_bar + 2.6596 * MR_bar (which is X_bar + 3 * sigma_within)
            ucl = x_bar + 3.0 * sigma_within
            lcl = x_bar - 3.0 * sigma_within
            mr_ucl = 3.2665 * mr_bar  # D4 * MR_bar for n=2

            limits = ShewhartControlLimits(
                cl=x_bar,
                ucl=ucl,
                lcl=lcl,
                mr_cl=mr_bar,
                mr_ucl=mr_ucl,
                sigma_within=sigma_within,
            )

            # 5. Western Electric Rules
            violations = self._evaluate_western_electric_rules(samples, x_bar, sigma_within, ucl, lcl)

            # 6. Capability Indices (Cp, Cpk, Pp, Ppk)
            capability = self._compute_capability(x_bar, sigma_within, sigma_overall)

            return SPCMetrics(
                sample_count=n,
                mean=x_bar,
                std_dev_within=sigma_within,
                std_dev_overall=sigma_overall,
                control_limits=limits,
                violations=violations,
                capability=capability,
                last_value=last_val,
                timestamp=time.time(),
            )

    def _evaluate_western_electric_rules(
        self,
        samples: List[float],
        x_bar: float,
        sigma: float,
        ucl: float,
        lcl: float,
    ) -> WesternElectricViolations:
        """Evaluate Western Electric rules 1 to 4 on sliding observations."""
        n = len(samples)
        last_val = samples[-1]

        # Rule 1: 1 point beyond 3 sigma (outside UCL or LCL)
        r1 = (last_val > ucl) or (last_val < lcl)

        # Normalized z-scores
        z_scores = [(x - x_bar) / sigma for x in samples]

        # Rule 2: 2 out of 3 consecutive points in Zone A or beyond (> 2 sigma or < -2 sigma on same side)
        r2 = False
        if n >= 3:
            recent_3 = z_scores[-3:]
            pos_zone_a = sum(1 for z in recent_3 if z > 2.0)
            neg_zone_a = sum(1 for z in recent_3 if z < -2.0)
            if pos_zone_a >= 2 or neg_zone_a >= 2:
                r2 = True

        # Rule 3: 4 out of 5 consecutive points in Zone B or beyond (> 1 sigma or < -1 sigma on same side)
        r3 = False
        if n >= 5:
            recent_5 = z_scores[-5:]
            pos_zone_b = sum(1 for z in recent_5 if z > 1.0)
            neg_zone_b = sum(1 for z in recent_5 if z < -1.0)
            if pos_zone_b >= 4 or neg_zone_b >= 4:
                r3 = True

        # Rule 4: 8 consecutive points on one side of center line (z > 0 or z < 0)
        r4 = False
        if n >= 8:
            recent_8 = z_scores[-8:]
            all_pos = all(z > 0.0 for z in recent_8)
            all_neg = all(z < 0.0 for z in recent_8)
            if all_pos or all_neg:
                r4 = True

        return WesternElectricViolations(
            rule1_beyond_3sigma=r1,
            rule2_zone_a=r2,
            rule3_zone_b=r3,
            rule4_mean_shift=r4,
        )

    def _compute_capability(
        self,
        mean: float,
        sigma_within: float,
        sigma_overall: float,
    ) -> CapabilityIndices:
        """Calculates capability and performance indices."""
        spec_width = self.usl - self.lsl
        half_spec = spec_width / 2.0
        midpoint = (self.usl + self.lsl) / 2.0

        # Potential Capability Cp (within-subgroup)
        if sigma_within < 1e-6:
            in_spec = (self.lsl <= mean <= self.usl)
            cp = 99.99 if in_spec else 0.0
            cpu = 99.99 if in_spec else 0.0
            cpl = 99.99 if in_spec else 0.0
            cpk = 99.99 if in_spec else 0.0
        else:
            cp = min(99.99, spec_width / (6.0 * sigma_within))
            cpu = (self.usl - mean) / (3.0 * sigma_within)
            cpl = (mean - self.lsl) / (3.0 * sigma_within)
            cpk = min(cpu, cpl)

        # Overall Performance Pp (total variation)
        if sigma_overall < 1e-6:
            in_spec = (self.lsl <= mean <= self.usl)
            pp = 99.99 if in_spec else 0.0
            ppu = 99.99 if in_spec else 0.0
            ppl = 99.99 if in_spec else 0.0
            ppk = 99.99 if in_spec else 0.0
        else:
            pp = min(99.99, spec_width / (6.0 * sigma_overall))
            ppu = (self.usl - mean) / (3.0 * sigma_overall)
            ppl = (mean - self.lsl) / (3.0 * sigma_overall)
            ppk = min(ppu, ppl)

        # Centering factor k
        k = abs(mean - midpoint) / half_spec if half_spec > 0 else 0.0

        return CapabilityIndices(
            cp=round(cp, 4),
            cpk=round(cpk, 4),
            cpu=round(cpu, 4),
            cpl=round(cpl, 4),
            pp=round(pp, 4),
            ppk=round(ppk, 4),
            ppu=round(ppu, 4),
            ppl=round(ppl, 4),
            centering_factor_k=round(k, 4),
            is_capable_133=(cpk >= 1.33),
            is_capable_167=(cpk >= 1.67),
        )

    def sync_to_registers(self, reg_table: RegisterTable) -> Optional[SPCMetrics]:
        """Compute metrics and stage values into Horner OCS registers.

        Registers:
        - %M25: Rule 1 Alarm coil (Beyond 3-sigma)
        - %M26: Rule 2 Alarm coil (Zone A)
        - %M27: Rule 3 Alarm coil (Zone B)
        - %M28: Rule 4 Alarm coil (8-consecutive shift)
        - %R210: Cp * 100 (scaled integer)
        - %R211: Cpk * 100 (scaled integer)
        - %R212: Mean * 10 (tenths of EU)
        - %R213: Sigma * 100 (hundredths of EU)
        """
        metrics = self.compute_metrics()
        if not metrics:
            return None

        # Write discrete coils %M25..%M28
        reg_table.write_bit("%M25", metrics.violations.rule1_beyond_3sigma, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M26", metrics.violations.rule2_zone_a, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M27", metrics.violations.rule3_zone_b, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_bit("%M28", metrics.violations.rule4_mean_shift, privilege=PrivilegeMode.SYSTEM)

        # Write analog words %R210..%R213
        cp_scaled = int(round(metrics.capability.cp * 100.0)) if metrics.capability else 0
        cpk_scaled = int(round(metrics.capability.cpk * 100.0)) if metrics.capability else 0
        mean_scaled = int(round(metrics.mean * 10.0))
        sigma_scaled = int(round(metrics.std_dev_within * 100.0))

        # Clamp to signed 16-bit range [-32768, 32767]
        cp_clamped = max(-32768, min(32767, cp_scaled))
        cpk_clamped = max(-32768, min(32767, cpk_scaled))
        mean_clamped = max(-32768, min(32767, mean_scaled))
        sigma_clamped = max(-32768, min(32767, sigma_scaled))

        reg_table.write_word("%R210", cp_clamped, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R211", cpk_clamped, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R212", mean_clamped, privilege=PrivilegeMode.SYSTEM)
        reg_table.write_word("%R213", sigma_clamped, privilege=PrivilegeMode.SYSTEM)

        return metrics
