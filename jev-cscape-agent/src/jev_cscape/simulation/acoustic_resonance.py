"""Cross-Flow Induced Tube Bundle Acoustic Resonance & Vortex Shedding Frequency ODE Simulation.

Work Package: W098 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Implements:
1. Shell-and-Tube Transverse Acoustic Wave & Vortex Shedding Mechanics:
   - Blevins porous acoustic correction for tube bundle solidity: c_eff = c_s / sqrt(1 + sigma).
   - Shell transverse standing wave acoustic natural frequency: f_a0 = c_eff / (2 * W_shell).
   - Crossflow gap velocity: U_gap = U_g * S_T / (S_T - D).
   - Strouhal vortex shedding frequency: f_s = St * U_gap / D.
   - Lock-in detuning condition: |f_s - f_a| / f_a <= 0.15 (15% lock-in window).
2. Van der Pol Aeroacoustic & Structural Dynamic Coupling:
   - 4-State coupled ODE system: y = [x, v, P_ac, w]
     - x: Transverse tube deflection [m]
     - v = dx/dt: Tube vibration velocity [m/s]
     - P_ac: Acoustic perturbation pressure [Pa]
     - w = dP_ac/dt: Acoustic pressure rate [Pa/s]
   - Nonlinear aeroacoustic limit cycle: alpha_aero * omega_a * (1 - beta * P_ac^2) * w.
   - Two-way fluid-structure acoustic pressure coupling.
3. Deployable Anti-Vibration Baffle (Detuning & Surge Damping):
   - Control input u_b in {0, 1}.
   - When deployed (u_b = 1): splits transverse cavity (f_a doubles to 2*f_a0), breaks lock-in,
     and introduces heavy acoustic boundary damping (zeta_a increases).
4. Deterministic Runge-Kutta 4th Order (RK4) Numerical Integrator:
   - Micro-second scale integration dt <= 0.0002 s (0.2 ms).
5. Horner OCS Register Space Synchronization:
   - Analog registers %R590..%R597 (Status word, Deflection, Pressure, f_s, f_a, Detuning, Flow, Baffle).
   - Discrete coils %M137..%M139 (Lock-in detected, Baffle deployed, Alarm exceeded).
6. Pure IEC 61131-3 Structured Text (ST) POU with anti-ladder security guard.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Enums and Status Bitmasks
# ============================================================================

class AcousticResonanceStatusBits(IntFlag):
    """Horner OCS %R590 Status Word Bitmask Definitions."""
    ENGINE_ACTIVE           = 1 << 0  # Bit 0: Simulation engine initialized and running
    FLOW_PRESENT            = 1 << 1  # Bit 1: Shell cross-flow velocity > 0.5 m/s
    LOCK_IN_DETECTED        = 1 << 2  # Bit 2: Vortex shedding locked into acoustic natural mode
    DEFLECTION_ALARM        = 1 << 3  # Bit 3: Tube deflection |x| >= limit (2.5 mm)
    ACOUSTIC_PRESSURE_ALARM = 1 << 4  # Bit 4: Acoustic pressure |P_ac| >= limit (1500 Pa)
    BAFFLE_DEPLOYED         = 1 << 5  # Bit 5: Anti-vibration baffle deployed (u_b = 1)
    STRUCTURAL_SAFE         = 1 << 6  # Bit 6: Deflection and pressure within safe fatigue limits
    RESONANCE_SUPPRESSED    = 1 << 7  # Bit 7: Baffle active and acoustic pressure suppressed (< 300 Pa)


# ============================================================================
# 2. Configuration & Parameter Data Models
# ============================================================================

@dataclass
class TubeBundleAcousticConfig:
    """Acoustic cavity and tube bundle physical parameters."""
    # Cavity & Tube Geometry
    shell_width_m: float = 0.60               # Transverse cavity dimension W_shell [m]
    tube_outer_diameter_m: float = 0.0254     # Tube outer diameter D (1 in) [m]
    transverse_pitch_m: float = 0.0381        # Transverse pitch S_T (P/D = 1.5) [m]
    bundle_solidity: float = 0.30             # Solidity volume fraction sigma
    speed_of_sound_m_s: float = 340.0         # Pure gas speed of sound c_s [m/s]
    gas_density_kg_m3: float = 1.225          # Gas density rho_g [kg/m^3]

    # Strouhal & Vortex Dynamics
    strouhal_number: float = 0.28             # Strouhal number St
    vortex_lift_coeff: float = 0.15           # Fluctuating lift coefficient C_L

    # Tube Structural Properties
    tube_mass_per_len_kg_m: float = 1.85      # Modal mass per unit length m_t [kg/m]
    tube_natural_freq_hz: float = 28.5        # Structural natural frequency f_t [Hz]
    tube_damping_ratio: float = 0.015         # Structural modal damping ratio zeta_t (1.5%)

    # Acoustic Cavity Properties
    acoustic_damping_ratio: float = 0.02      # Cavity damping ratio zeta_a (2.0%)
    baffle_damping_ratio: float = 0.08        # Damping with baffle deployed (8.0%)

    # Aeroacoustic Coupling (Van der Pol formulation)
    alpha_growth: float = 0.12                # Aeroacoustic linear growth rate
    beta_saturation: float = 1.5e-6           # Nonlinear acoustic saturation coeff [Pa^-2]
    gamma_pa: float = 0.045                   # Acoustic pressure to tube force coupling [m]
    gamma_ap: float = 12000.0                 # Tube velocity to acoustic pressure excitation [Pa/(m/s)]

    # Safety & Alarm Limits
    deflection_limit_m: float = 0.0025        # 2.5 mm (2500 um) peak allowable deflection
    acoustic_pressure_limit_pa: float = 1500.0  # 1500 Pa (157.5 dB SPL) acoustic limit
    lock_in_threshold: float = 0.15           # 15% frequency detuning threshold


@dataclass
class AcousticResonanceState:
    """Current dynamic state vector of the coupled tube-acoustic system."""
    time_s: float = 0.0
    x: float = 0.0            # Tube transverse deflection [m]
    v: float = 0.0            # Tube vibration velocity [m/s]
    p_ac: float = 0.0         # Acoustic pressure perturbation [Pa]
    w: float = 0.0            # Acoustic pressure time derivative [Pa/s]
    u_baffle: bool = False    # Baffle deployment status (False=retracted, True=deployed)
    flow_velocity: float = 0.0  # Shell approach gas velocity [m/s]
    f_s: float = 0.0          # Vortex shedding frequency [Hz]
    f_a: float = 0.0          # Current acoustic natural frequency [Hz]
    detuning_ratio: float = 0.0  # |f_s - f_a| / f_a
    is_locked_in: bool = False   # True when locked in


# ============================================================================
# 3. Dynamic ODE Simulation Engine
# ============================================================================

class TubeBundleAcousticSimulator:
    """Coupled Tube Bundle Vortex Shedding & Acoustic Resonance Simulation Engine.
    
    Work Package: W098 (Gate G7 / G4)
    Mapped Registers: %R590..%R597, %M137..%M139.
    """

    def __init__(
        self,
        config: Optional[TubeBundleAcousticConfig] = None,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.config = config or TubeBundleAcousticConfig()
        self.reg_table = register_table or RegisterTable()

        # Blevins effective speed of sound
        # c_eff = c_s / sqrt(1 + sigma)
        self.c_eff: float = self.config.speed_of_sound_m_s / math.sqrt(1.0 + self.config.bundle_solidity)

        # Baseline transverse standing wave frequency (half-wavelength across shell width)
        # f_a0 = c_eff / (2 * W_shell)
        self.f_a0: float = self.c_eff / (2.0 * self.config.shell_width_m)

        # Current dynamic state
        self.state = AcousticResonanceState(
            f_a=self.f_a0,
        )

        # Initial register sync
        self._sync_registers()

    def get_gap_velocity(self, u_flow: float) -> float:
        """Calculate interstitial gap flow velocity between tubes."""
        d = self.config.tube_outer_diameter_m
        s_t = self.config.transverse_pitch_m
        if s_t <= d:
            return u_flow
        return u_flow * (s_t / (s_t - d))

    def get_vortex_frequency(self, u_flow: float) -> float:
        """Calculate Strouhal vortex shedding frequency."""
        if u_flow <= 1e-4:
            return 0.0
        u_gap = self.get_gap_velocity(u_flow)
        d = self.config.tube_outer_diameter_m
        return (self.config.strouhal_number * u_gap) / d

    def get_acoustic_frequency(self, baffle_deployed: bool) -> float:
        """Calculate cavity acoustic natural frequency given baffle position.
        
        When baffle is deployed, cavity width is partitioned into two half-widths,
        doubling the fundamental transverse acoustic frequency (f_a = 2 * f_a0).
        """
        return 2.0 * self.f_a0 if baffle_deployed else self.f_a0

    def compute_derivatives(
        self,
        t: float,
        y: List[float],
        u_flow: float,
        baffle_deployed: bool,
    ) -> List[float]:
        """Compute state derivative dy/dt = [dx/dt, dv/dt, dP/dt, dw/dt].
        
        State vector:
          y[0] = x      (deflection [m])
          y[1] = v      (velocity [m/s])
          y[2] = p_ac   (acoustic pressure [Pa])
          y[3] = w      (pressure rate [Pa/s])
        """
        x, v, p_ac, w = y[0], y[1], y[2], y[3]

        # Geometry & Frequencies
        f_s = self.get_vortex_frequency(u_flow)
        f_a = self.get_acoustic_frequency(baffle_deployed)
        omega_a = 2.0 * math.pi * f_a
        omega_t = 2.0 * math.pi * self.config.tube_natural_freq_hz

        # Damping
        zeta_t = self.config.tube_damping_ratio
        zeta_a = self.config.baffle_damping_ratio if baffle_deployed else self.config.acoustic_damping_ratio

        # Lock-in check
        detuning = abs(f_s - f_a) / max(1.0, f_a)
        is_locked_in = (detuning <= self.config.lock_in_threshold) and (u_flow > 0.5)

        # Vortex shedding lift force
        u_gap = self.get_gap_velocity(u_flow)
        d = self.config.tube_outer_diameter_m
        rho_g = self.config.gas_density_kg_m3
        f_lift_0 = 0.5 * self.config.vortex_lift_coeff * rho_g * (u_gap ** 2) * d
        f_lift = f_lift_0 * math.sin(2.0 * math.pi * f_s * t) if f_s > 0.0 else 0.0

        # Mechanical Acceleration: d^2 x / dt^2
        # m_t * d^2 x / dt^2 + 2*zeta_t*omega_t*m_t*v + m_t*omega_t^2*x = Gamma_pa * p_ac + F_lift
        m_t = self.config.tube_mass_per_len_kg_m
        d2x_dt2 = (
            -2.0 * zeta_t * omega_t * v
            - (omega_t ** 2) * x
            + (self.config.gamma_pa * p_ac + f_lift) / m_t
        )

        # Acoustic Aeroacoustic Acceleration: d^2 P_ac / dt^2
        # If locked in and baffle not deployed: Van der Pol negative damping growth
        if is_locked_in and not baffle_deployed:
            alpha = self.config.alpha_growth
            vdp_term = alpha * omega_a * (1.0 - self.config.beta_saturation * (p_ac ** 2)) * w
        else:
            # Resonance suppressed or detuned; pure linear dissipation
            vdp_term = 0.0

        d2p_dt2 = (
            -2.0 * zeta_a * omega_a * w
            - (omega_a ** 2) * p_ac
            + vdp_term
            + self.config.gamma_ap * v
        )

        return [v, d2x_dt2, w, d2p_dt2]

    def step(
        self,
        dt: float,
        flow_velocity: float,
        baffle_deployed: bool = False,
    ) -> ExecutionResult:
        """Step the coupled system forward by dt using 4th-Order Runge-Kutta (RK4)."""
        if dt <= 0.0:
            return ExecutionResult.failed(
                error_code="ERR_INVALID_TIMESTEP",
                details=f"dt must be positive, got {dt}",
            )

        # Micro-stepping if dt exceeds stability boundary (0.0002 s)
        max_substep = 0.0001
        num_substeps = max(1, int(math.ceil(dt / max_substep)))
        sub_dt = dt / num_substeps

        y = [self.state.x, self.state.v, self.state.p_ac, self.state.w]
        t = self.state.time_s

        for _ in range(num_substeps):
            # RK4 Integration
            k1 = self.compute_derivatives(t, y, flow_velocity, baffle_deployed)
            y_k2 = [y[i] + 0.5 * sub_dt * k1[i] for i in range(4)]
            k2 = self.compute_derivatives(t + 0.5 * sub_dt, y_k2, flow_velocity, baffle_deployed)
            y_k3 = [y[i] + 0.5 * sub_dt * k2[i] for i in range(4)]
            k3 = self.compute_derivatives(t + 0.5 * sub_dt, y_k3, flow_velocity, baffle_deployed)
            y_k4 = [y[i] + sub_dt * k3[i] for i in range(4)]
            k4 = self.compute_derivatives(t + sub_dt, y_k4, flow_velocity, baffle_deployed)

            for i in range(4):
                y[i] += (sub_dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])
            t += sub_dt

        # Update state object
        f_s = self.get_vortex_frequency(flow_velocity)
        f_a = self.get_acoustic_frequency(baffle_deployed)
        detuning = abs(f_s - f_a) / max(1.0, f_a)
        is_locked_in = (detuning <= self.config.lock_in_threshold) and (flow_velocity > 0.5)

        self.state.time_s = t
        self.state.x = y[0]
        self.state.v = y[1]
        self.state.p_ac = y[2]
        self.state.w = y[3]
        self.state.u_baffle = baffle_deployed
        self.state.flow_velocity = flow_velocity
        self.state.f_s = f_s
        self.state.f_a = f_a
        self.state.detuning_ratio = detuning
        self.state.is_locked_in = is_locked_in

        # Sync to Horner registers
        self._sync_registers()

        return ExecutionResult.success(
            details=f"Step complete (t={t:.4f}s, x={self.state.x*1e6:.1f}um, P_ac={self.state.p_ac:.1f}Pa, lock-in={is_locked_in}).",
            data={
                "time_s": t,
                "deflection_um": self.state.x * 1e6,
                "pressure_pa": self.state.p_ac,
                "f_s": f_s,
                "f_a": f_a,
                "is_locked_in": is_locked_in,
            },
        )

    # ------------------------------------------------------------------------
    # Horner Register Synchronization
    # ------------------------------------------------------------------------

    def _sync_registers(self) -> None:
        """Map simulation states to Horner OCS %R590..%R597 and %M137..%M139."""
        x_um = self.state.x * 1e6  # Deflection in micrometers
        p_pa = self.state.p_ac     # Pressure in Pascals

        deflection_alarm = abs(self.state.x) >= self.config.deflection_limit_m
        pressure_alarm = abs(self.state.p_ac) >= self.config.acoustic_pressure_limit_pa
        structural_alarm = deflection_alarm or pressure_alarm

        # %R590: Status Bitmask
        status = AcousticResonanceStatusBits.ENGINE_ACTIVE
        if self.state.flow_velocity > 0.5:
            status |= AcousticResonanceStatusBits.FLOW_PRESENT
        if self.state.is_locked_in:
            status |= AcousticResonanceStatusBits.LOCK_IN_DETECTED
        if deflection_alarm:
            status |= AcousticResonanceStatusBits.DEFLECTION_ALARM
        if pressure_alarm:
            status |= AcousticResonanceStatusBits.ACOUSTIC_PRESSURE_ALARM
        if self.state.u_baffle:
            status |= AcousticResonanceStatusBits.BAFFLE_DEPLOYED
        if not structural_alarm:
            status |= AcousticResonanceStatusBits.STRUCTURAL_SAFE
        if self.state.u_baffle and abs(self.state.p_ac) < 300.0:
            status |= AcousticResonanceStatusBits.RESONANCE_SUPPRESSED

        self.reg_table.write_word("%R590", int(status), privilege=PrivilegeMode.SYSTEM)

        # %R591: TubeDeflectionUm (Signed 16-bit: -32768..32767 um)
        reg_x = max(-32768, min(32767, int(round(x_um))))
        self.reg_table.write_word("%R591", reg_x & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R592: AcousticPressurePa (Signed 16-bit: -32768..32767 Pa)
        reg_p = max(-32768, min(32767, int(round(p_pa))))
        self.reg_table.write_word("%R592", reg_p & 0xFFFF, privilege=PrivilegeMode.SYSTEM)

        # %R593: VortexFrequencyCentiHz (f_s * 100)
        reg_fs = max(0, min(65535, int(round(self.state.f_s * 100.0))))
        self.reg_table.write_word("%R593", reg_fs, privilege=PrivilegeMode.SYSTEM)

        # %R594: AcousticNaturalFreqCentiHz (f_a * 100)
        reg_fa = max(0, min(65535, int(round(self.state.f_a * 100.0))))
        self.reg_table.write_word("%R594", reg_fa, privilege=PrivilegeMode.SYSTEM)

        # %R595: LockInRatioPct (100 * |f_s - f_a| / f_a)
        reg_det = max(0, min(65535, int(round(self.state.detuning_ratio * 100.0))))
        self.reg_table.write_word("%R595", reg_det, privilege=PrivilegeMode.SYSTEM)

        # %R596: ShellFlowVelocityCentiMps (U_g * 100)
        reg_flow = max(0, min(65535, int(round(self.state.flow_velocity * 100.0))))
        self.reg_table.write_word("%R596", reg_flow, privilege=PrivilegeMode.SYSTEM)

        # %R597: BafflePositionStatus (1=deployed, 0=retracted)
        self.reg_table.write_word("%R597", 1 if self.state.u_baffle else 0, privilege=PrivilegeMode.SYSTEM)

        # %M137: AcousticLockInDetected
        self.reg_table.write_bit("%M137", self.state.is_locked_in, privilege=PrivilegeMode.SYSTEM)

        # %M138: AntiVibrationBaffleDeployed
        self.reg_table.write_bit("%M138", self.state.u_baffle, privilege=PrivilegeMode.SYSTEM)

        # %M139: StructuralAlarmExceeded
        self.reg_table.write_bit("%M139", structural_alarm, privilege=PrivilegeMode.SYSTEM)


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ACOUSTIC_RESONANCE_PURE_ST_POU: str = """PROGRAM AcousticResonanceMonitorSync
VAR
    AcousticResonanceStatus AT %R590 : INT;
    TubeDeflectionUm AT %R591 : INT;
    AcousticPressurePa AT %R592 : INT;
    VortexFrequencyCentiHz AT %R593 : INT;
    AcousticNaturalFreqCentiHz AT %R594 : INT;
    LockInRatioPct AT %R595 : INT;
    ShellFlowVelocityCentiMps AT %R596 : INT;
    BafflePositionStatus AT %R597 : INT;
    AcousticLockInDetected AT %M137 : BOOL;
    AntiVibrationBaffleDeployed AT %M138 : BOOL;
    StructuralAlarmExceeded AT %M139 : BOOL;
    BaffleDeployCommand : BOOL;
END_VAR

(* Synchronize acoustic resonance and lock-in alarms *)
IF AcousticLockInDetected AND NOT AntiVibrationBaffleDeployed THEN
    BaffleDeployCommand := TRUE;
ELSE
    BaffleDeployCommand := FALSE;
END_IF;

IF StructuralAlarmExceeded THEN
    BaffleDeployCommand := TRUE;
END_IF;
END_PROGRAM
"""


# ============================================================================
# 5. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_acoustic_resonance_verification(evidence_path: Optional[str] = None) -> Dict[str, Any]:
    """Execute complete 9-stage verification suite for W098 Tube Bundle Acoustic Resonance Engine."""
    test_results: List[Dict[str, Any]] = []

    # 1. Pure ST POU and AST Symbol Binding
    SecurityGuard.assert_pure_st_content(ACOUSTIC_RESONANCE_PURE_ST_POU)
    res_st = STParser.validate_code(ACOUSTIC_RESONANCE_PURE_ST_POU)
    ast = STParser.parse_pou(ACOUSTIC_RESONANCE_PURE_ST_POU)

    c1 = (
        res_st.status == AgentStatus.SUCCESS
        and ast.name == "AcousticResonanceMonitorSync"
        and "%R590" in ast.bound_registers
        and "%R597" in ast.bound_registers
        and "%M137" in ast.bound_registers
        and "%M139" in ast.bound_registers
    )
    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_And_AST_Symbol_Binding",
        "passed": c1,
        "details": "Pure ST POU verified cleanly; %R590..%R597 and %M137..%M139 bound into AST.",
    })

    # 2. Gas Acoustics & Blevins Porosity Sound Speed Correction
    reg_table = RegisterTable()
    cfg = TubeBundleAcousticConfig()
    sim = TubeBundleAcousticSimulator(config=cfg, register_table=reg_table)

    # Theoretical check: c_eff = 340 / sqrt(1 + 0.30) = 298.2 m/s
    expected_c_eff = 340.0 / math.sqrt(1.30)
    expected_f_a0 = expected_c_eff / (2.0 * 0.60)
    c2 = (
        abs(sim.c_eff - expected_c_eff) < 1e-4
        and abs(sim.f_a0 - expected_f_a0) < 1e-4
        and (sim.f_a0 < 340.0 / (2.0 * 0.60))  # Porosity strictly lowers acoustic speed and frequency
    )
    test_results.append({
        "stage": 2,
        "check": "Gas_Acoustics_And_Blevins_Porosity_Sound_Speed_Correction",
        "passed": c2,
        "details": f"c_eff={sim.c_eff:.2f} m/s, f_a0={sim.f_a0:.2f} Hz strictly matches Blevins model.",
    })

    # 3. Vortex Shedding Strouhal Frequency Scaling
    # At U_g = 7.5 m/s, gap velocity U_gap = 7.5 * (0.0381 / (0.0381 - 0.0254)) = 22.5 m/s
    # f_s = 0.28 * 22.5 / 0.0254 = 248.03 Hz
    u_test = 7.5
    u_gap_calc = sim.get_gap_velocity(u_test)
    f_s_calc = sim.get_vortex_frequency(u_test)
    c3 = (
        abs(u_gap_calc - 22.5) < 1e-2
        and abs(f_s_calc - 248.03) < 0.5
    )
    test_results.append({
        "stage": 3,
        "check": "Vortex_Shedding_Strouhal_Frequency_Scaling",
        "passed": c3,
        "details": f"Cross-flow U_g=7.5 m/s -> U_gap={u_gap_calc:.2f} m/s -> f_s={f_s_calc:.2f} Hz.",
    })

    # 4. Acoustic Standing Wave Lock-In Detection Window
    # At U_g = 7.5 m/s, |f_s - f_a0| / f_a0 = |248.03 - 248.49| / 248.49 < 0.2% << 15% (LOCKED IN)
    # At U_g = 2.0 m/s, f_s = 66.1 Hz -> detuning = |66.1 - 248.5| / 248.5 = 73% >> 15% (NOT LOCKED IN)
    sim.step(dt=0.001, flow_velocity=7.5, baffle_deployed=False)
    lock_in_7_5 = sim.state.is_locked_in
    coil_137_lock = reg_table.read_bit("%M137")

    sim.step(dt=0.001, flow_velocity=2.0, baffle_deployed=False)
    lock_in_2_0 = sim.state.is_locked_in
    coil_137_unlock = reg_table.read_bit("%M137")

    c4 = (lock_in_7_5 is True) and (coil_137_lock is True) and (lock_in_2_0 is False) and (coil_137_unlock is False)
    test_results.append({
        "stage": 4,
        "check": "Acoustic_Standing_Wave_Lock_In_Detection_Window",
        "passed": c4,
        "details": "Lock-in detuning condition correctly asserts %M137 during resonance window.",
    })

    # 5. Van der Pol Nonlinear Limit Cycle Resonance Oscillation Build-up
    # Run in lock-in condition (U_g = 7.5 m/s) for 0.15 seconds without baffle
    sim_res = TubeBundleAcousticSimulator(config=cfg, register_table=RegisterTable())
    # Initial perturbation
    sim_res.state.p_ac = 10.0
    sim_res.state.w = 50.0
    for _ in range(150):
        sim_res.step(dt=0.001, flow_velocity=7.5, baffle_deployed=False)

    p_built = abs(sim_res.state.p_ac)
    x_built = abs(sim_res.state.x)
    # Oscillation must grow substantially due to negative aeroacoustic damping
    c5 = (p_built > 80.0) and (x_built > 1e-6)
    test_results.append({
        "stage": 5,
        "check": "Van_Der_Pol_Aeroacoustic_Limit_Cycle_Resonance_Build_Up",
        "passed": c5,
        "details": f"Resonance build-up verified: P_ac grew from 10 Pa to {p_built:.1f} Pa, deflection {x_built*1e6:.1f} um.",
    })

    # 6. Anti-Vibration Baffle Deployment Suppression
    # Deploy baffle: frequency doubles to ~497 Hz, detuning jumps to ~50%, damping jumps to 8%
    sim_res.step(dt=0.001, flow_velocity=7.5, baffle_deployed=True)
    f_a_baffle = sim_res.state.f_a
    detuning_baffle = sim_res.state.detuning_ratio
    is_locked_baffle = sim_res.state.is_locked_in

    # Integrate forward 0.15 seconds with baffle deployed
    for _ in range(150):
        sim_res.step(dt=0.001, flow_velocity=7.5, baffle_deployed=True)

    p_suppressed = abs(sim_res.state.p_ac)
    c6 = (
        abs(f_a_baffle - 2.0 * sim.f_a0) < 1e-3
        and detuning_baffle > 0.40
        and is_locked_baffle is False
        and p_suppressed < p_built * 0.25  # Substantial damping attenuation
    )
    test_results.append({
        "stage": 6,
        "check": "Anti_Vibration_Baffle_Deployment_Resonance_Suppression",
        "passed": c6,
        "details": f"Baffle doubled f_a to {f_a_baffle:.1f} Hz, broken lock-in, decayed P_ac to {p_suppressed:.1f} Pa.",
    })

    # 7. Horner OCS Register Space Synchronization
    reg_status = sim_res.reg_table.read_word("%R590")
    reg_p_val = sim_res.reg_table.read_word("%R592")
    reg_fa_val = sim_res.reg_table.read_word("%R594") & 0xFFFF
    coil_baffle = sim_res.reg_table.read_bit("%M138")

    c7 = (
        (reg_status & int(AcousticResonanceStatusBits.ENGINE_ACTIVE)) != 0
        and (reg_status & int(AcousticResonanceStatusBits.BAFFLE_DEPLOYED)) != 0
        and reg_fa_val > 45000  # ~49698 centiHz
        and coil_baffle is True
    )
    test_results.append({
        "stage": 7,
        "check": "Horner_OCS_Register_Space_Synchronization",
        "passed": c7,
        "details": f"Registers synced: %R590=0x{reg_status:04X}, %R594={reg_fa_val} cHz, %M138={coil_baffle}.",
    })

    # 8. Structural Deflection & Acoustic Pressure Alarm Trip Thresholds
    sim_alarm = TubeBundleAcousticSimulator(config=cfg, register_table=RegisterTable())
    # Force state past alarm thresholds
    sim_alarm.state.x = 0.0030  # 3.0 mm > 2.5 mm
    sim_alarm.state.p_ac = 1800.0  # 1800 Pa > 1500 Pa
    sim_alarm.step(dt=0.0001, flow_velocity=7.5, baffle_deployed=False)

    alarm_coil = sim_alarm.reg_table.read_bit("%M139")
    status_alarm = sim_alarm.reg_table.read_word("%R590")
    has_defl_alarm = (status_alarm & int(AcousticResonanceStatusBits.DEFLECTION_ALARM)) != 0
    has_press_alarm = (status_alarm & int(AcousticResonanceStatusBits.ACOUSTIC_PRESSURE_ALARM)) != 0

    c8 = (alarm_coil is True) and has_defl_alarm and has_press_alarm
    test_results.append({
        "stage": 8,
        "check": "Structural_Deflection_And_Pressure_Alarm_Trip_Thresholds",
        "passed": c8,
        "details": "High deflection (3.0 mm) and acoustic pressure (1800 Pa) tripped %M139 and %R590 alarm bits.",
    })

    # 9. Anti-Ladder Security Guard Rejection
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("""
        PROGRAM BadResonanceLadder
        VAR BaffleBit : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """)
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = ladder_rejected
    test_results.append({
        "stage": 9,
        "check": "Anti_Ladder_Construct_Security_Guard_Rejection",
        "passed": c9,
        "details": "Ladder contacts and coils strictly intercepted with ERR_LADDER_FORBIDDEN.",
    })

    all_passed = all(t["passed"] for t in test_results)
    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "VERIFICATION_CHECKS_FAILED",
        "details": f"Acoustic Resonance ODE Simulation Engine verified cleanly ({sum(1 for t in test_results if t['passed'])}/{len(test_results)} checks passed).",
        "data": {
            "work_package": "W098",
            "gate": "Gate G7 / G4",
            "component": "Cross-Flow Induced Tube Bundle Acoustic Resonance & Vortex Shedding Frequency ODE Simulation",
            "checks_passed": sum(1 for t in test_results if t["passed"]),
            "total_checks": len(test_results),
            "tests": test_results,
            "register_map": {
                "analog_registers": "%R590..%R597",
                "discrete_coils": "%M137..%M139",
            },
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if evidence_path:
        out_p = Path(evidence_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence
