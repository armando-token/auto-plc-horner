"""In-Memory Deterministic Scan Cycle Simulation Engine for Horner OCS Controllers.

Work Package: W018 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Provides a 100% pure-software, zero-drift, discrete scan cycle execution engine
modeling Horner APG OCS controllers with double-buffering, input image latching,
output staging, transactional rollback on fault, system register/bit emulation,
and cycle-by-cycle telemetry capture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import datetime
import inspect
import math
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from pydantic import BaseModel

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.automation.channel_matrix import ChannelAccess, ChannelMatrix
from jev_cscape.simulation.models import (
    CycleSnapshot,
    EngineState,
    FaultCode,
    FaultPolicy,
    MemoryDiff,
    PacingMode,
    ScanPhase,
    SimulationBackend,
    SimulationFault,
    SimulationFaultError,
    SimulationState,
    TraceConfig,
)
from jev_cscape.simulation.trace import SimulationTrace
from jev_cscape.simulation.register_table import RegisterTable, WordOrder


class VirtualClock:
    """Deterministic virtual simulation clock for Horner OCS scan cycles.

    Uses exact microsecond integer arithmetic (_elapsed_us) to completely eliminate
    IEEE 754 floating-point drift over millions of scan cycles.
    """

    def __init__(self, default_dt_ms: float = 10.0) -> None:
        if default_dt_ms <= 0:
            raise ValueError(f"default_dt_ms must be positive, got {default_dt_ms}")
        self.default_dt_ms: float = float(default_dt_ms)
        self._elapsed_us: int = 0
        self._cycle_count: int = 0
        self._last_dt_ms: float = float(default_dt_ms)

    @property
    def cycle_count(self) -> int:
        """Total completed scan cycles."""
        return self._cycle_count

    @property
    def elapsed_us(self) -> int:
        """Total accumulated virtual simulation time in microseconds."""
        return self._elapsed_us

    @property
    def elapsed_ms(self) -> float:
        """Total accumulated virtual simulation time in milliseconds."""
        return self._elapsed_us / 1000.0

    @property
    def elapsed_seconds(self) -> float:
        """Total accumulated virtual simulation time in seconds."""
        return self._elapsed_us / 1_000_000.0

    @property
    def last_dt_ms(self) -> float:
        """The delta_t used during the last scan cycle in milliseconds."""
        return self._last_dt_ms

    def advance(self, dt_ms: Optional[float] = None) -> Tuple[int, float, float]:
        """Advance virtual clock by one discrete cycle.

        Returns (cycle_count, elapsed_ms, dt_ms).
        """
        step_dt = float(dt_ms) if dt_ms is not None else self.default_dt_ms
        if step_dt <= 0:
            raise ValueError(f"Scan step delta_t must be positive, got {step_dt}")

        dt_us = int(round(step_dt * 1000.0))
        self._cycle_count += 1
        self._elapsed_us += dt_us
        self._last_dt_ms = step_dt
        return self._cycle_count, self.elapsed_ms, step_dt

    def reset(self) -> None:
        """Reset virtual clock to zero cycles and zero elapsed time."""
        self._elapsed_us = 0
        self._cycle_count = 0
        self._last_dt_ms = self.default_dt_ms

    def format_iec_time(self) -> str:
        """Format total elapsed virtual time as an IEC 61131-3 TIME literal (e.g. T#10s)."""
        total_ms = int(round(self.elapsed_ms))
        if total_ms == 0:
            return "T#0ms"
        parts = []
        days, rem = divmod(total_ms, 86_400_000)
        hours, rem = divmod(rem, 3_600_000)
        minutes, rem = divmod(rem, 60_000)
        seconds, rem_ms = divmod(rem, 1000)
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds:
            parts.append(f"{seconds}s")
        if rem_ms:
            parts.append(f"{rem_ms}ms")
        elif not parts:
            parts.append("0ms")
        return f"T#{''.join(parts)}"


class CycleList(list):
    """List of CycleSnapshot objects with ExecutionResult metadata."""

    def __init__(
        self,
        items: Optional[List[CycleSnapshot]] = None,
        status: AgentStatus = AgentStatus.SUCCESS,
        data: Optional[Dict[str, Any]] = None,
        details: str = "",
    ) -> None:
        super().__init__(items or [])
        self.status = status
        self.data = data or {}
        self.details = details


@dataclass
class ScanContext:
    """Execution context passed to logic units during Phase 2 (Logic Solve)."""
    cycle: int = 0
    dt_ms: float = 10.0
    elapsed_time_ms: float = 0.0
    get_register: Callable[[str], Any] = field(default_factory=lambda: (lambda addr: 0))
    set_register: Callable[[str, Any], None] = field(default_factory=lambda: (lambda addr, val: None))
    get_variable: Callable[[str, Any], Any] = field(default_factory=lambda: (lambda name, default=None: default))
    set_variable: Callable[[str, Any], None] = field(default_factory=lambda: (lambda name, val: None))
    record_fault: Callable[[SimulationFault], None] = field(default_factory=lambda: (lambda fault: None))
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_index: Optional[int] = None
    dt: Optional[float] = None
    timestamp: Optional[float] = None
    cycle_number: Optional[int] = None
    dt_s: Optional[float] = None
    register_table: Optional[Any] = None
    reg_table: Optional[Any] = None
    scan_time_ms: Optional[float] = None

    def __post_init__(self) -> None:
        if self.reg_table is not None and self.register_table is None:
            self.register_table = self.reg_table
        if self.scan_time_ms is not None:
            self.dt_ms = self.scan_time_ms

        if self.cycle_number is not None:
            self.cycle = self.cycle_number
            self.scan_index = self.cycle_number
        elif self.scan_index is not None:
            self.cycle = self.scan_index
            self.cycle_number = self.scan_index
        else:
            self.scan_index = self.cycle
            self.cycle_number = self.cycle
        if self.dt_s is not None:
            self.dt = self.dt_s
            self.dt_ms = self.dt_s * 1000.0
        elif self.dt is not None:
            self.dt_ms = self.dt * 1000.0 if self.dt < 1.0 else self.dt
            self.dt_s = self.dt
        else:
            self.dt = self.dt_ms / 1000.0
            self.dt_s = self.dt
        if self.timestamp is not None:
            self.elapsed_time_ms = self.timestamp * 1000.0 if self.timestamp < 100.0 else self.timestamp
        else:
            self.timestamp = self.elapsed_time_ms / 1000.0
        if self.register_table is not None:
            rt = self.register_table
            if hasattr(rt, "read_word"):
                self.get_register = lambda addr: rt.read_word(addr)
            elif hasattr(rt, "get"):
                self.get_register = lambda addr: rt.get(addr, 0)
            if hasattr(rt, "write_word"):
                self.set_register = lambda addr, val: rt.write_word(addr, val)
            elif hasattr(rt, "set"):
                self.set_register = lambda addr, val: rt.set(addr, val)


class ILogicUnit(ABC):
    """Abstract interface for any executable logic block running during Phase 2."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this logic unit."""
        pass

    @property
    @abstractmethod
    def priority(self) -> int:
        """Execution priority (lower integer executes earlier)."""
        pass

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Whether the logic unit participates in the scan."""
        pass

    @abstractmethod
    def execute(self, ctx: ScanContext) -> None:
        """Execute logic evaluation for this cycle."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset internal unit state to initial conditions."""
        pass


class CallbackLogicUnit(ILogicUnit):
    """Logic unit adapter executing a user-provided Python callable."""

    def __init__(self, name: str, fn: Callable[[ScanContext], None], priority: int = 100) -> None:
        self._name = name
        self._fn = fn
        self._priority = priority
        self._enabled = True

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def execute(self, ctx: ScanContext) -> None:
        self._fn(ctx)

    def reset(self) -> None:
        pass


class SimulationEngine:
    """Pure-software in-memory cyclic scan engine conforming to Horner OCS architecture.

    Features:
    - Discrete 4-stage pipeline: Input latching -> System updates -> Logic solve -> Output commit.
    - Double-buffering & memory latching: prevents mid-scan sensor drift and intermediate output glitches.
    - Transactional rollback: uncommitted outputs discarded if unhandled logic exception occurs.
    - Horner OCS register banks: %I, %Q, %M, %D, %K, %AI, %AQ, %R, %SR, %S.
    - Deterministic virtual clock with integer microsecond precision.
    - High-throughput execution: 1,000 cycles run in < 5ms.
    """

    CLASSIFICATION: str = "TESTED_MOCK [offline/DEV only]"
    MODE: str = "offline/mock"

    def __init__(
        self,
        default_dt_ms: float = 10.0,
        delta_t_ms: Optional[float] = None,
        backend: SimulationBackend = SimulationBackend.EMULATED,
        pacing_mode: PacingMode = PacingMode.FAST,
        record_trace: bool = True,
        max_trace_size: int = 10_000,
        trace_config: Optional[TraceConfig] = None,
        fault_policy: FaultPolicy = FaultPolicy.HALT,
        deterministic: bool = False,
    ) -> None:
        dt = delta_t_ms if delta_t_ms is not None else default_dt_ms
        self.default_dt_ms: float = float(dt)
        self.backend: SimulationBackend = backend
        self.pacing_mode: PacingMode = pacing_mode
        self.record_trace: bool = record_trace
        self.max_trace_size: int = max_trace_size
        self.fault_policy: FaultPolicy = fault_policy
        self.deterministic: bool = deterministic

        self.virtual_clock = VirtualClock(default_dt_ms=self.default_dt_ms)
        self.cycle_count: int = 0
        self.elapsed_time_ms: float = 0.0
        self.state: SimulationState = SimulationState.IDLE
        self.phase: ScanPhase = ScanPhase.IDLE
        self.last_fault: Optional[Exception] = None

        # Register state space (W019)
        self.registers: RegisterTable = RegisterTable(default_dt_ms=self.default_dt_ms)
        self._variables: Dict[str, Any] = {}

        # Logic callbacks and units
        self._callbacks: List[Callable[..., None]] = []
        self._logic_units: List[ILogicUnit] = []

        # Execution trace
        if trace_config is not None:
            self.trace = SimulationTrace(config=trace_config)
        else:
            self.trace = SimulationTrace(
                config=TraceConfig(buffer_size=max_trace_size if record_trace else 0)
            )

    # --- Backward-Compatibility Facades for Register State ---

    @property
    def _pending_inputs(self) -> Dict[str, Any]:
        return self.registers.pending_inputs

    @_pending_inputs.setter
    def _pending_inputs(self, val: Dict[str, Any]) -> None:
        self.registers.pending_inputs = val

    @property
    def _latched_inputs(self) -> Dict[str, Any]:
        return self.registers.latched_inputs

    @_latched_inputs.setter
    def _latched_inputs(self, val: Dict[str, Any]) -> None:
        self.registers.latched_inputs = val

    @property
    def _staged_writes(self) -> Dict[str, Any]:
        return self.registers.staged_writes

    @_staged_writes.setter
    def _staged_writes(self, val: Dict[str, Any]) -> None:
        self.registers.staged_writes = val

    @property
    def _committed_memory(self) -> Dict[str, Any]:
        return self.registers.committed_memory

    @_committed_memory.setter
    def _committed_memory(self, val: Dict[str, Any]) -> None:
        self.registers.committed_memory = val

    @property
    def _system_bits(self) -> Dict[str, bool]:
        return self.registers.system_bits

    @_system_bits.setter
    def _system_bits(self, val: Dict[str, bool]) -> None:
        self.registers.system_bits = val

    @property
    def _system_registers(self) -> Dict[str, int]:
        return self.registers.system_registers

    @_system_registers.setter
    def _system_registers(self, val: Dict[str, int]) -> None:
        self.registers.system_registers = val

    def _initialize_system_registers(self) -> None:
        """Initialize default Horner system registers and bits prior to scan 0."""
        self.registers.initialize_system_registers()

    # --- Attachment & Registration API ---

    def register_logic_callback(self, cb: Callable[..., None]) -> None:
        """Register a user logic callback executed during Phase 2 of each scan cycle."""
        self._callbacks.append(cb)

    def add_logic_callback(self, cb: Callable[..., None]) -> None:
        """Alias for register_logic_callback."""
        self.register_logic_callback(cb)

    def attach_logic_unit(self, unit: ILogicUnit) -> None:
        """Register an ILogicUnit and keep logic units sorted by execution priority."""
        self._logic_units.append(unit)
        self._logic_units.sort(key=lambda u: u.priority)

    def set_delta_t(self, delta_t_ms: float) -> None:
        """Reconfigure default scan delta_t in milliseconds."""
        if delta_t_ms <= 0:
            raise ValueError(f"delta_t_ms must be positive, got {delta_t_ms}")
        self.default_dt_ms = float(delta_t_ms)
        self.virtual_clock.default_dt_ms = float(delta_t_ms)
        self.registers.set_delta_t(delta_t_ms)

    # --- Memory & Register Access API ---

    def set_input(self, address: str, value: Any) -> None:
        """External environment sets a pending input (latched at start of next scan)."""
        self.registers.set_input(address, value)

    def write_register(self, address: str, value: Any) -> None:
        """Write to memory. During Phase 2, writes to outputs/markers are staged."""
        self.registers.write_register(address, value)

    def set_register(self, address: str, value: Any) -> None:
        """Alias for write_register."""
        self.registers.set_register(address, value)

    def read_register(self, address: str) -> Any:
        """Read register value conforming to double-buffering & memory latching semantics."""
        return self.registers.read_register(address)

    def get_register(self, address: str) -> Any:
        """Alias for read_register."""
        return self.registers.read_register(address)

    def read_bit(self, address: str) -> bool:
        """Read a discrete Boolean address (%I, %Q, %M, %S, or %R.bit)."""
        return self.registers.read_bit(address)

    def write_bit(self, address: str, value: bool) -> None:
        """Write a discrete Boolean address (%I, %Q, %M, or %R.bit). Rejects system bits."""
        self.registers.write_bit(address, value)

    def read_word(self, address: str) -> int:
        """Read a 16-bit word register (%R, %AI, %AQ, %SR)."""
        return self.registers.read_word(address)

    def write_word(self, address: str, value: int) -> None:
        """Write a 16-bit word register (%R, %AI, %AQ). Protects %SR."""
        self.registers.write_word(address, value)

    def read_dint(self, base_address: str, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> int:
        """Read a 32-bit signed DINT across two consecutive 16-bit registers."""
        return self.registers.read_dint(base_address, word_order=word_order)

    def write_dint(self, base_address: str, value: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> None:
        """Write a 32-bit signed DINT across two consecutive 16-bit registers."""
        self.registers.write_dint(base_address, value, word_order=word_order)

    def read_udint(self, base_address: str, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> int:
        """Read a 32-bit unsigned UDINT across two consecutive 16-bit registers."""
        return self.registers.read_udint(base_address, word_order=word_order)

    def write_udint(self, base_address: str, value: int, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> None:
        """Write a 32-bit unsigned UDINT across two consecutive 16-bit registers."""
        self.registers.write_udint(base_address, value, word_order=word_order)

    def read_real(self, base_address: str, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> float:
        """Read a 32-bit IEEE 754 single-precision REAL across two consecutive registers."""
        return self.registers.read_real(base_address, word_order=word_order)

    def write_real(self, base_address: str, value: float, word_order: WordOrder = WordOrder.LOW_WORD_FIRST) -> None:
        """Write a 32-bit IEEE 754 single-precision REAL across two consecutive registers."""
        self.registers.write_real(base_address, value, word_order=word_order)

    def read_system_bit(self, index: int) -> bool:
        """Read a Horner system bit by 1-based integer index (e.g. 1 -> %S1, 7 -> %S7)."""
        return self.registers.read_system_bit(index)

    def get_committed_output(self, address: str) -> Any:
        """Read strictly from committed output memory table (external observer view)."""
        return self.registers.get_committed_output(address)

    def set_variable(self, name: str, value: Any) -> None:
        """Set a symbolic variable state."""
        self._variables[name] = value

    def get_variable(self, name: str, default: Any = None) -> Any:
        """Get a symbolic variable state with case-insensitive lookup."""
        n_up = name.upper()
        for k, v in self._variables.items():
            if k.upper() == n_up:
                return v
        return default

    def get_register_table(self) -> Dict[str, Any]:
        """Return an immutable snapshot dictionary of all register banks."""
        return self.registers.snapshot()

    def get_telemetry_trace(self) -> List[Dict[str, Any]]:
        """Return deterministic cycle-by-cycle simulated telemetry trace for all recorded cycles."""
        return self.trace.telemetry_trace()

    # --- Scan Execution Pipeline ---

    def _update_system_bits_and_registers(
        self,
        current_cycle: int,
        dt_ms: float,
        elapsed_time_ms: float,
        elapsed_us: int,
    ) -> None:
        """Stage 2: Advance Horner system bits and diagnostic registers."""
        self.registers.update_system(
            current_cycle=current_cycle,
            dt_ms=dt_ms,
            elapsed_time_ms=elapsed_time_ms,
            elapsed_us=elapsed_us,
        )

    def step(self, dt_ms: Optional[float] = None) -> CycleSnapshot:
        """Execute exactly one complete discrete PLC scan cycle.

        Phases:
        1. LATCH_INPUTS: Snapshot pending external inputs into frozen latched table.
        2. SOLVE_LOGIC: Update system bits/registers, execute callbacks/units with staging overlay.
        3. COMMIT_OUTPUTS: Atomically commit staged writes to committed memory.
        4. HOUSEKEEPING: Record snapshot, advance cycle counter and metrics.
        """
        if self.state == SimulationState.FAULTED:
            raise SimulationFaultError(
                "Cannot step while in FAULTED state. Call clear_fault() or reset()."
            )

        step_dt = float(dt_ms) if dt_ms is not None else self.default_dt_ms
        current_cycle = self.cycle_count
        wall_start = time.perf_counter()

        # -------------------------------------------------------------
        # Phase 1: LATCH_INPUTS
        # -------------------------------------------------------------
        self.phase = ScanPhase.LATCH_INPUTS
        self.registers.latch_inputs()

        # Advance virtual clock and timing
        _, elapsed_ms, _ = self.virtual_clock.advance(step_dt)
        self.elapsed_time_ms = elapsed_ms

        # -------------------------------------------------------------
        # Phase 2: SOLVE_LOGIC
        # -------------------------------------------------------------
        self.phase = ScanPhase.SOLVE_LOGIC
        self._update_system_bits_and_registers(
            current_cycle=current_cycle,
            dt_ms=step_dt,
            elapsed_time_ms=self.elapsed_time_ms,
            elapsed_us=self.virtual_clock.elapsed_us,
        )

        ctx = ScanContext(
            cycle=current_cycle,
            dt_ms=step_dt,
            elapsed_time_ms=self.elapsed_time_ms,
            get_register=self.read_register,
            set_register=self.write_register,
            get_variable=self.get_variable,
            set_variable=self.set_variable,
            record_fault=lambda f: None,
        )

        # Execute logic units and callbacks within protected staging overlay
        try:
            for unit in self._logic_units:
                if unit.is_enabled:
                    unit.execute(ctx)

            for cb in self._callbacks:
                sig = inspect.signature(cb)
                if len(sig.parameters) == 1:
                    cb(self)
                elif len(sig.parameters) >= 2:
                    cb(self, step_dt)
                else:
                    cb()
        except Exception as exc:
            # Transactional Rollback: Discard uncommitted staged writes
            self.cycle_count += 1
            self.state = SimulationState.FAULTED
            self.phase = ScanPhase.IDLE
            self.last_fault = exc
            self.registers.rollback_staged()
            raise SimulationFaultError(f"Simulation logic fault: {exc}") from exc

        # -------------------------------------------------------------
        # Phase 3: COMMIT_OUTPUTS
        # -------------------------------------------------------------
        self.phase = ScanPhase.COMMIT_OUTPUTS
        modified = self.registers.commit_staged()

        # -------------------------------------------------------------
        # Phase 4: HOUSEKEEPING
        # -------------------------------------------------------------
        self.phase = ScanPhase.HOUSEKEEPING
        if self.deterministic:
            wall_duration_us = 0.0
            base_time = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            snap_time = base_time + datetime.timedelta(microseconds=self.virtual_clock.elapsed_us)
            snapshot_timestamp = snap_time.isoformat()
        else:
            wall_duration_us = (time.perf_counter() - wall_start) * 1_000_000.0
            snapshot_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Realtime pacing if requested
        if self.pacing_mode == PacingMode.REALTIME:
            target_sleep_s = (step_dt / 1000.0) - (wall_duration_us / 1_000_000.0)
            if target_sleep_s > 0:
                time.sleep(target_sleep_s)

        self.cycle_count += 1
        self.state = SimulationState.RUNNING

        # Build Cycle Snapshot
        (
            latched_in,
            committed_out,
            internal_regs,
            committed_all,
            sys_bits,
            sys_regs,
        ) = self.registers.export_snapshot_components()

        snapshot = CycleSnapshot(
            cycle=current_cycle,
            time_ms=self.elapsed_time_ms,
            dt_ms=step_dt,
            phase=ScanPhase.IDLE,
            state=self.state,
            timestamp_utc=snapshot_timestamp,
            wall_duration_us=wall_duration_us,
            latched_inputs=latched_in,
            committed_outputs=committed_out,
            internal_registers=internal_regs,
            registers=committed_all,
            inputs=latched_in,
            outputs=committed_out,
            system_bits=sys_bits,
            system_registers=sys_regs,
            variables=dict(self._variables),
            modified_outputs=modified,
        )

        if self.record_trace:
            self.trace.append(snapshot)

        self.phase = ScanPhase.IDLE
        return snapshot

    def run_cycles(self, count: int, dt_ms: Optional[float] = None) -> CycleList:
        """Run multiple scan cycles deterministically without wall-clock sleep."""
        if count < 0:
            raise ValueError("Count must be non-negative")
        if count == 0:
            return CycleList([], status=AgentStatus.SUCCESS, data={"cycles_executed": 0})

        wall_start = time.perf_counter()
        snapshots: List[CycleSnapshot] = []

        for _ in range(count):
            snap = self.step(dt_ms)
            snapshots.append(snap)

        wall_duration_s = time.perf_counter() - wall_start
        data = {
            "cycles_executed": count,
            "total_cycles": self.virtual_clock.cycle_count,
            "virtual_elapsed_ms": self.virtual_clock.elapsed_ms,
            "wall_duration_ms": wall_duration_s * 1000.0,
            "sr1_scan_counter": self._system_registers.get("%SR1", 0),
            "sr5_scan_duration": self._system_registers.get(
                "%SR5", int(round(self.default_dt_ms))
            ),
            "pacing_mode": self.pacing_mode.value,
            "mode": "offline/mock",
        }
        details = (
            f"Executed {count} cycles cleanly. "
            f"Virtual elapsed: {self.virtual_clock.elapsed_ms:.1f}ms."
        )
        return CycleList(snapshots, status=AgentStatus.SUCCESS, data=data, details=details)

    def run(self, cycles: int, dt_ms: Optional[float] = None) -> ExecutionResult:
        """Run multiple cycles and return formal ExecutionResult envelope."""
        if cycles <= 0:
            return ExecutionResult.failed(
                error_code="INVALID_CYCLES",
                details=f"Cycle count must be positive integer, got {cycles}.",
            )

        cycle_list = self.run_cycles(cycles, dt_ms)
        return ExecutionResult.success(
            details=cycle_list.details,
            data=cycle_list.data,
        )

    def run_until(
        self,
        condition: Callable[["SimulationEngine"], bool],
        max_cycles: int = 10_000,
        dt_ms: Optional[float] = None,
    ) -> ExecutionResult:
        """Execute cycles until condition returns True or max_cycles is reached."""
        for _ in range(max_cycles):
            self.step(dt_ms)
            if condition(self):
                return ExecutionResult.success(
                    details=f"Condition met after {self.cycle_count} cycles.",
                    data={
                        "cycles": self.cycle_count,
                        "elapsed_ms": self.elapsed_time_ms,
                        "mode": "offline/mock",
                    },
                )

        return ExecutionResult.partial(
            details=f"Condition not met within max limit of {max_cycles} cycles.",
            data={
                "cycles": self.cycle_count,
                "elapsed_ms": self.elapsed_time_ms,
                "mode": "offline/mock",
            },
        )

    def clear_fault(self) -> None:
        """Clear active fault and restore engine state to IDLE."""
        self.last_fault = None
        self.state = SimulationState.IDLE
        self.registers.clear_fault()

    def reset(self) -> None:
        """Reset virtual clock, register banks, trace history, and fault states."""
        self.virtual_clock.reset()
        self.cycle_count = 0
        self.elapsed_time_ms = 0.0
        self.state = SimulationState.IDLE
        self.phase = ScanPhase.IDLE
        self.last_fault = None

        self.registers.reset()
        self._variables.clear()

        self.trace = SimulationTrace(config=self.trace.config)

        for unit in self._logic_units:
            unit.reset()

    def export_g4_evidence(
        self,
        filepath: Optional[Union[str, Any]] = None,
        invariants: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Export formal Gate G4 verification evidence conforming to JEV contract."""
        return self.trace.export_g4_evidence(
            filepath=filepath,
            invariants=invariants,
            work_package="W018",
        )
