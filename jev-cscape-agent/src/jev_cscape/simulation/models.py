"""Data models and enums for Horner OCS simulation engine, trace, and telemetry.

Work Package: W018 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]
"""

from __future__ import annotations

import datetime
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ScanPhase(str, Enum):
    """Discrete phases of the PLC scan cycle."""
    IDLE = "IDLE"
    LATCH_INPUTS = "LATCH_INPUTS"
    SOLVE_LOGIC = "SOLVE_LOGIC"
    COMMIT_OUTPUTS = "COMMIT_OUTPUTS"
    HOUSEKEEPING = "HOUSEKEEPING"


class EngineState(str, Enum):
    """Lifecycle state of the simulation engine."""
    STOPPED = "STOPPED"
    READY = "READY"
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    FAULTED = "FAULTED"


# SimulationState alias for backward/forward compatibility
SimulationState = EngineState


class SimulationFaultError(Exception):
    """Raised when an unhandled simulation logic fault occurs."""
    pass


class PacingMode(str, Enum):
    """Pacing mode for simulation execution."""
    FAST = "FAST"          # Zero sleep, deterministic in-memory compute
    REALTIME = "REALTIME"  # Paced against wall clock


class SimulationBackend(str, Enum):
    """Underlying simulation backend classification."""
    EMULATED = "EMULATED"  # Pure-Python software emulation


class FaultPolicy(str, Enum):
    """Policy for handling faults during logic execution."""
    HALT = "HALT"                      # Freeze execution and latch fault state
    FAIL_SAFE_STOP = "FAIL_SAFE_STOP"  # De-energize outputs (%Q=0, %AQ=0) and halt
    CONTINUE = "CONTINUE"              # Record fault in system registers and continue


class FaultCode(str, Enum):
    """Fault taxonomy codes for simulation engine containment."""
    FAULT_DIV_ZERO = "SIM_FAULT_DIV_ZERO"
    FAULT_REG_OUT_OF_BOUNDS = "SIM_FAULT_REG_OUT_OF_BOUNDS"
    FAULT_REG_READ_ONLY = "SIM_FAULT_REG_READ_ONLY"
    FAULT_LADDER_FORBIDDEN = "ERR_LADDER_FORBIDDEN"
    FAULT_LOOP_TIMEOUT = "SIM_FAULT_LOOP_TIMEOUT"
    FAULT_LOGIC_EXCEPTION = "SIM_FAULT_LOGIC_EXCEPTION"
    FAULT_TYPE_MISMATCH = "SIM_FAULT_TYPE_MISMATCH"


class SimulationFault(BaseModel):
    """Structured record of a simulation fault."""
    cycle: int
    elapsed_ms: float
    unit_name: str
    fault_code: str
    details: str


class MemoryMutation(BaseModel):
    """Represents a mutated register or variable value."""
    old_value: Any
    new_value: Any


class MemoryDiff(BaseModel):
    """Delta differences between two snapshots."""
    variables: Dict[str, MemoryMutation] = Field(default_factory=dict)
    registers: Dict[str, MemoryMutation] = Field(default_factory=dict)
    system_bits: Dict[str, MemoryMutation] = Field(default_factory=dict)
    mutations_count: int = 0

    @property
    def has_mutations(self) -> bool:
        return self.mutations_count > 0


class CycleSnapshot(BaseModel):
    """Frozen cycle snapshot combining memory states, metrics, and telemetry."""
    cycle: int = Field(..., description="Monotonically increasing 1-based cycle index")
    time_ms: float = Field(..., description="Accumulated virtual simulation time in milliseconds")
    dt_ms: float = Field(default=10.0, description="Cycle scan duration in milliseconds")
    phase: ScanPhase = Field(default=ScanPhase.IDLE)
    state: SimulationState = Field(default=SimulationState.IDLE)
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    wall_duration_us: float = Field(
        default=0.0, description="Host execution wall-clock time in microseconds"
    )

    # State stores
    latched_inputs: Dict[str, Any] = Field(default_factory=dict)
    committed_outputs: Dict[str, Any] = Field(default_factory=dict)
    internal_registers: Dict[str, Any] = Field(default_factory=dict)
    registers: Dict[str, Any] = Field(default_factory=dict)
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    system_bits: Dict[str, bool] = Field(default_factory=dict)
    system_registers: Dict[str, int] = Field(default_factory=dict)
    variables: Dict[str, Any] = Field(default_factory=dict)
    modified_outputs: List[str] = Field(default_factory=list)

    # Telemetry delta and fault
    diff: Optional[MemoryDiff] = None
    fault: Optional[Union[SimulationFault, str]] = None

    @property
    def elapsed_ms(self) -> float:
        """Alias for time_ms."""
        return self.time_ms

    @property
    def elapsed_time_ms(self) -> float:
        """Alias for time_ms."""
        return self.time_ms

    def get_var(self, name: str, default: Any = None) -> Any:
        """Case-insensitive variable lookup."""
        n_up = name.upper()
        for k, v in self.variables.items():
            if k.upper() == n_up:
                return v
        return default

    def get_register(self, addr: str, default: Any = None) -> Any:
        """Normalized Horner OCS register lookup (e.g. %r100 -> %R100)."""
        clean = addr.strip().upper()
        if not clean.startswith("%"):
            clean = "%" + clean

        if clean in self.system_bits:
            return self.system_bits[clean]
        if clean in self.system_registers:
            return self.system_registers[clean]
        if clean in self.registers:
            return self.registers[clean]
        if clean in self.committed_outputs:
            return self.committed_outputs[clean]
        if clean in self.latched_inputs:
            return self.latched_inputs[clean]
        if clean in self.internal_registers:
            return self.internal_registers[clean]
        return default

    def has_changed(self, name_or_addr: str) -> bool:
        """Query if a variable or register mutated in this cycle's diff."""
        if not self.diff:
            return False
        clean = name_or_addr.strip().upper()
        if clean.startswith("%"):
            return clean in self.diff.registers or clean in self.diff.system_bits
        for k in self.diff.variables:
            if k.upper() == clean:
                return True
        return False


class TraceConfig(BaseModel):
    """Configuration for simulation telemetry and snapshot recording."""
    buffer_size: Optional[int] = Field(
        default=None,
        description="Maximum snapshots to retain. None or <=0 indicates unbounded."
    )
    enable_diffing: bool = Field(default=True, description="Compute cycle-to-cycle memory diffs")
    record_registers: bool = Field(default=True, description="Include OCS register table in snapshots")
    record_variables: bool = Field(default=True, description="Include symbolic variables in snapshots")
    preserve_baseline: bool = Field(
        default=True, description="Always preserve baseline snapshot when buffer trims"
    )
