"""Simulation trace container, sliding-window telemetry, and Gate G4 evidence export.

Work Package: W018 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]
"""

from __future__ import annotations

import datetime
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from jev_cscape.simulation.models import (
    CycleSnapshot,
    MemoryDiff,
    MemoryMutation,
    TraceConfig,
)


class SimulationTrace:
    """Manages cycle telemetry, sliding buffer history, and Gate G4 evidence exports."""

    def __init__(self, config: Optional[TraceConfig] = None):
        self.config = config or TraceConfig()
        self._snapshots: List[CycleSnapshot] = []
        self._baseline_snapshot: Optional[CycleSnapshot] = None
        self._total_cycles_recorded: int = 0
        self._dropped_snapshots_count: int = 0

    @property
    def total_cycles_recorded(self) -> int:
        return self._total_cycles_recorded

    @property
    def snapshots(self) -> List[CycleSnapshot]:
        return list(self._snapshots)

    def __len__(self) -> int:
        return len(self._snapshots)

    def __getitem__(self, index: int) -> CycleSnapshot:
        return self._snapshots[index]

    def append(self, snapshot: CycleSnapshot) -> None:
        """Append a snapshot, computing diffs and enforcing buffer size constraints."""
        # Baseline preservation
        if self._total_cycles_recorded == 0:
            self._baseline_snapshot = snapshot

        # Automatic diff computation against previous snapshot
        if self.config.enable_diffing and len(self._snapshots) > 0:
            prev = self._snapshots[-1]
            snapshot.diff = self.compute_diff(prev, snapshot)

        self._snapshots.append(snapshot)
        self._total_cycles_recorded += 1

        # Enforce buffer limit (FIFO sliding window)
        if self.config.buffer_size and self.config.buffer_size > 0:
            while len(self._snapshots) > self.config.buffer_size:
                self._snapshots.pop(0)
                self._dropped_snapshots_count += 1

    @staticmethod
    def _values_differ(v1: Any, v2: Any) -> bool:
        """Epsilon-aware value comparison to avoid floating-point jitter."""
        if isinstance(v1, (float, int)) and isinstance(v2, (float, int)):
            return not math.isclose(float(v1), float(v2), rel_tol=1e-7, abs_tol=1e-9)
        return v1 != v2

    @classmethod
    def compute_diff(cls, snap_a: CycleSnapshot, snap_b: CycleSnapshot) -> MemoryDiff:
        """Compute delta changes between two snapshots."""
        mut_vars: Dict[str, MemoryMutation] = {}
        mut_regs: Dict[str, MemoryMutation] = {}
        mut_sys: Dict[str, MemoryMutation] = {}

        # Variable diff
        all_var_keys = set(snap_a.variables.keys()) | set(snap_b.variables.keys())
        for k in all_var_keys:
            v_a = snap_a.variables.get(k)
            v_b = snap_b.variables.get(k)
            if cls._values_differ(v_a, v_b):
                mut_vars[k] = MemoryMutation(old_value=v_a, new_value=v_b)

        # Register diff (internal + outputs + inputs)
        regs_a = {**snap_a.internal_registers, **snap_a.committed_outputs, **snap_a.latched_inputs}
        regs_b = {**snap_b.internal_registers, **snap_b.committed_outputs, **snap_b.latched_inputs}
        all_reg_keys = set(regs_a.keys()) | set(regs_b.keys())
        for k in all_reg_keys:
            r_a = regs_a.get(k)
            r_b = regs_b.get(k)
            if cls._values_differ(r_a, r_b):
                mut_regs[k] = MemoryMutation(old_value=r_a, new_value=r_b)

        # System bits diff
        all_sys_keys = set(snap_a.system_bits.keys()) | set(snap_b.system_bits.keys())
        for k in all_sys_keys:
            s_a = snap_a.system_bits.get(k)
            s_b = snap_b.system_bits.get(k)
            if s_a != s_b:
                mut_sys[k] = MemoryMutation(old_value=s_a, new_value=s_b)

        total_count = len(mut_vars) + len(mut_regs) + len(mut_sys)
        return MemoryDiff(
            variables=mut_vars,
            registers=mut_regs,
            system_bits=mut_sys,
            mutations_count=total_count,
        )

    def diff_cycles(self, cycle_a: int, cycle_b: int) -> MemoryDiff:
        """Compute memory diff between arbitrary historical cycle numbers."""
        snap_a = self.get_cycle(cycle_a)
        snap_b = self.get_cycle(cycle_b)
        if not snap_a or not snap_b:
            raise KeyError(f"Cycles {cycle_a} or {cycle_b} not available in trace buffer.")
        return self.compute_diff(snap_a, snap_b)

    def get_cycle(self, cycle_num: int) -> Optional[CycleSnapshot]:
        """Lookup snapshot by absolute cycle index."""
        if self._baseline_snapshot and self._baseline_snapshot.cycle == cycle_num:
            return self._baseline_snapshot
        for s in self._snapshots:
            if s.cycle == cycle_num:
                return s
        return None

    def latest(self) -> Optional[CycleSnapshot]:
        return self._snapshots[-1] if self._snapshots else None

    def first(self) -> Optional[CycleSnapshot]:
        return self._baseline_snapshot or (self._snapshots[0] if self._snapshots else None)

    def variable_history(self, var_name: str) -> List[Tuple[int, float, Any]]:
        """Return time-series [(cycle, time_ms, value)] for a variable."""
        history = []
        n_up = var_name.upper()
        for s in self._snapshots:
            val = None
            for k, v in s.variables.items():
                if k.upper() == n_up:
                    val = v
                    break
            if val is not None:
                history.append((s.cycle, s.time_ms, val))
        return history

    def register_history(self, reg_addr: str) -> List[Tuple[int, float, Any]]:
        """Return time-series [(cycle, time_ms, value)] for an OCS register."""
        history = []
        for s in self._snapshots:
            val = s.get_register(reg_addr)
            if val is not None:
                history.append((s.cycle, s.time_ms, val))
        return history

    def find_transitions(self, name_or_addr: str) -> List[Dict[str, Any]]:
        """Identify every cycle where a variable or register value transitioned."""
        transitions = []
        clean = name_or_addr.strip().upper()
        for s in self._snapshots:
            if s.has_changed(clean):
                diff = s.diff
                mut = None
                if diff:
                    if clean.startswith("%"):
                        mut = diff.registers.get(clean) or diff.system_bits.get(clean)
                    else:
                        for k, v in diff.variables.items():
                            if k.upper() == clean:
                                mut = v
                                break
                transitions.append({
                    "cycle": s.cycle,
                    "time_ms": s.time_ms,
                    "old_value": mut.old_value if mut else None,
                    "new_value": mut.new_value if mut else None,
                })
        return transitions

    def telemetry_trace(self) -> List[Dict[str, Any]]:
        """Return deterministic cycle-by-cycle simulated telemetry trace."""
        return [
            {
                "cycle": s.cycle,
                "time_ms": s.time_ms,
                "dt_ms": s.dt_ms,
                "phase": s.phase.value if hasattr(s.phase, "value") else str(s.phase),
                "state": s.state.value if hasattr(s.state, "value") else str(s.state),
                "latched_inputs": dict(s.latched_inputs),
                "committed_outputs": dict(s.committed_outputs),
                "internal_registers": dict(s.internal_registers),
                "registers": dict(s.registers),
                "system_bits": dict(s.system_bits),
                "system_registers": dict(s.system_registers),
                "variables": dict(s.variables),
                "modified_outputs": list(s.modified_outputs),
            }
            for s in self._snapshots
        ]

    def summary_telemetry(self) -> Dict[str, Any]:
        """Aggregate execution and timing telemetry across recorded trace."""
        if not self._snapshots:
            return {"total_cycles": 0, "status": "empty"}

        durations = [s.wall_duration_us for s in self._snapshots]
        total_time_ms = self._snapshots[-1].time_ms - self._snapshots[0].time_ms + self._snapshots[-1].dt_ms
        return {
            "total_cycles_recorded": self._total_cycles_recorded,
            "retained_snapshots": len(self._snapshots),
            "dropped_snapshots": self._dropped_snapshots_count,
            "total_simulated_time_ms": round(total_time_ms, 2),
            "avg_cycle_duration_us": round(sum(durations) / len(durations), 2) if durations else 0.0,
            "max_cycle_duration_us": max(durations) if durations else 0.0,
            "min_cycle_duration_us": min(durations) if durations else 0.0,
            "buffer_configured_limit": self.config.buffer_size,
        }

    def to_dict(self, compact: bool = False) -> Dict[str, Any]:
        """Export trace to structured dictionary."""
        return {
            "telemetry": self.summary_telemetry(),
            "snapshots": [
                s.model_dump(exclude={"diff"} if compact else None)
                for s in self._snapshots
            ],
        }

    def to_json(self, filepath: Optional[Union[str, Path]] = None, indent: int = 2) -> str:
        """Serialize trace to JSON with optional file export."""
        payload = self.to_dict()
        data_str = json.dumps(payload, indent=indent)
        if filepath:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data_str, encoding="utf-8")
        return data_str

    def export_g4_evidence(
        self,
        filepath: Optional[Union[str, Path]] = None,
        invariants: Optional[Dict[str, Any]] = None,
        work_package: str = "W018",
    ) -> Dict[str, Any]:
        """Export formal Gate G4 verification evidence conforming to JEV engineering contract."""
        last = self.latest()
        evidence = {
            "gate": "G4",
            "work_package": work_package,
            "status": "success",
            "mode": "offline/mock",
            "classification": "TESTED_MOCK [offline/DEV only]",
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "simulation_backend": "EMULATED",
            "hardware_lockout": "FAIL_CLOSED_ACTIVE",
            "straton_quarantine": "CERTIFIED_ISOLATED",
            "trace_summary": self.summary_telemetry(),
            "invariants": invariants or {},
            "final_registers": {
                **(last.internal_registers if last else {}),
                **(last.committed_outputs if last else {}),
                **(last.latched_inputs if last else {}),
            },
            "final_system_bits": last.system_bits if last else {},
            "final_variables": last.variables if last else {},
        }
        if filepath:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        return evidence
