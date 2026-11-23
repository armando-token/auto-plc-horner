"""Deterministic IEC 61131-3 Standard Function Blocks for Horner APG OCS Controllers.

Work Package: W020 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Provides standard timers (TON, TOF, TP) and counters (CTU, CTD, CTUD) with
integer microsecond zero-drift timekeeping, rising-edge detection, reset/load
semantics, optional Horner OCS register reflection (%R, %I, %Q, %M), and
ILogicUnit adapter integration with SimulationEngine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from jev_cscape.simulation.engine import ILogicUnit, ScanContext


class BaseFunctionBlock(ABC):
    """Abstract base class for deterministic IEC 61131-3 Function Blocks."""

    def __init__(self, name: str) -> None:
        self.name: str = name

    @abstractmethod
    def reset(self) -> None:
        """Reset internal function block state to initial conditions."""
        pass


class TON(BaseFunctionBlock):
    """IEC 61131-3 Timer On-Delay (TON).

    When IN transitions to TRUE, the timer accumulates elapsed time ET by dt_ms
    on each scan cycle until ET >= PT. When ET >= PT, output Q becomes TRUE.
    When IN transitions to FALSE, ET immediately resets to 0 and Q becomes FALSE.

    Uses integer microsecond arithmetic to guarantee zero IEEE 754 drift.
    """

    def __init__(
        self,
        name: str = "TON",
        pt_ms: float = 1000.0,
        in_reg: Optional[str] = None,
        pt_reg: Optional[str] = None,
        q_reg: Optional[str] = None,
        et_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pt_ms: float = float(pt_ms)
        self._pt_us: int = int(round(self.pt_ms * 1000.0))
        self._et_us: int = 0
        self._in_prev: bool = False
        self.q: bool = False

        # Optional Horner register bindings
        self.in_reg: Optional[str] = in_reg
        self.pt_reg: Optional[str] = pt_reg
        self.q_reg: Optional[str] = q_reg
        self.et_reg: Optional[str] = et_reg

    @property
    def et_ms(self) -> float:
        """Elapsed time in milliseconds."""
        return self._et_us / 1000.0

    @property
    def et_int_ms(self) -> int:
        """Elapsed time in integer milliseconds (Horner %R format)."""
        return int(round(self._et_us / 1000.0))

    def reset(self) -> None:
        """Reset timer state."""
        self._et_us = 0
        self.q = False
        self._in_prev = False

    def execute(
        self,
        in_val: bool,
        pt_ms: Optional[float] = None,
        dt_ms: float = 10.0,
    ) -> Tuple[bool, float]:
        """Execute one scan step of TON timer. Returns (Q, ET_ms)."""
        if pt_ms is not None:
            self.pt_ms = float(pt_ms)
            self._pt_us = int(round(self.pt_ms * 1000.0))

        dt_us = int(round(float(dt_ms) * 1000.0))

        if not in_val:
            self._et_us = 0
            self.q = False
        else:
            if self._et_us < self._pt_us:
                self._et_us += dt_us
                if self._et_us >= self._pt_us:
                    self._et_us = self._pt_us
                    self.q = True
            else:
                self.q = True

        self._in_prev = in_val
        return self.q, self.et_ms


class TOF(BaseFunctionBlock):
    """IEC 61131-3 Timer Off-Delay (TOF).

    When IN is TRUE, output Q is TRUE and ET is 0.
    When IN transitions to FALSE, the timer begins accumulating elapsed time ET.
    Output Q remains TRUE until ET >= PT, at which point Q becomes FALSE.
    If IN transitions back to TRUE at any time, ET resets to 0 and Q remains TRUE.
    """

    def __init__(
        self,
        name: str = "TOF",
        pt_ms: float = 1000.0,
        in_reg: Optional[str] = None,
        pt_reg: Optional[str] = None,
        q_reg: Optional[str] = None,
        et_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pt_ms: float = float(pt_ms)
        self._pt_us: int = int(round(self.pt_ms * 1000.0))
        self._et_us: int = 0
        self._in_prev: bool = False
        self.q: bool = False

        self.in_reg: Optional[str] = in_reg
        self.pt_reg: Optional[str] = pt_reg
        self.q_reg: Optional[str] = q_reg
        self.et_reg: Optional[str] = et_reg

    @property
    def et_ms(self) -> float:
        return self._et_us / 1000.0

    @property
    def et_int_ms(self) -> int:
        return int(round(self._et_us / 1000.0))

    def reset(self) -> None:
        self._et_us = 0
        self.q = False
        self._in_prev = False

    def execute(
        self,
        in_val: bool,
        pt_ms: Optional[float] = None,
        dt_ms: float = 10.0,
    ) -> Tuple[bool, float]:
        """Execute one scan step of TOF timer. Returns (Q, ET_ms)."""
        if pt_ms is not None:
            self.pt_ms = float(pt_ms)
            self._pt_us = int(round(self.pt_ms * 1000.0))

        dt_us = int(round(float(dt_ms) * 1000.0))

        if in_val:
            self.q = True
            self._et_us = 0
        else:
            if self.q:
                if self._et_us < self._pt_us:
                    self._et_us += dt_us
                    if self._et_us >= self._pt_us:
                        self._et_us = self._pt_us
                        self.q = False
                else:
                    self.q = False
            else:
                self._et_us = self._pt_us

        self._in_prev = in_val
        return self.q, self.et_ms


class TP(BaseFunctionBlock):
    """IEC 61131-3 Pulse Timer (TP).

    On the rising edge of IN (when not currently timing), output Q becomes TRUE
    and ET begins accumulating. Q remains TRUE for exactly PT duration regardless
    of whether IN remains TRUE or returns to FALSE.
    When ET >= PT, Q becomes FALSE. ET resets to 0 once IN returns to FALSE.
    """

    def __init__(
        self,
        name: str = "TP",
        pt_ms: float = 1000.0,
        in_reg: Optional[str] = None,
        pt_reg: Optional[str] = None,
        q_reg: Optional[str] = None,
        et_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pt_ms: float = float(pt_ms)
        self._pt_us: int = int(round(self.pt_ms * 1000.0))
        self._et_us: int = 0
        self._in_prev: bool = False
        self._is_timing: bool = False
        self.q: bool = False

        self.in_reg: Optional[str] = in_reg
        self.pt_reg: Optional[str] = pt_reg
        self.q_reg: Optional[str] = q_reg
        self.et_reg: Optional[str] = et_reg

    @property
    def et_ms(self) -> float:
        return self._et_us / 1000.0

    @property
    def et_int_ms(self) -> int:
        return int(round(self._et_us / 1000.0))

    def reset(self) -> None:
        self._et_us = 0
        self.q = False
        self._is_timing = False
        self._in_prev = False

    def execute(
        self,
        in_val: bool,
        pt_ms: Optional[float] = None,
        dt_ms: float = 10.0,
    ) -> Tuple[bool, float]:
        """Execute one scan step of TP pulse timer. Returns (Q, ET_ms)."""
        if pt_ms is not None:
            self.pt_ms = float(pt_ms)
            self._pt_us = int(round(self.pt_ms * 1000.0))

        dt_us = int(round(float(dt_ms) * 1000.0))

        # Detect rising edge of IN when idle
        if in_val and not self._in_prev and not self._is_timing:
            self._is_timing = True
            self.q = True
            self._et_us = 0

        if self._is_timing:
            if self._et_us < self._pt_us:
                self._et_us += dt_us
                if self._et_us >= self._pt_us:
                    self.q = False
                    if not in_val:
                        self._is_timing = False
                        self._et_us = 0
                    else:
                        self._et_us = self._pt_us
            else:
                self.q = False
                if not in_val:
                    self._is_timing = False
                    self._et_us = 0
        else:
            if not in_val:
                self._et_us = 0

        self._in_prev = in_val
        return self.q, self.et_ms


class CTU(BaseFunctionBlock):
    """IEC 61131-3 Up Counter (CTU).

    Detects rising edge (FALSE -> TRUE transition) on CU and increments CV by 1.
    Output Q becomes TRUE when CV >= PV.
    When RESET is TRUE, CV is immediately forced to 0 and Q becomes FALSE.
    """

    def __init__(
        self,
        name: str = "CTU",
        pv: int = 10,
        cu_reg: Optional[str] = None,
        reset_reg: Optional[str] = None,
        pv_reg: Optional[str] = None,
        q_reg: Optional[str] = None,
        cv_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pv: int = int(pv)
        self.cv: int = 0
        self.q: bool = False
        self._cu_prev: bool = False

        self.cu_reg: Optional[str] = cu_reg
        self.reset_reg: Optional[str] = reset_reg
        self.pv_reg: Optional[str] = pv_reg
        self.q_reg: Optional[str] = q_reg
        self.cv_reg: Optional[str] = cv_reg

    def reset(self) -> None:
        self.cv = 0
        self.q = False
        self._cu_prev = False

    def execute(
        self,
        cu_val: bool,
        reset_val: bool = False,
        pv: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """Execute one scan step of CTU counter. Returns (Q, CV)."""
        if pv is not None:
            self.pv = int(pv)

        if reset_val:
            self.cv = 0
            self.q = False
        else:
            # Positive edge on CU
            if cu_val and not self._cu_prev:
                if self.cv < 32767:
                    self.cv += 1
            self.q = (self.cv >= self.pv)

        self._cu_prev = cu_val
        return self.q, self.cv


class CTD(BaseFunctionBlock):
    """IEC 61131-3 Down Counter (CTD).

    Detects rising edge on CD and decrements CV by 1 down to 0.
    Output Q becomes TRUE when CV <= 0.
    When LOAD is TRUE, CV is set to PV.
    """

    def __init__(
        self,
        name: str = "CTD",
        pv: int = 10,
        cd_reg: Optional[str] = None,
        load_reg: Optional[str] = None,
        pv_reg: Optional[str] = None,
        q_reg: Optional[str] = None,
        cv_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pv: int = int(pv)
        self.cv: int = int(pv)
        self.q: bool = False
        self._cd_prev: bool = False

        self.cd_reg: Optional[str] = cd_reg
        self.load_reg: Optional[str] = load_reg
        self.pv_reg: Optional[str] = pv_reg
        self.q_reg: Optional[str] = q_reg
        self.cv_reg: Optional[str] = cv_reg

    def reset(self) -> None:
        self.cv = self.pv
        self.q = False
        self._cd_prev = False

    def execute(
        self,
        cd_val: bool,
        load_val: bool = False,
        pv: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """Execute one scan step of CTD counter. Returns (Q, CV)."""
        if pv is not None:
            self.pv = int(pv)

        if load_val:
            self.cv = self.pv
            self.q = (self.cv <= 0)
        else:
            if cd_val and not self._cd_prev:
                if self.cv > 0:
                    self.cv -= 1
            self.q = (self.cv <= 0)

        self._cd_prev = cd_val
        return self.q, self.cv


class CTUD(BaseFunctionBlock):
    """IEC 61131-3 Up/Down Bidirectional Counter (CTUD).

    Counts up on rising edge of CU, counts down on rising edge of CD.
    Output QU is TRUE when CV >= PV; output QD is TRUE when CV <= 0.
    RESET forces CV = 0. LOAD forces CV = PV.
    """

    def __init__(
        self,
        name: str = "CTUD",
        pv: int = 10,
        cu_reg: Optional[str] = None,
        cd_reg: Optional[str] = None,
        reset_reg: Optional[str] = None,
        load_reg: Optional[str] = None,
        pv_reg: Optional[str] = None,
        qu_reg: Optional[str] = None,
        qd_reg: Optional[str] = None,
        cv_reg: Optional[str] = None,
    ) -> None:
        super().__init__(name)
        self.pv: int = int(pv)
        self.cv: int = 0
        self.qu: bool = False
        self.qd: bool = True  # CV = 0 initially
        self._cu_prev: bool = False
        self._cd_prev: bool = False

        self.cu_reg: Optional[str] = cu_reg
        self.cd_reg: Optional[str] = cd_reg
        self.reset_reg: Optional[str] = reset_reg
        self.load_reg: Optional[str] = load_reg
        self.pv_reg: Optional[str] = pv_reg
        self.qu_reg: Optional[str] = qu_reg
        self.qd_reg: Optional[str] = qd_reg
        self.cv_reg: Optional[str] = cv_reg

    def reset(self) -> None:
        self.cv = 0
        self.qu = False
        self.qd = True
        self._cu_prev = False
        self._cd_prev = False

    def execute(
        self,
        cu_val: bool,
        cd_val: bool,
        reset_val: bool = False,
        load_val: bool = False,
        pv: Optional[int] = None,
    ) -> Tuple[bool, bool, int]:
        """Execute one scan step of CTUD counter. Returns (QU, QD, CV)."""
        if pv is not None:
            self.pv = int(pv)

        if reset_val:
            self.cv = 0
        elif load_val:
            self.cv = self.pv
        else:
            # Positive edge on CU
            if cu_val and not self._cu_prev:
                if self.cv < 32767:
                    self.cv += 1

            # Positive edge on CD
            if cd_val and not self._cd_prev:
                if self.cv > 0:
                    self.cv -= 1

        self.qu = (self.cv >= self.pv)
        self.qd = (self.cv <= 0)

        self._cu_prev = cu_val
        self._cd_prev = cd_val
        return self.qu, self.qd, self.cv


class FunctionBlockLogicUnit(ILogicUnit):
    """Adapter wrapping any IEC 61131-3 Function Block into an executable ILogicUnit."""

    def __init__(
        self,
        block: BaseFunctionBlock,
        priority: int = 100,
    ) -> None:
        self._block = block
        self._priority = priority
        self._enabled = True

    @property
    def name(self) -> str:
        return self._block.name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def block(self) -> BaseFunctionBlock:
        return self._block

    def execute(self, ctx: ScanContext) -> None:
        """Read bound input registers, execute function block step, and update bound outputs."""
        dt = ctx.dt_ms

        if isinstance(self._block, TON):
            in_val = ctx.get_register(self._block.in_reg) if self._block.in_reg else False
            pt_val = ctx.get_register(self._block.pt_reg) if self._block.pt_reg else self._block.pt_ms
            q, et = self._block.execute(bool(in_val), pt_ms=float(pt_val) if pt_val else None, dt_ms=dt)
            if self._block.q_reg:
                ctx.set_register(self._block.q_reg, q)
            if self._block.et_reg:
                ctx.set_register(self._block.et_reg, int(round(et)))

        elif isinstance(self._block, TOF):
            in_val = ctx.get_register(self._block.in_reg) if self._block.in_reg else False
            pt_val = ctx.get_register(self._block.pt_reg) if self._block.pt_reg else self._block.pt_ms
            q, et = self._block.execute(bool(in_val), pt_ms=float(pt_val) if pt_val else None, dt_ms=dt)
            if self._block.q_reg:
                ctx.set_register(self._block.q_reg, q)
            if self._block.et_reg:
                ctx.set_register(self._block.et_reg, int(round(et)))

        elif isinstance(self._block, TP):
            in_val = ctx.get_register(self._block.in_reg) if self._block.in_reg else False
            pt_val = ctx.get_register(self._block.pt_reg) if self._block.pt_reg else self._block.pt_ms
            q, et = self._block.execute(bool(in_val), pt_ms=float(pt_val) if pt_val else None, dt_ms=dt)
            if self._block.q_reg:
                ctx.set_register(self._block.q_reg, q)
            if self._block.et_reg:
                ctx.set_register(self._block.et_reg, int(round(et)))

        elif isinstance(self._block, CTU):
            cu_val = ctx.get_register(self._block.cu_reg) if self._block.cu_reg else False
            rst_val = ctx.get_register(self._block.reset_reg) if self._block.reset_reg else False
            pv_val = ctx.get_register(self._block.pv_reg) if self._block.pv_reg else self._block.pv
            q, cv = self._block.execute(bool(cu_val), reset_val=bool(rst_val), pv=int(pv_val) if pv_val else None)
            if self._block.q_reg:
                ctx.set_register(self._block.q_reg, q)
            if self._block.cv_reg:
                ctx.set_register(self._block.cv_reg, cv)

        elif isinstance(self._block, CTD):
            cd_val = ctx.get_register(self._block.cd_reg) if self._block.cd_reg else False
            load_val = ctx.get_register(self._block.load_reg) if self._block.load_reg else False
            pv_val = ctx.get_register(self._block.pv_reg) if self._block.pv_reg else self._block.pv
            q, cv = self._block.execute(bool(cd_val), load_val=bool(load_val), pv=int(pv_val) if pv_val else None)
            if self._block.q_reg:
                ctx.set_register(self._block.q_reg, q)
            if self._block.cv_reg:
                ctx.set_register(self._block.cv_reg, cv)

        elif isinstance(self._block, CTUD):
            cu_val = ctx.get_register(self._block.cu_reg) if self._block.cu_reg else False
            cd_val = ctx.get_register(self._block.cd_reg) if self._block.cd_reg else False
            rst_val = ctx.get_register(self._block.reset_reg) if self._block.reset_reg else False
            load_val = ctx.get_register(self._block.load_reg) if self._block.load_reg else False
            pv_val = ctx.get_register(self._block.pv_reg) if self._block.pv_reg else self._block.pv
            qu, qd, cv = self._block.execute(
                cu_val=bool(cu_val),
                cd_val=bool(cd_val),
                reset_val=bool(rst_val),
                load_val=bool(load_val),
                pv=int(pv_val) if pv_val else None,
            )
            if self._block.qu_reg:
                ctx.set_register(self._block.qu_reg, qu)
            if self._block.qd_reg:
                ctx.set_register(self._block.qd_reg, qd)
            if self._block.cv_reg:
                ctx.set_register(self._block.cv_reg, cv)

    def reset(self) -> None:
        self._block.reset()
