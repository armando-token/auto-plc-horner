"""HMI Multi-Screen Navigation Graph and Screen Supervisor.

Implements topological screen graph modeling, reachability verification,
breadcrumb stack tracking, transition execution, and role-based security barriers
for Horner Cscape OCS HMI screens.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pydantic import BaseModel, Field

from jev_cscape.security.exceptions import SecurityError


class SecurityLevel(str, Enum):
    """Hierarchical role-based access security levels for HMI screens and actions."""
    VIEWER = "VIEWER"         # Read-only observation
    OPERATOR = "OPERATOR"     # Standard plant operations, setpoint nudges, screen nav
    SUPERVISOR = "SUPERVISOR" # Recipe management, threshold tuning, batch changes
    ENGINEER = "ENGINEER"     # System diagnostics, PID calibration, hardware settings
    ADMIN = "ADMIN"           # Root administrative privileges, firmware & comm configuration


# Numeric ranking for security level enforcement
SECURITY_RANKS: Dict[str, int] = {
    SecurityLevel.VIEWER.value: 0,
    SecurityLevel.OPERATOR.value: 1,
    SecurityLevel.SUPERVISOR.value: 2,
    SecurityLevel.ENGINEER.value: 3,
    SecurityLevel.ADMIN.value: 4,
}


def check_permission(
    user_perm: Union[SecurityLevel, str],
    required_perm: Union[SecurityLevel, str],
) -> bool:
    """Check if the user's security level satisfies the required permission level."""
    u_str = user_perm.value if isinstance(user_perm, SecurityLevel) else str(user_perm).upper()
    r_str = required_perm.value if isinstance(required_perm, SecurityLevel) else str(required_perm).upper()
    user_rank = SECURITY_RANKS.get(u_str, 0)
    req_rank = SECURITY_RANKS.get(r_str, 0)
    return user_rank >= req_rank


class TransitionType(str, Enum):
    """Classification of HMI screen transitions."""
    DIRECT = "DIRECT"               # Direct navigation button
    DRILLDOWN = "DRILLDOWN"         # Sub-process or equipment detail drilldown
    RETURN = "RETURN"               # Back/Return navigation to parent or previous screen
    ALARM_JUMP = "ALARM_JUMP"       # Header alarm banner or alarm trigger redirect
    RECIPE_SELECT = "RECIPE_SELECT" # Recipe configuration navigation
    DIAGNOSTIC = "DIAGNOSTIC"       # Controller diagnostics jump
    BREADCRUMB_BACK = "BREADCRUMB_BACK" # Breadcrumb trail navigation


class HMINavigationError(Exception):
    """Base exception for HMI navigation failures."""
    pass


class ScreenNotFoundError(HMINavigationError):
    """Raised when an unknown screen ID is referenced."""
    pass


class InvalidTransitionError(HMINavigationError):
    """Raised when an invalid or undefined transition is requested."""
    pass


class SecurityAccessDeniedError(HMINavigationError, SecurityError):
    """Raised when a transition violates role-based security permissions."""
    pass


class ReachabilityError(HMINavigationError):
    """Raised when graph topology contains unreachable or dead-end screens."""
    pass


class NavigationHistoryError(HMINavigationError):
    """Raised when an illegal history/breadcrumb operation is attempted."""
    pass


class ScreenTransition(BaseModel):
    """Represents a directed transition between two HMI screens."""
    source_screen_id: int
    target_screen_id: int
    transition_type: Union[TransitionType, str] = TransitionType.DIRECT
    required_permission: Union[SecurityLevel, str] = SecurityLevel.OPERATOR
    trigger_register: Optional[str] = None
    description: Optional[str] = None

    def __init__(
        self,
        source_screen_id: int = 1,
        target_screen_id: int = 1,
        transition_type: Union[TransitionType, str] = TransitionType.DIRECT,
        required_permission: Union[SecurityLevel, str] = SecurityLevel.OPERATOR,
        trigger_register: Optional[str] = None,
        description: Optional[str] = None,
        **data: Any,
    ) -> None:
        if "source_screen_id" not in data:
            data["source_screen_id"] = source_screen_id
        if "target_screen_id" not in data:
            data["target_screen_id"] = target_screen_id
        if "transition_type" not in data:
            data["transition_type"] = transition_type
        if "required_permission" not in data:
            data["required_permission"] = required_permission
        if "trigger_register" not in data:
            data["trigger_register"] = trigger_register
        if "description" not in data:
            data["description"] = description
        super().__init__(**data)


class HMIScreen(BaseModel):
    """Definition of an individual HMI screen in the plant supervisory system."""
    screen_id: int
    name: str
    subtitle: Optional[str] = None
    description: Optional[str] = None
    required_permission: Union[SecurityLevel, str] = SecurityLevel.OPERATOR
    active_register: Optional[str] = None
    category: Optional[str] = "GENERAL"

    @property
    def display_name(self) -> str:
        """Formatted display name including subtitle if distinct."""
        if self.subtitle and self.subtitle != self.name:
            return f"{self.name} ({self.subtitle})"
        return self.name


class TransitionRecord(BaseModel):
    """Audit log entry for an executed screen transition."""
    source_screen_id: int
    target_screen_id: int
    transition_type: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    user_permission: str
    trigger_register: Optional[str] = None


class ReachabilityReport(BaseModel):
    """Topological reachability analysis result."""
    is_valid: bool
    unreachable_from_main: List[int]
    dead_end_screens: List[int]
    total_screens: int
    reachable_screens: int
    summary: str


# Canonical 7 plant screens specified by plant automation standard
CANONICAL_PLANT_SCREENS: List[HMIScreen] = [
    HMIScreen(
        screen_id=1,
        name="Main Overview",
        subtitle="Dashboard",
        description="Central plant overview dashboard showing dual-tank status, pumps, and alarms.",
        required_permission=SecurityLevel.OPERATOR,
        active_register="%D1",
        category="OVERVIEW",
    ),
    HMIScreen(
        screen_id=2,
        name="Tank 1 Detail",
        subtitle="Pump & Inflow",
        description="Detailed telemetry and manual controls for Tank 1 level and feed pump inflow.",
        required_permission=SecurityLevel.OPERATOR,
        active_register="%D2",
        category="PROCESS",
    ),
    HMIScreen(
        screen_id=3,
        name="Tank 2 Detail",
        subtitle="Drain & Discharge",
        description="Detailed telemetry and manual controls for Tank 2 level and drain/discharge pump.",
        required_permission=SecurityLevel.OPERATOR,
        active_register="%D3",
        category="PROCESS",
    ),
    HMIScreen(
        screen_id=4,
        name="Process Trends",
        subtitle="Real-time charts",
        description="Real-time trending charts for tank levels, flow rates, and pressures.",
        required_permission=SecurityLevel.OPERATOR,
        active_register="%D4",
        category="TRENDS",
    ),
    HMIScreen(
        screen_id=5,
        name="Active Alarms & Events",
        subtitle="Active Alarms & Events",
        description="Active alarm summary, acknowledge/silence controls, and historical event log.",
        required_permission=SecurityLevel.OPERATOR,
        active_register="%D5",
        category="ALARMS",
    ),
    HMIScreen(
        screen_id=6,
        name="Recipe Management",
        subtitle="Recipe Management",
        description="Batch recipe parameter management, setpoint profiles, and register deployment.",
        required_permission=SecurityLevel.SUPERVISOR,
        active_register="%D6",
        category="RECIPES",
    ),
    HMIScreen(
        screen_id=7,
        name="Controller Diagnostics & Communication Status",
        subtitle="Communication Status",
        description="OCS hardware health, scan cycle watchdog, CsCAN/Modbus communication diagnostics.",
        required_permission=SecurityLevel.ENGINEER,
        active_register="%D7",
        category="DIAGNOSTICS",
    ),
]


# Canonical transitions connecting the plant screens
CANONICAL_TRANSITIONS: List[ScreenTransition] = [
    # Outgoing from Screen 1 (Main Overview)
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=2,
        transition_type=TransitionType.DRILLDOWN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D2",
        description="Drilldown to Tank 1 Detail",
    ),
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=3,
        transition_type=TransitionType.DRILLDOWN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D3",
        description="Drilldown to Tank 2 Detail",
    ),
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=4,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D4",
        description="Open Process Trends",
    ),
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D5",
        description="View Active Alarms & Events",
    ),
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=6,
        transition_type=TransitionType.RECIPE_SELECT,
        required_permission=SecurityLevel.SUPERVISOR,
        trigger_register="%D6",
        description="Open Recipe Management (Supervisor)",
    ),
    ScreenTransition(
        source_screen_id=1,
        target_screen_id=7,
        transition_type=TransitionType.DIAGNOSTIC,
        required_permission=SecurityLevel.ENGINEER,
        trigger_register="%D7",
        description="Open Diagnostics & Comm Status (Engineer)",
    ),

    # Return paths back to Screen 1 (Main Overview)
    ScreenTransition(
        source_screen_id=2,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D1",
        description="Return from Tank 1 to Main Overview",
    ),
    ScreenTransition(
        source_screen_id=3,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D1",
        description="Return from Tank 2 to Main Overview",
    ),
    ScreenTransition(
        source_screen_id=4,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D1",
        description="Return from Trends to Main Overview",
    ),
    ScreenTransition(
        source_screen_id=5,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D1",
        description="Return from Alarms to Main Overview",
    ),
    ScreenTransition(
        source_screen_id=6,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.SUPERVISOR,
        trigger_register="%D1",
        description="Return from Recipes to Main Overview",
    ),
    ScreenTransition(
        source_screen_id=7,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.ENGINEER,
        trigger_register="%D1",
        description="Return from Diagnostics to Main Overview",
    ),

    # Cross-navigation between process screens (Screen 2, 3, 4)
    ScreenTransition(
        source_screen_id=2,
        target_screen_id=3,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D3",
        description="Switch from Tank 1 to Tank 2 Detail",
    ),
    ScreenTransition(
        source_screen_id=3,
        target_screen_id=2,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D2",
        description="Switch from Tank 2 to Tank 1 Detail",
    ),
    ScreenTransition(
        source_screen_id=2,
        target_screen_id=4,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D4",
        description="Switch from Tank 1 to Process Trends",
    ),
    ScreenTransition(
        source_screen_id=3,
        target_screen_id=4,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D4",
        description="Switch from Tank 2 to Process Trends",
    ),
    ScreenTransition(
        source_screen_id=4,
        target_screen_id=2,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D2",
        description="Switch from Process Trends to Tank 1 Detail",
    ),
    ScreenTransition(
        source_screen_id=4,
        target_screen_id=3,
        transition_type=TransitionType.DIRECT,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D3",
        description="Switch from Process Trends to Tank 2 Detail",
    ),

    # Global Alarm Header transitions (Screens 2, 3, 4, 6, 7 -> Screen 5)
    ScreenTransition(
        source_screen_id=2,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D5",
        description="Jump to Alarms from Tank 1 Detail",
    ),
    ScreenTransition(
        source_screen_id=3,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D5",
        description="Jump to Alarms from Tank 2 Detail",
    ),
    ScreenTransition(
        source_screen_id=4,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D5",
        description="Jump to Alarms from Process Trends",
    ),
    ScreenTransition(
        source_screen_id=6,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.SUPERVISOR,
        trigger_register="%D5",
        description="Jump to Alarms from Recipe Management",
    ),
    ScreenTransition(
        source_screen_id=7,
        target_screen_id=5,
        transition_type=TransitionType.ALARM_JUMP,
        required_permission=SecurityLevel.ENGINEER,
        trigger_register="%D5",
        description="Jump to Alarms from Controller Diagnostics",
    ),
]


class HMINavigationGraph:
    """Master HMI screen navigation graph and runtime screen supervisor.

    Manages screen definitions, directed transitions, reachability validation,
    runtime breadcrumb stack, transition audit history, and role-based security barriers.
    """

    def __init__(
        self,
        screens: Optional[List[HMIScreen]] = None,
        transitions: Optional[List[ScreenTransition]] = None,
        initial_screen_id: int = 1,
        current_permission: Union[SecurityLevel, str] = SecurityLevel.OPERATOR,
        auto_build_canonical: bool = True,
    ) -> None:
        self.screens: Dict[int, HMIScreen] = {}
        self.transitions: List[ScreenTransition] = []
        self._current_screen_id: int = initial_screen_id
        self._breadcrumb_stack: List[int] = [initial_screen_id]
        self._history: List[TransitionRecord] = []
        self._current_user_permission: SecurityLevel = (
            current_permission if isinstance(current_permission, SecurityLevel)
            else SecurityLevel(str(current_permission).upper())
        )

        if screens is not None:
            for s in screens:
                self.add_screen(s)
        elif auto_build_canonical:
            self._load_canonical_screens()

        if transitions is not None:
            for t in transitions:
                self.add_transition(t)
        elif auto_build_canonical:
            self._load_canonical_transitions()

        if self._current_screen_id not in self.screens and self.screens:
            first_id = next(iter(self.screens.keys()))
            self._current_screen_id = first_id
            self._breadcrumb_stack = [first_id]

    def _load_canonical_screens(self) -> None:
        for s in CANONICAL_PLANT_SCREENS:
            self.add_screen(s.model_copy())

    def _load_canonical_transitions(self) -> None:
        for t in CANONICAL_TRANSITIONS:
            self.add_transition(t.model_copy())

    @classmethod
    def create_canonical(
        cls,
        current_permission: Union[SecurityLevel, str] = SecurityLevel.OPERATOR,
    ) -> "HMINavigationGraph":
        """Instantiate graph populated with the canonical plant screens and transitions."""
        return cls(current_permission=current_permission, auto_build_canonical=True)

    def add_screen(self, screen: HMIScreen) -> None:
        """Register a new screen in the graph."""
        self.screens[screen.screen_id] = screen

    def add_transition(self, transition: ScreenTransition) -> None:
        """Register a directed transition in the graph."""
        self.transitions.append(transition)

    @property
    def current_screen_id(self) -> int:
        """Active screen ID."""
        return self._current_screen_id

    @property
    def current_screen(self) -> HMIScreen:
        """Active screen object."""
        if self._current_screen_id not in self.screens:
            raise ScreenNotFoundError(f"Screen ID {self._current_screen_id} not found in graph.")
        return self.screens[self._current_screen_id]

    @property
    def breadcrumb_stack(self) -> List[int]:
        """Current breadcrumb stack of screen IDs."""
        return list(self._breadcrumb_stack)

    @property
    def history(self) -> List[TransitionRecord]:
        """Audit log of executed screen transitions."""
        return list(self._history)

    @property
    def previous_screen_id(self) -> Optional[int]:
        """Previous screen ID from breadcrumb stack, or None if at root."""
        if len(self._breadcrumb_stack) >= 2:
            return self._breadcrumb_stack[-2]
        if self._history:
            return self._history[-1].source_screen_id
        return None

    @property
    def current_user_permission(self) -> SecurityLevel:
        """Current active user security level."""
        return self._current_user_permission

    def set_user_permission(self, level: Union[SecurityLevel, str]) -> None:
        """Set the active user security level for subsequent transitions."""
        if isinstance(level, SecurityLevel):
            self._current_user_permission = level
        else:
            self._current_user_permission = SecurityLevel(str(level).upper())

    def get_user_permission(self) -> SecurityLevel:
        """Return the active user security level."""
        return self._current_user_permission

    def get_screen(self, screen_id: int) -> Optional[HMIScreen]:
        """Retrieve screen definition by ID."""
        return self.screens.get(screen_id)

    def get_screen_by_name(self, name: str) -> Optional[HMIScreen]:
        """Retrieve screen definition by name or display name."""
        name_lower = name.strip().lower()
        for s in self.screens.values():
            if s.name.lower() == name_lower or s.display_name.lower() == name_lower:
                return s
        return None

    def get_transitions_from(self, source_screen_id: int) -> List[ScreenTransition]:
        """List all outgoing transitions from the given screen."""
        return [t for t in self.transitions if t.source_screen_id == source_screen_id]

    def get_transitions_to(self, target_screen_id: int) -> List[ScreenTransition]:
        """List all incoming transitions to the given screen."""
        return [t for t in self.transitions if t.target_screen_id == target_screen_id]

    def get_transition(self, source: int, target: int) -> Optional[ScreenTransition]:
        """Find directed transition between source and target screens."""
        for t in self.transitions:
            if t.source_screen_id == source and t.target_screen_id == target:
                return t
        return None

    def get_breadcrumbs(self) -> List[HMIScreen]:
        """Return list of HMIScreen objects corresponding to the current breadcrumb stack."""
        return [self.screens[sid] for sid in self._breadcrumb_stack if sid in self.screens]

    def can_navigate_to(
        self,
        target_screen_id: int,
        user_permission: Optional[Union[SecurityLevel, str]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify whether navigation from the current screen to target is valid and authorized."""
        effective_permission = user_permission if user_permission is not None else self._current_user_permission

        if target_screen_id not in self.screens:
            return False, f"Target screen ID {target_screen_id} does not exist."

        target_screen = self.screens[target_screen_id]
        if not check_permission(effective_permission, target_screen.required_permission):
            return False, (
                f"Security barrier: Target screen '{target_screen.name}' requires "
                f"'{target_screen.required_permission}', but current user has '{effective_permission}'."
            )

        transition = self.get_transition(self._current_screen_id, target_screen_id)
        if transition is None:
            return False, f"No directed transition exists from Screen {self._current_screen_id} to Screen {target_screen_id}."

        if not check_permission(effective_permission, transition.required_permission):
            return False, (
                f"Security barrier: Transition from {self._current_screen_id} to {target_screen_id} requires "
                f"'{transition.required_permission}', but current user has '{effective_permission}'."
            )

        return True, None

    def navigate_to(
        self,
        target_screen_id: int,
        user_permission: Optional[Union[SecurityLevel, str]] = None,
    ) -> HMIScreen:
        """Execute navigation from current screen to target screen with security and breadcrumb tracking."""
        effective_permission = user_permission if user_permission is not None else self._current_user_permission

        if target_screen_id not in self.screens:
            raise ScreenNotFoundError(f"Screen ID {target_screen_id} does not exist.")

        target_screen = self.screens[target_screen_id]
        transition = self.get_transition(self._current_screen_id, target_screen_id)
        if transition is None:
            raise InvalidTransitionError(
                f"No directed transition exists from Screen {self._current_screen_id} "
                f"to Screen {target_screen_id}."
            )

        # Enforce security barriers on screen and transition
        if not check_permission(effective_permission, target_screen.required_permission):
            raise SecurityAccessDeniedError(
                f"Access denied: Target screen '{target_screen.name}' requires permission "
                f"'{target_screen.required_permission}', but user has '{effective_permission}'."
            )

        if not check_permission(effective_permission, transition.required_permission):
            raise SecurityAccessDeniedError(
                f"Access denied: Transition requires permission "
                f"'{transition.required_permission}', but user has '{effective_permission}'."
            )

        # Record transition in audit history
        record = TransitionRecord(
            source_screen_id=self._current_screen_id,
            target_screen_id=target_screen_id,
            transition_type=(
                transition.transition_type.value
                if isinstance(transition.transition_type, TransitionType)
                else str(transition.transition_type)
            ),
            user_permission=(
                effective_permission.value
                if isinstance(effective_permission, SecurityLevel)
                else str(effective_permission)
            ),
            trigger_register=transition.trigger_register,
        )
        self._history.append(record)

        # Update breadcrumb stack:
        # If target is already in the stack, unwind back to that screen
        if target_screen_id in self._breadcrumb_stack:
            idx = self._breadcrumb_stack.index(target_screen_id)
            self._breadcrumb_stack = self._breadcrumb_stack[: idx + 1]
        else:
            self._breadcrumb_stack.append(target_screen_id)

        self._current_screen_id = target_screen_id
        return self.current_screen

    def navigate_back(self, strict: bool = False) -> HMIScreen:
        """Navigate back to the previous screen on the breadcrumb stack."""
        if len(self._breadcrumb_stack) <= 1:
            if strict:
                raise NavigationHistoryError("Cannot navigate back: already at root screen.")
            return self.current_screen

        # Pop the current top screen
        popped_id = self._breadcrumb_stack.pop()
        target_id = self._breadcrumb_stack[-1]

        # Audit record for return transition
        record = TransitionRecord(
            source_screen_id=popped_id,
            target_screen_id=target_id,
            transition_type=TransitionType.BREADCRUMB_BACK.value,
            user_permission=self._current_user_permission.value,
            trigger_register=self.screens[target_id].active_register,
        )
        self._history.append(record)

        self._current_screen_id = target_id
        return self.current_screen

    def reset_to_home(self) -> HMIScreen:
        """Reset navigation to Screen 1 (Main Overview) and clear breadcrumbs."""
        if 1 not in self.screens:
            raise ScreenNotFoundError("Screen 1 (Main Overview) does not exist in graph.")

        if self._current_screen_id != 1:
            record = TransitionRecord(
                source_screen_id=self._current_screen_id,
                target_screen_id=1,
                transition_type=TransitionType.RETURN.value,
                user_permission=self._current_user_permission.value,
                trigger_register="%D1",
            )
            self._history.append(record)

        self._current_screen_id = 1
        self._breadcrumb_stack = [1]
        return self.current_screen

    def trigger_by_register(
        self,
        register: str,
        user_permission: Optional[Union[SecurityLevel, str]] = None,
    ) -> HMIScreen:
        """Execute screen transition triggered by an OCS register (e.g. %D1, %D2)."""
        reg_upper = register.strip().upper()

        # Find matching transition from current screen by trigger_register
        for t in self.get_transitions_from(self._current_screen_id):
            if t.trigger_register and t.trigger_register.upper() == reg_upper:
                return self.navigate_to(t.target_screen_id, user_permission=user_permission)

        # Fallback: check if target screen matches active_register and transition exists
        for screen in self.screens.values():
            if screen.active_register and screen.active_register.upper() == reg_upper:
                if self.get_transition(self._current_screen_id, screen.screen_id) is not None:
                    return self.navigate_to(screen.screen_id, user_permission=user_permission)

        raise InvalidTransitionError(
            f"No valid transition from Screen {self._current_screen_id} for register '{register}'."
        )

    def validate_reachability(self, root_screen_id: int = 1) -> ReachabilityReport:
        """Verify reachability of all screens from root and ensure zero dead ends.

        Requirements:
        1. All screens in the graph must be reachable from root_screen_id (Main Overview).
        2. Zero dead-end screens: every screen must have a directed return path to root_screen_id.
        """
        if root_screen_id not in self.screens:
            return ReachabilityReport(
                is_valid=False,
                unreachable_from_main=list(self.screens.keys()),
                dead_end_screens=[],
                total_screens=len(self.screens),
                reachable_screens=0,
                summary=f"Root screen {root_screen_id} does not exist in the graph.",
            )

        # Build adjacency maps
        adj_forward: Dict[int, Set[int]] = {sid: set() for sid in self.screens}
        adj_backward: Dict[int, Set[int]] = {sid: set() for sid in self.screens}

        for t in self.transitions:
            if t.source_screen_id in adj_forward and t.target_screen_id in adj_forward:
                adj_forward[t.source_screen_id].add(t.target_screen_id)
                adj_backward[t.target_screen_id].add(t.source_screen_id)

        # Forward BFS from root: check reachability from root
        reachable_forward: Set[int] = {root_screen_id}
        queue: List[int] = [root_screen_id]
        while queue:
            curr = queue.pop(0)
            for nxt in adj_forward.get(curr, set()):
                if nxt not in reachable_forward:
                    reachable_forward.add(nxt)
                    queue.append(nxt)

        unreachable = sorted(set(self.screens.keys()) - reachable_forward)

        # Backward BFS from root: check which screens can return to root
        reachable_backward: Set[int] = {root_screen_id}
        queue = [root_screen_id]
        while queue:
            curr = queue.pop(0)
            for prev in adj_backward.get(curr, set()):
                if prev not in reachable_backward:
                    reachable_backward.add(prev)
                    queue.append(prev)

        dead_ends = sorted(set(self.screens.keys()) - reachable_backward)

        is_valid = (len(unreachable) == 0) and (len(dead_ends) == 0)

        if is_valid:
            summary = (
                f"Reachability verified: All {len(self.screens)} screens reachable from "
                f"Screen {root_screen_id} (Main Overview); zero dead-end screens."
            )
        else:
            summary = (
                f"Reachability validation FAILED: {len(unreachable)} unreachable screens "
                f"({unreachable}), {len(dead_ends)} dead-end screens ({dead_ends})."
            )

        return ReachabilityReport(
            is_valid=is_valid,
            unreachable_from_main=unreachable,
            dead_end_screens=dead_ends,
            total_screens=len(self.screens),
            reachable_screens=len(reachable_forward),
            summary=summary,
        )

    def assert_reachability(self, root_screen_id: int = 1) -> None:
        """Validate reachability and raise ReachabilityError if any screen is unreachable or a dead end."""
        report = self.validate_reachability(root_screen_id=root_screen_id)
        if not report.is_valid:
            raise ReachabilityError(report.summary)

    def export_topology(self) -> Dict[str, Any]:
        """Export full screen navigation graph topology as structured dictionary."""
        reachability_report = self.validate_reachability()
        return {
            "topology_name": "Horner OCS Dual-Tank Process Screen Topology",
            "cscape_version": "10.2.751.4",
            "root_screen_id": 1,
            "screens_count": len(self.screens),
            "transitions_count": len(self.transitions),
            "screens": [s.model_dump() for s in sorted(self.screens.values(), key=lambda x: x.screen_id)],
            "transitions": [t.model_dump() for t in self.transitions],
            "reachability": reachability_report.model_dump(),
            "security_levels": [level.value for level in SecurityLevel],
            "current_state": {
                "active_screen_id": self._current_screen_id,
                "breadcrumb_stack": list(self._breadcrumb_stack),
                "history_length": len(self._history),
                "current_user_permission": self._current_user_permission.value,
            },
        }

    def export_topology_json(
        self,
        output_path: Union[str, Path] = "artifacts/HMI/screen_topology.json",
    ) -> Path:
        """Export topology dictionary to JSON file on disk."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = self.export_topology()
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return target
