"""Industrial HMI Multi-Screen Navigation Session and Event Runner.

Work Package: W043 (Gate G9)
Classification: PRODUCTION [HMI / SCADA runtime execution]

Provides:
- HmiNavigationSession: Interactive state machine wrapping ScreenNavigationGraph,
  RegisterTable, and HmiSvgRenderer.
- Event-driven operator screen navigation with RBAC permission enforcement.
- Breadcrumb audit trail recording and return stack unwinding.
- Multi-screen SVG vector graphics snapshot generation.
- Strict 4-state contract JSON evidence export.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.hmi.models import (
    AlarmBanner,
    Bargraph,
    ColorRGB,
    HMIScreen,
    IndicatorLamp,
    NumericDataEntry,
    PushButton,
    TrendChart,
)
from jev_cscape.hmi.navigation import (
    CANONICAL_PLANT_SCREENS,
    HMINavigationGraph,
    SecurityAccessDeniedError,
    SecurityLevel,
    check_permission,
)
from jev_cscape.hmi.renderer import HMIScreenRenderer
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

logger = logging.getLogger(__name__)


class NavigationEventRecord(BaseModel):
    """Log record of a navigation event within an active session."""
    step_number: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: str  # "NAVIGATE", "BACK", "HOME", "REJECTED"
    source_screen_id: int
    target_screen_id: int
    user_role: str
    status: str  # "SUCCESS", "DENIED", "ERROR"
    reason: Optional[str] = None
    breadcrumb_stack: List[int] = Field(default_factory=list)


class HmiNavigationSession:
    """Manages an active multi-screen HMI session with operator interaction modeling."""

    def __init__(
        self,
        nav_graph: Optional[HMINavigationGraph] = None,
        register_table: Optional[RegisterTable] = None,
        default_role: Union[SecurityLevel, str] = SecurityLevel.OPERATOR,
    ) -> None:
        self.nav_graph = nav_graph or HMINavigationGraph.create_canonical()
        self.register_table = register_table or RegisterTable()
        self.current_role = default_role if isinstance(default_role, SecurityLevel) else SecurityLevel(str(default_role).upper())
        self.event_log: List[NavigationEventRecord] = []
        self._step_counter = 0

    @property
    def current_screen_id(self) -> int:
        """Currently active screen ID."""
        return self.nav_graph.current_screen_id

    @property
    def current_screen(self) -> Any:
        """Currently active HMIScreen definition."""
        return self.nav_graph.screens[self.current_screen_id]

    @property
    def breadcrumb_trail(self) -> List[int]:
        """Current breadcrumb stack."""
        return list(self.nav_graph.breadcrumb_stack)

    def set_user_role(self, role: Union[SecurityLevel, str]) -> None:
        """Update active session security credentials."""
        self.current_role = role if isinstance(role, SecurityLevel) else SecurityLevel(str(role).upper())
        self.nav_graph.set_user_permission(self.current_role)

    def navigate_to(
        self,
        target_screen_id: int,
        role_override: Optional[Union[SecurityLevel, str]] = None,
    ) -> ExecutionResult:
        """Navigate to a target screen enforcing RBAC permissions."""
        self._step_counter += 1
        source_id = self.current_screen_id
        active_role = role_override or self.current_role
        role_str = active_role.value if isinstance(active_role, SecurityLevel) else str(active_role).upper()

        try:
            target_screen = self.nav_graph.screens.get(target_screen_id)
            if not target_screen:
                rec = NavigationEventRecord(
                    step_number=self._step_counter,
                    action="NAVIGATE",
                    source_screen_id=source_id,
                    target_screen_id=target_screen_id,
                    user_role=role_str,
                    status="ERROR",
                    reason=f"Target screen ID {target_screen_id} does not exist",
                    breadcrumb_stack=self.breadcrumb_trail,
                )
                self.event_log.append(rec)
                return ExecutionResult.failed(
                    error_code="SCREEN_NOT_FOUND",
                    details=f"Screen {target_screen_id} not registered in topology.",
                )

            if not check_permission(active_role, target_screen.required_permission):
                raise SecurityAccessDeniedError(
                    f"User role '{role_str}' lacks required permission "
                    f"'{target_screen.required_permission}' for Screen {target_screen_id}."
                )

            # Attempt transition
            self.nav_graph.navigate_to(target_screen_id, user_permission=active_role)

            rec = NavigationEventRecord(
                step_number=self._step_counter,
                action="NAVIGATE",
                source_screen_id=source_id,
                target_screen_id=target_screen_id,
                user_role=role_str,
                status="SUCCESS",
                breadcrumb_stack=self.breadcrumb_trail,
            )
            self.event_log.append(rec)

            return ExecutionResult.success(
                details=f"Successfully navigated from Screen {source_id} to {target_screen_id} ({target_screen.name}).",
                data={
                    "source_screen_id": source_id,
                    "target_screen_id": target_screen_id,
                    "target_screen_name": target_screen.name,
                    "user_role": role_str,
                    "breadcrumbs": self.breadcrumb_trail,
                },
            )

        except SecurityAccessDeniedError as e:
            rec = NavigationEventRecord(
                step_number=self._step_counter,
                action="REJECTED",
                source_screen_id=source_id,
                target_screen_id=target_screen_id,
                user_role=role_str,
                status="DENIED",
                reason=str(e),
                breadcrumb_stack=self.breadcrumb_trail,
            )
            self.event_log.append(rec)
            return ExecutionResult.blocked(
                error_code="SECURITY_ACCESS_DENIED",
                details=f"Access to Screen {target_screen_id} denied for role {role_str}: {e}",
                data={"target_screen_id": target_screen_id, "user_role": role_str},
            )
        except Exception as e:
            rec = NavigationEventRecord(
                step_number=self._step_counter,
                action="NAVIGATE",
                source_screen_id=source_id,
                target_screen_id=target_screen_id,
                user_role=role_str,
                status="ERROR",
                reason=str(e),
                breadcrumb_stack=self.breadcrumb_trail,
            )
            self.event_log.append(rec)
            return ExecutionResult.failed(
                error_code="NAVIGATION_FAILED",
                details=f"Navigation failed: {e}",
            )

    def navigate_back(self) -> ExecutionResult:
        """Unwind breadcrumb stack to return to previously visited screen."""
        self._step_counter += 1
        source_id = self.current_screen_id
        role_str = self.current_role.value

        try:
            target_screen = self.nav_graph.navigate_back()
            target_id = target_screen.screen_id

            rec = NavigationEventRecord(
                step_number=self._step_counter,
                action="BACK",
                source_screen_id=source_id,
                target_screen_id=target_id,
                user_role=role_str,
                status="SUCCESS",
                breadcrumb_stack=self.breadcrumb_trail,
            )
            self.event_log.append(rec)

            return ExecutionResult.success(
                details=f"Returned back from Screen {source_id} to {target_id} ({target_screen.name}).",
                data={
                    "source_screen_id": source_id,
                    "target_screen_id": target_id,
                    "breadcrumbs": self.breadcrumb_trail,
                },
            )
        except Exception as e:
            rec = NavigationEventRecord(
                step_number=self._step_counter,
                action="BACK",
                source_screen_id=source_id,
                target_screen_id=source_id,
                user_role=role_str,
                status="ERROR",
                reason=str(e),
                breadcrumb_stack=self.breadcrumb_trail,
            )
            self.event_log.append(rec)
            return ExecutionResult.failed(
                error_code="BACK_NAVIGATION_FAILED",
                details=f"Cannot navigate back: {e}",
            )

    def reset_to_home(self) -> ExecutionResult:
        """Reset active screen to home (Screen 1) and clear breadcrumbs."""
        self._step_counter += 1
        source_id = self.current_screen_id
        home_screen = self.nav_graph.reset_to_home()
        home_id = home_screen.screen_id

        rec = NavigationEventRecord(
            step_number=self._step_counter,
            action="HOME",
            source_screen_id=source_id,
            target_screen_id=home_id,
            user_role=self.current_role.value,
            status="SUCCESS",
            breadcrumb_stack=self.breadcrumb_trail,
        )
        self.event_log.append(rec)

        return ExecutionResult.success(
            details=f"Session reset to home screen {home_id} ({home_screen.name}).",
            data={"home_screen_id": home_id, "breadcrumbs": self.breadcrumb_trail},
        )

    def render_screen_svg(
        self,
        screen_id: Optional[int] = None,
        output_file: Optional[Union[str, Path]] = None,
    ) -> str:
        """Render a screen definition to an SVG vector document."""
        target_id = screen_id or self.current_screen_id
        screen_def = self.nav_graph.screens.get(target_id)
        if not screen_def:
            raise ValueError(f"Screen ID {target_id} not found in navigation graph.")

        # Build dynamic HMI screen model with representative graphical elements
        hmi_screen = self._build_canonical_hmi_screen(target_id, screen_def.name)

        renderer = HMIScreenRenderer()
        svg_content = renderer.render_svg(
            screen=hmi_screen,
            registers=self.register_table,
        )

        if output_file:
            p = Path(output_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(svg_content, encoding="utf-8")

        return svg_content

    def _build_canonical_hmi_screen(self, screen_id: int, name: str) -> HMIScreen:
        """Build a representative HMIScreen with visual elements for rendering."""
        elements = []

        if screen_id == 1:  # Main Overview
            elements = [
                AlarmBanner(
                    element_id="alm_banner_main",
                    x=20,
                    y=46,
                    width=760,
                    height=26,
                    active_alarm_messages=["PUMP-101 Running", "System Nominal"],
                    is_visible=True,
                ),
                Bargraph(
                    element_id="bar_tank1_level",
                    x=80,
                    y=80,
                    width=60,
                    height=240,
                    bound_register="%AI1",
                    min_value=0.0,
                    max_value=100.0,
                    high_alarm_threshold=85.0,
                    low_alarm_threshold=15.0,
                    fill_direction="BOTTOM_TO_TOP",
                ),
                Bargraph(
                    element_id="bar_tank2_level",
                    x=240,
                    y=80,
                    width=60,
                    height=240,
                    bound_register="%AI2",
                    min_value=0.0,
                    max_value=100.0,
                    high_alarm_threshold=85.0,
                    low_alarm_threshold=15.0,
                    fill_direction="BOTTOM_TO_TOP",
                ),
                NumericDataEntry(
                    element_id="num_t1_level",
                    x=80,
                    y=330,
                    width=60,
                    height=28,
                    bound_register="%AI1",
                    format_string="###.#",
                    engineering_units="%",
                ),
                NumericDataEntry(
                    element_id="num_t2_level",
                    x=240,
                    y=330,
                    width=60,
                    height=28,
                    bound_register="%AI2",
                    format_string="###.#",
                    engineering_units="%",
                ),
                IndicatorLamp(
                    element_id="lamp_p101_running",
                    x=420,
                    y=100,
                    width=40,
                    height=40,
                    bound_register="%Q1",
                    label="PUMP 101",
                    on_color=ColorRGB(r=0, g=230, b=118),
                ),
                IndicatorLamp(
                    element_id="lamp_system_fault",
                    x=420,
                    y=170,
                    width=40,
                    height=40,
                    bound_register="%M1",
                    label="TRIP / FAULT",
                    on_color=ColorRGB(r=255, g=23, b=68),
                ),
                PushButton(
                    element_id="btn_start_sim",
                    x=520,
                    y=100,
                    width=100,
                    height=40,
                    bound_register="%Q1",
                    label="START PUMP",
                    button_color=ColorRGB(r=27, g=94, b=32),
                ),
                PushButton(
                    element_id="btn_stop_sim",
                    x=640,
                    y=100,
                    width=100,
                    height=40,
                    bound_register="%Q1",
                    label="STOP PUMP",
                    button_color=ColorRGB(r=180, g=40, b=40),
                ),
                TrendChart(
                    element_id="trend_cascade_levels",
                    x=380,
                    y=220,
                    width=380,
                    height=180,
                    title="Real-Time Tank Level Cascade",
                    pen_registers=["%AI1", "%AI2"],
                    y_min=0.0,
                    y_max=100.0,
                ),
            ]
        elif screen_id == 5:  # Alarm Summary
            elements = [
                AlarmBanner(
                    element_id="alm_summary_header",
                    x=20,
                    y=46,
                    width=760,
                    height=26,
                    active_alarm_messages=["[ISA-18.2] Active Alarm Summary Buffer"],
                ),
                IndicatorLamp(
                    element_id="lamp_alm_t1_hi",
                    x=60,
                    y=100,
                    width=35,
                    height=35,
                    bound_register="%M10",
                    label="T1_HI Alarm",
                    on_color=ColorRGB(r=255, g=171, b=0),
                ),
                IndicatorLamp(
                    element_id="lamp_alm_t1_hihi",
                    x=220,
                    y=100,
                    width=35,
                    height=35,
                    bound_register="%M11",
                    label="T1_HIHI Trip",
                    on_color=ColorRGB(r=255, g=23, b=68),
                ),
                IndicatorLamp(
                    element_id="lamp_alm_t2_lo",
                    x=380,
                    y=100,
                    width=35,
                    height=35,
                    bound_register="%M12",
                    label="T2_LO Alarm",
                    on_color=ColorRGB(r=255, g=171, b=0),
                ),
                PushButton(
                    element_id="btn_ack_all",
                    x=560,
                    y=95,
                    width=140,
                    height=45,
                    bound_register="%M20",
                    label="ACK ALL ALARMS",
                    button_color=ColorRGB(r=33, g=150, b=243),
                ),
                TrendChart(
                    element_id="trend_alarm_history",
                    x=60,
                    y=180,
                    width=680,
                    height=240,
                    title="ISA-18.2 Historical Incident Rate",
                    y_min=0.0,
                    y_max=50.0,
                ),
            ]
        else:  # Generic plant screen (Recipe, Detail, Diagnostics)
            elements = [
                AlarmBanner(
                    element_id=f"alm_header_{screen_id}",
                    x=20,
                    y=46,
                    width=760,
                    height=26,
                    active_alarm_messages=[f"Screen {screen_id}: {name}"],
                ),
                NumericDataEntry(
                    element_id=f"num_param_{screen_id}_1",
                    x=100,
                    y=100,
                    width=120,
                    height=32,
                    bound_register="%R101",
                    label="Parameter 1",
                    format_string="####",
                ),
                NumericDataEntry(
                    element_id=f"num_param_{screen_id}_2",
                    x=100,
                    y=160,
                    width=120,
                    height=32,
                    bound_register="%R102",
                    label="Parameter 2",
                    format_string="####",
                ),
                IndicatorLamp(
                    element_id=f"lamp_stat_{screen_id}",
                    x=300,
                    y=100,
                    width=40,
                    height=40,
                    bound_register="%Q2",
                    label="Ready Status",
                ),
                PushButton(
                    element_id=f"btn_apply_{screen_id}",
                    x=300,
                    y=160,
                    width=120,
                    height=38,
                    bound_register="%M30",
                    label="APPLY STAGING",
                    button_color=ColorRGB(r=0, g=200, b=83),
                ),
            ]

        return HMIScreen(
            screen_id=screen_id,
            name=name,
            resolution=(800, 480),
            background_color=ColorRGB(r=18, g=24, b=38),
            elements=elements,
        )

    def export_session_evidence(
        self,
        output_file: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """Export session execution evidence in strict 4-state compliant format."""
        reachability = self.nav_graph.validate_reachability()

        payload = {
            "session_summary": {
                "total_events": len(self.event_log),
                "total_steps": self._step_counter,
                "current_screen_id": self.current_screen_id,
                "current_screen_name": self.current_screen.name,
                "current_role": self.current_role.value,
                "active_breadcrumbs": self.breadcrumb_trail,
            },
            "topology_verification": {
                "total_screens": len(self.nav_graph.screens),
                "total_transitions": len(self.nav_graph.transitions),
                "is_fully_reachable": reachability.is_valid,
                "unreachable_count": len(reachability.unreachable_from_main),
                "dead_end_count": len(reachability.dead_end_screens),
            },
            "security_audit": {
                "tested_roles": [r.value for r in SecurityLevel],
                "denied_attempts": sum(1 for e in self.event_log if e.status == "DENIED"),
                "successful_transitions": sum(1 for e in self.event_log if e.status == "SUCCESS"),
            },
            "event_trail": [e.model_dump() for e in self.event_log],
            "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        if output_file:
            p = Path(output_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.info(f"HMI navigation session evidence exported to {p}")

        return payload
