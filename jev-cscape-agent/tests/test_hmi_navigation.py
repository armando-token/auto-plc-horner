"""Tests for HMI Navigation Graph, Screen Supervisor, and Security Barriers."""

import json
from pathlib import Path
import pytest

from jev_cscape.hmi import (
    CANONICAL_PLANT_SCREENS,
    CANONICAL_TRANSITIONS,
    HMINavigationError,
    HMINavigationGraph,
    HMIScreen,
    InvalidTransitionError,
    NavigationHistoryError,
    ReachabilityError,
    ReachabilityReport,
    ScreenNotFoundError,
    ScreenTransition,
    SecurityAccessDeniedError,
    SecurityLevel,
    TransitionType,
    check_permission,
)
from jev_cscape.security.exceptions import SecurityError


# ---------------------------------------------------------------------------
# Topology and Canonical Plant Screen Tests
# ---------------------------------------------------------------------------

def test_canonical_screens_topology():
    """Verify all 7 canonical plant screens are defined with expected names, IDs, and registers."""
    graph = HMINavigationGraph.create_canonical()
    assert len(graph.screens) == 7

    expected = [
        (1, "Main Overview", "Dashboard", SecurityLevel.OPERATOR, "%D1"),
        (2, "Tank 1 Detail", "Pump & Inflow", SecurityLevel.OPERATOR, "%D2"),
        (3, "Tank 2 Detail", "Drain & Discharge", SecurityLevel.OPERATOR, "%D3"),
        (4, "Process Trends", "Real-time charts", SecurityLevel.OPERATOR, "%D4"),
        (5, "Active Alarms & Events", "Active Alarms & Events", SecurityLevel.OPERATOR, "%D5"),
        (6, "Recipe Management", "Recipe Management", SecurityLevel.SUPERVISOR, "%D6"),
        (7, "Controller Diagnostics & Communication Status", "Communication Status", SecurityLevel.ENGINEER, "%D7"),
    ]

    for sid, name, subtitle, min_sec, reg in expected:
        screen = graph.get_screen(sid)
        assert screen is not None, f"Screen {sid} missing from canonical graph"
        assert screen.name == name
        assert screen.subtitle == subtitle
        assert screen.required_permission == min_sec
        assert screen.active_register == reg

    # Check lookup by name
    assert graph.get_screen_by_name("Main Overview") is not None
    assert graph.get_screen_by_name("main overview") is not None
    assert graph.get_screen_by_name("Main Overview (Dashboard)") is not None
    assert graph.get_screen_by_name("Tank 1 Detail") is not None
    assert graph.get_screen_by_name("Recipe Management") is not None
    assert graph.get_screen_by_name("Unknown Screen") is None


def test_screen_transition_initialization_styles():
    """Verify ScreenTransition accepts both positional and keyword arguments."""
    t_pos = ScreenTransition(
        1,
        2,
        TransitionType.DRILLDOWN,
        SecurityLevel.OPERATOR,
        "%D2",
        "Positional transition",
    )
    assert t_pos.source_screen_id == 1
    assert t_pos.target_screen_id == 2
    assert t_pos.transition_type == TransitionType.DRILLDOWN
    assert t_pos.required_permission == SecurityLevel.OPERATOR
    assert t_pos.trigger_register == "%D2"
    assert t_pos.description == "Positional transition"

    t_kw = ScreenTransition(
        source_screen_id=3,
        target_screen_id=1,
        transition_type=TransitionType.RETURN,
        required_permission=SecurityLevel.OPERATOR,
        trigger_register="%D1",
        description="Keyword transition",
    )
    assert t_kw.source_screen_id == 3
    assert t_kw.target_screen_id == 1
    assert t_kw.trigger_register == "%D1"


# ---------------------------------------------------------------------------
# Reachability and Graph Traversal Tests
# ---------------------------------------------------------------------------

def test_reachability_canonical_graph():
    """Verify all 7 canonical screens are reachable from Screen 1 and zero dead ends exist."""
    graph = HMINavigationGraph.create_canonical()
    report = graph.validate_reachability()

    assert report.is_valid is True
    assert report.total_screens == 7
    assert report.reachable_screens == 7
    assert len(report.unreachable_from_main) == 0
    assert len(report.dead_end_screens) == 0
    assert "Reachability verified" in report.summary

    # assert_reachability must succeed without raising
    graph.assert_reachability()


def test_reachability_detects_unreachable_node():
    """Verify reachability validation fails when an orphan screen is added."""
    graph = HMINavigationGraph.create_canonical()
    # Add screen 8 without any incoming transitions
    orphan_screen = HMIScreen(
        screen_id=8,
        name="Orphan Maintenance Screen",
        required_permission=SecurityLevel.ADMIN,
    )
    graph.add_screen(orphan_screen)

    report = graph.validate_reachability()
    assert report.is_valid is False
    assert 8 in report.unreachable_from_main

    with pytest.raises(ReachabilityError) as exc_info:
        graph.assert_reachability()
    assert "8" in str(exc_info.value)


def test_reachability_detects_dead_end_screen():
    """Verify reachability validation fails when a screen has no return path back to Main Overview."""
    graph = HMINavigationGraph.create_canonical()
    # Add screen 9 with transition from 1 -> 9, but no return path back to 1
    dead_screen = HMIScreen(
        screen_id=9,
        name="Dead-End Trap Screen",
        required_permission=SecurityLevel.OPERATOR,
    )
    graph.add_screen(dead_screen)
    graph.add_transition(
        ScreenTransition(
            source_screen_id=1,
            target_screen_id=9,
            transition_type=TransitionType.DIRECT,
            required_permission=SecurityLevel.OPERATOR,
        )
    )

    report = graph.validate_reachability()
    assert report.is_valid is False
    # Screen 9 is reachable from 1, but cannot return to 1
    assert 9 not in report.unreachable_from_main
    assert 9 in report.dead_end_screens

    with pytest.raises(ReachabilityError) as exc_info:
        graph.assert_reachability()
    assert "dead-end" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Transition Execution and Register Trigger Tests
# ---------------------------------------------------------------------------

def test_transition_execution_happy_path():
    """Verify sequential transitions between overview, tank details, and trends."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    assert graph.current_screen_id == 1

    # 1 -> 2 (Tank 1 Detail)
    s2 = graph.navigate_to(2)
    assert s2.screen_id == 2
    assert graph.current_screen_id == 2

    # 2 -> 3 (Tank 2 Detail)
    s3 = graph.navigate_to(3)
    assert s3.screen_id == 3
    assert graph.current_screen_id == 3

    # 3 -> 4 (Process Trends)
    s4 = graph.navigate_to(4)
    assert s4.screen_id == 4
    assert graph.current_screen_id == 4

    # 4 -> 1 (Main Overview)
    s1 = graph.navigate_to(1)
    assert s1.screen_id == 1
    assert graph.current_screen_id == 1


def test_transition_execution_invalid_destination():
    """Verify navigation to a non-existent screen raises ScreenNotFoundError."""
    graph = HMINavigationGraph.create_canonical()
    with pytest.raises(ScreenNotFoundError):
        graph.navigate_to(999)


def test_transition_execution_no_direct_path():
    """Verify navigation when no direct transition exists raises InvalidTransitionError."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.ADMIN)
    # No direct transition defined from Screen 6 (Recipes) to Screen 7 (Diagnostics)
    assert graph.get_transition(6, 7) is None

    # Move to Screen 6 first
    graph.navigate_to(6)
    assert graph.current_screen_id == 6

    # Attempt direct jump to 7
    with pytest.raises(InvalidTransitionError):
        graph.navigate_to(7)


def test_trigger_by_register():
    """Verify navigation driven by Horner OCS %D display registers."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    assert graph.current_screen_id == 1

    # Trigger %D2 should switch to Screen 2
    s2 = graph.trigger_by_register("%D2")
    assert s2.screen_id == 2
    assert graph.current_screen_id == 2

    # Trigger %D4 from Screen 2 should switch to Screen 4 (Trends)
    s4 = graph.trigger_by_register("%D4")
    assert s4.screen_id == 4

    # Trigger %D1 from Screen 4 returns to Screen 1
    s1 = graph.trigger_by_register("%D1")
    assert s1.screen_id == 1

    # Invalid register raises InvalidTransitionError
    with pytest.raises(InvalidTransitionError):
        graph.trigger_by_register("%D99")


# ---------------------------------------------------------------------------
# Security Barriers and Role Enforcement Tests
# ---------------------------------------------------------------------------

def test_permission_checker():
    """Verify check_permission hierarchy logic."""
    assert check_permission(SecurityLevel.OPERATOR, SecurityLevel.VIEWER) is True
    assert check_permission(SecurityLevel.OPERATOR, SecurityLevel.OPERATOR) is True
    assert check_permission(SecurityLevel.OPERATOR, SecurityLevel.SUPERVISOR) is False
    assert check_permission(SecurityLevel.SUPERVISOR, SecurityLevel.OPERATOR) is True
    assert check_permission(SecurityLevel.SUPERVISOR, SecurityLevel.SUPERVISOR) is True
    assert check_permission(SecurityLevel.SUPERVISOR, SecurityLevel.ENGINEER) is False
    assert check_permission(SecurityLevel.ENGINEER, SecurityLevel.SUPERVISOR) is True
    assert check_permission(SecurityLevel.ADMIN, SecurityLevel.ENGINEER) is True


def test_security_barrier_operator_blocked_from_supervisor_screen():
    """Verify an operator cannot navigate to Recipe Management (Screen 6)."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    assert graph.current_screen_id == 1

    can_nav, reason = graph.can_navigate_to(6)
    assert can_nav is False
    assert "Security barrier" in reason

    with pytest.raises(SecurityAccessDeniedError) as exc_info:
        graph.navigate_to(6)
    assert "Access denied" in str(exc_info.value)
    # Check that SecurityAccessDeniedError inherits from SecurityError
    assert isinstance(exc_info.value, SecurityError)


def test_security_barrier_supervisor_blocked_from_engineer_screen():
    """Verify a supervisor cannot navigate to Controller Diagnostics (Screen 7)."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.SUPERVISOR)
    assert graph.current_screen_id == 1

    # Supervisor CAN navigate to Recipe Management (Screen 6)
    can_nav, _ = graph.can_navigate_to(6)
    assert can_nav is True
    s6 = graph.navigate_to(6)
    assert s6.screen_id == 6

    # Return to 1
    graph.navigate_to(1)

    # Supervisor CANNOT navigate to Diagnostics (Screen 7)
    can_nav, reason = graph.can_navigate_to(7)
    assert can_nav is False
    assert "Security barrier" in reason

    with pytest.raises(SecurityAccessDeniedError):
        graph.navigate_to(7)


def test_security_barrier_elevation_and_access():
    """Verify setting user permission elevates access privileges dynamically."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)

    # Operator blocked from Screen 7
    with pytest.raises(SecurityAccessDeniedError):
        graph.navigate_to(7)

    # Elevate session to ENGINEER
    graph.set_user_permission(SecurityLevel.ENGINEER)
    assert graph.get_user_permission() == SecurityLevel.ENGINEER

    # Now allowed to navigate to Screen 7
    s7 = graph.navigate_to(7)
    assert s7.screen_id == 7
    assert graph.current_screen_id == 7


def test_per_call_user_permission_override():
    """Verify passing explicit user_permission in navigate_to overrides active session."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)

    # Calling navigate_to with explicit SUPERVISOR permission succeeds without changing session
    s6 = graph.navigate_to(6, user_permission=SecurityLevel.SUPERVISOR)
    assert s6.screen_id == 6
    assert graph.current_user_permission == SecurityLevel.OPERATOR


# ---------------------------------------------------------------------------
# Breadcrumb Stack Tracking and History Tests
# ---------------------------------------------------------------------------

def test_breadcrumb_stack_navigation_and_back():
    """Verify breadcrumb stack pushes, pops with navigate_back, and returns HMIScreen list."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    assert graph.breadcrumb_stack == [1]

    # Navigate 1 -> 2
    graph.navigate_to(2)
    assert graph.breadcrumb_stack == [1, 2]
    assert graph.previous_screen_id == 1

    # Navigate 2 -> 4
    graph.navigate_to(4)
    assert graph.breadcrumb_stack == [1, 2, 4]
    assert graph.previous_screen_id == 2

    breadcrumbs = graph.get_breadcrumbs()
    assert [b.screen_id for b in breadcrumbs] == [1, 2, 4]

    # Navigate back once -> should return to Screen 2
    prev = graph.navigate_back()
    assert prev.screen_id == 2
    assert graph.current_screen_id == 2
    assert graph.breadcrumb_stack == [1, 2]

    # Navigate back again -> should return to Screen 1
    prev = graph.navigate_back()
    assert prev.screen_id == 1
    assert graph.current_screen_id == 1
    assert graph.breadcrumb_stack == [1]

    # Navigate back at root non-strict returns current screen
    at_root = graph.navigate_back(strict=False)
    assert at_root.screen_id == 1

    # Navigate back at root strict raises NavigationHistoryError
    with pytest.raises(NavigationHistoryError):
        graph.navigate_back(strict=True)


def test_breadcrumb_stack_unwind_on_revisit():
    """Verify navigating to an ancestor in the breadcrumb stack unwinds the stack."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    graph.navigate_to(2)  # [1, 2]
    graph.navigate_to(4)  # [1, 2, 4]
    assert graph.breadcrumb_stack == [1, 2, 4]

    # Navigate directly back to Screen 2 from 4
    graph.navigate_to(2)
    assert graph.breadcrumb_stack == [1, 2]
    assert graph.current_screen_id == 2

    # Navigate to 1
    graph.navigate_to(1)
    assert graph.breadcrumb_stack == [1]


def test_reset_to_home():
    """Verify reset_to_home immediately resets screen to 1 and breadcrumbs to [1]."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    graph.navigate_to(2)
    graph.navigate_to(3)
    assert graph.current_screen_id == 3
    assert graph.breadcrumb_stack == [1, 2, 3]

    home = graph.reset_to_home()
    assert home.screen_id == 1
    assert graph.current_screen_id == 1
    assert graph.breadcrumb_stack == [1]


def test_transition_history_audit_trail():
    """Verify transition history logs all operations with timestamps and permissions."""
    graph = HMINavigationGraph.create_canonical(current_permission=SecurityLevel.OPERATOR)
    assert len(graph.history) == 0

    graph.navigate_to(2)
    graph.navigate_to(4)
    graph.navigate_back()

    assert len(graph.history) == 3
    rec1, rec2, rec3 = graph.history

    assert rec1.source_screen_id == 1
    assert rec1.target_screen_id == 2
    assert rec1.transition_type == TransitionType.DRILLDOWN.value
    assert rec1.user_permission == SecurityLevel.OPERATOR.value

    assert rec2.source_screen_id == 2
    assert rec2.target_screen_id == 4

    assert rec3.source_screen_id == 4
    assert rec3.target_screen_id == 2
    assert rec3.transition_type == TransitionType.BREADCRUMB_BACK.value


# ---------------------------------------------------------------------------
# Topology Export Tests
# ---------------------------------------------------------------------------

def test_export_topology_dict():
    """Verify export_topology produces comprehensive dictionary representation."""
    graph = HMINavigationGraph.create_canonical()
    topology = graph.export_topology()

    assert topology["cscape_version"] == "10.2.751.4"
    assert topology["screens_count"] == 7
    assert topology["transitions_count"] == len(CANONICAL_TRANSITIONS)
    assert topology["reachability"]["is_valid"] is True
    assert len(topology["screens"]) == 7
    assert "VIEWER" in topology["security_levels"]
    assert "OPERATOR" in topology["security_levels"]


def test_export_topology_json(tmp_path):
    """Verify export_topology_json saves valid JSON file."""
    graph = HMINavigationGraph.create_canonical()
    output_path = tmp_path / "HMI" / "screen_topology.json"

    saved_file = graph.export_topology_json(output_path)
    assert saved_file.exists()

    with open(saved_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["screens_count"] == 7
    assert data["reachability"]["is_valid"] is True
    assert len(data["screens"]) == 7
    assert len(data["transitions"]) == len(CANONICAL_TRANSITIONS)
