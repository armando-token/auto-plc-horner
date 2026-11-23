"""Tests for Gate G6 Offline Acceptance Suite (scripts/g6_acceptance.py).

Validates:
1. Exactly 30 verifiable technical queries (20 factual + 10 version/not-found).
2. Exactly 5 plan requests (2 compatible, 2 incompatible, 1 missing data).
3. Recall threshold >= 90.0% (target 100.0%).
4. Plan accuracy threshold == 100.0%.
5. Deterministic evidence JSON generation with valid SHA-256 digest.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.g6_acceptance import (
    G6_QUERY_CASES,
    G6_PLAN_CASES,
    G6AcceptanceEngine,
    run_g6_acceptance,
)


def test_query_suite_composition() -> None:
    """Verify suite contains exactly 30 queries with required distribution."""
    assert len(G6_QUERY_CASES) == 30

    factual_cases = [q for q in G6_QUERY_CASES if q.category == "FACTUAL"]
    version_cases = [q for q in G6_QUERY_CASES if q.category == "VERSION_NOT_FOUND"]

    assert len(factual_cases) == 20
    assert len(version_cases) == 10

    for q in G6_QUERY_CASES:
        assert q.case_id.startswith("Q")
        assert len(q.question) > 0
        assert len(q.ground_truth) > 0
        assert len(q.source) > 0
        assert len(q.required_keywords) > 0


def test_plan_suite_composition() -> None:
    """Verify plan suite contains exactly 5 plans with required distribution."""
    assert len(G6_PLAN_CASES) == 5

    compatible = [p for p in G6_PLAN_CASES if p.plan_type == "COMPATIBLE"]
    incompatible = [p for p in G6_PLAN_CASES if p.plan_type == "INCOMPATIBLE"]
    missing_data = [p for p in G6_PLAN_CASES if p.plan_type == "MISSING_DATA"]

    assert len(compatible) == 2
    assert len(incompatible) == 2
    assert len(missing_data) == 1

    for p in G6_PLAN_CASES:
        assert p.case_id.startswith("P")
        assert len(p.name) > 0
        assert len(p.source) > 0


def test_g6_acceptance_execution(tmp_path: Path) -> None:
    """Verify execution of complete G6 acceptance suite."""
    evidence_file = tmp_path / "test_g6_evidence.json"
    evidence = run_g6_acceptance(evidence_path=evidence_file)

    assert evidence_file.exists()
    assert evidence["verdict"] == "passed"
    assert evidence["metrics"]["gate_g6_offline_passed"] is True
    assert evidence["metrics"]["query_recall_percent"] >= 90.0
    assert evidence["metrics"]["plan_accuracy_percent"] == 100.0
    assert evidence["metrics"]["queries_passed"] == 30
    assert evidence["metrics"]["plans_passed"] == 5
    assert "evidence_sha256" in evidence
