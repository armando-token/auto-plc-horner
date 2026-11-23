"""Unit tests for Gate G12 Offline Technical Delivery, Horner Dossier & Closure (W091-W094 + W098)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.g12_release_campaign import (
    EXPECTED_BASELINE_CSP_SHA256,
    REPO_ROOT,
    evaluate_g12_hardware_bank,
    run_g12_release_campaign,
    verify_w091_clean_install_and_lockfiles,
    verify_w092_user_package_docs,
    verify_w093_horner_dossier_and_index,
    verify_w094_release_review,
)


def test_w091_clean_install_lockfiles_and_non_redistribution() -> None:
    res = verify_w091_clean_install_and_lockfiles(REPO_ROOT)
    assert res["status"] == "success", res["details"]
    assert res["error_code"] is None
    data = res["data"]
    assert data["proprietary_binaries_redistributed"] is False
    assert data["locked_packages_count"] == 16
    assert data["package_mismatches"] == []
    assert data["baseline_csp"]["sha256"] == EXPECTED_BASELINE_CSP_SHA256
    assert data["baseline_csp"]["verified"] is True
    assert data["binary_mismatches"] == []
    assert "Cscape.exe" in data["external_binaries"]
    assert (
        data["external_binaries"]["Cscape.exe"]["sha256"]
        == "4b82560db103b4f26a9163bee3ae29439712c1c69ccaac11d0e898e51dcde405"
    )


def test_w092_user_package_docs_and_honest_limitations() -> None:
    res = verify_w092_user_package_docs(REPO_ROOT)
    assert res["status"] == "success", res["details"]
    assert res["error_code"] is None
    checks = res["data"]["content_checks"]
    assert checks["env_example_has_placeholder_key"] is True
    assert checks["env_example_has_g12_bank_blocked"] is True
    assert checks["limitations_documents_4h_vs_24h"] is True
    assert checks["limitations_documents_g12_bank_blocked"] is True
    assert checks["limitations_documents_blocked_native_st_ld"] is True
    assert checks["limitations_documents_w5editst_opacity"] is True
    assert checks["limitations_documents_stop_and_recover"] is True
    assert checks["demo_documents_baseline_sha"] is True


def test_w093_horner_dossier_and_evidence_index() -> None:
    res = verify_w093_horner_dossier_and_index(REPO_ROOT)
    assert res["status"] == "success", res["details"]
    assert res["error_code"] is None
    assert res["data"]["indexed_artifact_count"] == 16
    assert res["data"]["collaboration_questions_count"] == 6
    assert res["data"]["missing_artifacts"] == []

    index_path = REPO_ROOT / "artifacts" / "G12" / "w093_horner_evidence_index.json"
    assert index_path.exists()
    index_json = json.loads(index_path.read_text(encoding="utf-8"))
    assert index_json["status"] == "success"
    assert len(index_json["gate_evidence_index"]) == 16
    assert len(index_json["horner_collaboration_questions"]) == 6


def test_w094_release_review_secrets_licenses_and_coherence() -> None:
    res = verify_w094_release_review(REPO_ROOT)
    assert res["status"] == "success", res["details"]
    assert res["error_code"] is None
    sec = res["data"]["security_checks"]
    coh = res["data"]["coherence_checks"]
    assert all(sec.values()), f"Security checks failed: {sec}"
    assert all(coh.values()), f"Coherence checks failed: {coh}"
    assert res["data"]["tracked_env_files"] == []
    assert res["data"]["env_history_commits"] == []
    assert res["data"]["leaked_secrets"] == []
    assert res["data"]["tracked_proprietary_binaries"] == []
    assert res["data"]["git_remotes"] == []


def test_g12_hardware_bank_strictly_blocked() -> None:
    bank = evaluate_g12_hardware_bank(REPO_ROOT)
    assert bank["status"] == "blocked"
    assert bank["error_code"] == "POL-G12-COMMISSIONING-LOCKOUT"
    assert bank["data"]["G12_bank"] == "blocked"
    assert bank["data"]["plc_connected"] is False
    for wp_id in ("W095", "W096", "W097"):
        assert bank["data"]["work_packages"][wp_id]["status"] == "blocked"


def test_full_g12_offline_release_campaign_and_w098_closure() -> None:
    report = run_g12_release_campaign(REPO_ROOT)
    assert report["status"] == "success"
    assert report["error_code"] is None
    data = report["data"]
    assert data["mode"] == "offline_only"
    assert data["live_cscape_launched"] is False
    assert data["G12_bank"] == "blocked"
    assert data["verdict"] == "PASS"

    wps = data["work_packages"]
    for wp_id in ("W091", "W092", "W093", "W094", "W098"):
        assert wps[wp_id]["status"] == "success"
    for wp_id in ("W095", "W096", "W097"):
        assert wps[wp_id]["status"] == "blocked"

    assert len(wps["W098"]["data"]["v2_backlog"]) == 6

    report_path = REPO_ROOT / "artifacts" / "G12" / "g12_release_report.json"
    txt_path = REPO_ROOT / "artifacts" / "G12" / "g12_acceptance.txt"
    assert report_path.exists()
    assert txt_path.exists()
    txt = txt_path.read_text(encoding="utf-8")
    assert "OVERALL GATE G12 OFFLINE ACCEPTANCE VERDICT: PASS (G12_bank=blocked)" in txt
