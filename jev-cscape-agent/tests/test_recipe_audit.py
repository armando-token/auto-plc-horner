"""Unit tests for RecipeAuditEngine (Gate G9/G5)."""

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.recipe_audit import (
    DiffType,
    DigitalSignoff,
    RecipeAuditEngine,
    RecipeLifecycleState,
    SignatureMeaning,
)
from jev_cscape.simulation.register_table import RegisterTable


@pytest.fixture
def audit_engine() -> RecipeAuditEngine:
    return RecipeAuditEngine()


@pytest.fixture
def clean_register_table() -> RegisterTable:
    return RegisterTable()


def test_genesis_block_initialization(audit_engine: RecipeAuditEngine):
    assert len(audit_engine.audit_chain) == 1
    genesis = audit_engine.audit_chain[0]
    assert genesis.record_index == 0
    assert genesis.action == "GENESIS"
    assert genesis.prev_hash == RecipeAuditEngine.GENESIS_HASH
    assert len(genesis.entry_hash) == 64


def test_create_draft_revision(audit_engine: RecipeAuditEngine):
    params = {"%R101": 500, "%R102": 1500, "%R103": 25}
    res = audit_engine.create_draft(
        recipe_id="WATER_BATCH_A",
        revision_id="REV_1",
        parameters=params,
        operator_id="OP_42",
        reason="First batch authoring",
    )
    assert res.status == AgentStatus.SUCCESS
    assert res.data["state"] == "DRAFT"
    assert len(audit_engine.audit_chain) == 2


def test_duplicate_draft_rejected(audit_engine: RecipeAuditEngine):
    params = {"%R101": 100}
    res1 = audit_engine.create_draft("RECIPE_1", "REV_1", params, "OP_1")
    assert res1.status == AgentStatus.SUCCESS

    res2 = audit_engine.create_draft("RECIPE_1", "REV_1", params, "OP_1")
    assert res2.status == AgentStatus.FAILED
    assert res2.error_code == "ERR_RECIPE_REVISION_EXISTS"


def test_parameter_diff_computation():
    old_p = {"%R101": 100, "%R102": 200, "%R103": 50}
    new_p = {"%R101": 150, "%R102": 200, "%R104": 75}

    diffs = RecipeAuditEngine.compute_diff(old_p, new_p)
    diff_map = {d.parameter_name: d for d in diffs}

    assert diff_map["%R101"].diff_type == DiffType.MODIFIED
    assert diff_map["%R101"].delta == 50.0
    assert diff_map["%R101"].percent_delta == 50.0

    assert diff_map["%R102"].diff_type == DiffType.UNCHANGED
    assert diff_map["%R103"].diff_type == DiffType.REMOVED
    assert diff_map["%R104"].diff_type == DiffType.ADDED


def test_signoff_and_approval(audit_engine: RecipeAuditEngine):
    params = {"%R101": 850}
    audit_engine.create_draft("RECIPE_1", "REV_1", params, "OP_1")

    signoff = DigitalSignoff(
        signer_id="SUP_07",
        signer_name="Alice QA",
        role="QA_MANAGER",
        meaning=SignatureMeaning.QUALITY_APPROVAL,
        comment="Validated against laboratory assay spec.",
    )
    res = audit_engine.sign_and_approve("RECIPE_1", "REV_1", signoff)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["state"] == "APPROVED"
    assert res.data["signer"] == "Alice QA"


def test_activate_recipe_and_synchronize_registers(
    audit_engine: RecipeAuditEngine,
    clean_register_table: RegisterTable,
):
    table = clean_register_table
    params = {"%R101": 850, "%R102": 4200}
    audit_engine.create_draft("RECIPE_1", "REV_1", params, "OP_1")

    signoff = DigitalSignoff(
        signer_id="SUP_07",
        signer_name="Alice QA",
        role="QA_MANAGER",
        meaning=SignatureMeaning.QUALITY_APPROVAL,
    )
    audit_engine.sign_and_approve("RECIPE_1", "REV_1", signoff)

    act_res = audit_engine.activate_recipe(
        "RECIPE_1",
        "REV_1",
        operator_id="OP_10",
        register_table=table,
    )
    assert act_res.status == AgentStatus.SUCCESS
    assert act_res.data["state"] == "ACTIVE"

    # Verify parameters synchronized to RegisterTable
    assert table.read_word("%R101") == 850
    assert table.read_word("%R102") == 4200


def test_atomic_rollback(
    audit_engine: RecipeAuditEngine,
    clean_register_table: RegisterTable,
):
    table = clean_register_table

    # Revision 1: golden baseline
    params_v1 = {"%R101": 100, "%R102": 200}
    audit_engine.create_draft("RECIPE_1", "REV_1", params_v1, "OP_1")
    sig1 = DigitalSignoff(
        signer_id="SUP_01",
        signer_name="Engineer One",
        role="ENGINEER",
        meaning=SignatureMeaning.QUALITY_APPROVAL,
    )
    audit_engine.sign_and_approve("RECIPE_1", "REV_1", sig1)
    audit_engine.activate_recipe("RECIPE_1", "REV_1", "OP_1", register_table=table)
    assert table.read_word("%R101") == 100

    # Revision 2: modified (higher setpoints)
    params_v2 = {"%R101": 999, "%R102": 888}
    audit_engine.create_draft("RECIPE_1", "REV_2", params_v2, "OP_1")
    sig2 = DigitalSignoff(
        signer_id="SUP_02",
        signer_name="Engineer Two",
        role="ENGINEER",
        meaning=SignatureMeaning.QUALITY_APPROVAL,
    )
    audit_engine.sign_and_approve("RECIPE_1", "REV_2", sig2)
    audit_engine.activate_recipe("RECIPE_1", "REV_2", "OP_1", register_table=table)
    assert table.read_word("%R101") == 999

    # Atomic Rollback to REV_1
    rollback_sig = DigitalSignoff(
        signer_id="QA_CHIEF",
        signer_name="Chief Inspector",
        role="QA_DIRECTOR",
        meaning=SignatureMeaning.QUALITY_APPROVAL,
        comment="Emergency regulatory rollback to baseline.",
    )
    rb_res = audit_engine.atomic_rollback(
        recipe_id="RECIPE_1",
        target_revision_id="REV_1",
        new_revision_id="REV_3_ROLLBACK",
        operator_id="QA_CHIEF",
        signoff=rollback_sig,
        register_table=table,
    )
    assert rb_res.status == AgentStatus.SUCCESS
    assert table.read_word("%R101") == 100
    assert table.read_word("%R102") == 200

    # Verify audit chain integrity
    report = audit_engine.verify_audit_chain()
    assert report["valid"] is True
    assert report["total_blocks"] > 4


def test_tamper_detection_in_audit_chain(audit_engine: RecipeAuditEngine):
    params = {"%R101": 50}
    audit_engine.create_draft("RECIPE_X", "REV_1", params, "OP_1")

    # Audit chain is valid before tampering
    assert audit_engine.verify_audit_chain()["valid"] is True

    # Tamper with block 1 operator_id
    audit_engine.audit_chain[1].operator_id = "MALICIOUS_ACTOR"

    # Verification must catch tamper
    tamper_report = audit_engine.verify_audit_chain()
    assert tamper_report["valid"] is False
    assert len(tamper_report["violations"]) > 0


def test_runner_recipe_audit_verification(tmp_path):
    from pathlib import Path
    from scripts.run_recipe_audit_verification import run_recipe_audit_verification
    repo_root = Path(__file__).resolve().parent.parent
    out_file = tmp_path / "recipe_audit_evidence.json"
    evidence = run_recipe_audit_verification(repo_root=repo_root, output_path=out_file)
    assert evidence["status"] == "success"
    assert out_file.exists()
    assert evidence["data"]["audit_summary"]["valid"] is True
