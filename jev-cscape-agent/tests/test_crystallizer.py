"""Tests for Batch Vacuum Evaporative Crystallizer Population Balance Equations and MOM ODE Solver.

Work Package: W083 (Gate G7 / G4)
"""

import json
import os
import tempfile
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.crystallizer import (
    CrystallizerModel,
    CrystallizerParameters,
    CrystallizerStatusBits,
    CRYSTALLIZER_PURE_ST_POU,
    run_crystallizer_verification,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class TestCrystallizerPureST:
    def test_pure_st_pou_valid(self):
        result = STParser.validate_code(CRYSTALLIZER_PURE_ST_POU)
        assert result.status == AgentStatus.SUCCESS
        ast = STParser.parse_pou(CRYSTALLIZER_PURE_ST_POU)
        assert ast.name == "W083_CrystallizerPopulationBalance"
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {"%R440", "%R441", "%R442", "%R443", "%R444", "%R445", "%R446", "%R447", "%M102", "%M103", "%M104"}
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_forbidden_ladder_constructs_rejected(self):
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[/]--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad ---( )--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM Bad RUNG 1: XIC %M102 OTE %M103 END_RUNG END_PROGRAM")


class TestCrystallizerPhysics:
    def test_solubility_and_clapeyron(self):
        model = CrystallizerModel()
        c_star_50 = model.solubility(323.15)  # 50 °C
        c_star_60 = model.solubility(333.15)  # 60 °C
        assert c_star_60 > c_star_50 >= 250.0

        p_sat_50 = model.clapeyron_p_sat(323.15)
        p_sat_60 = model.clapeyron_p_sat(333.15)
        assert p_sat_60 > p_sat_50
        assert 10000.0 < p_sat_50 < 30000.0

    def test_fines_cutoff_analytical_fractions(self):
        model = CrystallizerModel()
        f0, f1, f2, f3, f4 = model.compute_fines_fractions(100.0e-6)
        # f0 should be largest, f4 smallest
        assert 0.0 < f4 < f3 < f2 < f1 < f0 < 1.0

    def test_dynamic_rk4_step(self):
        model = CrystallizerModel()
        m_start = model.get_metrics()
        for _ in range(60):
            model.step_rk4(dt=1.0)
        m_end = model.get_metrics()
        assert m_end["time_s"] == 60.0
        assert m_end["L_10_um"] >= m_start["L_10_um"]
        assert m_end["V_L_m3"] <= m_start["V_L_m3"]


class TestCrystallizerRegisterMapping:
    def test_register_sync(self):
        rt = RegisterTable()
        model = CrystallizerModel(register_table=rt)
        for _ in range(120):
            model.step_rk4(dt=1.0)

        # Check registers
        r440 = rt.read_word("%R440")
        r441 = rt.read_word("%R441")
        r442 = rt.read_word("%R442")
        r443 = rt.read_word("%R443")
        r444 = rt.read_word("%R444")
        r447 = rt.read_word("%R447")

        assert r440 > 0
        assert r441 > 0
        assert r442 > 0
        assert r443 > 1000  # > 100.0 um
        assert r444 > 0
        assert r447 & CrystallizerStatusBits.ACTIVE

    def test_simulation_disabled_when_m102_false(self):
        rt = RegisterTable()
        model = CrystallizerModel(register_table=rt)
        rt.write_bit("%M102", False, privilege=PrivilegeMode.SYSTEM)
        t_before = model.time_s
        model.step_rk4(dt=1.0)
        assert model.time_s == t_before

    def test_emergency_fines_dissolution_override(self):
        rt = RegisterTable()
        model = CrystallizerModel(register_table=rt)
        rt.write_bit("%M103", True, privilege=PrivilegeMode.SYSTEM)
        model.step_rk4(dt=1.0)
        assert model.fines_dissolve_override is True
        assert rt.read_word("%R447") & CrystallizerStatusBits.FINES_DISSOLUTION_ACTIVE

    def test_alarm_reset_handshake(self):
        rt = RegisterTable()
        model = CrystallizerModel(register_table=rt)
        rt.write_bit("%M104", True, privilege=PrivilegeMode.SYSTEM)
        model.sync_registers()
        assert rt.read_bit("%M104") is False

    def test_full_verification_runner(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            ev_path = os.path.join(tmp_dir, "crystallizer_evidence.json")
            evidence = run_crystallizer_verification(ev_path)
            assert evidence["status"] == "success"
            assert evidence["error_code"] is None
            assert os.path.exists(ev_path)
            with open(ev_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert len(data["data"]["tests"]) == 5
            assert all(t["passed"] for t in data["data"]["tests"])
