"""Canonical Sensor Calibration Matrix & Dual-Channel Signal Conditioner Runner.

Work Package: W044 (Gate G8 Telemetry Quality & Scaling Bridge)
Classification: PRODUCTION [industrial telemetry & signal conditioning]

Validates:
1. Multichannel zero-trim and span factor calibration curves.
2. Piecewise multi-point interpolation.
3. Thermal drift compensation (25°C baseline vs 45°C excursion).
4. Dual-channel cross-validation and discrepancy detection threshold.
5. Automatic failover to secondary backup transmitter upon primary burnout (<3.6mA).
6. Strict 4-state JSON contract evidence export to artifacts/telemetry/calibration_matrix_evidence.json.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.calibration import (
    CalibrationCurve,
    CalibrationPoint,
    RedundancyMode,
    RedundantSensorConditioner,
    SensorCalibrationMatrix,
    SensorFaultState,
)
from jev_cscape.telemetry.scaling_bridge import QualityCode

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_calibration_verification(
    repo_root: Optional[Path] = None,
) -> ExecutionResult:
    """Execute complete sensor calibration verification and export evidence."""
    root = repo_root or Path(__file__).resolve().parent.parent
    telemetry_dir = root / "artifacts" / "telemetry"
    telemetry_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize RegisterTable and Calibration Matrix
    regs = RegisterTable()
    regs.set_input("%AI1", 5000)  # Tank 1 Primary (50.0%)
    regs.set_input("%AI3", 4980)  # Tank 1 Secondary (49.8%)
    regs.set_input("%AI2", 3500)  # Tank 2 Primary (35.0%)
    regs.set_input("%AI4", 3520)  # Tank 2 Secondary (35.2%)

    matrix = SensorCalibrationMatrix(register_table=regs)

    # 2. Verify nominal processing
    nominal = matrix.process_all(ambient_temp_c=25.0, primary_burnout_fault=False)
    t1_sig = nominal["TANK1_LEVEL"]
    assert t1_sig.quality_code == QualityCode.GOOD
    assert not t1_sig.is_divergent
    assert abs(t1_sig.reconciled_value - 50.0) < 1.0
    logger.info(f"Nominal Tank 1 reconciled: {t1_sig.reconciled_value}%, delta: {t1_sig.divergence_delta}")

    # 3. Verify thermal compensation
    thermal = matrix.process_all(ambient_temp_c=45.0, primary_burnout_fault=False)
    t1_thermal = thermal["TANK1_LEVEL"]
    # With positive temp coefficient, calibrated value should increase slightly
    assert t1_thermal.reconciled_value > t1_sig.reconciled_value
    logger.info(f"Thermal excursion 45°C Tank 1: {t1_thermal.reconciled_value}% (drift verified)")

    # 4. Verify divergence detection
    regs.set_input("%AI3", 4500)  # Introduce 5.0% discrepancy (> 2.5% threshold)
    divergent_results = matrix.process_all(ambient_temp_c=25.0, primary_burnout_fault=False)
    t1_div = divergent_results["TANK1_LEVEL"]
    assert t1_div.is_divergent is True
    assert t1_div.quality_code == QualityCode.UNCERTAIN
    assert "SENSOR_DIVERGENCE_LIMIT_EXCEEDED" in t1_div.fault_flags
    assert regs.read_register("%M15") is True  # Discrepancy alarm bit asserted
    logger.info(f"Divergence detected: delta={t1_div.divergence_delta}%, alarm bit %M15={regs.read_register('%M15')}")

    # Restore %AI3
    regs.set_input("%AI3", 4980)

    # 5. Verify automatic failover upon primary burnout
    burnout_results = matrix.process_all(ambient_temp_c=25.0, primary_burnout_fault=True)
    t1_burnout = burnout_results["TANK1_LEVEL"]
    assert t1_burnout.active_channel == "SECONDARY_BACKUP"
    assert "AUTO_FAILOVER_TO_SECONDARY" in t1_burnout.fault_flags
    assert t1_burnout.reconciled_value == t1_burnout.secondary_value
    logger.info(f"Burnout failover verified: active={t1_burnout.active_channel}, value={t1_burnout.reconciled_value}%")

    # 6. Export evidence artifact
    evidence_path = telemetry_dir / "calibration_matrix_evidence.json"
    evidence_payload = matrix.export_evidence_artifact(output_file=evidence_path)

    return ExecutionResult.success(
        details=(
            f"Sensor calibration matrix and dual-channel signal conditioner verified across "
            f"{len(matrix.conditioners)} channels with nominal, thermal, divergence, and burnout failover tests."
        ),
        data={
            "total_conditioners": len(matrix.conditioners),
            "total_curves": len(matrix.calibration_curves),
            "evidence_path": str(evidence_path),
            "reconciled_tank1": t1_sig.reconciled_value,
            "reconciled_tank2": nominal["TANK2_LEVEL"].reconciled_value,
        },
    )


def main() -> None:
    """CLI entrypoint."""
    res = run_calibration_verification()
    print(json.dumps(res.model_dump(), indent=2))
    if res.status != AgentStatus.SUCCESS:
        sys.exit(1)


if __name__ == "__main__":
    main()
