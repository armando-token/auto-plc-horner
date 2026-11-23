"""Unit Tests for HMI Recipe and Batch Parameter Management Subsystem.

Work Package: HMI / Supervisory Control
Classification: INDUSTRIAL_RECIPES & RECIPE_MANAGEMENT

Tests:
1. RecipeParameter validation, bounds checking, %R register enforcement, and type constraints.
2. RecipeDefinition parameter schema, lookup, and record validation.
3. Atomic recipe download to RegisterTable with transactional rollback on out-of-range values.
4. Snapshot capture from live Horner OCS %R register memory into new RecipeRecords.
5. JSON round-trip serialization and deserialization (file and string).
6. Canonical Water Treatment recipes verification (Low Flow, Normal Flow, Storm Surge Batch).
"""

import json
from pathlib import Path
import pytest

from jev_cscape.hmi.recipes import (
    RecipeDataType,
    RecipeDefinition,
    RecipeManager,
    RecipeNotFoundError,
    RecipeParameter,
    RecipeRecord,
    RecipeValidationError,
    create_canonical_water_treatment_manager,
)
from jev_cscape.simulation.register_table import RegisterTable


class TestRecipeParameter:
    """Tests for RecipeParameter definition, bounds validation, and data typing."""

    def test_valid_parameter_creation(self):
        param = RecipeParameter(
            name="tank_level",
            register_address="%R100",
            data_type=RecipeDataType.REAL,
            min_value=0.0,
            max_value=100.0,
            default_value=50.0,
            engineering_units="%",
            description="Tank level setpoint",
        )
        assert param.name == "tank_level"
        assert param.register_address == "%R100"
        assert param.data_type == RecipeDataType.REAL
        assert param.min_value == 0.0
        assert param.max_value == 100.0
        assert param.default_value == 50.0
        assert param.engineering_units == "%"

    def test_reject_non_r_register_addresses(self):
        """Recipe parameters must map strictly to Horner %R holding registers."""
        with pytest.raises(ValueError, match="%R"):
            RecipeParameter(
                name="invalid_input",
                register_address="%AI1",
                data_type=RecipeDataType.INT,
                min_value=0,
                max_value=32000,
                default_value=0,
            )

        with pytest.raises(ValueError, match="%R"):
            RecipeParameter(
                name="invalid_coil",
                register_address="%Q1",
                data_type=RecipeDataType.BOOL,
                min_value=0,
                max_value=1,
                default_value=0,
            )

    def test_reject_inverted_bounds_or_invalid_default(self):
        # min > max
        with pytest.raises(ValueError, match="cannot exceed max_value"):
            RecipeParameter(
                name="bad_bounds",
                register_address="%R10",
                min_value=100.0,
                max_value=50.0,
                default_value=75.0,
            )

        # default < min
        with pytest.raises(ValueError, match="must be within"):
            RecipeParameter(
                name="bad_default_low",
                register_address="%R10",
                min_value=10.0,
                max_value=50.0,
                default_value=5.0,
            )

        # default > max
        with pytest.raises(ValueError, match="must be within"):
            RecipeParameter(
                name="bad_default_high",
                register_address="%R10",
                min_value=10.0,
                max_value=50.0,
                default_value=60.0,
            )

    def test_value_validation_and_bounds_checking(self):
        param = RecipeParameter(
            name="flow_rate",
            register_address="%R101",
            data_type=RecipeDataType.REAL,
            min_value=0.0,
            max_value=25.0,
            default_value=10.0,
            engineering_units="m3/h",
        )
        assert param.validate_value(15.5) == 15.5
        assert param.validate_value("12.3") == 12.3

        # Out-of-bounds values
        with pytest.raises(RecipeValidationError, match="out of range"):
            param.validate_value(30.0)

        with pytest.raises(RecipeValidationError, match="out of range"):
            param.validate_value(-1.0)

        # NaN / Infinity / None
        with pytest.raises(RecipeValidationError, match="cannot be None"):
            param.validate_value(None)

        with pytest.raises(RecipeValidationError, match="NaN or Infinity"):
            param.validate_value(float("nan"))

    def test_integer_types_validation(self):
        # 16-bit INT
        int_param = RecipeParameter(
            name="int_param",
            register_address="%R201",
            data_type=RecipeDataType.INT,
            min_value=-1000,
            max_value=1000,
            default_value=0,
        )
        assert int_param.validate_value(500) == 500
        assert int_param.validate_value(-250) == -250

        # 16-bit UINT
        uint_param = RecipeParameter(
            name="uint_param",
            register_address="%R202",
            data_type=RecipeDataType.UINT,
            min_value=0,
            max_value=50000,
            default_value=1000,
        )
        assert uint_param.validate_value(45000) == 45000

        # 32-bit DINT
        dint_param = RecipeParameter(
            name="dint_param",
            register_address="%R203",
            data_type=RecipeDataType.DINT,
            min_value=-100000,
            max_value=100000,
            default_value=0,
        )
        assert dint_param.validate_value(86400) == 86400

        # Discrete BOOL
        bool_param = RecipeParameter(
            name="bool_param",
            register_address="%R205.1",
            data_type=RecipeDataType.BOOL,
            min_value=0,
            max_value=1,
            default_value=1,
        )
        assert bool_param.validate_value(True) is True
        assert bool_param.validate_value(False) is False
        assert bool_param.validate_value("true") is True


class TestRecipeDefinitionAndRecord:
    """Tests for RecipeDefinition schema and RecipeRecord validation."""

    @pytest.fixture
    def sample_definition(self) -> RecipeDefinition:
        return RecipeDefinition(
            recipe_id="DOSING_RECIPE",
            recipe_name="Chemical Dosing Recipe",
            description="Controls chemical dosing parameters",
            version="1.2.0",
            parameters=[
                RecipeParameter(
                    name="dose_rate",
                    register_address="%R10",
                    data_type=RecipeDataType.REAL,
                    min_value=0.0,
                    max_value=50.0,
                    default_value=10.0,
                    engineering_units="mg/L",
                ),
                RecipeParameter(
                    name="pump_rpm",
                    register_address="%R12",
                    data_type=RecipeDataType.INT,
                    min_value=100,
                    max_value=3000,
                    default_value=1200,
                    engineering_units="rpm",
                ),
            ],
        )

    def test_parameter_lookup(self, sample_definition: RecipeDefinition):
        assert sample_definition.has_parameter("dose_rate")
        assert sample_definition.has_parameter("pump_rpm")
        assert not sample_definition.has_parameter("unknown_param")
        assert sample_definition.get_parameter("dose_rate") is not None
        assert sample_definition.get_parameter("non_existent") is None

    def test_validate_record_valid(self, sample_definition: RecipeDefinition):
        record = RecipeRecord(
            record_id="REC_001",
            recipe_id="DOSING_RECIPE",
            values={"dose_rate": 25.0, "pump_rpm": 1800},
        )
        validated = sample_definition.validate_record(record)
        assert validated["dose_rate"] == 25.0
        assert validated["pump_rpm"] == 1800

    def test_validate_record_default_fill(self, sample_definition: RecipeDefinition):
        # Missing pump_rpm should be populated from default_value (1200)
        record = RecipeRecord(
            record_id="REC_002",
            recipe_id="DOSING_RECIPE",
            values={"dose_rate": 15.0},
        )
        validated = sample_definition.validate_record(record)
        assert validated["dose_rate"] == 15.0
        assert validated["pump_rpm"] == 1200

    def test_validate_record_unknown_parameter_rejected(self, sample_definition: RecipeDefinition):
        record = RecipeRecord(
            record_id="REC_BAD",
            recipe_id="DOSING_RECIPE",
            values={"dose_rate": 10.0, "unregistered_param": 99.0},
        )
        with pytest.raises(RecipeValidationError, match="Unknown parameter"):
            sample_definition.validate_record(record)

    def test_validate_record_out_of_bounds_rejected(self, sample_definition: RecipeDefinition):
        record = RecipeRecord(
            record_id="REC_BAD_VALUE",
            recipe_id="DOSING_RECIPE",
            values={"dose_rate": 150.0},  # max is 50.0
        )
        with pytest.raises(RecipeValidationError, match="out of range"):
            sample_definition.validate_record(record)


class TestAtomicDownloadWithRollback:
    """Tests for stage_recipe_to_registers with atomic download and rollback guarantees."""

    @pytest.fixture
    def manager_and_table(self):
        manager = RecipeManager()
        defn = RecipeDefinition(
            recipe_id="BATCH_PROCESS",
            recipe_name="Batch Process",
            parameters=[
                RecipeParameter(
                    name="temp_sp",
                    register_address="%R50",
                    data_type=RecipeDataType.REAL,
                    min_value=20.0,
                    max_value=120.0,
                    default_value=75.0,
                ),
                RecipeParameter(
                    name="pressure_sp",
                    register_address="%R52",
                    data_type=RecipeDataType.REAL,
                    min_value=0.0,
                    max_value=10.0,
                    default_value=2.5,
                ),
                RecipeParameter(
                    name="stir_speed",
                    register_address="%R54",
                    data_type=RecipeDataType.INT,
                    min_value=0,
                    max_value=1500,
                    default_value=500,
                ),
            ],
        )
        manager.register_definition(defn)
        table = RegisterTable()
        return manager, table

    def test_successful_staging_and_commit(self, manager_and_table):
        manager, table = manager_and_table

        record = manager.create_record(
            recipe_id="BATCH_PROCESS",
            values={"temp_sp": 85.0, "pressure_sp": 4.0, "stir_speed": 750},
            record_id="BATCH_01",
        )

        res = manager.stage_recipe_to_registers(record, table, commit=True)
        assert res["status"] == "success"
        assert res["committed"] is True
        assert manager.active_record_id == "BATCH_01"

        # Verify registers in table
        assert pytest.approx(table.read_real("%R50"), rel=1e-4) == 85.0
        assert pytest.approx(table.read_real("%R52"), rel=1e-4) == 4.0
        assert table.read_word("%R54") == 750

    def test_atomic_rollback_on_out_of_range_parameter(self, manager_and_table):
        """When an out-of-range parameter is encountered during staging,
        all staged modifications must be rolled back, leaving registers unchanged."""
        manager, table = manager_and_table

        # Pre-seed registers with baseline values
        table.write_real("%R50", 50.0)
        table.write_real("%R52", 1.5)
        table.write_word("%R54", 300)
        table.commit_staged()

        assert pytest.approx(table.read_real("%R50"), rel=1e-4) == 50.0
        assert pytest.approx(table.read_real("%R52"), rel=1e-4) == 1.5
        assert table.read_word("%R54") == 300

        # Create record where temp_sp is valid (85.0), but stir_speed exceeds max (5000 > 1500)
        bad_record = RecipeRecord(
            record_id="BATCH_INVALID",
            recipe_id="BATCH_PROCESS",
            values={"temp_sp": 85.0, "pressure_sp": 3.0, "stir_speed": 5000},
        )

        with pytest.raises(RecipeValidationError, match="out of range"):
            manager.stage_recipe_to_registers(bad_record, table, commit=True)

        # Verify atomic rollback: temp_sp must NOT be 85.0; it must be rolled back to 50.0
        assert pytest.approx(table.read_real("%R50"), rel=1e-4) == 50.0
        assert pytest.approx(table.read_real("%R52"), rel=1e-4) == 1.5
        assert table.read_word("%R54") == 300
        # Staged writes must be empty
        assert len(table.staged_writes) == 0

    def test_atomic_rollback_on_first_parameter_invalid(self, manager_and_table):
        """If the first parameter is out-of-bounds, no registers are mutated."""
        manager, table = manager_and_table

        table.write_real("%R50", 60.0)
        table.commit_staged()

        bad_record = RecipeRecord(
            record_id="BATCH_BAD_TEMP",
            recipe_id="BATCH_PROCESS",
            values={"temp_sp": 500.0, "pressure_sp": 2.0, "stir_speed": 200},  # temp max is 120
        )

        with pytest.raises(RecipeValidationError, match="out of range"):
            manager.stage_recipe_to_registers(bad_record, table)

        assert pytest.approx(table.read_real("%R50"), rel=1e-4) == 60.0
        assert len(table.staged_writes) == 0


class TestSnapshotRegistersToRecipe:
    """Tests for snapshotting live Horner %R registers into a new RecipeRecord."""

    def test_snapshot_from_registers(self):
        manager = create_canonical_water_treatment_manager()
        table = RegisterTable()

        # Write custom process values directly into the register table
        table.write_real("%R101", 12.5)     # inflow_setpoint
        table.write_real("%R103", 62.0)     # tank_level_target
        table.write_word("%R105", 22000)    # pump_speed_setpoint
        table.write_real("%R106", 65.0)     # discharge_valve_pos
        table.write_real("%R108", 6.8)      # chemical_dose_ppm
        table.write_real("%R110", 85.0)     # coagulant_dose_ml_min
        table.write_real("%R112", 88.0)     # hi_level_alarm_limit
        table.write_real("%R114", 18.0)     # lo_level_alarm_limit
        table.write_dint("%R116", 5400)     # filter_backwash_interval_s
        table.write_word("%R118", 900)      # batch_cycle_time_s
        table.write_word("%R120", 1)        # auto_mode_enable
        table.commit_staged()

        # Capture snapshot from registers
        captured_record = manager.snapshot_registers_to_recipe(
            recipe_id="WATER_TREATMENT_PROCESS",
            register_table=table,
            record_id="WT_FIELD_SNAPSHOT_01",
            description="Field calibration capture",
        )

        assert captured_record.record_id == "WT_FIELD_SNAPSHOT_01"
        assert captured_record.recipe_id == "WATER_TREATMENT_PROCESS"
        assert captured_record.description == "Field calibration capture"

        assert pytest.approx(captured_record.values["inflow_setpoint"], rel=1e-3) == 12.5
        assert pytest.approx(captured_record.values["tank_level_target"], rel=1e-3) == 62.0
        assert captured_record.values["pump_speed_setpoint"] == 22000
        assert pytest.approx(captured_record.values["discharge_valve_pos"], rel=1e-3) == 65.0
        assert pytest.approx(captured_record.values["chemical_dose_ppm"], rel=1e-3) == 6.8
        assert pytest.approx(captured_record.values["coagulant_dose_ml_min"], rel=1e-3) == 85.0
        assert pytest.approx(captured_record.values["hi_level_alarm_limit"], rel=1e-3) == 88.0
        assert pytest.approx(captured_record.values["lo_level_alarm_limit"], rel=1e-3) == 18.0
        assert captured_record.values["filter_backwash_interval_s"] == 5400
        assert captured_record.values["batch_cycle_time_s"] == 900
        assert captured_record.values["auto_mode_enable"] is True

        # Ensure the captured record was saved in manager
        assert manager.get_record("WT_FIELD_SNAPSHOT_01") is captured_record


class TestJsonRoundTripSerialization:
    """Tests for exporting and importing recipes to/from JSON."""

    def test_json_string_round_trip(self):
        manager = create_canonical_water_treatment_manager()
        json_str = manager.export_to_json(indent=2)

        # Deserialize into a fresh manager
        restored = RecipeManager.from_json(json_str)

        assert set(restored.definitions.keys()) == set(manager.definitions.keys())
        assert set(restored.records.keys()) == set(manager.records.keys())

        orig_wt = manager.get_record("WT_NORMAL_FLOW")
        rest_wt = restored.get_record("WT_NORMAL_FLOW")
        assert orig_wt.record_id == rest_wt.record_id
        assert orig_wt.values == rest_wt.values

    def test_json_file_round_trip(self, tmp_path: Path):
        manager = create_canonical_water_treatment_manager()
        filepath = tmp_path / "test_recipes.json"

        manager.export_to_json(filepath=filepath)
        assert filepath.exists()

        restored = RecipeManager.from_json(filepath)
        assert len(restored.definitions) == len(manager.definitions)
        assert len(restored.records) == len(manager.records)

        # Re-staging from restored manager works cleanly
        table = RegisterTable()
        storm = restored.get_record("WT_STORM_SURGE")
        res = restored.stage_recipe_to_registers(storm, table)
        assert res["status"] == "success"
        assert pytest.approx(table.read_real("%R101"), rel=1e-4) == 22.0
        assert table.read_word("%R105") == 31000


class TestCanonicalWaterTreatmentRecipes:
    """Tests for the canonical Water Treatment recipes and plant_recipes.json artifact."""

    def test_canonical_recipes_structure(self):
        manager = create_canonical_water_treatment_manager()
        assert "WATER_TREATMENT_PROCESS" in manager.definitions

        records = manager.list_records("WATER_TREATMENT_PROCESS")
        assert len(records) == 3

        record_ids = {r.record_id for r in records}
        assert record_ids == {"WT_LOW_FLOW", "WT_NORMAL_FLOW", "WT_STORM_SURGE"}

        # Validate that all 3 records comply with the schema
        definition = manager.get_definition("WATER_TREATMENT_PROCESS")
        for rec in records:
            validated = definition.validate_record(rec)
            assert len(validated) == len(definition.parameters)

    def test_stage_all_three_canonical_recipes(self):
        manager = create_canonical_water_treatment_manager()
        table = RegisterTable()

        # 1. Low Flow
        rec_low = manager.get_record("WT_LOW_FLOW")
        manager.stage_recipe_to_registers(rec_low, table)
        assert pytest.approx(table.read_real("%R101"), rel=1e-4) == 3.5
        assert pytest.approx(table.read_real("%R103"), rel=1e-4) == 35.0
        assert table.read_word("%R105") == 8000
        assert table.read_dint("%R116") == 7200

        # 2. Normal Flow
        rec_norm = manager.get_record("WT_NORMAL_FLOW")
        manager.stage_recipe_to_registers(rec_norm, table)
        assert pytest.approx(table.read_real("%R101"), rel=1e-4) == 8.5
        assert pytest.approx(table.read_real("%R103"), rel=1e-4) == 50.0
        assert table.read_word("%R105") == 16000
        assert table.read_dint("%R116") == 3600

        # 3. Storm Surge
        rec_storm = manager.get_record("WT_STORM_SURGE")
        manager.stage_recipe_to_registers(rec_storm, table)
        assert pytest.approx(table.read_real("%R101"), rel=1e-4) == 22.0
        assert pytest.approx(table.read_real("%R103"), rel=1e-4) == 75.0
        assert table.read_word("%R105") == 31000
        assert table.read_dint("%R116") == 1800

    def test_artifact_plant_recipes_json_exists_and_valid(self):
        artifact_path = Path("artifacts/HMI/plant_recipes.json")
        assert artifact_path.exists(), "artifacts/HMI/plant_recipes.json must exist"

        content = artifact_path.read_text(encoding="utf-8")
        data = json.loads(content)
        assert "definitions" in data
        assert "records" in data
        assert "WATER_TREATMENT_PROCESS" in data["definitions"]
        assert "WT_LOW_FLOW" in data["records"]
        assert "WT_NORMAL_FLOW" in data["records"]
        assert "WT_STORM_SURGE" in data["records"]

        # Validate with manager
        manager = RecipeManager.from_json(artifact_path)
        assert len(manager.definitions) >= 1
        assert len(manager.records) >= 3
