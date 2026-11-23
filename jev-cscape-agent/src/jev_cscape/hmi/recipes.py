"""Industrial Recipe and Batch Parameter Management Subsystem.

Work Package: HMI / Recipe Management
Classification: INDUSTRIAL_RECIPES & RECIPE_MANAGEMENT

Provides:
- RecipeDataType: Supported OCS data types (INT, UINT, WORD, DINT, UDINT, REAL, BOOL).
- RecipeParameter: Parameter definition with Horner %R register binding, bounds checking,
  default value, and engineering units.
- RecipeDefinition: Recipe schema and parameter inventory.
- RecipeRecord: Concrete recipe dataset / batch parameter setpoints.
- RecipeManager: Storage, validation, atomic register staging with rollback,
  snapshot capture, and JSON serialization.
"""

from __future__ import annotations

import datetime
from enum import Enum
import json
import math
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator

from jev_cscape.automation.channel_matrix import ChannelAccess
from jev_cscape.simulation.register_table import RegisterTable


class RecipeDataType(str, Enum):
    """Supported Horner OCS register data types for recipe parameters."""
    INT = "INT"       # 16-bit signed integer (-32768..32767)
    UINT = "UINT"     # 16-bit unsigned integer (0..65535)
    WORD = "WORD"     # 16-bit unsigned word (0..65535, alias for UINT)
    DINT = "DINT"     # 32-bit signed integer (-2147483648..2147483647, 2 consecutive %R words)
    UDINT = "UDINT"   # 32-bit unsigned integer (0..4294967295, 2 consecutive %R words)
    REAL = "REAL"     # 32-bit IEEE 754 float (2 consecutive %R words)
    BOOL = "BOOL"     # Discrete boolean (%R.bit or word 0/1)


class RecipeValidationError(ValueError):
    """Raised when a recipe parameter value violates engineering bounds or schema rules."""
    pass


class RecipeNotFoundError(KeyError):
    """Raised when a requested recipe definition or record is not found."""
    pass


class RecipeRegisterError(RuntimeError):
    """Raised when recipe register operations fail or encounter addressing faults."""
    pass


class RecipeParameter(BaseModel):
    """Industrial recipe parameter bound to a Horner OCS %R register.

    Defines engineering limits, data type, unit of measure, and default setpoint.
    """
    name: str = Field(..., description="Unique parameter identifier, e.g. 'inflow_setpoint'")
    register_address: str = Field(..., description="Horner OCS holding register, e.g. '%R101'")
    data_type: RecipeDataType = Field(default=RecipeDataType.REAL, description="Data type representation")
    min_value: float = Field(..., description="Minimum allowable engineering unit setpoint")
    max_value: float = Field(..., description="Maximum allowable engineering unit setpoint")
    default_value: float = Field(..., description="Default nominal setpoint")
    engineering_units: str = Field(default="", description="Engineering unit label, e.g. 'm3/h', '%', 'degC'")
    description: str = Field(default="", description="Human-readable parameter description")

    @field_validator("register_address")
    @classmethod
    def _validate_register_address(cls, v: str) -> str:
        clean = v.strip().upper()
        if not clean.startswith("%"):
            clean = "%" + clean
        if not clean.startswith("%R"):
            raise ValueError(f"Recipe parameter register must be a %R holding register, got '{v}'")
        # Validate format using RegisterTable address parser
        parsed = RegisterTable.parse_address(clean)
        if parsed.prefix != "%R":
            raise ValueError(f"Recipe parameter register must be a %R holding register, got '{clean}'")
        return clean

    @model_validator(mode="after")
    def _validate_bounds(self) -> RecipeParameter:
        if self.min_value > self.max_value:
            raise ValueError(
                f"min_value ({self.min_value}) cannot exceed max_value ({self.max_value}) for parameter '{self.name}'"
            )
        if self.default_value < self.min_value or self.default_value > self.max_value:
            raise ValueError(
                f"default_value ({self.default_value}) must be within [{self.min_value}, {self.max_value}] for parameter '{self.name}'"
            )
        return self

    def validate_value(self, value: Any) -> Union[float, int, bool]:
        """Validates that a candidate value complies with type constraints and [min, max] limits."""
        if value is None:
            raise RecipeValidationError(f"Parameter '{self.name}' value cannot be None")

        # String parsing
        if isinstance(value, str):
            try:
                if self.data_type == RecipeDataType.BOOL:
                    value = value.strip().lower() in ("true", "1", "yes", "on")
                elif self.data_type in (RecipeDataType.INT, RecipeDataType.UINT, RecipeDataType.WORD, RecipeDataType.DINT, RecipeDataType.UDINT):
                    value = int(value)
                else:
                    value = float(value)
            except (ValueError, TypeError) as err:
                raise RecipeValidationError(
                    f"Cannot parse '{value}' into {self.data_type.value} for parameter '{self.name}': {err}"
                )

        if self.data_type == RecipeDataType.BOOL:
            b_val = bool(value)
            num_val = 1.0 if b_val else 0.0
            if num_val < self.min_value or num_val > self.max_value:
                raise RecipeValidationError(
                    f"Parameter '{self.name}' boolean value {b_val} outside allowable range [{self.min_value}, {self.max_value}]"
                )
            return b_val

        # Handle numeric types
        if isinstance(value, bool):
            value = 1 if value else 0

        if not isinstance(value, (int, float)):
            raise RecipeValidationError(
                f"Parameter '{self.name}' expects numeric value, got {type(value).__name__}"
            )

        if math.isnan(value) or math.isinf(value):
            raise RecipeValidationError(f"Parameter '{self.name}' cannot be NaN or Infinity")

        # Range verification
        if value < self.min_value or value > self.max_value:
            raise RecipeValidationError(
                f"Parameter '{self.name}' value {value} out of range [{self.min_value}, {self.max_value}] {self.engineering_units}"
            )

        if self.data_type == RecipeDataType.REAL:
            return float(value)

        # Integer range verification
        int_val = int(round(value))
        if self.data_type == RecipeDataType.INT:
            if not (-32768 <= int_val <= 32767):
                raise RecipeValidationError(
                    f"Parameter '{self.name}' value {int_val} out of 16-bit INT bounds [-32768, 32767]"
                )
            return int_val
        elif self.data_type in (RecipeDataType.UINT, RecipeDataType.WORD):
            if not (0 <= int_val <= 65535):
                raise RecipeValidationError(
                    f"Parameter '{self.name}' value {int_val} out of 16-bit UINT bounds [0, 65535]"
                )
            return int_val
        elif self.data_type == RecipeDataType.DINT:
            if not (-2147483648 <= int_val <= 2147483647):
                raise RecipeValidationError(
                    f"Parameter '{self.name}' value {int_val} out of 32-bit DINT bounds [-2147483648, 2147483647]"
                )
            return int_val
        elif self.data_type == RecipeDataType.UDINT:
            if not (0 <= int_val <= 4294967295):
                raise RecipeValidationError(
                    f"Parameter '{self.name}' value {int_val} out of 32-bit UDINT bounds [0, 4294967295]"
                )
            return int_val

        return value


class RecipeRecord(BaseModel):
    """A concrete recipe record / batch instance containing parameter values."""
    record_id: str = Field(..., description="Unique record identifier, e.g. 'WT_LOW_FLOW'")
    recipe_id: str = Field(..., description="Associated recipe definition identifier")
    values: Dict[str, Union[float, int, bool]] = Field(default_factory=dict, description="Parameter name to value mapping")
    description: str = Field(default="", description="Batch / recipe record description")
    created_at: Optional[str] = Field(default=None, description="ISO timestamp of record creation")
    updated_at: Optional[str] = Field(default=None, description="ISO timestamp of last update")


class RecipeDefinition(BaseModel):
    """Recipe schema definition defining the inventory of parameters, ranges, and addresses."""
    recipe_id: str = Field(..., description="Unique recipe schema identifier, e.g. 'WATER_TREATMENT_PROCESS'")
    recipe_name: str = Field(..., description="Human-readable recipe name")
    description: str = Field(default="", description="Detailed schema description")
    version: str = Field(default="1.0.0", description="Semantic version string")
    parameters: List[RecipeParameter] = Field(default_factory=list, description="Ordered parameter list")

    def get_parameter(self, name: str) -> Optional[RecipeParameter]:
        """Look up a parameter definition by name."""
        for p in self.parameters:
            if p.name == name:
                return p
        return None

    def has_parameter(self, name: str) -> bool:
        """Check whether a parameter exists in this recipe definition."""
        return self.get_parameter(name) is not None

    def validate_values(self, values: Dict[str, Any]) -> Dict[str, Union[float, int, bool]]:
        """Validates an arbitrary dictionary of values against definition limits."""
        validated: Dict[str, Union[float, int, bool]] = {}
        param_map = {p.name: p for p in self.parameters}

        # Check for unknown parameters
        for k in values.keys():
            if k not in param_map:
                raise RecipeValidationError(
                    f"Unknown parameter '{k}' in values for recipe '{self.recipe_id}'"
                )

        # Validate all defined parameters (filling defaults if omitted)
        for p in self.parameters:
            if p.name in values:
                val = values[p.name]
            else:
                val = p.default_value
            validated[p.name] = p.validate_value(val)

        return validated

    def validate_record(self, record: RecipeRecord) -> Dict[str, Union[float, int, bool]]:
        """Validates all values in a RecipeRecord against definition limits."""
        if record.recipe_id != self.recipe_id:
            raise RecipeValidationError(
                f"Record recipe_id mismatch: expected '{self.recipe_id}', got '{record.recipe_id}'"
            )
        return self.validate_values(record.values)


class RecipeManager:
    """Industrial Recipe and Batch Parameter Manager for Horner OCS Automation.

    Provides storage, validation, atomic staging to %R registers with automatic rollback,
    snapshot capture from live registers, and JSON persistence.
    """

    def __init__(self) -> None:
        self.definitions: Dict[str, RecipeDefinition] = {}
        self.records: Dict[str, RecipeRecord] = {}
        self.active_record_id: Optional[str] = None

    def register_definition(self, definition: RecipeDefinition) -> None:
        """Registers a recipe schema definition."""
        self.definitions[definition.recipe_id] = definition

    def get_definition(self, recipe_id: str) -> RecipeDefinition:
        """Retrieves a recipe definition or raises RecipeNotFoundError."""
        if recipe_id not in self.definitions:
            raise RecipeNotFoundError(f"Recipe definition '{recipe_id}' not found.")
        return self.definitions[recipe_id]

    def list_definitions(self) -> List[RecipeDefinition]:
        """Returns all registered recipe definitions."""
        return list(self.definitions.values())

    def create_record(
        self,
        recipe_id: str,
        values: Dict[str, Any],
        record_id: Optional[str] = None,
        description: str = "",
    ) -> RecipeRecord:
        """Creates and stores a validated RecipeRecord."""
        definition = self.get_definition(recipe_id)
        validated_values = definition.validate_values(values)

        if record_id is None:
            record_id = f"{recipe_id}_REC_{len(self.records) + 1:03d}"

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record = RecipeRecord(
            record_id=record_id,
            recipe_id=recipe_id,
            values=validated_values,
            description=description,
            created_at=now,
            updated_at=now,
        )
        self.records[record_id] = record
        return record

    def add_record(self, record: RecipeRecord, validate: bool = True) -> None:
        """Adds an existing RecipeRecord with optional validation."""
        if validate:
            definition = self.get_definition(record.recipe_id)
            definition.validate_record(record)
        self.records[record.record_id] = record

    def get_record(self, record_id: str) -> RecipeRecord:
        """Retrieves a recipe record or raises RecipeNotFoundError."""
        if record_id not in self.records:
            raise RecipeNotFoundError(f"Recipe record '{record_id}' not found.")
        return self.records[record_id]

    def list_records(self, recipe_id: Optional[str] = None) -> List[RecipeRecord]:
        """Returns all recipe records, optionally filtered by recipe_id."""
        if recipe_id is None:
            return list(self.records.values())
        return [r for r in self.records.values() if r.recipe_id == recipe_id]

    # -------------------------------------------------------------------------
    # Register Operations: Atomic Staging & Rollback, Snapshot Capture
    # -------------------------------------------------------------------------

    def stage_recipe_to_registers(
        self,
        record: RecipeRecord,
        register_table: RegisterTable,
        commit: bool = True,
    ) -> Dict[str, Any]:
        """Atomically downloads recipe parameters to Horner OCS %R registers.

        Guarantees transactional atomicity:
        If any parameter value violates engineering bounds or if a register write fails,
        all staged writes are rolled back and register table memory is restored to its
        exact prior state before the method call.

        Returns a dictionary summary of the staging operation.
        """
        definition = self.get_definition(record.recipe_id)

        # 1. Capture snapshot before touching registers for atomic rollback guarantee
        initial_snap = register_table.snapshot()

        try:
            # 2. Check for unexpected parameter names
            for key in record.values:
                if not definition.has_parameter(key):
                    raise RecipeValidationError(
                        f"Unknown parameter '{key}' in recipe record '{record.record_id}'"
                    )

            # 3. Write each parameter; validate bounds on the fly
            written_registers: List[str] = []
            for param in definition.parameters:
                val = record.values.get(param.name, param.default_value)
                # Bounds and type validation: raises RecipeValidationError on out-of-range
                validated_val = param.validate_value(val)

                addr = param.register_address
                if param.data_type == RecipeDataType.REAL:
                    register_table.write_real(addr, float(validated_val))
                    w1, w2 = register_table.get_consecutive_addresses(addr, 2)
                    written_registers.extend([w1, w2])
                elif param.data_type == RecipeDataType.DINT:
                    register_table.write_dint(addr, int(validated_val))
                    w1, w2 = register_table.get_consecutive_addresses(addr, 2)
                    written_registers.extend([w1, w2])
                elif param.data_type == RecipeDataType.UDINT:
                    register_table.write_udint(addr, int(validated_val))
                    w1, w2 = register_table.get_consecutive_addresses(addr, 2)
                    written_registers.extend([w1, w2])
                elif param.data_type == RecipeDataType.INT:
                    register_table.write_word(addr, int(validated_val))
                    written_registers.append(addr)
                elif param.data_type in (RecipeDataType.UINT, RecipeDataType.WORD):
                    register_table.write_word(addr, int(validated_val) & 0xFFFF)
                    written_registers.append(addr)
                elif param.data_type == RecipeDataType.BOOL:
                    if "." in addr:
                        register_table.write_bit(addr, bool(validated_val))
                    else:
                        register_table.write_word(addr, 1 if validated_val else 0)
                    written_registers.append(addr)
                else:
                    register_table.write_word(addr, int(validated_val))
                    written_registers.append(addr)

            # 4. Commit staged memory if requested
            if commit:
                register_table.commit_staged()

            self.active_record_id = record.record_id

            return {
                "status": "success",
                "record_id": record.record_id,
                "recipe_id": record.recipe_id,
                "committed": commit,
                "written_registers": written_registers,
                "parameters_count": len(definition.parameters),
            }

        except Exception:
            # Atomic rollback: revert all staged changes and restore snapshot
            register_table.rollback_staged()
            register_table.restore_snapshot(initial_snap)
            raise

    def snapshot_registers_to_recipe(
        self,
        recipe_id: str,
        register_table: RegisterTable,
        record_id: Optional[str] = None,
        description: str = "",
    ) -> RecipeRecord:
        """Reads current %R values from register table and captures a new RecipeRecord."""
        definition = self.get_definition(recipe_id)
        values: Dict[str, Union[float, int, bool]] = {}

        for param in definition.parameters:
            addr = param.register_address
            if param.data_type == RecipeDataType.REAL:
                val = register_table.read_real(addr)
                values[param.name] = round(float(val), 4)
            elif param.data_type == RecipeDataType.DINT:
                values[param.name] = int(register_table.read_dint(addr))
            elif param.data_type == RecipeDataType.UDINT:
                values[param.name] = int(register_table.read_udint(addr))
            elif param.data_type == RecipeDataType.INT:
                values[param.name] = int(register_table.read_word(addr))
            elif param.data_type in (RecipeDataType.UINT, RecipeDataType.WORD):
                values[param.name] = int(register_table.read_uword(addr))
            elif param.data_type == RecipeDataType.BOOL:
                if "." in addr:
                    values[param.name] = bool(register_table.read_bit(addr))
                else:
                    values[param.name] = bool(register_table.read_word(addr))
            else:
                values[param.name] = register_table.read_word(addr)

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if record_id is None:
            record_id = f"{recipe_id}_SNAP_{int(time.time() * 1000)}"

        record = RecipeRecord(
            record_id=record_id,
            recipe_id=recipe_id,
            values=values,
            description=description or f"Snapshot captured from registers at {now}",
            created_at=now,
            updated_at=now,
        )
        self.records[record.record_id] = record
        return record

    # -------------------------------------------------------------------------
    # JSON Persistence & Serialization
    # -------------------------------------------------------------------------

    def export_to_dict(self) -> Dict[str, Any]:
        """Serializes all definitions and records to a plain dictionary."""
        return {
            "version": "1.0.0",
            "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "active_record_id": self.active_record_id,
            "definitions": {k: v.model_dump() for k, v in self.definitions.items()},
            "records": {k: v.model_dump() for k, v in self.records.items()},
        }

    def export_to_json(
        self,
        filepath: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Serializes manager state to a JSON string and optionally writes to file."""
        data = self.export_to_dict()
        json_str = json.dumps(data, indent=indent)

        if filepath is not None:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str, encoding="utf-8")

        return json_str

    def import_from_dict(self, data: Dict[str, Any]) -> None:
        """Loads definitions and records from a dictionary."""
        defs = data.get("definitions", {})
        for d_id, d_data in defs.items():
            self.definitions[d_id] = RecipeDefinition.model_validate(d_data)

        recs = data.get("records", {})
        for r_id, r_data in recs.items():
            self.records[r_id] = RecipeRecord.model_validate(r_data)

        if "active_record_id" in data:
            self.active_record_id = data.get("active_record_id")

    def import_from_json(self, json_str_or_filepath: Union[str, Path]) -> None:
        """Loads definitions and records from a JSON string or file path."""
        p = Path(str(json_str_or_filepath))
        if p.exists() and p.is_file():
            content = p.read_text(encoding="utf-8")
        else:
            content = str(json_str_or_filepath)

        data = json.loads(content)
        self.import_from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecipeManager:
        """Constructs a RecipeManager instance from a dictionary."""
        manager = cls()
        manager.import_from_dict(data)
        return manager

    @classmethod
    def from_json(cls, json_str_or_filepath: Union[str, Path]) -> RecipeManager:
        """Constructs a RecipeManager instance from a JSON string or file."""
        manager = cls()
        manager.import_from_json(json_str_or_filepath)
        return manager


def create_canonical_water_treatment_manager() -> RecipeManager:
    """Creates a RecipeManager pre-configured with canonical Water Treatment recipes.

    Recipes:
    1. Water Treatment Low Flow (WT_LOW_FLOW)
    2. Water Treatment Normal Flow (WT_NORMAL_FLOW)
    3. Storm Surge Batch (WT_STORM_SURGE)
    """
    manager = RecipeManager()

    water_treatment_def = RecipeDefinition(
        recipe_id="WATER_TREATMENT_PROCESS",
        recipe_name="Water Treatment Plant Process Setpoints",
        description="Industrial process setpoints and batch parameters for Horner OCS automated water treatment facility.",
        version="1.0.0",
        parameters=[
            RecipeParameter(
                name="inflow_setpoint",
                register_address="%R101",
                data_type=RecipeDataType.REAL,
                min_value=0.0,
                max_value=30.0,
                default_value=8.5,
                engineering_units="m3/h",
                description="Inlet raw water flow rate setpoint",
            ),
            RecipeParameter(
                name="tank_level_target",
                register_address="%R103",
                data_type=RecipeDataType.REAL,
                min_value=10.0,
                max_value=95.0,
                default_value=50.0,
                engineering_units="%",
                description="Buffer tank regulated liquid level target",
            ),
            RecipeParameter(
                name="pump_speed_setpoint",
                register_address="%R105",
                data_type=RecipeDataType.INT,
                min_value=0,
                max_value=32000,
                default_value=16000,
                engineering_units="counts",
                description="Main discharge pump VFD analog speed command (0..32000 counts)",
            ),
            RecipeParameter(
                name="discharge_valve_pos",
                register_address="%R106",
                data_type=RecipeDataType.REAL,
                min_value=0.0,
                max_value=100.0,
                default_value=50.0,
                engineering_units="%",
                description="Modulating discharge valve position setpoint",
            ),
            RecipeParameter(
                name="chemical_dose_ppm",
                register_address="%R108",
                data_type=RecipeDataType.REAL,
                min_value=0.5,
                max_value=25.0,
                default_value=5.0,
                engineering_units="ppm",
                description="Disinfectant / chlorine dosing target concentration",
            ),
            RecipeParameter(
                name="coagulant_dose_ml_min",
                register_address="%R110",
                data_type=RecipeDataType.REAL,
                min_value=5.0,
                max_value=200.0,
                default_value=45.0,
                engineering_units="mL/min",
                description="Coagulant polymer dosing rate for flocculation",
            ),
            RecipeParameter(
                name="hi_level_alarm_limit",
                register_address="%R112",
                data_type=RecipeDataType.REAL,
                min_value=60.0,
                max_value=98.0,
                default_value=85.0,
                engineering_units="%",
                description="High liquid level warning alarm trip threshold",
            ),
            RecipeParameter(
                name="lo_level_alarm_limit",
                register_address="%R114",
                data_type=RecipeDataType.REAL,
                min_value=5.0,
                max_value=40.0,
                default_value=20.0,
                engineering_units="%",
                description="Low liquid level warning alarm trip threshold",
            ),
            RecipeParameter(
                name="filter_backwash_interval_s",
                register_address="%R116",
                data_type=RecipeDataType.DINT,
                min_value=300,
                max_value=86400,
                default_value=3600,
                engineering_units="s",
                description="Automatic media filter backwash sequence trigger interval",
            ),
            RecipeParameter(
                name="batch_cycle_time_s",
                register_address="%R118",
                data_type=RecipeDataType.INT,
                min_value=30,
                max_value=7200,
                default_value=600,
                engineering_units="s",
                description="Duration of batch cycle sequence in seconds",
            ),
            RecipeParameter(
                name="auto_mode_enable",
                register_address="%R120",
                data_type=RecipeDataType.BOOL,
                min_value=0,
                max_value=1,
                default_value=1,
                engineering_units="bool",
                description="Master supervisory autonomous recipe execution enable flag",
            ),
        ],
    )

    manager.register_definition(water_treatment_def)

    # 1. Low Flow Recipe Record
    manager.add_record(
        RecipeRecord(
            record_id="WT_LOW_FLOW",
            recipe_id="WATER_TREATMENT_PROCESS",
            description="Water Treatment Low Flow: Off-peak / overnight low demand operating mode.",
            values={
                "inflow_setpoint": 3.5,
                "tank_level_target": 35.0,
                "pump_speed_setpoint": 8000,
                "discharge_valve_pos": 25.0,
                "chemical_dose_ppm": 2.5,
                "coagulant_dose_ml_min": 20.0,
                "hi_level_alarm_limit": 80.0,
                "lo_level_alarm_limit": 15.0,
                "filter_backwash_interval_s": 7200,
                "batch_cycle_time_s": 1200,
                "auto_mode_enable": True,
            },
        ),
        validate=True,
    )

    # 2. Normal Flow Recipe Record
    manager.add_record(
        RecipeRecord(
            record_id="WT_NORMAL_FLOW",
            recipe_id="WATER_TREATMENT_PROCESS",
            description="Water Treatment Normal Flow: Standard daytime nominal municipal water treatment mode.",
            values={
                "inflow_setpoint": 8.5,
                "tank_level_target": 50.0,
                "pump_speed_setpoint": 16000,
                "discharge_valve_pos": 50.0,
                "chemical_dose_ppm": 5.0,
                "coagulant_dose_ml_min": 45.0,
                "hi_level_alarm_limit": 85.0,
                "lo_level_alarm_limit": 20.0,
                "filter_backwash_interval_s": 3600,
                "batch_cycle_time_s": 600,
                "auto_mode_enable": True,
            },
        ),
        validate=True,
    )

    # 3. Storm Surge Batch Record
    manager.add_record(
        RecipeRecord(
            record_id="WT_STORM_SURGE",
            recipe_id="WATER_TREATMENT_PROCESS",
            description="Storm Surge Batch: High-throughput storm surge emergency batch processing mode.",
            values={
                "inflow_setpoint": 22.0,
                "tank_level_target": 75.0,
                "pump_speed_setpoint": 31000,
                "discharge_valve_pos": 95.0,
                "chemical_dose_ppm": 15.0,
                "coagulant_dose_ml_min": 140.0,
                "hi_level_alarm_limit": 95.0,
                "lo_level_alarm_limit": 30.0,
                "filter_backwash_interval_s": 1800,
                "batch_cycle_time_s": 300,
                "auto_mode_enable": True,
            },
        ),
        validate=True,
    )

    return manager
