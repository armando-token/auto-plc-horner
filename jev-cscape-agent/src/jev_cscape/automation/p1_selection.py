"""Horner P1 Controller Hardware Field Selection Model.

Encapsulates controller family, I/O model profiles (Model 1–6), register sizing,
and hardware configuration rules without requiring physical PLC connectivity.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ControllerSeries(str, Enum):
    """Horner OCS Controller Families supported in Cscape 10.2."""
    X_SERIES = "X_Series"
    XL_SERIES = "XL_Series"
    CANVAS_P1 = "Canvas_P1"
    RCC_SERIES = "RCC_Series"


class IOModelProfile(BaseModel):
    """Hardware I/O specification for a specific controller model."""
    model_number: int
    name: str
    digital_inputs: int
    digital_outputs: int
    analog_inputs: int
    analog_outputs: int
    relay_outputs: int = 0
    rtd_tc_channels: int = 0
    description: str


class ControllerTargetProfile(BaseModel):
    """Complete specification of a Horner OCS target hardware profile."""
    target_id: str
    series: ControllerSeries
    model_name: str
    part_number: str
    io_profile: IOModelProfile
    screen_resolution: str
    max_registers_r: int = 9999
    max_analog_in_ai: int = 512
    max_analog_out_aq: int = 512
    max_digital_in_i: int = 2048
    max_digital_out_q: int = 2048
    max_markers_m: int = 2048
    ethernet_ports: int = 1
    can_ports: int = 1
    serial_ports: int = 2


class P1FieldSelector:
    """Manages P1 controller selection and hardware validation matrices."""

    # Standard Horner P1 profiles
    PROFILES: Dict[str, ControllerTargetProfile] = {
        "P1_CANVAS_M1": ControllerTargetProfile(
            target_id="P1_CANVAS_M1",
            series=ControllerSeries.CANVAS_P1,
            model_name="Canvas 7 P1 Model 1",
            part_number="HE-CP7-M1",
            io_profile=IOModelProfile(
                model_number=1,
                name="Model 1",
                digital_inputs=12,
                digital_outputs=0,
                relay_outputs=6,
                analog_inputs=4,
                analog_outputs=0,
                description="12 DC In, 6 Relay Out, 4 Analog In (0-10V / 4-20mA)",
            ),
            screen_resolution="800x480",
        ),
        "P1_CANVAS_M2": ControllerTargetProfile(
            target_id="P1_CANVAS_M2",
            series=ControllerSeries.CANVAS_P1,
            model_name="Canvas 7 P1 Model 2",
            part_number="HE-CP7-M2",
            io_profile=IOModelProfile(
                model_number=2,
                name="Model 2",
                digital_inputs=12,
                digital_outputs=12,
                relay_outputs=0,
                analog_inputs=2,
                analog_outputs=0,
                description="12 DC In, 12 DC Out, 2 Analog In",
            ),
            screen_resolution="800x480",
        ),
        "P1_CANVAS_M3": ControllerTargetProfile(
            target_id="P1_CANVAS_M3",
            series=ControllerSeries.CANVAS_P1,
            model_name="Canvas 7 P1 Model 3",
            part_number="HE-CP7-M3",
            io_profile=IOModelProfile(
                model_number=3,
                name="Model 3",
                digital_inputs=12,
                digital_outputs=12,
                relay_outputs=0,
                analog_inputs=2,
                analog_outputs=2,
                description="12 DC In, 12 DC Out, 2 Analog In, 2 Analog Out",
            ),
            screen_resolution="800x480",
        ),
        "P1_CANVAS_M5": ControllerTargetProfile(
            target_id="P1_CANVAS_M5",
            series=ControllerSeries.CANVAS_P1,
            model_name="Canvas 7 P1 Model 5",
            part_number="HE-CP7-M5",
            io_profile=IOModelProfile(
                model_number=5,
                name="Model 5",
                digital_inputs=12,
                digital_outputs=12,
                relay_outputs=0,
                analog_inputs=2,
                analog_outputs=2,
                rtd_tc_channels=2,
                description="12 DC In, 12 DC Out, 2 Universal RTD/TC In, 2 Analog Out",
            ),
            screen_resolution="800x480",
        ),
    }

    @classmethod
    def get_profile(cls, target_id: str) -> Optional[ControllerTargetProfile]:
        """Look up target profile by ID."""
        return cls.PROFILES.get(target_id)

    @classmethod
    def list_target_ids(cls) -> List[str]:
        """List all available P1 target identifiers."""
        return list(cls.PROFILES.keys())

    @classmethod
    def validate_io_allocation(
        cls,
        target_id: str,
        used_digital_in: int,
        used_digital_out: int,
        used_analog_in: int,
        used_analog_out: int,
    ) -> Dict[str, Any]:
        """Validate whether a project's I/O requirements fit within target P1 boundaries."""
        prof = cls.get_profile(target_id)
        if not prof:
            return {"valid": False, "error": f"Unknown target profile '{target_id}'"}

        io = prof.io_profile
        total_di = io.digital_inputs
        total_do = io.digital_outputs + io.relay_outputs
        total_ai = io.analog_inputs + io.rtd_tc_channels
        total_ao = io.analog_outputs

        di_ok = used_digital_in <= total_di
        do_ok = used_digital_out <= total_do
        ai_ok = used_analog_in <= total_ai
        ao_ok = used_analog_out <= total_ao

        valid = di_ok and do_ok and ai_ok and ao_ok
        return {
            "valid": valid,
            "target_id": target_id,
            "model_name": prof.model_name,
            "utilization": {
                "digital_in": f"{used_digital_in}/{total_di}",
                "digital_out": f"{used_digital_out}/{total_do}",
                "analog_in": f"{used_analog_in}/{total_ai}",
                "analog_out": f"{used_analog_out}/{total_ao}",
            },
            "violations": [
                f"Exceeded DI: needed {used_digital_in} but available {total_di}" for _ in [1] if not di_ok
            ] + [
                f"Exceeded DO: needed {used_digital_out} but available {total_do}" for _ in [1] if not do_ok
            ] + [
                f"Exceeded AI: needed {used_analog_in} but available {total_ai}" for _ in [1] if not ai_ok
            ] + [
                f"Exceeded AO: needed {used_analog_out} but available {total_ao}" for _ in [1] if not ao_ok
            ]
        }
