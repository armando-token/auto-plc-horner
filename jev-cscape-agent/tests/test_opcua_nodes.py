"""Unit and integration test suite for OPC UA Part 5 Information Model & Address Space.

Work Package: W052 (Gate G8 / G6)
Classification: TEST [100% pure software, zero socket listener, strict 4-state contract]
"""

from __future__ import annotations

import json
from pathlib import Path
import uuid
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.opcua_nodes import (
    AccessLevel,
    DATA_TYPE_BOOLEAN,
    DATA_TYPE_FLOAT,
    DATA_TYPE_INT16,
    IdType,
    MethodNode,
    NodeClass,
    NodeId,
    OPCUAAddressSpace,
    REF_HAS_COMPONENT,
    REF_ORGANIZES,
    StatusCode,
    VariableNode,
)
from jev_cscape.telemetry.scaling_bridge import (
    ModbusScalingBridge,
    OPCQualityFlag,
    QualityCode,
    ScalingType,
    TelemetryPoint,
)
from scripts.run_opcua_nodes_verification import run_opcua_nodes_verification


def test_node_id_parsing_and_serialization() -> None:
    # Numeric
    nid_num = NodeId.parse("ns=0;i=85")
    assert nid_num.namespace == 0
    assert nid_num.identifier == 85
    assert nid_num.id_type == IdType.NUMERIC
    assert str(nid_num) == "ns=0;i=85"

    # String
    nid_str = NodeId.parse("ns=1;s=Device.Sensor1")
    assert nid_str.namespace == 1
    assert nid_str.identifier == "Device.Sensor1"
    assert nid_str.id_type == IdType.STRING
    assert str(nid_str) == "ns=1;s=Device.Sensor1"

    # GUID
    raw_uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    nid_guid = NodeId.parse("ns=2;g=12345678-1234-5678-1234-567812345678")
    assert nid_guid.namespace == 2
    assert nid_guid.identifier == raw_uid
    assert nid_guid.id_type == IdType.GUID
    assert str(nid_guid) == "ns=2;g=12345678-1234-5678-1234-567812345678"

    # ByteString
    nid_b = NodeId.parse("ns=1;b=AQID")
    assert nid_b.namespace == 1
    assert nid_b.identifier == b"\x01\x02\x03"
    assert nid_b.id_type == IdType.BYTESTRING
    assert str(nid_b) == "ns=1;b=AQID"

    # Shorthand i=
    nid_short = NodeId.parse("i=84")
    assert nid_short.namespace == 0
    assert nid_short.identifier == 84

    # Invalid format error handling
    with pytest.raises(ValueError):
        NodeId.parse("invalid_node_id")


def test_address_space_root_and_horner_hierarchy() -> None:
    space = OPCUAAddressSpace(default_horner_space=True)
    assert len(space.namespaces) >= 2

    # Root, Objects, Types, Views
    root = space.get_node(NodeId(0, 84))
    objects = space.get_node(NodeId(0, 85))
    types = space.get_node(NodeId(0, 86))
    views = space.get_node(NodeId(0, 87))

    assert root is not None and root.node_class == NodeClass.OBJECT
    assert objects is not None and objects.node_class == NodeClass.OBJECT
    assert types is not None and types.node_class == NodeClass.OBJECT
    assert views is not None and views.node_class == NodeClass.OBJECT

    # Horner controller and channel folders
    ctrl = space.get_node("ns=1;s=HornerOCS")
    assert ctrl is not None
    assert ctrl.display_name.text == "Horner OCS Controller"

    inputs_folder = space.get_node("ns=1;s=HornerOCS.Inputs")
    assert inputs_folder is not None


def test_browse_navigation_and_filtering() -> None:
    space = OPCUAAddressSpace(default_horner_space=True)

    # Browse forward from Root (ns=0;i=84)
    forward_refs = space.browse("ns=0;i=84", direction="forward")
    assert len(forward_refs) >= 3
    targets = [target.node_id for _, target in forward_refs]
    assert NodeId(0, 85) in targets  # Objects
    assert NodeId(0, 86) in targets  # Types
    assert NodeId(0, 87) in targets  # Views

    # Browse inverse from Objects (ns=0;i=85)
    inverse_refs = space.browse("ns=0;i=85", direction="inverse")
    assert len(inverse_refs) >= 1
    assert inverse_refs[0][1].node_id == NodeId(0, 84)

    # Filtered browse by reference type
    organizes_refs = space.browse("ns=0;i=84", direction="forward", reference_type_id=REF_ORGANIZES)
    assert len(organizes_refs) == 3


def test_variable_node_read_write_and_access_levels() -> None:
    space = OPCUAAddressSpace(default_horner_space=False)

    var_rw = VariableNode(
        node_id=NodeId(1, "VarRW", IdType.STRING),
        browse_name="VarRW",
        initial_value=10.0,
        access_level=AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE,
    )
    var_ro = VariableNode(
        node_id=NodeId(1, "VarRO", IdType.STRING),
        browse_name="VarRO",
        initial_value=20.0,
        access_level=AccessLevel.CURRENT_READ,
    )
    space.add_node(var_rw)
    space.add_node(var_ro)

    # Read values
    st, dv = space.read_value(var_rw.node_id)
    assert st == StatusCode.GOOD
    assert dv is not None and dv.value == 10.0

    # Write RW
    st_write = space.write_value(var_rw.node_id, 15.5)
    assert st_write == StatusCode.GOOD
    _, dv2 = space.read_value(var_rw.node_id)
    assert dv2 is not None and dv2.value == 15.5

    # Write RO with USER privilege should fail
    st_ro = space.write_value(var_ro.node_id, 25.0, privilege="USER")
    assert st_ro == StatusCode.BAD_NOT_WRITABLE

    # Write RO with SYSTEM privilege should succeed
    st_ro_sys = space.write_value(var_ro.node_id, 25.0, privilege="SYSTEM")
    assert st_ro_sys == StatusCode.GOOD
    _, dv3 = space.read_value(var_ro.node_id)
    assert dv3 is not None and dv3.value == 25.0


def test_eu_range_validation_status_code() -> None:
    space = OPCUAAddressSpace(default_horner_space=False)

    var_eu = VariableNode(
        node_id=NodeId(1, "PressureEU", IdType.STRING),
        browse_name="PressureEU",
        initial_value=2.0,
        eu_range=(0.0, 10.0),
        engineering_units="bar",
    )
    space.add_node(var_eu)

    # In range
    st1 = space.write_value(var_eu.node_id, 5.0)
    assert st1 == StatusCode.GOOD

    # Out of range
    st2 = space.write_value(var_eu.node_id, 12.5)
    assert st2 == StatusCode.UNCERTAIN_EU_EXCEEDED
    assert not st2.is_good
    assert st2.is_uncertain


def test_method_node_invocation() -> None:
    space = OPCUAAddressSpace(default_horner_space=False)

    def calc_square(args: list) -> tuple:
        val = args[0]
        return StatusCode.GOOD, [val * val]

    method = MethodNode(
        node_id=NodeId(1, "CalcSquare", IdType.STRING),
        browse_name="CalcSquare",
        handler=calc_square,
    )
    space.add_node(method)

    st, res = space.call_method(method.node_id, [4])
    assert st == StatusCode.GOOD
    assert res == [16]

    # Non-existent method
    st_bad, _ = space.call_method(NodeId(1, "NonExistent", IdType.STRING), [])
    assert st_bad == StatusCode.BAD_NODE_ID_UNKNOWN


def test_register_table_bidirectional_synchronization() -> None:
    space = OPCUAAddressSpace(default_horner_space=False)
    reg_table = RegisterTable()

    node_r = VariableNode(
        node_id=NodeId(1, "R100", IdType.STRING),
        browse_name="R100",
        horner_register="%R100",
        data_type=DATA_TYPE_FLOAT,
    )
    node_m = VariableNode(
        node_id=NodeId(1, "M10", IdType.STRING),
        browse_name="M10",
        horner_register="%M10",
        data_type=DATA_TYPE_BOOLEAN,
    )
    node_aq = VariableNode(
        node_id=NodeId(1, "AQ1", IdType.STRING),
        browse_name="AQ1",
        horner_register="%AQ1",
        data_type=DATA_TYPE_INT16,
    )

    space.add_node(node_r)
    space.add_node(node_m)
    space.add_node(node_aq)

    # Seed RegisterTable
    reg_table.write_real("%R100", 42.5, privilege=PrivilegeMode.SYSTEM)
    reg_table.write_bit("%M10", True, privilege=PrivilegeMode.SYSTEM)
    reg_table.write_word("%AQ1", 16000, privilege=PrivilegeMode.SYSTEM)

    # Sync RegisterTable -> OPC UA
    count_from = space.sync_from_register_table(reg_table)
    assert count_from == 3

    _, dvr = space.read_value(node_r.node_id)
    _, dvm = space.read_value(node_m.node_id)
    _, dvaq = space.read_value(node_aq.node_id)

    assert dvr is not None and abs(dvr.value - 42.5) < 1e-3
    assert dvm is not None and dvm.value is True
    assert dvaq is not None and dvaq.value == 16000

    # Write in OPC UA and sync to RegisterTable
    space.write_value(node_r.node_id, 99.2)
    space.write_value(node_m.node_id, False)
    space.write_value(node_aq.node_id, 8000)

    count_to = space.sync_to_register_table(reg_table, privilege=PrivilegeMode.SYSTEM)
    assert count_to == 3

    assert abs(reg_table.read_real("%R100") - 99.2) < 1e-3
    assert reg_table.read_bit("%M10") is False
    assert reg_table.read_word("%AQ1") == 8000


def test_modbus_scaling_bridge_synchronization() -> None:
    space = OPCUAAddressSpace(default_horner_space=True)
    bridge = ModbusScalingBridge()

    pt = TelemetryPoint(
        name="TankLevel",
        channel="%AI1",
        modbus_address=100,
        raw_min=0.0,
        raw_max=32000.0,
        eu_min=0.0,
        eu_max=100.0,
        eu_unit="%",
    )
    bridge.register_point(pt)
    bridge.update_point_raw("%AI1", 24000)  # 75.0%

    synced = space.sync_from_scaling_bridge(bridge)
    assert synced >= 1

    node = space.get_node("ns=1;s=HornerOCS.Telemetry.TankLevel")
    assert node is not None
    assert isinstance(node, VariableNode)
    assert node.horner_register == "%AI1"
    assert node.engineering_units == "%"

    _, dv = space.read_value(node.node_id)
    assert dv is not None
    assert abs(dv.value - 75.0) < 1e-2
    assert dv.status_code == StatusCode.GOOD


def test_verification_runner_contract(tmp_path: Path) -> None:
    test_evidence_file = tmp_path / "opcua_evidence_test.json"
    result = run_opcua_nodes_verification(output_path=test_evidence_file)

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["all_passed"] is True
    assert test_evidence_file.exists()

    with open(test_evidence_file, "r", encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["status"] == "success"
    assert len(payload["data"]["assertions"]) >= 8
