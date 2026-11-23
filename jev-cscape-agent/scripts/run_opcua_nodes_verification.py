"""Canonical verification runner for OPC UA Part 5 Information Model & Address Space Node Manager.

Work Package: W052 (Gate G8 / G6)
Classification: VERIFICATION [strict 4-state engineering contract]

Produces:
- artifacts/telemetry/opcua_nodes_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
import uuid

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


def run_opcua_nodes_verification(
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute complete verification of OPC UA Address Space Information Model."""
    evidence_dir = Path("artifacts/telemetry")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target_output = output_path or (evidence_dir / "opcua_nodes_evidence.json")

    start_time = time.perf_counter()
    assertions: List[Dict[str, Any]] = []

    # 1. Initialize Address Space
    space = OPCUAAddressSpace(default_horner_space=True)
    ns_list = space.namespaces
    assertions.append({
        "check": "standard_namespaces_registered",
        "passed": len(ns_list) >= 2 and ns_list[0] == "http://opcfoundation.org/UA/" and ns_list[1] == "urn:horner:ocs:telemetry",
        "details": f"Namespaces: {ns_list}",
    })

    # 2. Check Standard Roots
    root_node = space.get_node(NodeId(0, 84))
    objects_node = space.get_node(NodeId(0, 85))
    types_node = space.get_node(NodeId(0, 86))
    views_node = space.get_node(NodeId(0, 87))
    assertions.append({
        "check": "standard_roots_present",
        "passed": all([root_node, objects_node, types_node, views_node]),
        "details": "Root, Objects, Types, Views nodes verified in Namespace 0",
    })

    # 3. Check Horner OCS Hierarchy
    horner_ctrl = space.get_node("ns=1;s=HornerOCS")
    browse_objects = space.browse("ns=0;i=85", direction="forward")
    horner_found = any(node.node_id == horner_ctrl.node_id for _, node in browse_objects if horner_ctrl)
    assertions.append({
        "check": "horner_controller_hierarchy",
        "passed": horner_ctrl is not None and horner_found,
        "details": "HornerOCS object organized under Objects root folder",
    })

    # 4. Check NodeId Parsing Across Types
    nid_num = NodeId.parse("ns=0;i=84")
    nid_str = NodeId.parse("ns=1;s=Test.Tag")
    raw_uid = uuid.uuid4()
    nid_guid = NodeId.parse(f"ns=1;g={raw_uid}")
    nid_byte = NodeId.parse("ns=1;b=AQIDBA==")
    assertions.append({
        "check": "node_id_parsing_multi_format",
        "passed": (
            nid_num.id_type == IdType.NUMERIC
            and nid_str.id_type == IdType.STRING
            and nid_guid.id_type == IdType.GUID
            and nid_byte.id_type == IdType.BYTESTRING
            and str(nid_num) == "ns=0;i=84"
            and str(nid_str) == "ns=1;s=Test.Tag"
        ),
        "details": "Verified Numeric, String, GUID, ByteString NodeId parsing & serialization",
    })

    # 5. Populate Telemetry VariableNodes
    t_tank = VariableNode(
        node_id=NodeId(1, "HornerOCS.Telemetry.TankTemp", IdType.STRING),
        browse_name="TankTemp",
        data_type=DATA_TYPE_FLOAT,
        initial_value=65.5,
        access_level=AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE,
        horner_register="%R100",
        eu_range=(0.0, 100.0),
        engineering_units="degC",
        description="Tank Bulk Liquid Temperature",
    )
    p_tank = VariableNode(
        node_id=NodeId(1, "HornerOCS.Telemetry.TankPressure", IdType.STRING),
        browse_name="TankPressure",
        data_type=DATA_TYPE_FLOAT,
        initial_value=1.5,
        access_level=AccessLevel.CURRENT_READ,  # Read-only
        horner_register="%R102",
        eu_range=(0.0, 5.0),
        engineering_units="bar",
        description="Headspace Pressure",
    )
    m_alarm = VariableNode(
        node_id=NodeId(1, "HornerOCS.Telemetry.HighAlarm", IdType.STRING),
        browse_name="HighAlarm",
        data_type=DATA_TYPE_BOOLEAN,
        initial_value=False,
        access_level=AccessLevel.CURRENT_READ | AccessLevel.CURRENT_WRITE,
        horner_register="%M1",
        description="High Level Warning Alarm Coil",
    )

    space.add_node(t_tank)
    space.add_node(p_tank)
    space.add_node(m_alarm)

    space.add_reference("ns=1;s=HornerOCS", REF_HAS_COMPONENT, t_tank.node_id)
    space.add_reference("ns=1;s=HornerOCS", REF_HAS_COMPONENT, p_tank.node_id)
    space.add_reference("ns=1;s=HornerOCS", REF_HAS_COMPONENT, m_alarm.node_id)

    # 6. Add and Execute MethodNode
    reset_called = False

    def handle_reset_alarms(args: List[Any]) -> Tuple[StatusCode, List[Any]]:
        nonlocal reset_called
        reset_called = True
        return StatusCode.GOOD, ["All alarms cleared successfully"]

    reset_method = MethodNode(
        node_id=NodeId(1, "HornerOCS.Methods.ResetAlarms", IdType.STRING),
        browse_name="ResetAlarms",
        handler=handle_reset_alarms,
        description="Reset active alarms in OCS memory",
    )
    space.add_node(reset_method)
    space.add_reference("ns=1;s=HornerOCS", REF_HAS_COMPONENT, reset_method.node_id)

    call_status, call_results = space.call_method(reset_method.node_id, [])
    assertions.append({
        "check": "method_node_invocation",
        "passed": call_status == StatusCode.GOOD and reset_called and len(call_results) == 1,
        "details": f"Method ResetAlarms invoked with result: {call_results}",
    })

    # 7. Read and Write AccessLevel Enforcement
    status_read, dv_read = space.read_value(t_tank.node_id)
    write_status_rw = space.write_value(t_tank.node_id, 72.4)
    write_status_ro = space.write_value(p_tank.node_id, 2.0, privilege="USER")
    write_status_eu = space.write_value(t_tank.node_id, 150.0)  # Exceeds eu_range (0..100)

    assertions.append({
        "check": "access_level_and_range_validation",
        "passed": (
            status_read == StatusCode.GOOD
            and dv_read is not None
            and dv_read.value == 65.5
            and write_status_rw == StatusCode.GOOD
            and write_status_ro == StatusCode.BAD_NOT_WRITABLE
            and write_status_eu == StatusCode.UNCERTAIN_EU_EXCEEDED
        ),
        "details": f"RW write={write_status_rw.name}, RO write={write_status_ro.name}, EU exceed={write_status_eu.name}",
    })

    # 8. RegisterTable Bidirectional Synchronization
    reg_table = RegisterTable()
    # Write initial values in RegisterTable
    reg_table.write_real("%R100", 88.5, privilege=PrivilegeMode.SYSTEM)
    reg_table.write_bit("%M1", True, privilege=PrivilegeMode.SYSTEM)

    # Sync RegisterTable -> OPC UA
    synced_from_regs = space.sync_from_register_table(reg_table)
    _, dv_t_sync = space.read_value(t_tank.node_id)
    _, dv_m_sync = space.read_value(m_alarm.node_id)

    # Write from OPC UA and sync -> RegisterTable
    space.write_value(t_tank.node_id, 55.0)
    synced_to_regs = space.sync_to_register_table(reg_table, privilege=PrivilegeMode.SYSTEM)
    r100_in_regs = reg_table.read_real("%R100")

    assertions.append({
        "check": "register_table_bidirectional_sync",
        "passed": (
            synced_from_regs >= 2
            and dv_t_sync is not None
            and abs(dv_t_sync.value - 88.5) < 1e-3
            and dv_m_sync is not None
            and dv_m_sync.value is True
            and synced_to_regs >= 1
            and abs(r100_in_regs - 55.0) < 1e-3
        ),
        "details": f"Synced from regs: {synced_from_regs}, synced to regs: {synced_to_regs}, R100={r100_in_regs}",
    })

    # 9. ModbusScalingBridge Integration
    bridge = ModbusScalingBridge()
    pt = TelemetryPoint(
        name="InletFlow",
        channel="%R10",
        modbus_address=10,
        raw_min=0.0,
        raw_max=32000.0,
        eu_min=0.0,
        eu_max=100.0,
        scaling_type=ScalingType.LINEAR,
        eu_unit="L/min",
    )
    bridge.register_point(pt)
    bridge.update_point_raw("%R10", 16000)  # 50.0 L/min Good
    pt.current_quality = QualityCode.UNCERTAIN
    pt.current_quality_word = OPCQualityFlag.UNCERTAIN | OPCQualityFlag.EU_EXCEEDED

    synced_bridge = space.sync_from_scaling_bridge(bridge)
    inlet_node = space.get_node("ns=1;s=HornerOCS.Telemetry.InletFlow")
    _, dv_inlet = space.read_value("ns=1;s=HornerOCS.Telemetry.InletFlow") if inlet_node else (StatusCode.BAD, None)

    assertions.append({
        "check": "modbus_scaling_bridge_sync",
        "passed": (
            synced_bridge >= 1
            and inlet_node is not None
            and dv_inlet is not None
            and abs(dv_inlet.value - 50.0) < 1e-2
            and dv_inlet.status_code == StatusCode.UNCERTAIN_EU_EXCEEDED
        ),
        "details": f"Bridge point auto-created in namespace 1 with value {dv_inlet.value if dv_inlet else None} and status {dv_inlet.status_code.name if dv_inlet else None}",
    })

    # Summary and Evidence Export
    all_passed = all(a["passed"] for a in assertions)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    evidence_payload = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_OPCUA_VERIFICATION_FAILED",
        "details": f"OPC UA address space verification completed: {sum(1 for a in assertions if a['passed'])}/{len(assertions)} assertions passed in {duration_ms:.2f} ms.",
        "data": {
            "all_passed": all_passed,
            "duration_ms": duration_ms,
            "namespaces": space.namespaces,
            "total_nodes": len(space._nodes),
            "assertions": assertions,
            "address_space_summary": space.to_dict(),
        },
    }

    with open(target_output, "w", encoding="utf-8") as f:
        json.dump(evidence_payload, f, indent=2)

    return evidence_payload


if __name__ == "__main__":
    result = run_opcua_nodes_verification()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "success" else 1)
