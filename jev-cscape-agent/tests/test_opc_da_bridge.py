"""Comprehensive Unit and Integration Test Suite for Industrial OPC DA / XML-DA Protocol Wrapper & Legacy COM/DCOM Bridge Engine.

Work Package: W178 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1390..%R1397, %M324..%M325).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: OPC DA/XML-DA group and item hierarchy, CLSID resolution, HRESULT diagnostics.
4. Section 4: Synchronous/Asynchronous transactions, latency tracking, deadband filtering.
5. Section 5: Quality code evaluation (Good 0xC0, Bad 0x00, Uncertain 0x40).
6. Section 6: Process safety trips (0xCB01 DCOM RPC disconnect, 0xCB02 update timeout, 0xCB03 bad quality, 0xCB04 invalid CLSID) and Horner coil assertion (%M324, %M325).
7. Section 7: Horner OCS register space synchronization (%R1390..%R1397, %M324..%M325) with PrivilegeMode.SYSTEM.
8. Section 8: ILogicUnit scan cycle execution and state machine transitions.
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.opc_da_bridge import (
    CLSID_CscapeOpcDaServer,
    CLSID_LegacyHornerDcomServer,
    CLSID_OpcServerList,
    DEFAULT_GROUP_UPDATE_RATE_MS,
    DEFAULT_PROGID_HORNER,
    DCOM_RPC_DISCONNECT,
    E_FAIL,
    E_INVALIDARG,
    E_NOINTERFACE,
    GROUP_UPDATE_TIMEOUT,
    GROUP_UPDATE_TIMEOUT_MS,
    IID_IConnectionPointContainer,
    IID_IOPCAsyncIO2,
    IID_IOPCBrowseServerAddressSpace,
    IID_IOPCCommon,
    IID_IOPCGroupStateMgt,
    IID_IOPCItemMgt,
    IID_IOPCSyncIO,
    IID_IUnknown,
    INVALID_CLSID,
    ITEM_BAD_QUALITY,
    LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU,
    LEGACY_COM_DCOM_POU,
    MAX_OPC_GROUPS,
    NOMINAL_LATENCY_SCALED,
    NOMINAL_TRANSACTION_LATENCY_MS,
    OPC_BRANCH,
    OPC_DA_BRIDGE_POU,
    OPC_DA_BRIDGE_SYNC_POU,
    OPC_DA_ERR_BAD_QUALITY,
    OPC_DA_ERR_DCOM_RPC_DISCONNECT,
    OPC_DA_ERR_INVALID_CLSID,
    OPC_DA_ERR_UPDATE_TIMEOUT,
    OPC_DA_XML_BRIDGE_SYNC_POU,
    OPC_E_BADTYPE,
    OPC_E_INVALIDFILTER,
    OPC_E_INVALIDHANDLE,
    OPC_E_UNKNOWNITEMID,
    OPC_ERR_DCOM_RPC_DISCONNECT,
    OPC_ERR_GROUP_UPDATE_TIMEOUT,
    OPC_ERR_INVALID_CLSID,
    OPC_ERR_ITEM_BAD_QUALITY,
    OPC_FLAT,
    OPC_LEAF,
    OPC_PROP_CDT,
    OPC_PROP_EUINFO,
    OPC_PROP_RIGHTS,
    OPC_QUALITY_BAD,
    OPC_QUALITY_COMM_FAILURE,
    OPC_QUALITY_CONFIG_ERROR,
    OPC_QUALITY_DEVICE_FAILURE,
    OPC_QUALITY_EU_EXCEEDED,
    OPC_QUALITY_GOOD,
    OPC_QUALITY_LAST_KNOWN_VALUE,
    OPC_QUALITY_LAST_USABLE_VALUE,
    OPC_QUALITY_LOCAL_OVERRIDE,
    OPC_QUALITY_NOT_CONNECTED,
    OPC_QUALITY_OUT_OF_SERVICE,
    OPC_QUALITY_SENSOR_FAILURE,
    OPC_QUALITY_SENSOR_NOT_ACCURATE,
    OPC_QUALITY_UNCERTAIN,
    OPC_READABLE,
    OPC_S_CLAMP,
    OPC_S_UNSUPPORTEDRATE,
    OPC_WRITEABLE,
    PURE_ST_POU,
    REGDB_E_CLASSNOTREG,
    RPC_E_CALL_FAILED,
    RPC_E_DISCONNECTED,
    RPC_E_SERVER_DIED,
    STANDARD_UPDATE_RATES_MS,
    S_FALSE,
    S_OK,
    UPDATE_TIMEOUT,
    VT_BOOL,
    VT_BSTR,
    VT_I2,
    VT_I4,
    VT_R4,
    VT_R8,
    OpcAddressSpace,
    OpcAddressSpaceNode,
    OpcBridgeStateBits,
    OpcDaBridge,
    OpcDaBridgeEngine,
    OpcDaBridgeError,
    OpcDaBridgeSync,
    OpcDaDiagnosticCode,
    OpcDaTransaction,
    OpcDcomRpcDisconnectError,
    OpcGatewayState,
    OpcGroup,
    OpcGroupCapacityError,
    OpcGroupUpdateTimeoutError,
    OpcInvalidClsidError,
    OpcInvalidHandleError,
    OpcItem,
    OpcItemBadQualityError,
    XmlDaBridge,
    evaluate_quality_summary,
    extract_hresult_word,
    format_hresult,
    is_bad_quality,
    is_good_quality,
    is_uncertain_quality,
    resolve_clsid,
    resolve_progid,
    run_opc_da_bridge_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    validate_clsid_format,
    verify_opc_da_bridge_pure_st,
    verify_opc_da_pure_st,
)


@pytest.fixture
def clean_register_table() -> RegisterTable:
    """Fixture providing clean Horner OCS RegisterTable."""
    return RegisterTable()


@pytest.fixture
def opc_engine(clean_register_table: RegisterTable) -> OpcDaBridgeEngine:
    """Fixture providing fresh OpcDaBridgeEngine bound to clean RegisterTable."""
    return OpcDaBridgeEngine(register_table=clean_register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Register Bindings (%R1390..%R1397, %M324..%M325)
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    EXPECTED_REGISTERS = {
        "%R1390", "%R1391", "%R1392", "%R1393",
        "%R1394", "%R1395", "%R1396", "%R1397",
        "%M324", "%M325",
    }

    def test_verify_opc_da_bridge_pure_st_helper(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_opc_da_bridge_pure_st() is True
        assert verify_opc_da_pure_st() is True

    def test_pure_st_pou_ast_parsing_primary(self) -> None:
        """Parse OPC_DA_XML_BRIDGE_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(OPC_DA_XML_BRIDGE_SYNC_POU)
        assert pou is not None
        assert pou.name == "OpcDaXmlBridgeSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "ConnectedOpcGroupsCount",
            "ActiveOpcItemsCount",
            "OpcDaTransactionLatencyMsScaled",
            "OpcItemQualityCodeWord",
            "DcomReconnectFailuresCount",
            "OpcBridgeStateWord",
            "OpcGroupUpdateRateMs",
            "DiagnosticStatusCode",
            "OpcDaBridgePermissive",
            "OpcDaBridgeFaultTrip",
            "BridgeHealthy",
        }
        assert expected_vars.issubset(var_names)
        assert set(pou.bound_registers) == self.EXPECTED_REGISTERS

    def test_pure_st_pou_ast_parsing_legacy_alias(self) -> None:
        """Parse LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)
        assert pou is not None
        assert pou.name == "LegacyComDcomOpcBridgeSync"
        assert pou.pou_type == POUType.PROGRAM
        assert set(pou.bound_registers) == self.EXPECTED_REGISTERS

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all POU aliases pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(OPC_DA_XML_BRIDGE_SYNC_POU)
        SecurityGuard.assert_pure_st_content(LEGACY_COM_DCOM_OPC_BRIDGE_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(OPC_DA_BRIDGE_POU)
        SecurityGuard.assert_pure_st_content(OPC_DA_BRIDGE_SYNC_POU)
        SecurityGuard.assert_pure_st_content(LEGACY_COM_DCOM_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests verifying ladder logic constructs are strictly rejected."""

    def test_ladder_contacts_rejected(self) -> None:
        """Reject ASCII ladder contacts ---[ ]--- and inverted ---[/]---."""
        bad_st_1 = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadContactsInv\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_coils_rejected(self) -> None:
        """Reject ASCII ladder coils ---( )---, set ---(S)---, and reset ---(R)---."""
        bad_st_1 = "PROGRAM BadCoils\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadCoilsSet\nVAR Y: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_3 = "PROGRAM BadCoilsReset\nVAR Y: BOOL; END_VAR\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_3)
        res3 = STParser.validate_code(bad_st_3)
        assert res3.status == AgentStatus.FAILED
        assert res3.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_mnemonics_rejected(self) -> None:
        """Reject ladder mnemonics XIC, XIO, OTE, OTL, OTU, and RUNG/NETWORK blocks."""
        bad_st_1 = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadNetwork\nVAR W: BOOL; END_VAR\nNETWORK 1\nOTL %M324\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_3 = "PROGRAM BadXioOtu\nVAR A: BOOL; END_VAR\nXIO %M10 OTU %M20\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_3)
        res3 = STParser.validate_code(bad_st_3)
        assert res3.status == AgentStatus.FAILED
        assert res3.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: OPC DA/XML-DA Group and Item Hierarchy, CLSID Resolution, HRESULTs
# ============================================================================

class TestSection3GroupAndItemHierarchyClsidHresult:
    """Tests for COM/DCOM architecture, CLSID/IID resolution, hierarchy, and HRESULTs."""

    def test_clsid_resolution_standard_progids(self) -> None:
        """Verify resolution of standard industrial OPC ProgIDs to CLSIDs."""
        assert resolve_clsid("Horner.Cscape.OPCDA") == CLSID_CscapeOpcDaServer
        assert resolve_clsid("Horner.Legacy.DCOM") == CLSID_LegacyHornerDcomServer
        assert resolve_clsid("OPC.ServerList") == CLSID_OpcServerList
        assert resolve_clsid(CLSID_CscapeOpcDaServer) == CLSID_CscapeOpcDaServer
        assert resolve_progid("Horner.Cscape.OPCDA") == CLSID_CscapeOpcDaServer

    def test_clsid_resolution_unknown_or_unregistered_raises(self) -> None:
        """Verify unregistered CLSID raises OpcInvalidClsidError."""
        with pytest.raises(OpcInvalidClsidError):
            resolve_clsid("{99999999-8888-7777-6666-555555555555}")
        with pytest.raises(OpcInvalidClsidError):
            resolve_clsid("Unregistered.Vendor.OPCServer.1")

    def test_validate_clsid_format_helper(self) -> None:
        """Verify CLSID GUID format validation helper."""
        assert validate_clsid_format(CLSID_CscapeOpcDaServer) is True
        assert validate_clsid_format("A4B3C2D1-1390-4821-A494-00C04F68C315") is True
        assert validate_clsid_format("not-a-guid") is False
        assert validate_clsid_format("12345") is False

    def test_query_interface_emulation(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify QueryInterface succeeds for supported OPC interfaces and fails for others."""
        for iid in [
            IID_IUnknown,
            IID_IOPCSyncIO,
            IID_IOPCAsyncIO2,
            IID_IOPCGroupStateMgt,
            IID_IOPCItemMgt,
            IID_IOPCBrowseServerAddressSpace,
            IID_IConnectionPointContainer,
            IID_IOPCCommon,
        ]:
            hr, iface = opc_engine.query_interface(iid)
            assert hr == S_OK
            assert iface is not None

        hr_bad, iface_bad = opc_engine.query_interface("{00000000-1111-2222-3333-444444444444}")
        assert hr_bad == E_NOINTERFACE
        assert iface_bad is None

    def test_hresult_exact_values_and_formatting(self) -> None:
        """Verify standard HRESULT error constants conform to COM specifications."""
        assert S_OK == 0x00000000
        assert S_FALSE == 0x00000001
        assert E_FAIL == 0x80004005
        assert E_INVALIDARG == 0x80070057
        assert E_NOINTERFACE == 0x80004002
        assert REGDB_E_CLASSNOTREG == 0x80040154
        assert RPC_E_DISCONNECTED == 0x80010108
        assert RPC_E_SERVER_DIED == 0x800706BE
        assert RPC_E_CALL_FAILED == 0x80010001
        assert OPC_E_INVALIDHANDLE == 0xC0040001
        assert OPC_E_BADTYPE == 0xC0040004
        assert OPC_E_UNKNOWNITEMID == 0xC0040007
        assert OPC_E_INVALIDFILTER == 0xC0040008
        assert OPC_S_UNSUPPORTEDRATE == 0x0004000D
        assert OPC_S_CLAMP == 0x00040002

        # Formatting helper
        s_ok_str = format_hresult(S_OK)
        assert "0x00000000" in s_ok_str
        assert "Success" in s_ok_str

        rpc_str = format_hresult(RPC_E_DISCONNECTED)
        assert "0x80010108" in rpc_str
        assert "RPC disconnected" in rpc_str

        # Word extraction
        assert extract_hresult_word(RPC_E_DISCONNECTED) == 0x0108
        assert extract_hresult_word(S_OK) == 0x0000

    def test_group_and_item_creation_hierarchy(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify creating groups and monitored items builds correct hierarchy."""
        grp = opc_engine.add_group(name="CustomGroup", update_rate_ms=500, percent_deadband=2.5)
        assert grp.name == "CustomGroup"
        assert grp.update_rate_ms == 500
        assert grp.percent_deadband == 2.5
        assert grp.server_handle in opc_engine.groups

        item1 = opc_engine.add_item_to_group(
            group_handle=grp.server_handle,
            item_id="Custom.Tag1",
            canonical_data_type=VT_R4,
            initial_value=123.45,
            eu_info=(0.0, 500.0),
        )
        assert item1.item_id == "Custom.Tag1"
        assert item1.value == 123.45
        assert item1.server_handle in grp.items
        assert grp.items_by_id["Custom.Tag1"] is item1

    def test_group_capacity_ceiling_at_16(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify group creation respects maximum capacity of 16 groups."""
        while len(opc_engine.groups) < MAX_OPC_GROUPS:
            opc_engine.add_group(f"Group_{len(opc_engine.groups) + 1}")

        assert len(opc_engine.groups) == 16

        with pytest.raises(OpcGroupCapacityError):
            opc_engine.add_group("Overflow_Group_17")

    def test_group_and_item_removal(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify removing groups and items updates collections and references."""
        grp = opc_engine.add_group("RemovableGroup")
        h_grp = grp.server_handle
        it = opc_engine.add_item_to_group(h_grp, "RemovableItem")
        h_it = it.server_handle

        assert h_it in grp.items
        removed_it = grp.remove_item(h_it)
        assert removed_it is it
        assert h_it not in grp.items

        assert h_grp in opc_engine.groups
        removed_grp = opc_engine.remove_group(h_grp)
        assert removed_grp is True
        assert h_grp not in opc_engine.groups

    def test_address_space_hierarchical_and_flat_browsing(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify hierarchical and flat browsing of the OPC address space."""
        addr = opc_engine.address_space
        root_branches = addr.browse_item_ids(browse_type=OPC_BRANCH)
        assert "HornerOCS" in root_branches
        assert "ProcessUnits" in root_branches
        assert "Diagnostics" in root_branches

        flat_leaves = addr.browse_item_ids(browse_type=OPC_FLAT)
        assert len(flat_leaves) >= 40

        # Browse down into HornerOCS -> HoldingRegisters
        assert addr.change_browse_position(3, "HornerOCS") == S_OK
        assert addr.change_browse_position(3, "HoldingRegisters") == S_OK
        leafs = addr.browse_item_ids(browse_type=OPC_LEAF)
        assert len(leafs) == 32
        assert "HornerOCS.HoldingRegisters.%R1000" in leafs

        # Browse up back to root
        assert addr.change_browse_position(1) == S_OK
        assert addr.change_browse_position(1) == S_OK

    def test_xml_da_bridge_methods_and_soap_formatting(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify XML-DA 1.01 get_status, read, write, and SOAP envelope formatting."""
        xml = opc_engine.xml_da_bridge
        status_info = xml.get_status()
        assert status_info["ServerState"] == "running"
        assert "10.2.751.4" in status_info["ProductVersion"]

        read_res = xml.read(["ProcessUnits.Furnace.Zone1Temp"])
        assert len(read_res["Items"]) == 1
        assert read_res["Items"][0]["Quality"] == "good"

        write_res = xml.write(["ProcessUnits.Furnace.Zone1Temp"], [850.0])
        assert len(write_res["Errors"]) == 1
        assert write_res["Errors"][0] == S_OK

        envelope = xml.format_soap_envelope("<MyBodyPayload/>")
        assert "<SOAP-ENV:Envelope" in envelope
        assert "<MyBodyPayload/>" in envelope


# ============================================================================
# Section 4: Synchronous/Asynchronous Transactions, Latency Tracking, Deadband
# ============================================================================

class TestSection4SyncAsyncTransactionsLatencyDeadband:
    """Tests for sync/async read/write, transaction latency, and deadband filtering."""

    def test_synchronous_read_and_write(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify IOPCSyncIO::Write updates items and IOPCSyncIO::Read retrieves them."""
        grp = opc_engine.groups[1]
        handles = [it.server_handle for it in list(grp.items.values())[:3]]

        w_errs = opc_engine.sync_write(grp.server_handle, handles, [123, 456, 789])
        assert all(e == S_OK for e in w_errs)

        vals, quals, times, r_errs = opc_engine.sync_read(grp.server_handle, handles)
        assert vals == [123, 456, 789]
        assert all(q == OPC_QUALITY_GOOD for q in quals)
        assert all(e == S_OK for e in r_errs)
        assert all(t > 0 for t in times)

    def test_synchronous_read_invalid_handle_returns_error(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify sync read with invalid item handle returns OPC_E_INVALIDHANDLE."""
        grp = opc_engine.groups[1]
        vals, quals, times, errs = opc_engine.sync_read(grp.server_handle, [99999])
        assert vals == [None]
        assert quals == [OPC_QUALITY_BAD]
        assert errs == [OPC_E_INVALIDHANDLE]

    def test_synchronous_write_type_mismatch_returns_badtype(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify sync write with incompatible data type returns OPC_E_BADTYPE."""
        grp = opc_engine.groups[1]
        int_item = [it for it in grp.items.values() if it.canonical_data_type == VT_I2][0]

        w_errs = opc_engine.sync_write(grp.server_handle, [int_item.server_handle], ["invalid_integer"])
        assert w_errs == [OPC_E_BADTYPE]

    def test_asynchronous_transactions(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify IOPCAsyncIO2::Read and IOPCAsyncIO2::Write transactions."""
        grp = opc_engine.groups[1]
        handles = [it.server_handle for it in list(grp.items.values())[:2]]

        # Async write
        cancel_id_w, async_tx_w = opc_engine.async_write(grp.server_handle, handles, [555, 666])
        assert cancel_id_w in opc_engine.active_async_transactions
        assert async_tx_w.transaction_type == "ASYNC_WRITE"
        assert async_tx_w.status == "COMPLETED"

        # Async read
        cancel_id_r, async_tx_r = opc_engine.async_read(grp.server_handle, handles)
        assert cancel_id_r in opc_engine.active_async_transactions
        assert async_tx_r.transaction_type == "ASYNC_READ"
        assert async_tx_r.values == [555, 666]
        assert async_tx_r.status == "COMPLETED"

    def test_nominal_latency_tracking_r1392(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify transaction latency tracking scales x10 ms into %R1392."""
        grp = opc_engine.groups[1]
        handles = [list(grp.items.values())[0].server_handle]

        opc_engine.sync_read(grp.server_handle, handles, simulated_latency_override_ms=4.2)
        assert opc_engine.transaction_latency_ms == pytest.approx(4.2, rel=1e-3)
        assert opc_engine.latency_scaled == 42
        assert opc_engine.reg_table.read_word("%R1392") == 42

    def test_deadband_filtering_suppresses_sub_threshold_changes(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify deadband filtering suppresses changes below threshold percentage of EU span."""
        grp = opc_engine.groups[1]
        grp.percent_deadband = 5.0  # 5% deadband
        item = list(grp.items.values())[0]
        item.eu_info = (0.0, 100.0)  # Span = 100.0, 5% is 5.0
        item.last_published_value = 50.0

        # Change by 2.0 (2% of span) < 5% -> suppressed
        assert grp.evaluate_deadband(item, 52.0) is False

    def test_deadband_filtering_publishes_above_threshold_changes(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify deadband filtering allows changes at or above threshold percentage of EU span."""
        grp = opc_engine.groups[1]
        grp.percent_deadband = 5.0
        item = list(grp.items.values())[0]
        item.eu_info = (0.0, 100.0)
        item.last_published_value = 50.0

        # Change by 6.0 (6% of span) >= 5% -> published
        assert grp.evaluate_deadband(item, 56.0) is True

    def test_zero_deadband_always_publishes(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify 0.0% deadband always permits publishing updates."""
        grp = opc_engine.groups[1]
        grp.percent_deadband = 0.0
        item = list(grp.items.values())[0]
        item.deadband_pct = 0.0
        item.last_published_value = 10.0

        assert grp.evaluate_deadband(item, 10.01) is True


# ============================================================================
# Section 5: Quality Code Evaluation (Good 0xC0, Bad 0x00, Uncertain 0x40)
# ============================================================================

class TestSection5QualityCodeEvaluation:
    """Tests for OPC DA quality code bitmask definitions, substatuses, and evaluation."""

    def test_good_quality_codes_and_predicates(self) -> None:
        """Verify Good quality (0xC0), Local Override (0xD8), and predicate helpers."""
        assert OPC_QUALITY_GOOD == 0xC0
        assert is_good_quality(0xC0) is True
        assert is_good_quality(OPC_QUALITY_LOCAL_OVERRIDE) is True
        assert is_bad_quality(0xC0) is False
        assert is_uncertain_quality(0xC0) is False

    def test_bad_quality_codes_and_substatuses(self) -> None:
        """Verify Bad quality (0x00) substatus bitmasks and predicate helpers."""
        assert OPC_QUALITY_BAD == 0x00
        assert OPC_QUALITY_CONFIG_ERROR == 0x04
        assert OPC_QUALITY_NOT_CONNECTED == 0x08
        assert OPC_QUALITY_DEVICE_FAILURE == 0x0C
        assert OPC_QUALITY_SENSOR_FAILURE == 0x10
        assert OPC_QUALITY_LAST_KNOWN_VALUE == 0x14
        assert OPC_QUALITY_COMM_FAILURE == 0x18
        assert OPC_QUALITY_OUT_OF_SERVICE == 0x1C

        for q in [
            OPC_QUALITY_BAD,
            OPC_QUALITY_CONFIG_ERROR,
            OPC_QUALITY_NOT_CONNECTED,
            OPC_QUALITY_DEVICE_FAILURE,
            OPC_QUALITY_SENSOR_FAILURE,
            OPC_QUALITY_COMM_FAILURE,
        ]:
            assert is_bad_quality(q) is True
            assert is_good_quality(q) is False
            assert is_uncertain_quality(q) is False

    def test_uncertain_quality_codes_and_substatuses(self) -> None:
        """Verify Uncertain quality (0x40) substatus bitmasks and predicate helpers."""
        assert OPC_QUALITY_UNCERTAIN == 0x40
        assert OPC_QUALITY_LAST_USABLE_VALUE == 0x44
        assert OPC_QUALITY_SENSOR_NOT_ACCURATE == 0x50
        assert OPC_QUALITY_EU_EXCEEDED == 0x54

        for q in [
            OPC_QUALITY_UNCERTAIN,
            OPC_QUALITY_LAST_USABLE_VALUE,
            OPC_QUALITY_SENSOR_NOT_ACCURATE,
            OPC_QUALITY_EU_EXCEEDED,
        ]:
            assert is_uncertain_quality(q) is True
            assert is_good_quality(q) is False
            assert is_bad_quality(q) is False

    def test_evaluate_quality_summary_composite(self) -> None:
        """Verify composite quality evaluation across multiple item qualities."""
        # Empty -> Good
        assert evaluate_quality_summary([]) == OPC_QUALITY_GOOD

        # All good -> Good
        assert evaluate_quality_summary([OPC_QUALITY_GOOD, OPC_QUALITY_LOCAL_OVERRIDE]) == OPC_QUALITY_GOOD

        # One uncertain, no bad -> Uncertain
        assert evaluate_quality_summary([OPC_QUALITY_GOOD, OPC_QUALITY_SENSOR_NOT_ACCURATE]) == OPC_QUALITY_UNCERTAIN

        # One bad -> Bad
        assert evaluate_quality_summary([OPC_QUALITY_GOOD, OPC_QUALITY_SENSOR_NOT_ACCURATE, OPC_QUALITY_SENSOR_FAILURE]) == OPC_QUALITY_BAD

    def test_quality_code_word_r1393_synchronization(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify %R1393 reflects current OPC quality word."""
        opc_engine.item_quality_code = OPC_QUALITY_GOOD
        opc_engine.sync_to_registers()
        assert opc_engine.reg_table.read_uword("%R1393") == 0x00C0

        opc_engine.item_quality_code = OPC_QUALITY_UNCERTAIN
        opc_engine.sync_to_registers()
        assert opc_engine.reg_table.read_uword("%R1393") == 0x0040

        opc_engine.item_quality_code = OPC_QUALITY_BAD
        opc_engine.sync_to_registers()
        assert opc_engine.reg_table.read_uword("%R1393") == 0x0000


# ============================================================================
# Section 6: Process Safety Trips & Horner Coil Assertion (%M324, %M325)
# ============================================================================

class TestSection6ProcessSafetyTripsAndCoils:
    """Tests for safety trips (0xCB01..0xCB04), coil assertions (%M324, %M325), and latching."""

    def test_trip_cb01_dcom_rpc_disconnect(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Trip 0xCB01: DCOM RPC disconnect clears %M324, sets %M325, increments %R1394."""
        opc_engine.simulate_rpc_disconnect()

        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_DCOM_RPC_DISCONNECT
        assert opc_engine.diagnostic_code == 0xCB01
        assert opc_engine.permissive is False
        assert opc_engine.fault_trip is True
        assert opc_engine.reg_table.read_uword("%R1397") == 0xCB01
        assert opc_engine.reg_table.read_bit("%M324") is False
        assert opc_engine.reg_table.read_bit("%M325") is True
        assert opc_engine.reg_table.read_word("%R1394") >= 1

    def test_trip_cb02_update_timeout(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Trip 0xCB02: Group update stall > 2500ms trips safety interlock."""
        grp = opc_engine.groups[1]
        grp.time_since_last_update_ms = 2505.0

        opc_engine.scan_step(dt=0.001)

        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_GROUP_UPDATE_TIMEOUT
        assert opc_engine.diagnostic_code == 0xCB02
        assert opc_engine.permissive is False
        assert opc_engine.fault_trip is True
        assert opc_engine.reg_table.read_uword("%R1397") == 0xCB02
        assert opc_engine.reg_table.read_bit("%M324") is False
        assert opc_engine.reg_table.read_bit("%M325") is True

    def test_trip_cb03_bad_quality(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Trip 0xCB03: Critical process item reporting Bad quality (0x00) trips interlock."""
        crit_item = opc_engine.find_item_by_id("ProcessUnits.Furnace.Zone1Temp")
        assert crit_item is not None
        crit_item.quality = OPC_QUALITY_BAD

        opc_engine.scan_step(dt=0.001)

        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_ITEM_BAD_QUALITY
        assert opc_engine.diagnostic_code == 0xCB03
        assert opc_engine.permissive is False
        assert opc_engine.fault_trip is True
        assert opc_engine.reg_table.read_uword("%R1397") == 0xCB03
        assert opc_engine.reg_table.read_bit("%M324") is False
        assert opc_engine.reg_table.read_bit("%M325") is True

    def test_trip_cb04_invalid_clsid(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Trip 0xCB04: Invalid CLSID connection attempt trips safety interlock."""
        with pytest.raises(OpcInvalidClsidError):
            opc_engine.connect_server("{A0B0C0D0-0000-0000-0000-000000000000}")

        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OPC_ERR_INVALID_CLSID
        assert opc_engine.diagnostic_code == 0xCB04
        assert opc_engine.permissive is False
        assert opc_engine.fault_trip is True
        assert opc_engine.reg_table.read_uword("%R1397") == 0xCB04
        assert opc_engine.reg_table.read_bit("%M324") is False
        assert opc_engine.reg_table.read_bit("%M325") is True

    def test_safety_latch_persists_across_multiple_scans(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify safety trip remains latched across subsequent scan cycles."""
        opc_engine.simulate_rpc_disconnect()
        assert opc_engine.fault_trip is True

        for _ in range(5):
            opc_engine.scan_step(dt=0.010)
            assert opc_engine.fault_trip is True
            assert opc_engine.permissive is False
            assert opc_engine.reg_table.read_bit("%M325") is True
            assert opc_engine.reg_table.read_bit("%M324") is False

    def test_operator_manual_reset_handshake_restores_permissive(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify reset_fault restores permissive coil %M324 and clears %M325."""
        opc_engine.simulate_rpc_disconnect()
        assert opc_engine.fault_trip is True

        opc_engine.reconnect_dcom()
        res = opc_engine.reset_fault(force=True)

        assert res.status == AgentStatus.SUCCESS
        assert opc_engine.fault_trip is False
        assert opc_engine.permissive is True
        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OK
        assert opc_engine.reg_table.read_uword("%R1397") == 0x0000
        assert opc_engine.reg_table.read_bit("%M324") is True
        assert opc_engine.reg_table.read_bit("%M325") is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization & PrivilegeMode.SYSTEM
# ============================================================================

class TestSection7RegisterSpaceSynchronization:
    """Tests for %R1390..%R1397 and %M324..%M325 Horner register bindings."""

    def test_register_space_layout_initial(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify initial register values across %R1390..%R1397 and %M324..%M325."""
        opc_engine.sync_to_registers()
        rt = opc_engine.reg_table

        # %R1390: ConnectedOpcGroupsCount (1 default group)
        assert rt.read_word("%R1390") == 1
        # %R1391: ActiveOpcItemsCount (64 default items)
        assert rt.read_word("%R1391") == 64
        # %R1392: OpcDaTransactionLatencyMsScaled (35 = 3.5 ms)
        assert rt.read_word("%R1392") == NOMINAL_LATENCY_SCALED
        # %R1393: OpcItemQualityCodeWord (0x00C0 = GOOD)
        assert rt.read_uword("%R1393") == OPC_QUALITY_GOOD
        # %R1394: DcomReconnectFailuresCount (0)
        assert rt.read_word("%R1394") == 0
        # %R1395: OpcBridgeStateWord (Server connected and permissive active)
        state_word = rt.read_word("%R1395")
        assert (state_word & int(OpcBridgeStateBits.SERVER_CONNECTED)) != 0
        assert (state_word & int(OpcBridgeStateBits.PERMISSIVE)) != 0
        # %R1396: OpcGroupUpdateRateMs (100)
        assert rt.read_word("%R1396") == DEFAULT_GROUP_UPDATE_RATE_MS
        # %R1397: DiagnosticStatusCode (0x0000)
        assert rt.read_uword("%R1397") == 0x0000
        # Discrete Coils
        assert rt.read_bit("%M324") is True
        assert rt.read_bit("%M325") is False

    def test_system_privilege_mode_enforced(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify safe write helpers use PrivilegeMode.SYSTEM."""
        rt = opc_engine.reg_table
        safe_write_word(rt, "%R1392", 50)
        safe_write_uword(rt, "%R1393", 0x00C0)
        safe_write_bit(rt, "%M324", True)

        assert rt.read_word("%R1392") == 50
        assert rt.read_uword("%R1393") == 0x00C0
        assert rt.read_bit("%M324") is True

    def test_bridge_state_word_bitmask_flags(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify bitmask flags update dynamically on connection and fault injection."""
        state_word = opc_engine.compute_state_word()
        assert (state_word & int(OpcBridgeStateBits.SERVER_CONNECTED)) != 0
        assert (state_word & int(OpcBridgeStateBits.GROUPS_ACTIVE)) != 0

        # Inject RPC disconnect
        opc_engine.simulate_rpc_disconnect()
        state_fault = opc_engine.compute_state_word()
        assert (state_fault & int(OpcBridgeStateBits.FAULT_TRIP)) != 0
        assert (state_fault & int(OpcBridgeStateBits.RPC_DISCONNECT_FAULT)) != 0

    def test_live_register_binding_bidirectional_sync(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify live RegisterTable synchronization with bound %R registers."""
        rt = opc_engine.reg_table
        grp = opc_engine.groups[1]
        bound_item = [it for it in grp.items.values() if it.register_binding == "%R1000"][0]

        # 1. RegisterTable write reflected in sync read
        safe_write_word(rt, "%R1000", 3210)
        vals, _, _, _ = opc_engine.sync_read(grp.server_handle, [bound_item.server_handle])
        assert vals == [3210]

        # 2. Sync write reflected in RegisterTable
        opc_engine.sync_write(grp.server_handle, [bound_item.server_handle], [8899])
        assert rt.read_word("%R1000") == 8899


# ============================================================================
# Section 8: ILogicUnit Scan Cycle Execution and State Machine Transitions
# ============================================================================

class TestSection8ILogicUnitScanCycleAndStateMachine:
    """Tests verifying simulation engine ILogicUnit interface and state transitions."""

    def test_ilogicunit_properties_and_execution(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify name, priority, is_enabled, execute with ScanContext, and reset."""
        assert opc_engine.name == "opc_da_bridge"
        assert opc_engine.priority == 92
        assert opc_engine.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: opc_engine.reg_table.read_register(addr),
            set_register=lambda addr, val: opc_engine.reg_table.write_register(
                addr, val, privilege=PrivilegeMode.SYSTEM
            ),
            get_variable=lambda k, d=None: None,
            set_variable=lambda k, v: None,
            record_fault=lambda fault: None,
        )
        opc_engine.execute(ctx)
        assert opc_engine.elapsed_time_ms >= 10.0

    def test_ilogicunit_clock_advancement(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify scan_step advances internal simulation clock."""
        t0 = opc_engine.elapsed_time_ms
        opc_engine.scan_step(dt=0.010)
        assert opc_engine.elapsed_time_ms == pytest.approx(t0 + 10.0, rel=1e-3)

    def test_ilogicunit_reset_lifecycle(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify reset restores engine to healthy state."""
        opc_engine.simulate_rpc_disconnect()
        assert opc_engine.fault_trip is True

        opc_engine.reconnect_dcom()
        opc_engine.reset()
        assert opc_engine.fault_trip is False
        assert opc_engine.permissive is True
        assert opc_engine.diagnostic_code == OpcDaDiagnosticCode.OK

    def test_state_machine_transitions(self, opc_engine: OpcDaBridgeEngine) -> None:
        """Verify state transitions across IDLE, CONNECTING, GROUP_ACTIVE, and FAULT."""
        assert opc_engine.state == OpcGatewayState.GROUP_ACTIVE

        # Fault state
        opc_engine.simulate_rpc_disconnect()
        assert opc_engine.state == OpcGatewayState.OPC_FAULT

        # Reset
        opc_engine.reconnect_dcom()
        opc_engine.reset_fault(force=True)
        assert opc_engine.state == OpcGatewayState.GROUP_ACTIVE


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test Writing Evidence JSON
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests executing the 9-stage verification suite and checking evidence output."""

    def test_run_opc_da_bridge_verification_suite(self) -> None:
        """Execute 9-stage verification suite, assert all pass, and verify evidence JSON file."""
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "opc_da_bridge_evidence.json"
            res = run_opc_da_bridge_verification(output_path=output_file)

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9
            assert len(res["data"]["tests"]) == 9

            for t in res["data"]["tests"]:
                assert t["passed"] is True
                assert "stage" in t
                assert "check" in t

            assert output_file.exists()
            with open(output_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["checks_passed"] == 9
            assert saved["data"]["work_package"] == "W178"
            assert saved["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
            assert saved["data"]["register_map"]["analog_registers"] == "%R1390..%R1397"
            assert saved["data"]["register_map"]["discrete_coils"] == "%M324..%M325"
