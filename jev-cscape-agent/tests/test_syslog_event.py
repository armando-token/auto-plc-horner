"""Unit tests for Real-Time SCADA Process Event Logger & Syslog RFC 5424 Serializer (W062).

Tests:
1. Syslog PRI calculation ((Facility * 8) + Severity).
2. RFC 5424 serialization format and timestamp parsing.
3. Structured Data parameter escaping ('\\', '\"', ']').
4. UTF-8 BOM encoding for unicode / non-ASCII message strings.
5. Forward-secure cryptographic hash chain continuity from genesis anchor.
6. Cryptographic tamper detection on simulated log tampering or history rewrite.
7. Token bucket rate limiter behavior on high-frequency event bursts.
8. Emergency and Alert unconditional rate limiter bypass.
9. Sliding-window event deduplication against alarm chatter.
10. Emergency and Alert deduplication bypass.
11. Horner OCS register space synchronization (%R260..%R264, %M56..%M57).
12. ILogicUnit protocol compliance and scan cycle execution.
13. Pure ST boundary enforcement: rejection of illegal ladder logic constructs.
14. Complete end-to-end verification runner and artifact generation.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.syslog_event import (
    GENESIS_HASH,
    EventDeduplicator,
    StructuredDataElement,
    StructuredDataParam,
    SyslogEventLogger,
    SyslogFacility,
    SyslogMessage,
    SyslogSeverity,
    SyslogStatusFlag,
    TokenBucketRateLimiter,
    verify_hash_chain,
    verify_syslog_event_and_export_evidence,
)


def test_syslog_message_pri_calculation() -> None:
    """Verify RFC 5424 PRI = (Facility * 8) + Severity."""
    # LOCAL0 (16) * 8 + INFORMATIONAL (6) = 134
    msg1 = SyslogMessage(
        facility=SyslogFacility.LOCAL0,
        severity=SyslogSeverity.INFORMATIONAL,
        timestamp=datetime.now(timezone.utc),
        hostname="cscape",
        app_name="scada",
        proc_id="1",
        msg_id="TEST",
        structured_data=(),
        msg="Test message",
        sequence_num=1,
        prev_hash="000",
        curr_hash="111",
    )
    assert msg1.pri == 134

    # LOCAL0 (16) * 8 + EMERGENCY (0) = 128
    msg2 = dataclasses_replace(msg1, severity=SyslogSeverity.EMERGENCY)
    assert msg2.pri == 128

    # KERN (0) * 8 + ALERT (1) = 1
    msg3 = dataclasses_replace(msg1, facility=SyslogFacility.KERN, severity=SyslogSeverity.ALERT)
    assert msg3.pri == 1


def test_syslog_rfc5424_serialization_format() -> None:
    """Verify serialized string adheres strictly to RFC 5424 grammar."""
    dt = datetime(2026, 10, 2, 14, 30, 0, 123456, tzinfo=timezone.utc)
    sd = StructuredDataElement(
        "origin@48577",
        (StructuredDataParam("swVersion", "10.2"),),
    )
    msg = SyslogMessage(
        facility=SyslogFacility.LOCAL0,
        severity=SyslogSeverity.WARNING,
        timestamp=dt,
        hostname="cscape-host",
        app_name="jev-agent",
        proc_id="42",
        msg_id="TEMP_WARN",
        structured_data=(sd,),
        msg="High tank temperature",
        sequence_num=1,
        prev_hash="a",
        curr_hash="b",
    )
    serialized = msg.serialize()
    # Expected: <132>1 2026-10-02T14:30:00.123456Z cscape-host jev-agent 42 TEMP_WARN [origin@48577 swVersion="10.2"] High tank temperature
    assert serialized.startswith("<132>1 2026-10-02T14:30:00.123456Z cscape-host jev-agent 42 TEMP_WARN")
    assert '[origin@48577 swVersion="10.2"]' in serialized
    assert serialized.endswith("High tank temperature")


def test_syslog_structured_data_escaping() -> None:
    """Verify backslash, quote, and right-bracket characters are escaped per RFC 5424."""
    param = StructuredDataParam("pattern", r'c:\path\file "quote" [tag]')
    formatted = param.format()
    # \ -> \\, " -> \", ] -> \]
    assert formatted == r'pattern="c:\\path\\file \"quote\" [tag\]"'


def test_syslog_unicode_bom_handling() -> None:
    """Verify non-ASCII characters trigger UTF-8 BOM prefix per RFC 5424."""
    msg = SyslogMessage(
        facility=SyslogFacility.LOCAL0,
        severity=SyslogSeverity.NOTICE,
        timestamp=datetime.now(timezone.utc),
        hostname="cscape",
        app_name="app",
        proc_id="1",
        msg_id="UNICODE",
        structured_data=(),
        msg="Pressure normal: 100 \u03bcPa \u00b0C",  # Unicode mu and degree
        sequence_num=1,
        prev_hash="a",
        curr_hash="b",
    )
    serialized = msg.serialize()
    assert "\xef\xbb\xbf" in serialized
    assert "Pressure normal: 100 \u03bcPa \u00b0C" in serialized


def test_forward_secure_hash_chain_integrity() -> None:
    """Verify sequential events build a valid, unbroken cryptographic hash chain."""
    logger = SyslogEventLogger()
    for i in range(10):
        ev = logger.log(
            facility=SyslogFacility.LOCAL0,
            severity=SyslogSeverity.INFORMATIONAL,
            msg_id=f"EV_{i}",
            msg=f"Event payload number {i}",
        )
        assert ev is not None

    assert len(logger.events) == 10
    valid, err = verify_hash_chain(logger.events)
    assert valid is True
    assert err is None


def test_hash_chain_tamper_detection() -> None:
    """Verify modifying any payload or hash link is detected immediately by auditor."""
    logger = SyslogEventLogger()
    for i in range(5):
        logger.log(
            facility=SyslogFacility.LOCAL0,
            severity=SyslogSeverity.INFORMATIONAL,
            msg_id=f"EV_{i}",
            msg=f"Payload {i}",
        )

    # 1. Modify payload of message 2
    original_msg = logger.events[2]
    tampered_msg = dataclasses_replace(original_msg, msg="TAMPERED PAYLOAD")
    tampered_events = list(logger.events)
    tampered_events[2] = tampered_msg

    valid, err = verify_hash_chain(tampered_events)
    assert valid is False
    assert "Digest corruption at sequence 3" in str(err)

    # 2. Break chain pointer of message 4
    tampered_events_2 = list(logger.events)
    tampered_events_2[4] = dataclasses_replace(logger.events[4], prev_hash="bad_hash_pointer")
    valid2, err2 = verify_hash_chain(tampered_events_2)
    assert valid2 is False
    assert "Hash pointer mismatch at sequence 5" in str(err2)


def test_token_bucket_rate_limiter() -> None:
    """Verify token bucket drops non-emergency events when capacity is exhausted."""
    # Capacity 5, refill rate 0.1 tokens/sec
    limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=0.1)

    # First 5 events allowed
    for _ in range(5):
        assert limiter.allow(SyslogSeverity.INFORMATIONAL) is True

    # 6th event blocked
    assert limiter.allow(SyslogSeverity.INFORMATIONAL) is False
    assert limiter.allow(SyslogSeverity.WARNING) is False


def test_emergency_alert_rate_limit_bypass() -> None:
    """Verify Emergency and Alert events bypass rate limiter even when empty."""
    limiter = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0)
    assert limiter.allow(SyslogSeverity.INFORMATIONAL) is True
    assert limiter.allow(SyslogSeverity.INFORMATIONAL) is False  # Empty!

    # Emergency and Alert bypass
    assert limiter.allow(SyslogSeverity.EMERGENCY) is True
    assert limiter.allow(SyslogSeverity.ALERT) is True
    assert limiter.allow(SyslogSeverity.EMERGENCY) is True


def test_sliding_window_deduplication() -> None:
    """Verify rapid duplicates within dedup window are suppressed."""
    dedup = EventDeduplicator(window_s=0.500)
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.WARNING, "WARN1", "Chatter") is False
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.WARNING, "WARN1", "Chatter") is True
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.WARNING, "WARN1", "Different") is False


def test_emergency_alert_dedup_bypass() -> None:
    """Verify Emergency and Alert are never suppressed by deduplication."""
    dedup = EventDeduplicator(window_s=1.0)
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.ALERT, "ALM1", "Tripped") is False
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.ALERT, "ALM1", "Tripped") is False
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.EMERGENCY, "ALM2", "Stop") is False
    assert dedup.is_duplicate(SyslogFacility.LOCAL0, SyslogSeverity.EMERGENCY, "ALM2", "Stop") is False


def test_horner_register_synchronization() -> None:
    """Verify %R260..%R264 and %M56..%M57 reflect logger telemetry accurately."""
    reg = RegisterTable()
    logger = SyslogEventLogger(register_table=reg, rate_limit_capacity=2.0, rate_limit_refill=0.0)

    # Initial registers
    assert reg.read_bit("%M56") is True
    assert reg.read_bit("%M57") is False
    assert reg.read_word("%R260") & SyslogStatusFlag.ACTIVE
    assert reg.read_word("%R261") == 0
    assert reg.read_word("%R262") == 0

    # Log 2 allowed
    logger.log(SyslogFacility.LOCAL0, SyslogSeverity.INFORMATIONAL, "A", "Msg A")
    logger.log(SyslogFacility.LOCAL0, SyslogSeverity.INFORMATIONAL, "B", "Msg B")
    # Log 1 dropped by rate limiter
    logger.log(SyslogFacility.LOCAL0, SyslogSeverity.INFORMATIONAL, "C", "Msg C")

    assert reg.read_word("%R261") == 2
    assert reg.read_word("%R262") == 0
    assert reg.read_word("%R263") == 1  # 1 dropped
    assert reg.read_word("%R260") & SyslogStatusFlag.RATE_LIMIT_ACTIVE

    # Reset via %M57
    reg.write_bit("%M57", True, privilege=PrivilegeMode.SYSTEM)
    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: 0,
        set_register=lambda addr, val: None,
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )
    logger.execute(ctx)

    assert reg.read_word("%R261") == 0
    assert reg.read_word("%R263") == 0
    assert reg.read_bit("%M57") is False


def test_ilogicunit_scan_context_execution() -> None:
    """Verify SyslogEventLogger executes inside ScanContext as an ILogicUnit."""
    logger = SyslogEventLogger()
    assert logger.priority == 90
    assert logger.name == "SyslogEventLoggerUnit"
    assert logger.is_enabled is True

    ctx = ScanContext(
        cycle=10,
        dt_ms=10.0,
        elapsed_time_ms=100.0,
        get_register=lambda addr: 0,
        set_register=lambda addr, val: None,
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )
    logger.execute(ctx)


def test_pure_st_ladder_rejection() -> None:
    """Verify security guard intercepts ladder constructs in Syslog context."""
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content("---[ ]---; (* illegal ladder in logger script *)")


def test_verify_syslog_event_evidence_export(tmp_path: Path) -> None:
    """Verify canonical verification function runs cleanly and generates evidence."""
    ev_file = tmp_path / "syslog_evidence.json"
    log_file = tmp_path / "scada.log"

    result = verify_syslog_event_and_export_evidence(str(ev_file), str(log_file))
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert ev_file.exists()
    assert log_file.exists()

    with open(ev_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert data["data"]["cryptographic_chain"]["chain_valid"] is True


def dataclasses_replace(obj: SyslogMessage, **changes: Any) -> SyslogMessage:
    """Helper to shallow-replace fields on frozen dataclass."""
    d = {f.name: getattr(obj, f.name) for f in dataclasses.fields(obj)}
    d.update(changes)
    return SyslogMessage(**d)
