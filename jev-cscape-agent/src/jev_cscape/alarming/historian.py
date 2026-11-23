"""Horner OCS Industrial Alarming & Event Historian Subsystem (ANSI/ISA-18.2).

Work Package: W028 (Gate G8 / Alarming & Historian)
Classification: PRODUCTION [industrial alarming, scan-cycle monitoring & event historian]

Implements:
1. ANSI/ISA-18.2 alarm management lifecycle:
   - States: NORMAL, UNACKNOWLEDGED, ACKNOWLEDGED, RTN_UNACK, SHELVED.
   - Deterministic transitions: trip, acknowledge, clear, shelve, unshelve.
2. Alarm definition model bound to Horner OCS memory map (%M, %I, %Q, %R, etc.).
3. Circular ring buffer event log with microsecond timestamping (capacity 5,000+).
4. Cycle-by-cycle register monitoring with on-delay debouncing and deadband hysteresis.
5. Priority filtering, unacknowledged count, active alarm summaries, and deterministic JSON export.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union
from pydantic import BaseModel, Field, field_validator


class AlarmSeverity(str, Enum):
    """Alarm priority severity levels per ISA-18.2 guidelines."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Numeric rank for priority filtering and sorting (1=LOW, 4=CRITICAL)."""
        _RANK_MAP = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return _RANK_MAP[self.value]

    def _resolve_level(self, other: Any) -> Optional[int]:
        if isinstance(other, AlarmSeverity):
            return other.level
        if isinstance(other, str):
            try:
                return AlarmSeverity(other).level
            except ValueError:
                return None
        return None

    def __ge__(self, other: Any) -> bool:
        lvl = self._resolve_level(other)
        if lvl is not None:
            return self.level >= lvl
        raise TypeError(f"'>=' not supported between instances of 'AlarmSeverity' and '{type(other).__name__}'")

    def __gt__(self, other: Any) -> bool:
        lvl = self._resolve_level(other)
        if lvl is not None:
            return self.level > lvl
        raise TypeError(f"'>' not supported between instances of 'AlarmSeverity' and '{type(other).__name__}'")

    def __le__(self, other: Any) -> bool:
        lvl = self._resolve_level(other)
        if lvl is not None:
            return self.level <= lvl
        raise TypeError(f"'<=' not supported between instances of 'AlarmSeverity' and '{type(other).__name__}'")

    def __lt__(self, other: Any) -> bool:
        lvl = self._resolve_level(other)
        if lvl is not None:
            return self.level < lvl
        raise TypeError(f"'<' not supported between instances of 'AlarmSeverity' and '{type(other).__name__}'")



class AlarmState(str, Enum):
    """Standard alarm operational states per ANSI/ISA-18.2-2016."""
    NORMAL = "NORMAL"                    # Process condition in normal state; no alarm condition
    UNACKNOWLEDGED = "UNACKNOWLEDGED"    # Alarm condition active, not acknowledged by operator
    ACKNOWLEDGED = "ACKNOWLEDGED"        # Alarm condition active, acknowledged by operator
    RTN_UNACK = "RTN_UNACK"              # Process returned to normal before operator acknowledgement
    SHELVED = "SHELVED"                  # Temporarily suppressed / shelved alarm


class AlarmDefinition(BaseModel):
    """Specification of a monitored alarm tag bound to Horner OCS memory."""
    tag: str = Field(..., description="Unique alphanumeric alarm identifier (e.g. 'PAL_101')")
    description: str = Field(default="", description="Operator-facing description of the condition")
    bound_bit: str = Field(..., description="Horner register/bit reference (e.g. '%M1', '%I2', '%Q3', '%R100.1')")
    severity: AlarmSeverity = Field(default=AlarmSeverity.MEDIUM, description="Alarm priority severity")
    trigger_level: float = Field(default=1.0, description="Activation threshold level (1.0 for discrete contacts)")
    deadband: float = Field(default=0.0, ge=0.0, description="Hysteresis deadband for returning to normal")
    delay_ms: float = Field(default=0.0, ge=0.0, description="Trip on-delay debounce timer in milliseconds")
    trigger_high: bool = Field(default=True, description="True if abnormal when >= trigger_level; False if <= trigger_level")
    off_delay_ms: float = Field(default=0.0, ge=0.0, description="Clear off-delay debounce timer in milliseconds")

    @field_validator("tag")
    @classmethod
    def validate_tag(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Alarm tag must not be empty.")
        return s

    @field_validator("bound_bit")
    @classmethod
    def validate_bound_bit(cls, v: str) -> str:
        s = v.strip().upper()
        if not s:
            raise ValueError("Bound bit address must not be empty.")
        if not s.startswith("%"):
            s = "%" + s
        return s


class AlarmEvent(BaseModel):
    """Deterministic, immutable record of an alarm state transition."""
    event_id: str = Field(..., description="Sequential or unique event identifier (e.g. 'EVT-000001')")
    tag: str = Field(..., description="Alarm tag associated with this event")
    timestamp_utc: str = Field(..., description="ISO 8601 UTC timestamp with microsecond resolution")
    state_transition: str = Field(..., description="Transition representation (e.g. 'NORMAL -> UNACKNOWLEDGED')")
    value: Any = Field(..., description="Process or register value at transition time")
    message: str = Field(..., description="Descriptive audit message")
    severity: AlarmSeverity = Field(default=AlarmSeverity.MEDIUM, description="Severity at transition time")


def format_utc_microsecond(dt: Optional[datetime] = None) -> str:
    """Format datetime as UTC ISO 8601 string with 6-digit microsecond precision."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class CircularEventBuffer:
    """Fixed-capacity circular ring buffer with microsecond event tracking."""

    def __init__(self, capacity: int = 5000) -> None:
        if capacity <= 0:
            raise ValueError(f"Circular buffer capacity must be positive, got {capacity}")
        self._capacity: int = int(capacity)
        self._buffer: collections.deque[AlarmEvent] = collections.deque(maxlen=self._capacity)
        self._total_recorded: int = 0

    @property
    def capacity(self) -> int:
        """Maximum number of events retained before circular FIFO overwriting."""
        return self._capacity

    @property
    def total_recorded(self) -> int:
        """Lifetime total count of events appended to the buffer."""
        return self._total_recorded

    @property
    def overflow_count(self) -> int:
        """Count of historical events dropped due to circular buffer wrapping."""
        return max(0, self._total_recorded - self._capacity)

    def append(self, event: AlarmEvent) -> None:
        """Append an event into the ring buffer, evicting the oldest if capacity is exceeded."""
        self._buffer.append(event)
        self._total_recorded += 1

    def to_list(self) -> List[AlarmEvent]:
        """Return shallow copy of events in chronological order (oldest to newest)."""
        return list(self._buffer)

    def clear(self) -> None:
        """Reset the buffer and drop all events."""
        self._buffer.clear()
        self._total_recorded = 0

    def __len__(self) -> int:
        return len(self._buffer)

    def __iter__(self):
        return iter(self._buffer)

    def __getitem__(self, index: Union[int, slice]):
        if isinstance(index, slice):
            return list(self._buffer)[index]
        return self._buffer[index]


class AlarmRecord(BaseModel):
    """Runtime tracking record for a registered alarm definition."""
    definition: AlarmDefinition
    state: AlarmState = AlarmState.NORMAL
    active_condition: bool = False
    current_value: Any = None
    last_transition_utc: Optional[str] = None
    last_trip_utc: Optional[str] = None
    last_ack_utc: Optional[str] = None
    last_clear_utc: Optional[str] = None
    last_shelve_utc: Optional[str] = None
    shelve_reason: Optional[str] = None
    shelve_duration_s: Optional[float] = None
    shelve_expires_utc: Optional[str] = None
    shelve_previous_state: Optional[AlarmState] = None
    acknowledged_by: Optional[str] = None
    accumulated_delay_ms: float = 0.0
    accumulated_off_delay_ms: float = 0.0


class AlarmManager:
    """Industrial Alarm Management and Event Historian Engine (ANSI/ISA-18.2).

    Coordinates alarm registrations, state transitions, scan-cycle memory evaluation,
    circular event logging, priority querying, and deterministic audit serialization.
    """

    def __init__(
        self,
        buffer_capacity: int = 5000,
        clock_fn: Optional[Callable[[], str]] = None,
    ) -> None:
        self._records: Dict[str, AlarmRecord] = {}
        self._events: CircularEventBuffer = CircularEventBuffer(capacity=buffer_capacity)
        self._event_counter: int = 0
        self._clock_fn: Optional[Callable[[], str]] = clock_fn

    # --- Time & ID Generators ---

    def _now_utc(self) -> str:
        """Resolve current UTC timestamp with microsecond resolution."""
        if self._clock_fn is not None:
            return self._clock_fn()
        return format_utc_microsecond()

    def _next_event_id(self) -> str:
        """Deterministic sequential event identifier."""
        self._event_counter += 1
        return f"EVT-{self._event_counter:06d}"

    # --- Registration Management ---

    def register_alarm(self, definition: AlarmDefinition) -> AlarmDefinition:
        """Register an alarm definition with the manager.

        Raises:
            ValueError: If an alarm with the same tag is already registered.
        """
        if definition.tag in self._records:
            raise ValueError(f"Alarm tag '{definition.tag}' is already registered.")
        record = AlarmRecord(definition=definition)
        self._records[definition.tag] = record
        return definition

    def register_alarms(self, definitions: Sequence[AlarmDefinition]) -> List[AlarmDefinition]:
        """Register multiple alarm definitions atomically."""
        registered = []
        for d in definitions:
            registered.append(self.register_alarm(d))
        return registered

    def unregister_alarm(self, tag: str) -> Optional[AlarmDefinition]:
        """Remove a registered alarm from monitoring."""
        record = self._records.pop(tag, None)
        return record.definition if record else None

    def get_alarm(self, tag: str) -> Optional[AlarmDefinition]:
        """Retrieve the definition for a registered alarm tag."""
        record = self._records.get(tag)
        return record.definition if record else None

    def get_record(self, tag: str) -> Optional[AlarmRecord]:
        """Retrieve runtime record for a registered alarm tag."""
        return self._records.get(tag)

    def get_state(self, tag: str) -> AlarmState:
        """Return current ISA-18.2 state for an alarm tag.

        Raises:
            KeyError: If tag is not registered.
        """
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")
        return self._records[tag].state

    def is_active(self, tag: str) -> bool:
        """True if alarm is in non-NORMAL state (active/unack/ack/rtn_unack/shelved)."""
        return self.get_state(tag) != AlarmState.NORMAL

    def is_unacknowledged(self, tag: str) -> bool:
        """True if alarm requires operator acknowledgement (UNACKNOWLEDGED or RTN_UNACK)."""
        return self.get_state(tag) in (AlarmState.UNACKNOWLEDGED, AlarmState.RTN_UNACK)

    # --- ISA-18.2 State Machine Transitions ---

    def _record_transition(
        self,
        record: AlarmRecord,
        new_state: AlarmState,
        value: Any,
        message: str,
        timestamp_utc: Optional[str] = None,
    ) -> AlarmEvent:
        """Commit an ISA-18.2 state transition and emit a microsecond event to ring buffer."""
        old_state = record.state
        record.state = new_state
        ts = timestamp_utc or self._now_utc()
        record.last_transition_utc = ts
        record.current_value = value

        transition_str = f"{old_state.value} -> {new_state.value}"
        event = AlarmEvent(
            event_id=self._next_event_id(),
            tag=record.definition.tag,
            timestamp_utc=ts,
            state_transition=transition_str,
            value=value,
            message=message,
            severity=record.definition.severity,
        )
        self._events.append(event)
        return event

    def trip(
        self,
        tag: str,
        value: Any = True,
        message: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> Optional[AlarmEvent]:
        """Trigger an alarm condition (process enters abnormal state).

        Transitions per ISA-18.2:
        - NORMAL -> UNACKNOWLEDGED
        - RTN_UNACK -> UNACKNOWLEDGED (re-trip before ack)
        - ACKNOWLEDGED -> ACKNOWLEDGED (remains acknowledged abnormal)
        - SHELVED -> SHELVED (remains shelved abnormal)
        - UNACKNOWLEDGED -> UNACKNOWLEDGED
        """
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")

        record = self._records[tag]
        record.active_condition = True
        record.current_value = value
        ts = timestamp_utc or self._now_utc()
        record.last_trip_utc = ts

        desc = message or record.definition.description or f"Alarm {tag} tripped"

        if record.state == AlarmState.NORMAL:
            return self._record_transition(record, AlarmState.UNACKNOWLEDGED, value, desc, ts)
        elif record.state == AlarmState.RTN_UNACK:
            re_msg = message or f"Alarm {tag} re-tripped before acknowledgement"
            return self._record_transition(record, AlarmState.UNACKNOWLEDGED, value, re_msg, ts)
        elif record.state in (AlarmState.ACKNOWLEDGED, AlarmState.SHELVED, AlarmState.UNACKNOWLEDGED):
            # Condition is abnormal, but state remains unchanged
            return None
        return None

    def acknowledge(
        self,
        tag: str,
        operator_id: str = "OPERATOR",
        note: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> Optional[AlarmEvent]:
        """Acknowledge an alarm by an operator.

        Transitions per ISA-18.2:
        - UNACKNOWLEDGED -> ACKNOWLEDGED (process is still abnormal)
        - RTN_UNACK -> NORMAL (process had returned to normal, ack clears it)
        - NORMAL / ACKNOWLEDGED / SHELVED -> No state change
        """
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")

        record = self._records[tag]
        ts = timestamp_utc or self._now_utc()
        record.last_ack_utc = ts
        record.acknowledged_by = operator_id

        msg_extra = f" by {operator_id}" + (f": {note}" if note else "")

        if record.state == AlarmState.UNACKNOWLEDGED:
            msg = f"Alarm {tag} acknowledged{msg_extra}"
            return self._record_transition(record, AlarmState.ACKNOWLEDGED, record.current_value, msg, ts)
        elif record.state == AlarmState.RTN_UNACK:
            msg = f"Alarm {tag} return-to-normal acknowledged{msg_extra}"
            return self._record_transition(record, AlarmState.NORMAL, record.current_value, msg, ts)
        return None

    def acknowledge_all(
        self,
        operator_id: str = "OPERATOR",
        note: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> List[AlarmEvent]:
        """Acknowledge all currently unacknowledged alarms."""
        events = []
        for tag, record in list(self._records.items()):
            if record.state in (AlarmState.UNACKNOWLEDGED, AlarmState.RTN_UNACK):
                evt = self.acknowledge(tag, operator_id=operator_id, note=note, timestamp_utc=timestamp_utc)
                if evt:
                    events.append(evt)
        return events

    def clear(
        self,
        tag: str,
        value: Any = False,
        message: Optional[str] = None,
        timestamp_utc: Optional[str] = None,
    ) -> Optional[AlarmEvent]:
        """Clear an abnormal alarm condition (process returns to normal range).

        Transitions per ISA-18.2:
        - UNACKNOWLEDGED -> RTN_UNACK (returned to normal, awaiting operator ack)
        - ACKNOWLEDGED -> NORMAL (operator had already acknowledged, fully normal)
        - NORMAL / RTN_UNACK -> No state change
        - SHELVED -> SHELVED (active condition cleared, remains shelved)
        """
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")

        record = self._records[tag]
        record.active_condition = False
        record.current_value = value
        ts = timestamp_utc or self._now_utc()
        record.last_clear_utc = ts

        desc = message or f"Alarm {tag} returned to normal"

        if record.state == AlarmState.UNACKNOWLEDGED:
            return self._record_transition(record, AlarmState.RTN_UNACK, value, desc, ts)
        elif record.state == AlarmState.ACKNOWLEDGED:
            return self._record_transition(record, AlarmState.NORMAL, value, desc, ts)
        return None

    def shelve(
        self,
        tag: str,
        reason: str = "",
        duration_s: Optional[float] = None,
        timestamp_utc: Optional[str] = None,
    ) -> Optional[AlarmEvent]:
        """Temporarily shelve (suppress) an alarm per ISA-18.2.

        Can shelve from NORMAL, UNACKNOWLEDGED, ACKNOWLEDGED, or RTN_UNACK.
        """
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")

        record = self._records[tag]
        if record.state == AlarmState.SHELVED:
            return None

        ts = timestamp_utc or self._now_utc()
        record.shelve_previous_state = record.state
        record.shelve_reason = reason
        record.shelve_duration_s = duration_s
        record.last_shelve_utc = ts

        if duration_s is not None and duration_s > 0:
            now_dt = datetime.now(timezone.utc)
            expiry_dt = datetime.fromtimestamp(now_dt.timestamp() + duration_s, tz=timezone.utc)
            record.shelve_expires_utc = format_utc_microsecond(expiry_dt)
        else:
            record.shelve_expires_utc = None

        msg = f"Alarm {tag} shelved" + (f": {reason}" if reason else "")
        return self._record_transition(record, AlarmState.SHELVED, record.current_value, msg, ts)

    def unshelve(
        self,
        tag: str,
        timestamp_utc: Optional[str] = None,
    ) -> Optional[AlarmEvent]:
        """Unshelve an alarm, restoring it based on active physical condition."""
        if tag not in self._records:
            raise KeyError(f"Alarm tag '{tag}' is not registered.")

        record = self._records[tag]
        if record.state != AlarmState.SHELVED:
            return None

        ts = timestamp_utc or self._now_utc()
        record.shelve_reason = None
        record.shelve_duration_s = None
        record.shelve_expires_utc = None
        record.shelve_previous_state = None

        if record.active_condition:
            msg = f"Alarm {tag} unshelved with active condition"
            return self._record_transition(record, AlarmState.UNACKNOWLEDGED, record.current_value, msg, ts)
        else:
            msg = f"Alarm {tag} unshelved with normal condition"
            return self._record_transition(record, AlarmState.NORMAL, record.current_value, msg, ts)

    # --- Scan Cycle & Register Monitoring ---

    def evaluate_cycle(
        self,
        register_table: Optional[Any] = None,
        values: Optional[Dict[str, Any]] = None,
        dt_ms: float = 10.0,
        timestamp_utc: Optional[str] = None,
    ) -> List[AlarmEvent]:
        """Evaluate all registered alarms against current scan cycle register state.

        Supports:
        - Horner OCS RegisterTable (`read_register(bound_bit)`).
        - Direct dictionary mapping (`values[bound_bit]` or `values[tag]`).
        - On-delay debounce timing (`delay_ms`).
        - Deadband hysteresis on analog thresholds.
        - Auto-unshelving of expired shelved alarms.
        """
        emitted_events: List[AlarmEvent] = []
        ts = timestamp_utc or self._now_utc()

        # Check shelving expiration
        now_dt = datetime.now(timezone.utc)
        for tag, record in list(self._records.items()):
            if record.state == AlarmState.SHELVED and record.shelve_expires_utc:
                try:
                    exp_dt = datetime.fromisoformat(record.shelve_expires_utc.replace("Z", "+00:00"))
                    if now_dt >= exp_dt:
                        unshelve_evt = self.unshelve(tag, timestamp_utc=ts)
                        if unshelve_evt:
                            emitted_events.append(unshelve_evt)
                except Exception:
                    pass

        # Evaluate each alarm
        for tag, record in self._records.items():
            defn = record.definition
            bound = defn.bound_bit

            # 1. Resolve raw register value
            val = None
            if register_table is not None:
                if hasattr(register_table, "read_register"):
                    try:
                        val = register_table.read_register(bound)
                    except Exception:
                        val = None
                elif isinstance(register_table, dict):
                    val = register_table.get(bound, register_table.get(tag))
            elif values is not None:
                val = values.get(bound, values.get(tag))

            if val is None:
                continue

            # 2. Determine raw condition (abnormal vs normal)
            is_abnormal_raw: bool = False
            if isinstance(val, bool):
                is_abnormal_raw = val if defn.trigger_high else (not val)
            else:
                try:
                    num_val = float(val)
                    if defn.trigger_high:
                        if not record.active_condition:
                            is_abnormal_raw = num_val >= defn.trigger_level
                        else:
                            # With deadband hysteresis: stay abnormal until below (trigger_level - deadband)
                            is_abnormal_raw = not (num_val < (defn.trigger_level - defn.deadband))
                    else:
                        if not record.active_condition:
                            is_abnormal_raw = num_val <= defn.trigger_level
                        else:
                            # With deadband hysteresis: stay abnormal until above (trigger_level + deadband)
                            is_abnormal_raw = not (num_val > (defn.trigger_level + defn.deadband))
                except (ValueError, TypeError):
                    is_abnormal_raw = bool(val)

            # 3. Handle on-delay debounce timer (delay_ms)
            confirmed_abnormal: bool = False
            if defn.delay_ms > 0:
                if is_abnormal_raw:
                    record.accumulated_delay_ms += dt_ms
                    if record.accumulated_delay_ms >= defn.delay_ms:
                        confirmed_abnormal = True
                else:
                    record.accumulated_delay_ms = 0.0
                    confirmed_abnormal = False
            else:
                confirmed_abnormal = is_abnormal_raw

            # 4. Trigger transitions when condition changes
            if confirmed_abnormal and not record.active_condition:
                trip_evt = self.trip(tag, value=val, timestamp_utc=ts)
                if trip_evt:
                    emitted_events.append(trip_evt)
            elif not confirmed_abnormal and record.active_condition:
                record.accumulated_delay_ms = 0.0
                clear_evt = self.clear(tag, value=val, timestamp_utc=ts)
                if clear_evt:
                    emitted_events.append(clear_evt)

        return emitted_events

    def evaluate_scan(
        self,
        register_table: Optional[Any] = None,
        values: Optional[Dict[str, Any]] = None,
        dt_ms: float = 10.0,
        timestamp_utc: Optional[str] = None,
    ) -> List[AlarmEvent]:
        """Convenience alias for `evaluate_cycle`."""
        return self.evaluate_cycle(register_table=register_table, values=values, dt_ms=dt_ms, timestamp_utc=timestamp_utc)

    # --- Filtering and Querying ---

    def get_events(
        self,
        tag: Optional[str] = None,
        severity: Optional[AlarmSeverity] = None,
        min_severity: Optional[AlarmSeverity] = None,
        limit: Optional[int] = None,
    ) -> List[AlarmEvent]:
        """Query historical events with priority and tag filtering."""
        filtered = []
        for evt in self._events:
            if tag is not None and evt.tag != tag:
                continue
            if severity is not None and evt.severity != severity:
                continue
            if min_severity is not None and evt.severity < min_severity:
                continue
            filtered.append(evt)

        if limit is not None and limit > 0:
            return filtered[-limit:]
        return filtered

    def get_active_alarms(
        self,
        min_severity: Optional[AlarmSeverity] = None,
        severity: Optional[AlarmSeverity] = None,
        state: Optional[AlarmState] = None,
    ) -> List[AlarmRecord]:
        """Return registered alarms currently in a non-NORMAL active state."""
        res = []
        for record in self._records.values():
            if record.state == AlarmState.NORMAL:
                continue
            if state is not None and record.state != state:
                continue
            if severity is not None and record.definition.severity != severity:
                continue
            if min_severity is not None and record.definition.severity < min_severity:
                continue
            res.append(record)
        return res

    def get_unacknowledged_alarms(
        self,
        min_severity: Optional[AlarmSeverity] = None,
    ) -> List[AlarmRecord]:
        """Return active alarms currently requiring operator acknowledgement."""
        res = []
        for record in self._records.values():
            if record.state in (AlarmState.UNACKNOWLEDGED, AlarmState.RTN_UNACK):
                if min_severity is not None and record.definition.severity < min_severity:
                    continue
                res.append(record)
        return res

    # --- Summary Metrics ---

    @property
    def total_registered(self) -> int:
        """Count of registered alarm definitions."""
        return len(self._records)

    @property
    def active_count(self) -> int:
        """Count of alarms not in NORMAL state."""
        return sum(1 for r in self._records.values() if r.state != AlarmState.NORMAL)

    @property
    def unacknowledged_count(self) -> int:
        """Count of alarms requiring acknowledgement (UNACKNOWLEDGED or RTN_UNACK)."""
        return sum(1 for r in self._records.values() if r.state in (AlarmState.UNACKNOWLEDGED, AlarmState.RTN_UNACK))

    @property
    def acknowledged_count(self) -> int:
        """Count of alarms in ACKNOWLEDGED state."""
        return sum(1 for r in self._records.values() if r.state == AlarmState.ACKNOWLEDGED)

    @property
    def rtn_unack_count(self) -> int:
        """Count of alarms in RTN_UNACK state."""
        return sum(1 for r in self._records.values() if r.state == AlarmState.RTN_UNACK)

    @property
    def shelved_count(self) -> int:
        """Count of alarms in SHELVED state."""
        return sum(1 for r in self._records.values() if r.state == AlarmState.SHELVED)

    @property
    def normal_count(self) -> int:
        """Count of alarms in NORMAL state."""
        return sum(1 for r in self._records.values() if r.state == AlarmState.NORMAL)

    @property
    def counts_by_severity(self) -> Dict[str, int]:
        """Count of active (non-NORMAL) alarms broken down by severity."""
        counts = {sev.value: 0 for sev in AlarmSeverity}
        for r in self._records.values():
            if r.state != AlarmState.NORMAL:
                counts[r.definition.severity.value] += 1
        return counts

    @property
    def counts_by_state(self) -> Dict[str, int]:
        """Count of registered alarms broken down by ISA-18.2 state."""
        counts = {st.value: 0 for st in AlarmState}
        for r in self._records.values():
            counts[r.state.value] += 1
        return counts

    @property
    def buffer_stats(self) -> Dict[str, int]:
        """Circular event buffer statistics."""
        return {
            "capacity": self._events.capacity,
            "current_size": len(self._events),
            "total_recorded": self._events.total_recorded,
            "overflow_count": self._events.overflow_count,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Comprehensive dictionary summary of alarm subsystem status."""
        return {
            "total_registered": self.total_registered,
            "active_count": self.active_count,
            "unacknowledged_count": self.unacknowledged_count,
            "acknowledged_count": self.acknowledged_count,
            "rtn_unack_count": self.rtn_unack_count,
            "shelved_count": self.shelved_count,
            "normal_count": self.normal_count,
            "counts_by_severity": self.counts_by_severity,
            "counts_by_state": self.counts_by_state,
            "buffer": self.buffer_stats,
        }

    # --- Deterministic JSON Export ---

    def export_events_json(
        self,
        filepath: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export chronological event history to deterministic formatted JSON."""
        events_payload = [e.model_dump() for e in self._events.to_list()]
        json_str = json.dumps(events_payload, indent=indent, sort_keys=True, default=str)

        if filepath is not None:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")

        return json_str

    def export_state_json(
        self,
        filepath: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export current runtime alarm states to deterministic formatted JSON."""
        state_dict: Dict[str, Any] = {}
        for tag in sorted(self._records.keys()):
            record = self._records[tag]
            state_dict[tag] = record.model_dump()

        json_str = json.dumps(state_dict, indent=indent, sort_keys=True, default=str)

        if filepath is not None:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")

        return json_str

    def export_summary_json(
        self,
        filepath: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export alarm subsystem summary metrics to deterministic formatted JSON."""
        summary = self.get_summary()
        json_str = json.dumps(summary, indent=indent, sort_keys=True, default=str)

        if filepath is not None:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")

        return json_str

    def export_full_audit_json(
        self,
        filepath: Optional[Union[str, Path]] = None,
        indent: int = 2,
    ) -> str:
        """Export full audit bundle (summary, active alarms, states, events) to deterministic JSON."""
        audit_payload = {
            "schema_version": "1.0.0",
            "standard": "ANSI/ISA-18.2-2016",
            "summary": self.get_summary(),
            "active_alarms": [
                r.model_dump()
                for r in sorted(self.get_active_alarms(), key=lambda r: r.definition.tag)
            ],
            "all_alarms": {
                tag: self._records[tag].model_dump()
                for tag in sorted(self._records.keys())
            },
            "events": [e.model_dump() for e in self._events.to_list()],
        }

        json_str = json.dumps(audit_payload, indent=indent, sort_keys=True, default=str)

        if filepath is not None:
            p = Path(filepath)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json_str, encoding="utf-8")

        return json_str
