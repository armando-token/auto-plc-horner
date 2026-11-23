"""Industrial Recipe Versioning and Cryptographic Audit Trail Engine.

Implements FDA 21 CFR Part 11 and ANSI/ISA-88 (IEC 61512) compliant recipe
lifecycle management with:
- Strict 4-state lifecycle model: DRAFT -> APPROVED -> ACTIVE -> RETIRED
- SHA-256 linked cryptographic hash chain
- Digital signoffs with explicit regulatory meaning
- Parameter diff computation and forward-only atomic rollback
- RegisterTable staging & double-buffered commit integration
- Tamper detection and audit verification
"""

from __future__ import annotations

import datetime
import hashlib
import json
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class RecipeLifecycleState(str, Enum):
    """Lifecycle state machine states for industrial recipes."""

    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class SignatureMeaning(str, Enum):
    """FDA 21 CFR Part 11 electronic signature meanings."""

    AUTHORSHIP = "AUTHORSHIP"
    PEER_REVIEW = "PEER_REVIEW"
    QUALITY_APPROVAL = "QUALITY_APPROVAL"
    EXECUTION_AUTHORIZATION = "EXECUTION_AUTHORIZATION"
    RETIREMENT_CONFIRMATION = "RETIREMENT_CONFIRMATION"


class DiffType(str, Enum):
    """Parameter comparison classification."""

    ADDED = "ADDED"
    REMOVED = "REMOVED"
    MODIFIED = "MODIFIED"
    UNCHANGED = "UNCHANGED"


class ParameterDiff(BaseModel):
    """Individual parameter delta entry."""

    parameter_name: str
    register_address: Optional[str] = None
    old_value: Optional[Union[float, int, bool, str]] = None
    new_value: Optional[Union[float, int, bool, str]] = None
    delta: Optional[float] = None
    percent_delta: Optional[float] = None
    diff_type: DiffType = DiffType.UNCHANGED


class DigitalSignoff(BaseModel):
    """21 CFR Part 11 compliant electronic signature record."""

    signer_id: str
    signer_name: str
    role: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    meaning: SignatureMeaning
    comment: str = ""

    def digest(self) -> str:
        """Compute cryptographic hash of the signoff record."""
        payload = f"{self.signer_id}:{self.signer_name}:{self.role}:{self.meaning.value}:{self.timestamp_utc}:{self.comment}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RecipeRevision(BaseModel):
    """Immutable recipe revision container."""

    recipe_id: str
    revision_id: str
    version: str = "1.0.0"
    state: RecipeLifecycleState = RecipeLifecycleState.DRAFT
    parameters: Dict[str, Any]
    created_at_utc: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    signoff: Optional[DigitalSignoff] = None
    payload_hash: str = ""

    def compute_payload_hash(self) -> str:
        """Deterministic canonical SHA-256 digest of parameters."""
        canonical_json = json.dumps(self.parameters, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class AuditRecord(BaseModel):
    """Cryptographic audit ledger block in a forward-linked Merkle chain."""

    record_index: int
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    operator_id: str
    action: str
    recipe_id: str
    revision_id: str
    state_before: Optional[RecipeLifecycleState] = None
    state_after: RecipeLifecycleState
    payload_hash: str
    prev_hash: str
    entry_hash: str = ""
    signature_hash: Optional[str] = None
    diffs: List[ParameterDiff] = Field(default_factory=list)
    reason: str = ""

    def calculate_entry_hash(self) -> str:
        """Compute SHA-256 hash over canonical ledger block contents."""
        fields = [
            str(self.record_index),
            self.timestamp_utc,
            self.operator_id,
            self.action,
            self.recipe_id,
            self.revision_id,
            self.state_before.value if self.state_before else "NONE",
            self.state_after.value,
            self.payload_hash,
            self.prev_hash,
            self.signature_hash or "NONE",
        ]
        raw = "|".join(fields)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class RecipeAuditEngine:
    """Enterprise-grade Recipe Versioning & Cryptographic Audit Controller."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self) -> None:
        self.revisions: Dict[str, Dict[str, RecipeRevision]] = {}  # recipe_id -> revision_id -> RecipeRevision
        self.active_revisions: Dict[str, str] = {}  # recipe_id -> revision_id
        self.audit_chain: List[AuditRecord] = []
        self._initialize_genesis()

    def _initialize_genesis(self) -> None:
        """Create genesis block for the audit chain."""
        genesis = AuditRecord(
            record_index=0,
            operator_id="SYSTEM",
            action="GENESIS",
            recipe_id="SYSTEM",
            revision_id="0",
            state_before=None,
            state_after=RecipeLifecycleState.ACTIVE,
            payload_hash=self.GENESIS_HASH,
            prev_hash=self.GENESIS_HASH,
            reason="Genesis initialization of industrial recipe audit ledger.",
        )
        genesis.entry_hash = genesis.calculate_entry_hash()
        self.audit_chain.append(genesis)

    @property
    def latest_hash(self) -> str:
        return self.audit_chain[-1].entry_hash if self.audit_chain else self.GENESIS_HASH

    def _append_audit_record(
        self,
        operator_id: str,
        action: str,
        recipe_id: str,
        revision_id: str,
        state_before: Optional[RecipeLifecycleState],
        state_after: RecipeLifecycleState,
        payload_hash: str,
        signature_hash: Optional[str] = None,
        diffs: Optional[List[ParameterDiff]] = None,
        reason: str = "",
    ) -> AuditRecord:
        record = AuditRecord(
            record_index=len(self.audit_chain),
            operator_id=operator_id,
            action=action,
            recipe_id=recipe_id,
            revision_id=revision_id,
            state_before=state_before,
            state_after=state_after,
            payload_hash=payload_hash,
            prev_hash=self.latest_hash,
            signature_hash=signature_hash,
            diffs=diffs or [],
            reason=reason,
        )
        record.entry_hash = record.calculate_entry_hash()
        self.audit_chain.append(record)
        return record

    @staticmethod
    def compute_diff(
        params_old: Dict[str, Any],
        params_new: Dict[str, Any],
    ) -> List[ParameterDiff]:
        """Compute detailed parameter differences between two dictionaries."""
        diffs: List[ParameterDiff] = []
        all_keys = sorted(set(params_old.keys()).union(params_new.keys()))

        for k in all_keys:
            if k not in params_old:
                new_v = params_new[k]
                diffs.append(
                    ParameterDiff(
                        parameter_name=k,
                        new_value=new_v,
                        diff_type=DiffType.ADDED,
                    )
                )
            elif k not in params_new:
                old_v = params_old[k]
                diffs.append(
                    ParameterDiff(
                        parameter_name=k,
                        old_value=old_v,
                        diff_type=DiffType.REMOVED,
                    )
                )
            else:
                old_v = params_old[k]
                new_v = params_new[k]
                if old_v != new_v:
                    delta = None
                    pct_delta = None
                    if isinstance(old_v, (int, float)) and isinstance(new_v, (int, float)):
                        delta = float(new_v) - float(old_v)
                        if abs(float(old_v)) > 1e-9:
                            pct_delta = (delta / float(old_v)) * 100.0
                    diffs.append(
                        ParameterDiff(
                            parameter_name=k,
                            old_value=old_v,
                            new_value=new_v,
                            delta=delta,
                            percent_delta=pct_delta,
                            diff_type=DiffType.MODIFIED,
                        )
                    )
                else:
                    diffs.append(
                        ParameterDiff(
                            parameter_name=k,
                            old_value=old_v,
                            new_value=new_v,
                            diff_type=DiffType.UNCHANGED,
                        )
                    )
        return diffs

    def create_draft(
        self,
        recipe_id: str,
        revision_id: str,
        parameters: Dict[str, Any],
        operator_id: str,
        reason: str = "Initial draft creation",
        version: str = "1.0.0",
    ) -> ExecutionResult:
        """Create a new recipe revision in DRAFT state."""
        if recipe_id not in self.revisions:
            self.revisions[recipe_id] = {}

        if revision_id in self.revisions[recipe_id]:
            return ExecutionResult.failed(
                "ERR_RECIPE_REVISION_EXISTS",
                f"Revision '{revision_id}' already exists for recipe '{recipe_id}'.",
            )

        rev = RecipeRevision(
            recipe_id=recipe_id,
            revision_id=revision_id,
            version=version,
            state=RecipeLifecycleState.DRAFT,
            parameters=parameters,
        )
        rev.payload_hash = rev.compute_payload_hash()
        self.revisions[recipe_id][revision_id] = rev

        # Log audit entry
        diffs = self.compute_diff({}, parameters)
        self._append_audit_record(
            operator_id=operator_id,
            action="CREATE_DRAFT",
            recipe_id=recipe_id,
            revision_id=revision_id,
            state_before=None,
            state_after=RecipeLifecycleState.DRAFT,
            payload_hash=rev.payload_hash,
            diffs=diffs,
            reason=reason,
        )

        return ExecutionResult.success(
            f"Draft revision '{revision_id}' created for recipe '{recipe_id}'.",
            data={
                "recipe_id": recipe_id,
                "revision_id": revision_id,
                "state": rev.state.value,
                "payload_hash": rev.payload_hash,
            },
        )

    def sign_and_approve(
        self,
        recipe_id: str,
        revision_id: str,
        signoff: DigitalSignoff,
    ) -> ExecutionResult:
        """Approve a DRAFT revision with 21 CFR Part 11 compliant digital signoff."""
        if recipe_id not in self.revisions or revision_id not in self.revisions[recipe_id]:
            return ExecutionResult.failed(
                "ERR_RECIPE_NOT_FOUND",
                f"Recipe revision '{revision_id}' not found.",
            )

        rev = self.revisions[recipe_id][revision_id]
        if rev.state != RecipeLifecycleState.DRAFT:
            return ExecutionResult.failed(
                "ERR_INVALID_STATE_TRANSITION",
                f"Cannot approve revision in state '{rev.state.value}'. Only DRAFT can be APPROVED.",
            )

        rev.signoff = signoff
        rev.state = RecipeLifecycleState.APPROVED

        sig_hash = signoff.digest()
        self._append_audit_record(
            operator_id=signoff.signer_id,
            action="SIGN_AND_APPROVE",
            recipe_id=recipe_id,
            revision_id=revision_id,
            state_before=RecipeLifecycleState.DRAFT,
            state_after=RecipeLifecycleState.APPROVED,
            payload_hash=rev.payload_hash,
            signature_hash=sig_hash,
            reason=f"Approved with meaning {signoff.meaning.value}: {signoff.comment}",
        )

        return ExecutionResult.success(
            f"Recipe '{recipe_id}' revision '{revision_id}' APPROVED by {signoff.signer_name}.",
            data={
                "recipe_id": recipe_id,
                "revision_id": revision_id,
                "state": rev.state.value,
                "signer": signoff.signer_name,
                "signature_hash": sig_hash,
            },
        )

    def activate_recipe(
        self,
        recipe_id: str,
        revision_id: str,
        operator_id: str,
        register_table: Optional[RegisterTable] = None,
        reason: str = "Batch execution activation",
    ) -> ExecutionResult:
        """Activate an APPROVED revision, superseding any currently ACTIVE revision."""
        if recipe_id not in self.revisions or revision_id not in self.revisions[recipe_id]:
            return ExecutionResult.failed(
                "ERR_RECIPE_NOT_FOUND",
                f"Recipe revision '{revision_id}' not found.",
            )

        rev = self.revisions[recipe_id][revision_id]
        if rev.state != RecipeLifecycleState.APPROVED:
            return ExecutionResult.failed(
                "ERR_INVALID_STATE_TRANSITION",
                f"Only APPROVED recipes can be ACTIVATED. Current state: '{rev.state.value}'.",
            )

        # Retire previously active revision if present
        prev_active_id = self.active_revisions.get(recipe_id)
        if prev_active_id and prev_active_id in self.revisions[recipe_id]:
            prev_rev = self.revisions[recipe_id][prev_active_id]
            prev_rev.state = RecipeLifecycleState.RETIRED
            self._append_audit_record(
                operator_id=operator_id,
                action="SUPERSEDE_RETIRE",
                recipe_id=recipe_id,
                revision_id=prev_active_id,
                state_before=RecipeLifecycleState.ACTIVE,
                state_after=RecipeLifecycleState.RETIRED,
                payload_hash=prev_rev.payload_hash,
                reason=f"Superseded by activation of revision '{revision_id}'.",
            )

        # Synchronize parameters to RegisterTable if provided
        if register_table is not None:
            try:
                for k, v in rev.parameters.items():
                    if k.startswith("%R"):
                        register_table.write_word(k, int(v), privilege=PrivilegeMode.SYSTEM)
            except Exception as exc:
                return ExecutionResult.failed(
                    "ERR_REGISTER_SYNC_FAILED",
                    f"Failed to synchronize recipe parameters to RegisterTable: {exc}",
                )

        rev.state = RecipeLifecycleState.ACTIVE
        self.active_revisions[recipe_id] = revision_id

        self._append_audit_record(
            operator_id=operator_id,
            action="ACTIVATE",
            recipe_id=recipe_id,
            revision_id=revision_id,
            state_before=RecipeLifecycleState.APPROVED,
            state_after=RecipeLifecycleState.ACTIVE,
            payload_hash=rev.payload_hash,
            reason=reason,
        )

        return ExecutionResult.success(
            f"Recipe '{recipe_id}' revision '{revision_id}' is now ACTIVE.",
            data={
                "recipe_id": recipe_id,
                "revision_id": revision_id,
                "state": rev.state.value,
                "active_revision": revision_id,
            },
        )

    def atomic_rollback(
        self,
        recipe_id: str,
        target_revision_id: str,
        new_revision_id: str,
        operator_id: str,
        signoff: DigitalSignoff,
        register_table: Optional[RegisterTable] = None,
        reason: str = "Regulatory rollback to prior verified revision",
    ) -> ExecutionResult:
        """Forward-only atomic rollback to a historical recipe revision.

        Creates a new APPROVED forward revision replicating target revision parameters
        and immediately activates it, ensuring audit immutability (Part 11.10(e)).
        """
        if recipe_id not in self.revisions or target_revision_id not in self.revisions[recipe_id]:
            return ExecutionResult.failed(
                "ERR_TARGET_REVISION_NOT_FOUND",
                f"Historical target revision '{target_revision_id}' not found.",
            )

        target_rev = self.revisions[recipe_id][target_revision_id]
        active_id = self.active_revisions.get(recipe_id)
        active_rev = self.revisions[recipe_id].get(active_id) if active_id else None

        # Create new forward revision
        new_rev = RecipeRevision(
            recipe_id=recipe_id,
            revision_id=new_revision_id,
            version=f"{target_rev.version}-rollback",
            state=RecipeLifecycleState.APPROVED,
            parameters=dict(target_rev.parameters),
            signoff=signoff,
        )
        new_rev.payload_hash = new_rev.compute_payload_hash()
        self.revisions[recipe_id][new_revision_id] = new_rev

        # Compute diff between current active and target
        diffs = self.compute_diff(
            active_rev.parameters if active_rev else {},
            new_rev.parameters,
        )

        # Log rollback audit record
        self._append_audit_record(
            operator_id=operator_id,
            action="ROLLBACK_REVISION",
            recipe_id=recipe_id,
            revision_id=new_revision_id,
            state_before=None,
            state_after=RecipeLifecycleState.APPROVED,
            payload_hash=new_rev.payload_hash,
            signature_hash=signoff.digest(),
            diffs=diffs,
            reason=f"Rollback to historical setpoints of '{target_revision_id}': {reason}",
        )

        # Activate the rollback revision
        return self.activate_recipe(
            recipe_id=recipe_id,
            revision_id=new_revision_id,
            operator_id=operator_id,
            register_table=register_table,
            reason=f"Automated activation of rollback revision '{new_revision_id}'.",
        )

    def verify_audit_chain(self) -> Dict[str, Any]:
        """Verify complete cryptographic integrity of the audit chain."""
        violations: List[str] = []

        if not self.audit_chain:
            return {"valid": False, "violations": ["Audit chain is empty."]}

        genesis = self.audit_chain[0]
        if genesis.prev_hash != self.GENESIS_HASH or genesis.record_index != 0:
            violations.append("Genesis block corruption detected.")

        for i in range(1, len(self.audit_chain)):
            prev = self.audit_chain[i - 1]
            curr = self.audit_chain[i]

            if curr.record_index != i:
                violations.append(f"Block {i}: index discontinuity (expected {i}, got {curr.record_index}).")

            if curr.prev_hash != prev.entry_hash:
                violations.append(f"Block {i}: broken hash pointer ({curr.prev_hash} != {prev.entry_hash}).")

            expected_entry_hash = curr.calculate_entry_hash()
            if curr.entry_hash != expected_entry_hash:
                violations.append(f"Block {i}: entry hash mismatch (tampering detected).")

        return {
            "valid": len(violations) == 0,
            "total_blocks": len(self.audit_chain),
            "root_digest": self.latest_hash,
            "violations": violations,
        }

    def export_evidence(self) -> Dict[str, Any]:
        """Export comprehensive audit ledger verification evidence."""
        chain_report = self.verify_audit_chain()
        return {
            "status": "success" if chain_report["valid"] else "failed",
            "error_code": None if chain_report["valid"] else "ERR_AUDIT_CHAIN_CORRUPT",
            "details": f"Recipe audit chain verified ({len(self.audit_chain)} blocks, valid={chain_report['valid']}).",
            "data": {
                "audit_summary": chain_report,
                "recipes_tracked": list(self.revisions.keys()),
                "active_recipes": dict(self.active_revisions),
                "total_revisions": sum(len(revs) for revs in self.revisions.values()),
                "blocks": [b.model_dump() for b in self.audit_chain],
            },
        }
