"""Unit tests for TypeSafe SystemOne JevPolicy (Megaplan 12.3 & 12.4)."""

import pytest
from pydantic import ValidationError

from jev_cscape.agents.policy import (
    JevPolicy,
    JevDecision,
    ChoiceQuestion,
    NoulQuestion,
    ScoreQuestion,
    ChoiceAnswer,
)


def test_choice_question_schema() -> None:
    """Verify ChoiceQuestion enforces options and rejects chat fields."""
    q = ChoiceQuestion(
        options=["maintain", "increase", "decrease"],
        instructions="Decide plant actuation",
    )
    assert q.type == "choice"
    assert len(q.options) == 3

    # Extra/chat fields must be rejected
    with pytest.raises(ValidationError):
        ChoiceQuestion(
            options=["a", "b"],
            messages=[{"role": "user", "content": "hi"}],  # Chat field forbidden
        )


def test_noul_question_schema() -> None:
    """Verify NoulQuestion enforces instructions and rejects chat fields."""
    q = NoulQuestion(instructions="Does this express urgency?")
    assert q.type == "noul"

    with pytest.raises(ValidationError):
        NoulQuestion(
            instructions="Does this express urgency?",
            prompt="hi",  # Chat field forbidden
        )


def test_mock_policy_evaluation() -> None:
    """Verify JevPolicy in mock mode returns exact SystemOne typed choice structure."""
    policy = JevPolicy(mock_mode=True)
    state = "Tank level currently at 45.0%. Target setpoint 50.0%. Need to increase inflow."
    questions = {
        "actuation": ChoiceQuestion(
            options=["maintain", "increase_inflow", "decrease_inflow", "other"],
            instructions="Select control action",
        ),
        "is_urgent": NoulQuestion(
            instructions="Is there an emergency condition?",
        ),
    }

    decision = policy.evaluate(state, questions)
    assert isinstance(decision, JevDecision)
    assert decision.http_status == 200
    assert "actuation" in decision.answers
    assert "is_urgent" in decision.answers

    # Verify choice answer structure
    act_ans = decision.answers["actuation"]
    assert act_ans["type"] == "choice"
    assert act_ans["choice"] in ["maintain", "increase_inflow", "decrease_inflow", "other"]
    assert 0.0 <= act_ans["confidence"] <= 1.0
    assert isinstance(act_ans["probabilities"], dict)

    # Verify helper methods
    choice_val = decision.get_choice("actuation")
    assert choice_val == act_ans["choice"]
    conf_val = decision.get_confidence("actuation")
    assert conf_val == act_ans["confidence"]

    # Verify noul answer structure
    noul_ans = decision.answers["is_urgent"]
    assert noul_ans["type"] == "noul"
    assert 0.0 <= noul_ans["noul"] <= 1.0


def test_policy_no_secrets_leaked() -> None:
    """Verify JevPolicy does not reveal secret key in repr or string representation."""
    policy = JevPolicy(api_key="SUPER_SECRET_JEV_TOKEN_12345", mock_mode=True)
    rep = repr(policy)
    assert "SUPER_SECRET" not in rep
