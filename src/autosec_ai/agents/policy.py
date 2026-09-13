from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityPolicy:
    """Deterministic authorization rules for proposed agent actions.

    This policy is a security boundary external to the agent and its LLM.
    LLM output may propose an action, but must never authorize itself; callers
    must evaluate proposals against this policy before execution.
    """

    allowed_tools: set[str] = field(default_factory=set)
    allowed_targets: set[str] = field(default_factory=set)
    parameter_limits: dict[str, Any] = field(default_factory=dict)
