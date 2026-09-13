from ..llm.client import LLMClient
from .action import AgentAction


class AgentPlanningError(ValueError):
    """Raised when an LLM response cannot be converted to an action."""


class AgentPlanner:
    """Convert an LLM proposal into an action without executing it."""

    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    def plan(self, objective: str, target: str) -> AgentAction:
        """Generate and parse an action proposal for an objective and target."""
        prompt = f"objective={objective}\ntarget={target}"
        response = self.llm_client.generate(prompt)
        fields: dict[str, str] = {}

        for line in response.splitlines():
            if not line.strip():
                continue
            key, separator, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not separator or key not in {"tool_name", "target"} or not value:
                raise AgentPlanningError(
                    "Expected non-empty tool_name and target fields."
                )
            if key in fields:
                raise AgentPlanningError(f"Duplicate field: {key}")
            fields[key] = value

        missing = {"tool_name", "target"} - fields.keys()
        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise AgentPlanningError(f"Missing required field(s): {missing_fields}")

        return AgentAction(tool_name=fields["tool_name"], target=fields["target"])
