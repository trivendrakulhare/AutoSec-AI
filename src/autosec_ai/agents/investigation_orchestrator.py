from .action import AgentAction
from .investigation import (
    InvestigationState,
    InvestigationStep,
    append_investigation_step,
    format_investigation_feedback,
)
from .planner import AgentPlanner
from .policy import SecurityPolicy
from .validator import ActionValidator
from ..tools.registry import ToolRegistry


class InvestigationOrchestrator:
    """Advance an investigation by exactly one validated action."""

    def __init__(
        self,
        planner: AgentPlanner,
        validator: ActionValidator,
        registry: ToolRegistry,
        policy: SecurityPolicy,
    ) -> None:
        self.planner = planner
        self.validator = validator
        self.registry = registry
        self.policy = policy

    def advance(self, state: InvestigationState) -> InvestigationState:
        """Propose, validate, and optionally execute exactly one action."""
        if not isinstance(state, InvestigationState):
            raise TypeError("state must be an InvestigationState")

        action = self.planner.plan(
            state.objective,
            state.target,
            format_investigation_feedback(state),
        )
        if not isinstance(action, AgentAction):
            raise TypeError("planner must return an AgentAction")

        validation = self.validator.validate(action, self.registry, self.policy)
        if not validation.allowed:
            step = InvestigationStep(
                step_number=len(state.steps) + 1,
                proposed_action=action,
                validation_status=validation.code,
            )
            return append_investigation_step(state, step)

        tool = self.registry.get(action.tool_name)
        result = tool.execute(action.target, action.parameters)
        step = InvestigationStep(
            step_number=len(state.steps) + 1,
            proposed_action=action,
            validation_status=validation.code,
            tool_result=result,
        )
        return append_investigation_step(state, step)