from autosec_ai.analyzers.finding_assessment import FindingAssessor

from .action import AgentAction
from .investigation import (
    InvestigationState,
    InvestigationStep,
    append_investigation_step,
    format_investigation_feedback,
)
from .planner import AgentPlanner
from .policy import SecurityPolicy
from .result_processor import InvestigationResultProcessorRegistry
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
        result_processor_registry: InvestigationResultProcessorRegistry | None = None,
        finding_assessor: FindingAssessor | None = None,
    ) -> None:
        self.planner = planner
        self.validator = validator
        self.registry = registry
        self.policy = policy
        self.result_processor_registry = result_processor_registry
        self.finding_assessor = finding_assessor

    def advance(self, state: InvestigationState) -> InvestigationState:
        """Propose, validate, and optionally execute exactly one action.

        ToolResult statuses determine bounded TOOL_ERROR termination; runtime
        exceptions from execution or post-processing intentionally propagate.
        """
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
                validation_allowed=validation.allowed,
            )
            return append_investigation_step(state, step)

        tool = self.registry.get(action.tool_name)
        result = tool.execute(action.target, action.parameters)
        finding_context = None
        assessment = None
        if result.status == "success" and self.result_processor_registry is not None:
            processor = self.result_processor_registry.get(action.tool_name)
            if processor is not None:
                finding_context = processor.process(action, result)
                if finding_context is not None and self.finding_assessor is not None:
                    assessment = self.finding_assessor.assess_context(finding_context)
        step = InvestigationStep(
            step_number=len(state.steps) + 1,
            proposed_action=action,
            validation_status=validation.code,
            validation_allowed=validation.allowed,
            tool_result=result,
            finding_context=finding_context,
            assessment=assessment,
        )
        return append_investigation_step(state, step)
