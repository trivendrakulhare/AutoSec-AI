from dataclasses import dataclass

from autosec_ai.agents.bounded_investigation import (
    InvestigationRunResult,
    InvestigationTerminationReason,
)


@dataclass(frozen=True)
class InvestigationEvaluation:
    """Deterministic execution metrics, not vulnerability or AI quality scores."""

    total_steps: int
    allowed_actions: int
    rejected_actions: int
    executed_actions: int
    successful_tool_executions: int
    failed_tool_executions: int
    deterministic_findings: int
    ai_assessments: int
    termination_reason: InvestigationTerminationReason


def evaluate_investigation(
    result: InvestigationRunResult,
) -> InvestigationEvaluation:
    """Count execution behavior represented in an investigation run result."""
    if not isinstance(result, InvestigationRunResult):
        raise TypeError("result must be an InvestigationRunResult")

    steps = result.state.steps
    tool_results = [step.tool_result for step in steps if step.tool_result is not None]
    return InvestigationEvaluation(
        total_steps=len(steps),
        allowed_actions=sum(step.validation_allowed for step in steps),
        rejected_actions=sum(not step.validation_allowed for step in steps),
        executed_actions=len(tool_results),
        successful_tool_executions=sum(
            tool_result.status == "success" for tool_result in tool_results
        ),
        failed_tool_executions=sum(
            tool_result.status != "success" for tool_result in tool_results
        ),
        deterministic_findings=sum(
            step.finding_context is not None for step in steps
        ),
        ai_assessments=sum(step.assessment is not None for step in steps),
        termination_reason=result.termination_reason,
    )
