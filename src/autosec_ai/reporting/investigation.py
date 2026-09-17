import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping
from typing import Any

from autosec_ai.agents.bounded_investigation import (
    InvestigationRunResult,
    InvestigationTerminationReason,
)


@dataclass(frozen=True)
class InvestigationFindingReport:
    rule_id: str
    message: str
    severity: str
    category: str
    cwe: str | None
    source_tool: str


@dataclass(frozen=True)
class InvestigationAssessmentReport:
    classification: str
    confidence: str
    rationale: str
    impact: str
    recommendations: tuple[str, ...]


@dataclass(frozen=True)
class InvestigationStepReport:
    step_number: int
    proposed_tool: str
    proposed_target: str
    proposed_parameters: Mapping[str, Any]
    validation_allowed: bool
    validation_status: str
    tool_status: str | None
    tool_error: str | None
    deterministic_finding: InvestigationFindingReport | None = None
    ai_assessment: InvestigationAssessmentReport | None = None


@dataclass(frozen=True)
class InvestigationReport:
    objective: str
    target: str
    termination_reason: InvestigationTerminationReason
    total_steps: int
    steps: tuple[InvestigationStepReport, ...]


def build_investigation_report(
    result: InvestigationRunResult,
) -> InvestigationReport:
    """Transform an existing run result into an analyst-facing report."""
    if not isinstance(result, InvestigationRunResult):
        raise TypeError("result must be an InvestigationRunResult")

    steps = tuple(_build_step_report(step) for step in result.state.steps)
    return InvestigationReport(
        objective=result.state.objective,
        target=result.state.target,
        termination_reason=result.termination_reason,
        total_steps=len(steps),
        steps=steps,
    )


def _build_step_report(step) -> InvestigationStepReport:
    finding = step.finding_context.finding if step.finding_context else None
    deterministic_finding = (
        InvestigationFindingReport(
            rule_id=finding.rule_id,
            message=finding.message,
            severity=finding.severity,
            category=finding.category,
            cwe=finding.cwe,
            source_tool=finding.source_tool,
        )
        if finding is not None
        else None
    )
    assessment = step.assessment
    ai_assessment = (
        InvestigationAssessmentReport(
            classification=assessment.classification,
            confidence=assessment.confidence,
            rationale=assessment.rationale,
            impact=assessment.impact,
            recommendations=tuple(assessment.recommendations),
        )
        if assessment is not None
        else None
    )
    return InvestigationStepReport(
        step_number=step.step_number,
        proposed_tool=step.proposed_action.tool_name,
        proposed_target=step.proposed_action.target,
        proposed_parameters=_freeze_parameters(step.proposed_action.parameters),
        validation_allowed=step.validation_allowed,
        validation_status=step.validation_status,
        tool_status=step.tool_result.status if step.tool_result else None,
        tool_error=step.tool_result.error if step.tool_result else None,
        deterministic_finding=deterministic_finding,
        ai_assessment=ai_assessment,
    )


def _report_data(report: InvestigationReport) -> dict[str, Any]:
    return {
        "objective": report.objective,
        "target": report.target,
        "termination_reason": report.termination_reason.value,
        "total_steps": report.total_steps,
        "steps": [
            {
                "step_number": step.step_number,
                "proposed_tool": step.proposed_tool,
                "proposed_target": step.proposed_target,
                "proposed_parameters": _thaw_parameters(step.proposed_parameters),
                "validation_allowed": step.validation_allowed,
                "validation_status": step.validation_status,
                "tool_result": (
                    {
                        "status": step.tool_status,
                        "error": step.tool_error,
                    }
                    if step.tool_status is not None
                    else None
                ),
                "deterministic_finding": (
                    {
                        "rule_id": step.deterministic_finding.rule_id,
                        "message": step.deterministic_finding.message,
                        "severity": step.deterministic_finding.severity,
                        "category": step.deterministic_finding.category,
                        "cwe": step.deterministic_finding.cwe,
                        "source_tool": step.deterministic_finding.source_tool,
                    }
                    if step.deterministic_finding is not None
                    else None
                ),
                "ai_assessment": (
                    {
                        "classification": step.ai_assessment.classification,
                        "confidence": step.ai_assessment.confidence,
                        "rationale": step.ai_assessment.rationale,
                        "impact": step.ai_assessment.impact,
                        "recommendations": list(
                            step.ai_assessment.recommendations
                        ),
                    }
                    if step.ai_assessment is not None
                    else None
                ),
            }
            for step in report.steps
        ],
    }


def format_investigation_report_json(report: InvestigationReport) -> str:
    """Return stable machine-readable JSON for an investigation report."""
    if not isinstance(report, InvestigationReport):
        raise TypeError("report must be an InvestigationReport")
    return json.dumps(_report_data(report), sort_keys=True)


def _freeze_parameters(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                key: _freeze_parameters(item)
                for key, item in value.items()
            }
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_parameters(item) for item in value)
    return value


def _thaw_parameters(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_parameters(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_parameters(item) for item in value]
    return value


_ANSI_SEQUENCE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))"
)


def _terminal_text(value: str) -> str:
    without_ansi = _ANSI_SEQUENCE.sub("", value)
    return "".join(
        character
        for character in without_ansi
        if character in "\n\t" or ord(character) >= 32
    )


def _terminal_json(value: Any) -> str:
    return json.dumps(_terminal_json_value(value), sort_keys=True)


def _terminal_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return _terminal_text(value)
    if isinstance(value, Mapping):
        return {key: _terminal_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_terminal_json_value(item) for item in value]
    return value


def format_investigation_report(report: InvestigationReport) -> str:
    """Format a report as readable, control-sequence-safe plain text."""
    if not isinstance(report, InvestigationReport):
        raise TypeError("report must be an InvestigationReport")

    lines = [
        "AUTOSEC-AI SECURITY INVESTIGATION",
        "=================================",
        "",
        f"Objective: {_terminal_text(report.objective)}",
        f"Target: {_terminal_text(report.target)}",
        f"Termination: {_terminal_text(report.termination_reason.value)}",
        f"Steps: {report.total_steps}",
    ]
    for step in report.steps:
        lines.extend(
            [
                "",
                f"STEP {step.step_number}",
                "------",
                f"Proposed tool: {_terminal_text(step.proposed_tool)}",
                f"Target: {_terminal_text(step.proposed_target)}",
                f"Parameters: {_terminal_json(step.proposed_parameters)}",
                "",
                f"Authorization: {'ALLOWED' if step.validation_allowed else 'REJECTED'}",
                f"Validation: {_terminal_text(step.validation_status)}",
                "",
                f"Tool result: {_terminal_text(step.tool_status) if step.tool_status is not None else 'none'}",
            ]
        )
        if step.tool_error is not None:
            lines.append(f"Tool error: {_terminal_text(step.tool_error)}")
        if step.deterministic_finding is not None:
            finding = step.deterministic_finding
            lines.extend(
                [
                    "",
                    "Deterministic finding",
                    f"  Rule: {_terminal_text(finding.rule_id)}",
                    f"  Severity: {_terminal_text(finding.severity)}",
                    f"  Category: {_terminal_text(finding.category)}",
                    f"  CWE: {_terminal_text(finding.cwe) if finding.cwe is not None else 'none'}",
                    f"  Source: {_terminal_text(finding.source_tool)}",
                    f"  Message: {_terminal_text(finding.message)}",
                ]
            )
        if step.ai_assessment is not None:
            assessment = step.ai_assessment
            lines.extend(
                [
                    "",
                    "AI assessment",
                    f"  Classification: {_terminal_text(assessment.classification)}",
                    f"  Confidence: {_terminal_text(assessment.confidence)}",
                    f"  Rationale: {_terminal_text(assessment.rationale)}",
                    f"  Impact: {_terminal_text(assessment.impact)}",
                    "  Recommendations:",
                    *[
                        f"    - {_terminal_text(recommendation)}"
                        for recommendation in assessment.recommendations
                    ],
                ]
            )
    return "\n".join(lines)