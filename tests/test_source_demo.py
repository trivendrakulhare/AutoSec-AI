import json

from autosec_ai.agents.action import AgentAction
from autosec_ai.agents.bounded_investigation import (
    InvestigationRunResult,
    InvestigationTerminationReason,
)
from autosec_ai.agents.investigation import InvestigationState, InvestigationStep
from autosec_ai.analyzers.finding_assessment import FindingAssessment
from autosec_ai.analyzers.context import FindingContext
from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.application.source_demo import (
    DEFAULT_SOURCE_TARGET,
    evaluate_investigation,
    run_source_security_demo,
)
from autosec_ai.cli import main as cli_main
from autosec_ai.reporting.investigation import (
    build_investigation_report,
    format_investigation_report_json,
)
from autosec_ai.tools.external import ExternalToolResult
from autosec_ai.tools.result import ToolResult
from autosec_ai.llm.mock import MockLLMClient


class FakeExternalRunner:
    def __init__(self, stdout, return_code=0):
        self.stdout = stdout
        self.return_code = return_code
        self.calls = []

    def run(self, executable, arguments):
        self.calls.append((executable, arguments))
        return ExternalToolResult(
            self.return_code, self.stdout, "", False
        )


def _semgrep_output():
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "autosec-c-unsafe-strcpy",
                    "path": DEFAULT_SOURCE_TARGET,
                    "start": {"line": 56},
                    "extra": {
                        "message": "Unsafe strcpy usage",
                        "severity": "ERROR",
                        "metadata": {
                            "category": "memory-safety",
                            "cwe": ["CWE-120"],
                        },
                    },
                }
            ]
        }
    )


def test_controlled_source_pipeline_records_real_finding_and_assessment():
    runner = FakeExternalRunner(_semgrep_output())

    result = run_source_security_demo(external_runner=runner)
    step = result.state.steps[0]

    assert result.termination_reason is InvestigationTerminationReason.MAX_STEPS_REACHED
    assert len(result.state.steps) == 1
    assert step.validation_allowed is True
    assert step.validation_status == "VALID"
    assert step.tool_result is not None
    assert step.tool_result.status == "success"
    assert step.finding_context is not None
    assert step.finding_context.finding.rule_id == "autosec-c-unsafe-strcpy"
    assert step.finding_context.finding.source_tool == "semgrep"
    assert step.assessment is not None
    assert step.assessment.classification == "needs_review"
    assert step.assessment is not step.finding_context
    assert runner.calls[0][1][-1] == DEFAULT_SOURCE_TARGET


def test_source_demo_crosses_real_policy_and_validator():
    runner = FakeExternalRunner(_semgrep_output())
    planner = MockLLMClient(
        "tool_name=semgrep\n"
        f"target={DEFAULT_SOURCE_TARGET}\n"
        'parameters={"rule_pack":"untrusted"}'
    )

    result = run_source_security_demo(
        external_runner=runner,
        planner_client=planner,
    )

    step = result.state.steps[0]
    assert result.termination_reason is InvestigationTerminationReason.ACTION_REJECTED
    assert step.validation_status == "UNAUTHORIZED_PARAMETER"
    assert step.tool_result is None
    assert step.finding_context is None
    assert step.assessment is None
    assert runner.calls == []


def test_evaluation_counts_execution_behavior_exactly():
    finding_step = InvestigationStep(
        1,
        AgentAction("semgrep", DEFAULT_SOURCE_TARGET),
        "VALID",
        True,
        ToolResult("semgrep", DEFAULT_SOURCE_TARGET, "success"),
        finding_context=FindingContext(
            SecurityFinding(
                "RULE-1", "Observed issue", "ERROR", DEFAULT_SOURCE_TARGET,
                1, "memory-safety", "CWE-120", "semgrep",
            ),
            (),
        ),
        assessment=FindingAssessment(
            "needs_review", "low", "Review.", "Unknown.", []
        ),
    )
    rejected_step = InvestigationStep(
        2,
        AgentAction("blocked", DEFAULT_SOURCE_TARGET),
        "UNAUTHORIZED_TOOL",
        False,
    )
    failed_step = InvestigationStep(
        3,
        AgentAction("semgrep", DEFAULT_SOURCE_TARGET),
        "VALID",
        True,
        ToolResult("semgrep", DEFAULT_SOURCE_TARGET, "unknown"),
    )
    result = InvestigationRunResult(
        InvestigationState(
            "Assess the fixture", DEFAULT_SOURCE_TARGET,
            (finding_step, rejected_step, failed_step),
        ),
        InvestigationTerminationReason.TOOL_ERROR,
    )

    metrics = evaluate_investigation(result)

    assert metrics.total_steps == 3
    assert metrics.allowed_actions == 2
    assert metrics.rejected_actions == 1
    assert metrics.executed_actions == 2
    assert metrics.successful_tool_executions == 1
    assert metrics.failed_tool_executions == 1
    assert metrics.deterministic_findings == 1
    assert metrics.ai_assessments == 1
    assert metrics.termination_reason is InvestigationTerminationReason.TOOL_ERROR


def test_source_demo_report_json_is_deterministic_and_keeps_sections_separate():
    first = run_source_security_demo(external_runner=FakeExternalRunner(_semgrep_output()))
    second = run_source_security_demo(external_runner=FakeExternalRunner(_semgrep_output()))

    first_json = format_investigation_report_json(build_investigation_report(first))
    second_json = format_investigation_report_json(build_investigation_report(second))

    assert first_json == second_json
    payload = json.loads(first_json)
    assert payload["termination_reason"] == "MAX_STEPS_REACHED"
    assert payload["steps"][0]["deterministic_finding"]["rule_id"] == "autosec-c-unsafe-strcpy"
    assert payload["steps"][0]["ai_assessment"]["classification"] == "needs_review"


def test_source_demo_cli_is_marked_controlled_and_json_is_report(capsys, monkeypatch):
    result = run_source_security_demo(external_runner=FakeExternalRunner(_semgrep_output()))
    monkeypatch.setattr("autosec_ai.cli.run_source_security_demo", lambda: result)

    assert cli_main(["source-demo"]) == 0
    text = capsys.readouterr().out
    assert "SIMULATED / CONTROLLED AUTOMOTIVE SECURITY DEMONSTRATION" in text
    assert "MAX_STEPS_REACHED" in text

    assert cli_main(["source-demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_steps"] == 1
    assert payload["steps"][0]["tool_result"]["status"] == "success"
