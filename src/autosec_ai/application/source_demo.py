from pathlib import Path
from typing import Any

from autosec_ai.agents.action import AgentAction
from autosec_ai.agents.bounded_investigation import (
    BoundedInvestigationRunner,
    InvestigationRunConfig,
    InvestigationRunResult,
)
from autosec_ai.agents.investigation import InvestigationState
from autosec_ai.agents.investigation_orchestrator import InvestigationOrchestrator
from autosec_ai.agents.planner import AgentPlanner
from autosec_ai.agents.policy import SecurityPolicy
from autosec_ai.agents.result_processor import (
    InvestigationResultProcessor,
    InvestigationResultProcessorRegistry,
)
from autosec_ai.agents.validator import ActionValidator
from autosec_ai.analyzers.context import FindingContext, build_finding_context
from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.analyzers.finding_assessment import LLMFindingAssessor
from autosec_ai.analyzers.rule_pack import RulePackRegistry
from autosec_ai.analyzers.semgrep import SemgrepAnalyzer
from autosec_ai.llm.client import LLMClient
from autosec_ai.llm.mock import MockLLMClient
from autosec_ai.tools.external import ExternalToolRunner
from autosec_ai.tools.registry import ToolRegistry
from autosec_ai.tools.result import ToolResult
from autosec_ai.tools.semgrep import SemgrepSecurityTool
from autosec_ai.evaluation import InvestigationEvaluation, evaluate_investigation
DEFAULT_SOURCE_TARGET = "tests/fixtures/ecu_vulnerable.c"
DEFAULT_RULE_PACK = "automotive"
SOURCE_TOOL_NAME = "semgrep"


class SourceFindingResultProcessor(InvestigationResultProcessor):
    """Convert the first deterministic source finding into finding context."""

    def process(
        self, action: AgentAction, result: ToolResult
    ) -> FindingContext | None:
        if result.tool_name != SOURCE_TOOL_NAME:
            raise ValueError("Source processor received an unexpected tool result")
        if not isinstance(result.data, list):
            raise TypeError("Source analysis result data must be a list")
        if not result.data:
            return None
        finding = result.data[0]
        if not isinstance(finding, SecurityFinding):
            raise TypeError("Source analysis result entries must be SecurityFinding")
        return build_finding_context(finding)


def build_source_security_demo(
    *,
    external_runner: ExternalToolRunner | None = None,
    planner_client: LLMClient | None = None,
    assessor_client: LLMClient | None = None,
    target: str = DEFAULT_SOURCE_TARGET,
    rule_pack: str = DEFAULT_RULE_PACK,
    executable: str = "semgrep",
) -> BoundedInvestigationRunner:
    """Assemble the controlled source investigation without running it."""
    project_root = Path(__file__).resolve().parents[3]
    trusted_rule_pack = project_root / "rules" / "semgrep" / "automotive-c.yml"
    registry = ToolRegistry()
    analyzer = SemgrepAnalyzer(
        external_runner or ExternalToolRunner(),
        RulePackRegistry({DEFAULT_RULE_PACK: str(trusted_rule_pack)}),
        executable=executable,
    )
    source_tool = SemgrepSecurityTool(analyzer)
    registry.register(source_tool)

    planner_client = planner_client or MockLLMClient(
        f"tool_name={SOURCE_TOOL_NAME}\n"
        f"target={target}\n"
        f'parameters={{"rule_pack": "{rule_pack}"}}'
    )
    assessor_client = assessor_client or MockLLMClient(
        '{"classification":"needs_review","confidence":"medium",'
        '"rationale":"The deterministic scanner reported an unsafe string operation; exploitability was not established.",'
        '"impact":"Potential memory-safety impact requires code review.",'
        '"recommendations":["Review input bounds and replace unsafe string operations."]}'
    )
    processors = InvestigationResultProcessorRegistry()
    processors.register(SOURCE_TOOL_NAME, SourceFindingResultProcessor())
    policy = SecurityPolicy(
        allowed_tools={SOURCE_TOOL_NAME},
        allowed_targets={target},
        allowed_parameter_values={
            SOURCE_TOOL_NAME: {"rule_pack": {DEFAULT_RULE_PACK}}
        },
    )
    orchestrator = InvestigationOrchestrator(
        AgentPlanner(planner_client),
        ActionValidator(),
        registry,
        policy,
        processors,
        LLMFindingAssessor(assessor_client),
    )
    return BoundedInvestigationRunner(
        orchestrator,
        InvestigationRunConfig(max_steps=1),
    )


def run_source_security_demo(**kwargs: Any) -> InvestigationRunResult:
    """Run one bounded controlled source investigation."""
    target = kwargs.get("target", DEFAULT_SOURCE_TARGET)
    runner = build_source_security_demo(**kwargs)
    return runner.run(
        InvestigationState(
            objective="Assess the controlled automotive ECU source fixture.",
            target=target,
        )
    )
