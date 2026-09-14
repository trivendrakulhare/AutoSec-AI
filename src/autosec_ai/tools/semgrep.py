from typing import Any

from autosec_ai.analyzers.semgrep import SemgrepAnalyzer

from .base import SecurityTool
from .result import ToolResult


class SemgrepSecurityTool(SecurityTool):
    """Expose the Semgrep analyzer through the agent tool interface."""

    def __init__(self, analyzer: SemgrepAnalyzer) -> None:
        self.analyzer = analyzer

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def description(self) -> str:
        return "Runs Semgrep with an authorized rule pack against a target."

    def execute(
        self, target: str, parameters: dict[str, Any] | None = None
    ) -> ToolResult:
        if parameters is None or not isinstance(parameters.get("rule_pack"), str):
            raise ValueError("Semgrep requires a rule_pack parameter.")

        findings = self.analyzer.analyze(target, parameters["rule_pack"])
        return ToolResult(
            tool_name=self.name,
            target=target,
            status="success",
            data=findings,
        )