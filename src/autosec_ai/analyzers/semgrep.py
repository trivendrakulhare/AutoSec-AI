import json
from typing import Any

from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.analyzers.source_code import SourceCodeAnalyzer
from autosec_ai.tools.external import ExternalToolRunner


class SemgrepParsingError(ValueError):
    """Raised when Semgrep output cannot be parsed into findings."""


class SemgrepExecutionError(RuntimeError):
    """Raised when Semgrep times out or exits unsuccessfully."""


class SemgrepAnalyzer(SourceCodeAnalyzer):
    """Analyze a source-code target using Semgrep JSON output."""

    def __init__(
        self,
        runner: ExternalToolRunner,
        executable: str = "semgrep",
    ) -> None:
        self.runner = runner
        self.executable = executable

    def analyze(self, target: str) -> list[SecurityFinding]:
        """Run Semgrep against a target and normalize its findings."""
        result = self.runner.run(self.executable, ["scan", "--json", target])

        if result.timed_out:
            raise SemgrepExecutionError("Semgrep execution timed out.")
        if result.return_code != 0:
            raise SemgrepExecutionError(
                f"Semgrep exited with code {result.return_code}: {result.stderr}"
            )

        try:
            payload = json.loads(result.stdout)
            records = payload["results"]
            if not isinstance(records, list):
                raise TypeError("results must be a list")
            return [self._normalize_record(record) for record in records]
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise SemgrepParsingError("Malformed Semgrep JSON output.") from error

    @staticmethod
    def _normalize_record(record: Any) -> SecurityFinding:
        if not isinstance(record, dict):
            raise TypeError("result must be an object")

        extra = record.get("extra", {})
        if not isinstance(extra, dict):
            raise TypeError("extra must be an object")
        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TypeError("metadata must be an object")

        start = record.get("start", {})
        if not isinstance(start, dict):
            raise TypeError("start must be an object")
        line = start.get("line")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
            raise TypeError("start.line must be an integer or null")

        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(value) for value in cwe)
        elif cwe is not None and not isinstance(cwe, str):
            cwe = str(cwe)

        category = metadata.get("category", "source-code")
        if not isinstance(category, str) or not category:
            category = "source-code"

        severity = extra.get("severity", "")
        if not isinstance(severity, str):
            severity = str(severity)

        return SecurityFinding(
            rule_id=str(record.get("check_id", "")),
            message=str(extra.get("message", "")),
            severity=severity.upper(),
            file=str(record.get("path", "")),
            line=line,
            category=category,
            cwe=cwe,
            source_tool="semgrep",
        )