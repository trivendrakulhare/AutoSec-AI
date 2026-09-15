from dataclasses import dataclass

from autosec_ai.tools.external import ExternalToolRunner

from .binary import BinaryAnalyzer
from .finding import SecurityFinding


@dataclass(frozen=True)
class BinaryAnalysisEvidence:
    """Deterministic evidence retained from a binary analysis pass."""

    imported_symbol: str
    analysis_tool: str
    analysis_type: str


def format_binary_analysis_context(
    finding: SecurityFinding, evidence: BinaryAnalysisEvidence
) -> str:
    """Return deterministic evidence text suitable for a downstream assessor."""
    return (
        "OBSERVED EVIDENCE:\n"
        f"rule_id={finding.rule_id}\n"
        f"message={finding.message}\n"
        f"severity={finding.severity}\n"
        f"file={finding.file}\n"
        f"line={finding.line}\n"
        f"category={finding.category}\n"
        f"cwe={finding.cwe}\n"
        f"source_tool={finding.source_tool}\n\n"
        "OBSERVED BINARY EVIDENCE:\n"
        f"imported_symbol={evidence.imported_symbol}\n"
        f"analysis_tool={evidence.analysis_tool}\n"
        f"analysis_type={evidence.analysis_type}\n\n"
        "LIMITATION:\n"
        "Imported-function presence alone does not establish exploitability; "
        "this is observed evidence only and does not imply execution or exploitability."
    )


class ImportedFunctionBinaryAnalyzer(BinaryAnalyzer):
    """Detect selected dangerous imported functions with the platform nm tool."""

    _STRCPY_IMPORTS = ("_strcpy", "___strcpy_chk")

    def __init__(self, runner: ExternalToolRunner, executable: str = "nm") -> None:
        self.runner = runner
        self.executable = executable
        self.last_evidence: BinaryAnalysisEvidence | None = None

    def analyze(self, target: str) -> list[SecurityFinding]:
        result = self.runner.run(self.executable, ["-u", target])
        if result.timed_out or result.return_code != 0:
            self.last_evidence = None
            return []

        detected = None
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            symbol = parts[-1]
            if symbol in self._STRCPY_IMPORTS:
                detected = BinaryAnalysisEvidence(
                    imported_symbol=symbol,
                    analysis_tool=self.executable,
                    analysis_type="imported-symbol inspection",
                )
                break

        self.last_evidence = detected
        if detected is None:
            return []

        return [
            SecurityFinding(
                rule_id="BIN-MEM-UNSAFE-STRCPY",
                message=(
                    "Potentially dangerous memory-unsafe function strcpy was "
                    "detected in the binary imports."
                ),
                severity="MEDIUM",
                file=target,
                line=None,
                category="binary-analysis",
                cwe="CWE-120",
                source_tool="nm",
            )
        ]