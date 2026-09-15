from autosec_ai.tools.external import ExternalToolRunner

from .binary import BinaryAnalyzer
from .finding import SecurityFinding


class ImportedFunctionBinaryAnalyzer(BinaryAnalyzer):
    """Detect selected dangerous imported functions with the platform nm tool."""

    _STRCPY_IMPORTS = ("_strcpy", "___strcpy_chk")

    def __init__(self, runner: ExternalToolRunner, executable: str = "nm") -> None:
        self.runner = runner
        self.executable = executable

    def analyze(self, target: str) -> list[SecurityFinding]:
        result = self.runner.run(self.executable, ["-u", target])
        if result.timed_out or result.return_code != 0:
            return []

        detected = False
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts:
                continue
            symbol = parts[-1]
            if symbol in self._STRCPY_IMPORTS:
                detected = True
                break

        if not detected:
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