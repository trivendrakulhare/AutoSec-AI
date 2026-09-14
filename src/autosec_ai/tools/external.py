from dataclasses import dataclass
import subprocess


@dataclass
class ExternalToolResult:
    """Result captured from an external tool execution."""

    return_code: int
    stdout: str
    stderr: str
    timed_out: bool


class ExternalToolRunner:
    """Run a known external executable without invoking a shell."""

    def run(
        self,
        executable: str,
        arguments: list[str],
        timeout_seconds: int = 60,
    ) -> ExternalToolResult:
        """Execute an external tool and return its captured result."""
        command = [executable, *arguments]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            return ExternalToolResult(-1, stdout, stderr, True)

        return ExternalToolResult(
            completed.returncode,
            completed.stdout,
            completed.stderr,
            False,
        )