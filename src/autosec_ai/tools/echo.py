from .base import SecurityTool
from .result import ToolResult


class EchoSecurityTool(SecurityTool):
    """Minimal security tool used to validate the tool architecture."""

    @property
    def name(self) -> str:
        return "echo_security_tool"

    @property
    def description(self) -> str:
        return "Returns information about the target provided to the tool."

    def execute(self, target: str) -> ToolResult:
        return ToolResult(
            tool_name=self.name,
            target=target,
            status="success",
            data={"message": f"Target received: {target}"},
        )
