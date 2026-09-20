from .base import SecurityTool


class ToolRegistry:
    """Registry of security tools available to the agent."""

    def __init__(self) -> None:
        self._tools: dict[str, SecurityTool] = {}

    def register(self, tool: SecurityTool) -> None:
        """Register a security tool by its unique name."""
        if not isinstance(tool, SecurityTool):
            raise TypeError("tool must be a SecurityTool")
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")

        self._tools[tool.name] = tool

    def get(self, name: str) -> SecurityTool:
        """Return a registered tool by name."""
        return self._tools[name]

    def list_tools(self) -> list[SecurityTool]:
        """Return all registered security tools."""
        return list(self._tools.values())