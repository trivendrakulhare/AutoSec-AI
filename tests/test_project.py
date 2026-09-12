import pytest

from autosec_ai.agents.state import AgentState
from autosec_ai.tools.base import SecurityTool
from autosec_ai.tools.echo import EchoSecurityTool
from autosec_ai.tools.result import ToolResult


def test_project_import():
    import autosec_ai

    assert autosec_ai.__name__ == "autosec_ai"


def test_agent_state_initialization():
    state = AgentState(
        objective="Identify security vulnerabilities",
        target="fixtures/ecu_vulnerable.c",
    )

    assert state.objective == "Identify security vulnerabilities"
    assert state.target == "fixtures/ecu_vulnerable.c"
    assert state.actions_taken == []
    assert state.observations == []
    assert state.findings == []


def test_echo_security_tool():
    tool = EchoSecurityTool()

    result = tool.execute("fixtures/ecu_vulnerable.c")

    assert result.tool_name == "echo_security_tool"
    assert result.target == "fixtures/ecu_vulnerable.c"
    assert result.status == "success"
    assert result.data == {
        "message": "Target received: fixtures/ecu_vulnerable.c"
    }
    assert result.error is None


def test_security_tool_contract():
    class IncompleteSecurityTool(SecurityTool):
        pass

    with pytest.raises(TypeError):
        IncompleteSecurityTool()


def test_tool_result():
    result = ToolResult(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        status="success",
        data={"message": "Target received"},
    )

    assert result.tool_name == "echo_security_tool"
    assert result.target == "fixtures/ecu_vulnerable.c"
    assert result.status == "success"
    assert result.data == {"message": "Target received"}
    assert result.error is None
