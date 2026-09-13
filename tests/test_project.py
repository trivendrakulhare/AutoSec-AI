import pytest

from autosec_ai.agents.state import AgentState
from autosec_ai.tools.base import SecurityTool
from autosec_ai.tools.echo import EchoSecurityTool
from autosec_ai.tools.result import ToolResult
from autosec_ai.tools.registry import ToolRegistry
from autosec_ai.agents.action import AgentAction
from autosec_ai.agents.validator import ActionValidator
from autosec_ai.agents.orchestrator import AgentOrchestrator
from autosec_ai.agents.planner import AgentPlanner, AgentPlanningError
from autosec_ai.llm.client import LLMClient
from autosec_ai.llm.mock import MockLLMClient


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


def test_tool_registry():
    registry = ToolRegistry()
    tool = EchoSecurityTool()

    registry.register(tool)

    assert registry.get("echo_security_tool") is tool
    assert registry.list_tools() == [tool]


def test_tool_registry_rejects_duplicate_tool_names():
    registry = ToolRegistry()
    first_tool = EchoSecurityTool()
    second_tool = EchoSecurityTool()

    registry.register(first_tool)

    with pytest.raises(ValueError):
        registry.register(second_tool)

def test_agent_action():
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    assert action.tool_name == "echo_security_tool"
    assert action.target == "fixtures/ecu_vulnerable.c"

def test_action_validator_allows_registered_tool():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())

    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    validator = ActionValidator()
    result = validator.validate(action, registry)

    assert result.allowed is True
    assert result.code == "VALID"


def test_action_validator_rejects_unknown_tool():
    registry = ToolRegistry()

    action = AgentAction(
        tool_name="unknown_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    validator = ActionValidator()
    result = validator.validate(action, registry)

    assert result.allowed is False
    assert result.code == "UNKNOWN_TOOL"


def test_orchestrator_executes_validated_tool_and_updates_state():
    registry = ToolRegistry()
    tool = EchoSecurityTool()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    action = AgentAction(tool_name=tool.name, target="ecu.c")

    updated_state = AgentOrchestrator(
        state, registry, ActionValidator()
    ).execute(action)

    assert updated_state is state
    assert updated_state.actions_taken == ["echo_security_tool:ecu.c"]
    assert updated_state.observations == [
        "Tool echo_security_tool executed successfully for ecu.c."
    ]


def test_orchestrator_does_not_execute_rejected_action():
    class CountingTool(EchoSecurityTool):
        executions = 0

        def execute(self, target: str) -> ToolResult:
            self.executions += 1
            return super().execute(target)

    tool = CountingTool()
    registry = ToolRegistry()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    action = AgentAction(tool_name="unknown_tool", target="ecu.c")

    updated_state = AgentOrchestrator(
        state, registry, ActionValidator()
    ).execute(action)

    assert tool.executions == 0
    assert updated_state.actions_taken == []
    assert "Action rejected (UNKNOWN_TOOL)" in updated_state.observations[0]


def test_orchestrator_records_tool_execution_failure():
    class FailingTool(SecurityTool):
        @property
        def name(self) -> str:
            return "failing_tool"

        @property
        def description(self) -> str:
            return "Tool used to test execution failures."

        def execute(self, target: str) -> ToolResult:
            raise RuntimeError("tool unavailable")

    registry = ToolRegistry()
    registry.register(FailingTool())
    state = AgentState(objective="Assess ECU", target="ecu.c")
    action = AgentAction(tool_name="failing_tool", target="ecu.c")

    AgentOrchestrator(state, registry, ActionValidator()).execute(action)

    assert state.observations == [
        "Tool execution failed for failing_tool: tool unavailable"
    ]


def test_llm_client_is_abstract():
    with pytest.raises(TypeError):
        LLMClient()


def test_mock_llm_client_returns_predefined_response():
    client = MockLLMClient("tool_name=echo_security_tool\ntarget=ecu.c")

    assert client.generate("ignored prompt") == (
        "tool_name=echo_security_tool\ntarget=ecu.c"
    )


def test_agent_planner_converts_valid_response_to_action():
    planner = AgentPlanner(
        MockLLMClient("tool_name=echo_security_tool\ntarget=ecu.c")
    )

    action = planner.plan("Assess ECU", "ecu.c")

    assert action == AgentAction(tool_name="echo_security_tool", target="ecu.c")


def test_agent_planner_rejects_malformed_response():
    planner = AgentPlanner(MockLLMClient("tool_name=echo_security_tool"))

    with pytest.raises(AgentPlanningError, match="Missing required field"):
        planner.plan("Assess ECU", "ecu.c")


def test_agent_planner_does_not_require_tool_registry():
    planner = AgentPlanner(MockLLMClient("tool_name=echo_security_tool\ntarget=ecu.c"))

    assert planner.plan("Assess ECU", "ecu.c").tool_name == "echo_security_tool"
