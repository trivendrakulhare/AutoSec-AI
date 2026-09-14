import json
import pytest
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.analyzers.semgrep import (
    SemgrepAnalyzer,
    SemgrepExecutionError,
    SemgrepParsingError,
)
from autosec_ai.analyzers.rule_pack import (
    RulePackNotFoundError,
    RulePackRegistry,
)
from autosec_ai.analyzers.source_code import SourceCodeAnalyzer
from autosec_ai.agents.state import AgentState
from autosec_ai.tools.base import SecurityTool
from autosec_ai.tools.echo import EchoSecurityTool
from autosec_ai.tools.external import ExternalToolRunner
from autosec_ai.tools.external import ExternalToolResult
from autosec_ai.tools.result import ToolResult
from autosec_ai.tools.registry import ToolRegistry
from autosec_ai.agents.action import AgentAction
from autosec_ai.agents.validator import ActionValidator
from autosec_ai.agents.policy import SecurityPolicy
from autosec_ai.agents.orchestrator import AgentOrchestrator
from autosec_ai.agents.planner import AgentPlanner, AgentPlanningError
from autosec_ai.llm.client import LLMClient
from autosec_ai.llm.mock import MockLLMClient
from autosec_ai.llm.openai_client import (
    OpenAIClient,
    OpenAIConfigurationError,
    OpenAIRequestError,
)


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


def test_security_finding_fields_and_nullable_values():
    finding = SecurityFinding(
        rule_id="TEST-001",
        message="Test vulnerability",
        severity="HIGH",
        file="fixtures/ecu_vulnerable.c",
        line=10,
        category="memory-safety",
        cwe="CWE-120",
        source_tool="test_scanner",
    )

    assert finding.rule_id == "TEST-001"
    assert finding.message == "Test vulnerability"
    assert finding.severity == "HIGH"
    assert finding.file == "fixtures/ecu_vulnerable.c"
    assert finding.line == 10
    assert finding.category == "memory-safety"
    assert finding.cwe == "CWE-120"
    assert finding.source_tool == "test_scanner"

    nullable_finding = SecurityFinding(
        rule_id="TEST-002",
        message="Missing optional metadata",
        severity="LOW",
        file="fixtures/ecu_vulnerable.c",
        line=None,
        category="metadata",
        cwe=None,
        source_tool="test_scanner",
    )

    assert nullable_finding.line is None
    assert nullable_finding.cwe is None


def test_source_code_analyzer_interface():
    with pytest.raises(TypeError):
        SourceCodeAnalyzer()

    class MinimalSourceCodeAnalyzer(SourceCodeAnalyzer):
        def analyze(self, target: str) -> list[SecurityFinding]:
            return [
                SecurityFinding(
                    rule_id="TEST-001",
                    message="Test vulnerability",
                    severity="HIGH",
                    file=target,
                    line=10,
                    category="memory-safety",
                    cwe="CWE-120",
                    source_tool="test_scanner",
                )
            ]

    analyzer = MinimalSourceCodeAnalyzer()
    findings = analyzer.analyze("fixtures/ecu_vulnerable.c")

    assert len(findings) == 1
    assert isinstance(findings[0], SecurityFinding)
    assert findings[0].file == "fixtures/ecu_vulnerable.c"


def test_external_tool_runner_successful_execution():
    completed = SimpleNamespace(returncode=0, stdout="output", stderr="warning")
    with patch("autosec_ai.tools.external.subprocess.run", return_value=completed) as run:
        result = ExternalToolRunner().run("scanner", ["--target", "ecu.c"], 12)

    run.assert_called_once_with(
        ["scanner", "--target", "ecu.c"],
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
    )
    assert result.return_code == 0
    assert result.stdout == "output"
    assert result.stderr == "warning"
    assert result.timed_out is False


def test_external_tool_runner_returns_non_zero_exit_code():
    completed = SimpleNamespace(returncode=7, stdout="", stderr="failed")
    with patch("autosec_ai.tools.external.subprocess.run", return_value=completed):
        result = ExternalToolRunner().run("scanner", [])

    assert result.return_code == 7
    assert result.stderr == "failed"
    assert result.timed_out is False


def test_external_tool_runner_handles_timeout():
    timeout = subprocess.TimeoutExpired(["scanner"], 60, output="partial")
    with patch(
        "autosec_ai.tools.external.subprocess.run",
        side_effect=timeout,
    ):
        result = ExternalToolRunner().run("scanner", [])

    assert result.return_code == -1
    assert result.timed_out is True


def test_external_tool_runner_never_enables_shell():
    completed = SimpleNamespace(returncode=0, stdout="", stderr="")
    with patch("autosec_ai.tools.external.subprocess.run", return_value=completed) as run:
        ExternalToolRunner().run("scanner", ["--safe"])

    assert run.call_args.kwargs.get("shell", False) is False


def test_semgrep_analyzer_normalizes_two_findings():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(
        return_code=0,
        stdout='''{
            "results": [
                {
                    "check_id": "c.security.buffer-overflow",
                    "path": "src/ecu.c",
                    "start": {"line": 12},
                    "extra": {
                        "message": "Unsafe copy",
                        "severity": "warning",
                        "metadata": {
                            "category": "memory-safety",
                            "cwe": ["CWE-120"]
                        }
                    }
                },
                {
                    "check_id": "c.security.command-injection",
                    "path": "src/diagnostic.c",
                    "start": {"line": 24},
                    "extra": {
                        "message": "Untrusted command input",
                        "severity": "error",
                        "metadata": {"cwe": "CWE-78"}
                    }
                }
            ]
        }''',
        stderr="",
        timed_out=False,
    )

    findings = SemgrepAnalyzer(runner).analyze("fixtures/ecu_vulnerable.c")

    runner.run.assert_called_once_with(
        "semgrep",
        ["scan", "--json", "fixtures/ecu_vulnerable.c"],
    )
    assert findings == [
        SecurityFinding(
            rule_id="c.security.buffer-overflow",
            message="Unsafe copy",
            severity="WARNING",
            file="src/ecu.c",
            line=12,
            category="memory-safety",
            cwe="CWE-120",
            source_tool="semgrep",
        ),
        SecurityFinding(
            rule_id="c.security.command-injection",
            message="Untrusted command input",
            severity="ERROR",
            file="src/diagnostic.c",
            line=24,
            category="source-code",
            cwe="CWE-78",
            source_tool="semgrep",
        ),
    ]


def test_semgrep_analyzer_normalizes_missing_cwe_to_none():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(
        0,
        '{"results":[{"check_id":"RULE-1","path":"ecu.c",'
        '"start":{"line":1},"extra":{"message":"Issue",'
        '"severity":"info","metadata":{}}}]}',
        "",
        False,
    )

    findings = SemgrepAnalyzer(runner).analyze("ecu.c")

    assert findings[0].cwe is None


@pytest.mark.parametrize("line", ["12", True])
def test_semgrep_analyzer_rejects_non_integer_line_metadata(line):
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(
        0,
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "RULE-1",
                        "path": "ecu.c",
                        "start": {"line": line},
                        "extra": {},
                    }
                ]
            }
        ),
        "",
        False,
    )

    with pytest.raises(SemgrepParsingError):
        SemgrepAnalyzer(runner).analyze("ecu.c")


def test_semgrep_analyzer_rejects_malformed_json():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(0, "not-json", "", False)

    with pytest.raises(SemgrepParsingError):
        SemgrepAnalyzer(runner).analyze("ecu.c")


def test_semgrep_analyzer_rejects_non_zero_exit_code():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(2, "", "invalid config", False)

    with pytest.raises(SemgrepExecutionError, match="2.*invalid config"):
        SemgrepAnalyzer(runner).analyze("ecu.c")


def test_semgrep_analyzer_rejects_timeout():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(-1, "", "", True)

    with pytest.raises(SemgrepExecutionError, match="timed out"):
        SemgrepAnalyzer(runner).analyze("ecu.c")


def test_rule_pack_registry_resolves_registered_rule_pack():
    registry = RulePackRegistry({"automotive": "rules/automotive.yml"})

    assert registry.resolve("automotive") == "rules/automotive.yml"


def test_rule_pack_registry_rejects_unknown_rule_pack():
    registry = RulePackRegistry({"automotive": "rules/automotive.yml"})

    with pytest.raises(RulePackNotFoundError):
        registry.resolve("unknown")


def test_rule_pack_registry_resolves_multiple_rule_packs_independently():
    registry = RulePackRegistry(
        {
            "automotive": "rules/automotive.yml",
            "memory-safety": "rules/memory-safety.yml",
        }
    )

    assert registry.resolve("automotive") == "rules/automotive.yml"
    assert registry.resolve("memory-safety") == "rules/memory-safety.yml"


def test_rule_pack_registry_does_not_resolve_unregistered_paths():
    registry = RulePackRegistry({"automotive": "rules/automotive.yml"})

    with pytest.raises(RulePackNotFoundError):
        registry.resolve("rules/other.yml")


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
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
    )

    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    validator = ActionValidator()
    result = validator.validate(action, registry, policy)

    assert result.allowed is True
    assert result.code == "VALID"


def test_action_validator_rejects_unknown_tool():
    registry = ToolRegistry()
    policy = SecurityPolicy(
        allowed_tools={"unknown_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
    )

    action = AgentAction(
        tool_name="unknown_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    validator = ActionValidator()
    result = validator.validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "UNKNOWN_TOOL"


def test_action_validator_rejects_unauthorized_tool():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"different_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "UNAUTHORIZED_TOOL"


def test_action_validator_rejects_unauthorized_target():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"different_target"},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "UNAUTHORIZED_TARGET"


def test_action_validator_allows_parameter_within_limit():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        parameter_limits={"echo_security_tool": {"scan_depth": 3}},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"scan_depth": 2},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is True
    assert result.code == "VALID"


def test_action_validator_rejects_parameter_exceeding_limit():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        parameter_limits={"echo_security_tool": {"scan_depth": 3}},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"scan_depth": 4},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "RESOURCE_LIMIT_EXCEEDED"


def test_action_validator_allows_parameter_without_defined_limit():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        parameter_limits={"echo_security_tool": {"scan_depth": 3}},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"request_count": 1000},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is True
    assert result.code == "VALID"


def test_action_validator_does_not_compare_boolean_to_numeric_limit():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        parameter_limits={"echo_security_tool": {"enabled": 0}},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"enabled": True},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is True
    assert result.code == "VALID"


def test_empty_security_policy_rejects_registered_tool():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
    )

    result = ActionValidator().validate(action, registry, SecurityPolicy())

    assert result.allowed is False
    assert result.code == "UNAUTHORIZED_TOOL"


def test_orchestrator_checks_policy_before_executing_registered_tool():
    class CountingEchoSecurityTool(EchoSecurityTool):
        def __init__(self) -> None:
            self.execution_count = 0

        def execute(self, target: str) -> ToolResult:
            self.execution_count += 1
            return super().execute(target)

    tool = CountingEchoSecurityTool()
    registry = ToolRegistry()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    action = AgentAction(tool_name=tool.name, target="ecu.c")
    policy = SecurityPolicy(
        allowed_tools=set(),
        allowed_targets={"ecu.c"},
    )

    updated_state = AgentOrchestrator(
        state, registry, ActionValidator(), policy
    ).execute(action)

    assert tool.execution_count == 0
    assert updated_state.actions_taken == []
    assert "Action rejected (UNAUTHORIZED_TOOL)" in updated_state.observations[0]


def test_llm_action_with_unauthorized_target_cannot_reach_tool_execution():
    class CountingEchoSecurityTool(EchoSecurityTool):
        def __init__(self) -> None:
            self.execution_count = 0

        def execute(self, target: str) -> ToolResult:
            self.execution_count += 1
            return super().execute(target)

    tool = CountingEchoSecurityTool()
    registry = ToolRegistry()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="unauthorized-ecu.c")
    policy = SecurityPolicy(
        allowed_tools={tool.name},
        allowed_targets={"authorized-ecu.c"},
    )
    action = AgentPlanner(
        MockLLMClient("tool_name=echo_security_tool\ntarget=unauthorized-ecu.c")
    ).plan(state.objective, state.target)

    updated_state = AgentOrchestrator(
        state, registry, ActionValidator(), policy
    ).execute(action)

    assert "Action rejected (UNAUTHORIZED_TARGET)" in updated_state.observations[0]
    assert tool.execution_count == 0
    assert updated_state.actions_taken == []


def test_orchestrator_executes_validated_tool_and_updates_state():
    registry = ToolRegistry()
    tool = EchoSecurityTool()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    action = AgentAction(tool_name=tool.name, target="ecu.c")

    updated_state = AgentOrchestrator(
        state,
        registry,
        ActionValidator(),
        SecurityPolicy(
            allowed_tools={"echo_security_tool"},
            allowed_targets={"ecu.c"},
        ),
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
        state,
        registry,
        ActionValidator(),
        SecurityPolicy(
            allowed_tools={"echo_security_tool"},
            allowed_targets={"ecu.c"},
        ),
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

    AgentOrchestrator(
        state,
        registry,
        ActionValidator(),
        SecurityPolicy(
            allowed_tools={"failing_tool"},
            allowed_targets={"ecu.c"},
        ),
    ).execute(action)

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


def test_openai_client_implements_llm_client():
    assert isinstance(OpenAIClient(sdk_client=object()), LLMClient)


def test_openai_client_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(OpenAIConfigurationError, match="OPENAI_API_KEY"):
        OpenAIClient()


def test_openai_client_uses_default_model(monkeypatch):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    client = OpenAIClient(sdk_client=object())

    assert client.model == "gpt-5.6-luna"


def test_openai_client_uses_environment_model(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "environment-model")

    client = OpenAIClient(sdk_client=object())

    assert client.model == "environment-model"


def test_openai_client_explicit_model_overrides_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "environment-model")

    client = OpenAIClient(model="test-model", sdk_client=object())

    assert client.model == "test-model"


def test_openai_client_uses_mocked_responses_api():
    class FakeResponses:
        def __init__(self):
            self.calls = []

        def create(self, **kwargs):
            self.calls.append(kwargs)
            return type("Response", (), {"output_text": "generated text"})()

    class FakeSDKClient:
        def __init__(self):
            self.responses = FakeResponses()

    sdk_client = FakeSDKClient()
    client = OpenAIClient(model="test-model", sdk_client=sdk_client)

    assert client.generate("assess this ECU") == "generated text"
    assert sdk_client.responses.calls == [
        {"model": "test-model", "input": "assess this ECU"}
    ]


def test_openai_client_converts_sdk_failure_without_exposing_credentials():
    class FailingResponses:
        def create(self, **kwargs):
            raise RuntimeError("request failed with secret-key-value")

    class FakeSDKClient:
        responses = FailingResponses()

    with pytest.raises(OpenAIRequestError) as error:
        OpenAIClient(sdk_client=FakeSDKClient()).generate("prompt")

    assert str(error.value) == "OpenAI request failed."
    assert "secret-key-value" not in str(error.value)
