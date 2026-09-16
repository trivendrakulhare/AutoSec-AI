import json
import pytest
import shutil
import subprocess
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import Mock, patch

from autosec_ai.analyzers.finding import SecurityFinding
from autosec_ai.analyzers.finding_assessment import (
    FindingAssessment,
    FindingAssessmentParsingError,
    FindingAssessor,
    LLMFindingAssessor,
)
from autosec_ai.analyzers.binary import BinaryAnalyzer
from autosec_ai.analyzers.binary_imports import (
    BinaryAnalysisEvidence,
    ImportedFunctionBinaryAnalyzer,
    format_binary_analysis_context,
)
from autosec_ai.analyzers.protected_data import ProtectedDataVehicleAnalyzer
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
from autosec_ai.tools.semgrep import SemgrepSecurityTool
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
from autosec_ai.automotive import (
    CANMessage,
    ECU,
    READ_DATA_BY_IDENTIFIER,
    SIMULATED_VIN_IDENTIFIER,
    SIMULATED_VIN_VALUE,
    SIMULATED_PROTECTED_IDENTIFIER,
    SIMULATED_PROTECTED_VALUE,
    SimulatedECU,
    DiagnosticDataPolicy,
    UDSRequest,
    UDSResponse,
    VehicleAnalysisEvidence,
    perform_uds_probe,
)
from autosec_ai.analyzers.vehicle import VehicleAnalyzer


def test_project_import():
    import autosec_ai

    assert autosec_ai.__name__ == "autosec_ai"


def test_valid_ecu_and_invalid_ecu_identifier():
    ecu = ECU(identifier=0x7E0, name="Simulated Engine ECU")

    assert ecu.identifier == 0x7E0
    assert ecu.name == "Simulated Engine ECU"
    with pytest.raises(TypeError):
        ECU(identifier=True, name="Invalid ECU")
    with pytest.raises(ValueError):
        ECU(identifier=0x800, name="Invalid ECU")
    with pytest.raises(TypeError):
        ECU(identifier="0x7E0", name="Invalid ECU")


def test_can_message_validates_standard_id_and_classic_payload():
    assert CANMessage(arbitration_id=0x000, payload=b"").payload == b""
    assert CANMessage(arbitration_id=0x7FF, payload=b"12345678").arbitration_id == 0x7FF

    with pytest.raises(ValueError):
        CANMessage(arbitration_id=-1, payload=b"")
    with pytest.raises(ValueError):
        CANMessage(arbitration_id=0x800, payload=b"")
    with pytest.raises(ValueError):
        CANMessage(arbitration_id=0x100, payload=b"123456789")
    with pytest.raises(TypeError):
        CANMessage(arbitration_id=True, payload=b"")
    with pytest.raises(TypeError):
        CANMessage(arbitration_id=0x100, payload=bytearray(b"data"))


def test_uds_request_validates_service_id_and_payload():
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=SIMULATED_VIN_IDENTIFIER.to_bytes(2, byteorder="big"),
    )

    assert request.target_ecu_identifier == 0x7E0
    assert request.service_id == 0x22
    with pytest.raises(ValueError):
        UDSRequest(target_ecu_identifier=0x7E0, service_id=0x100, payload=b"")
    with pytest.raises(TypeError):
        UDSRequest(target_ecu_identifier=0x7E0, service_id=True, payload=b"")
    with pytest.raises(TypeError):
        UDSRequest(target_ecu_identifier=0x7E0, service_id="0x22", payload=b"")
    with pytest.raises(TypeError):
        UDSRequest(target_ecu_identifier=0x7E0, service_id=0x22, payload=bytearray())


def test_automotive_value_objects_are_immutable():
    ecu = ECU(identifier=0x7E0, name="Simulated ECU")
    message = CANMessage(arbitration_id=0x100, payload=b"data")
    request = UDSRequest(target_ecu_identifier=0x7E0, service_id=0x22, payload=b"")
    response = UDSResponse(target_ecu_identifier=0x7E0, positive=True, payload=b"ok")

    for value_object, field in (
        (ecu, "name"),
        (message, "payload"),
        (request, "service_id"),
        (response, "positive"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value_object, field, None)


def test_uds_response_rejects_non_boolean_positive_value():
    with pytest.raises(TypeError):
        UDSResponse(target_ecu_identifier=0x7E0, positive=1, payload=b"")


def test_uds_response_rejects_non_bytes_payload():
    with pytest.raises(TypeError):
        UDSResponse(target_ecu_identifier=0x7E0, positive=True, payload=bytearray())


def test_simulated_ecu_returns_deterministic_positive_read_data_response():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=SIMULATED_VIN_IDENTIFIER.to_bytes(2, byteorder="big"),
    )

    response = simulator.handle_request(request)

    assert response == UDSResponse(
        target_ecu_identifier=0x7E0,
        positive=True,
        payload=b"\x62\xf1\x90" + SIMULATED_VIN_VALUE,
    )


@pytest.mark.parametrize("payload", [b"", b"\xf1", b"\xf1\x90\x00"])
def test_simulated_ecu_rejects_invalid_read_data_by_identifier_length(payload):
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=payload,
    )

    response = simulator.handle_request(request)

    assert response.positive is False
    assert response.payload == b"\x7f\x22\x13"


def test_simulated_ecu_rejects_unsupported_service_deterministically():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(target_ecu_identifier=0x7E0, service_id=0x10, payload=b"")

    response = simulator.handle_request(request)

    assert response == UDSResponse(
        target_ecu_identifier=0x7E0,
        positive=False,
        payload=b"\x7f\x10\x11",
    )


def test_simulated_ecu_rejects_unsupported_data_identifier_deterministically():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=b"\xf1\x91",
    )

    response = simulator.handle_request(request)

    assert response == UDSResponse(
        target_ecu_identifier=0x7E0,
        positive=False,
        payload=b"\x7f\x22\x31",
    )


def test_simulated_ecu_rejects_request_for_another_ecu_deterministically():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E1,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=SIMULATED_VIN_IDENTIFIER.to_bytes(2, byteorder="big"),
    )

    response = simulator.handle_request(request)

    assert response == UDSResponse(
        target_ecu_identifier=0x7E0,
        positive=False,
        payload=b"\x7f\x22\x31",
    )


def test_vehicle_analyzer_is_independent_and_returns_security_findings():
    assert not issubclass(VehicleAnalyzer, BinaryAnalyzer)
    assert not issubclass(VehicleAnalyzer, SourceCodeAnalyzer)
    assert VehicleAnalyzer.__abstractmethods__ == {"analyze"}


def test_vehicle_analysis_evidence_is_immutable_and_observation_only():
    evidence = VehicleAnalysisEvidence(
        target_ecu_identifier=0x7E0,
        service_id=0x22,
        request_payload=b"\xf1\x90",
        response_positive=True,
        response_payload=b"\x62\xf1\x90test",
        analysis_type="single-uds-probe",
    )

    with pytest.raises(FrozenInstanceError):
        evidence.service_id = 0x10
    assert not {
        "vulnerable",
        "exploitable",
        "attack_successful",
        "risk_score",
        "criticality",
    }.intersection(evidence.__dataclass_fields__)


@pytest.mark.parametrize(
    ("analysis_type", "error_type"),
    [(None, TypeError), (123, TypeError), ("", ValueError)],
)
def test_vehicle_analysis_evidence_rejects_invalid_analysis_type(
    analysis_type, error_type
):
    with pytest.raises(error_type):
        VehicleAnalysisEvidence(
            target_ecu_identifier=0x7E0,
            service_id=0x22,
            request_payload=b"\xf1\x90",
            response_positive=True,
            response_payload=b"\x62\xf1\x90test",
            analysis_type=analysis_type,
        )


def test_diagnostic_data_policy_is_immutable_and_validates_did_boundaries():
    lower = DiagnosticDataPolicy(0x0000, authorization_required=False)
    upper = DiagnosticDataPolicy(0xFFFF, authorization_required=True)

    assert lower.data_identifier == 0x0000
    assert upper.data_identifier == 0xFFFF
    with pytest.raises(FrozenInstanceError):
        lower.data_identifier = 0x1234
    with pytest.raises(ValueError):
        DiagnosticDataPolicy(-1, authorization_required=False)
    with pytest.raises(ValueError):
        DiagnosticDataPolicy(0x10000, authorization_required=False)
    with pytest.raises(TypeError):
        DiagnosticDataPolicy(True, authorization_required=False)


def test_secure_simulator_denies_unauthenticated_protected_did():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"), policy)
    request = UDSRequest(0x7E0, READ_DATA_BY_IDENTIFIER, b"\xf1\xa0")

    response = simulator.handle_request(request)

    assert response.positive is False
    assert response.payload == b"\x7f\x22\x33"


def test_secure_simulator_is_default_for_protected_did():
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"))
    request = UDSRequest(0x7E0, READ_DATA_BY_IDENTIFIER, b"\xf1\xa0")

    response = simulator.handle_request(request)

    assert response.positive is False
    assert response.payload == b"\x7f\x22\x33"


def test_misconfigured_simulator_returns_only_synthetic_protected_data():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    simulator = SimulatedECU(
        ECU(0x7E0, "Simulated ECU"),
        policy,
        allow_unauthenticated_protected_data=True,
    )
    request = UDSRequest(0x7E0, READ_DATA_BY_IDENTIFIER, b"\xf1\xa0")

    response = simulator.handle_request(request)

    assert response == UDSResponse(
        target_ecu_identifier=0x7E0,
        positive=True,
        payload=b"\x62\xf1\xa0" + SIMULATED_PROTECTED_VALUE,
    )
    assert SIMULATED_PROTECTED_VALUE.startswith(b"SYNTHETIC")


def test_secure_protected_data_analyzer_returns_no_finding_and_retains_evidence():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"), policy)
    analyzer = ProtectedDataVehicleAnalyzer(simulator, policy)

    findings = analyzer.analyze(simulator.ecu)

    assert findings == []
    assert analyzer.last_evidence == VehicleAnalysisEvidence(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        request_payload=b"\xf1\xa0",
        response_positive=False,
        response_payload=b"\x7f\x22\x33",
        analysis_type="unauthenticated-protected-data-probe",
    )


def test_protected_data_analyzer_rejects_mismatched_simulator_policy():
    simulator_policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    analyzer_policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, False)
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"), simulator_policy)

    with pytest.raises(ValueError):
        ProtectedDataVehicleAnalyzer(simulator, analyzer_policy)


def test_protected_data_analyzer_rejects_inconsistent_target():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"), policy)
    analyzer = ProtectedDataVehicleAnalyzer(simulator, policy)

    with pytest.raises(ValueError):
        analyzer.analyze(ECU(0x7E1, "Different ECU"))


def test_protected_data_analyzer_requires_exact_synthetic_protected_response():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)

    class UnexpectedDataSimulator:
        def __init__(self):
            self.ecu = ECU(0x7E0, "Simulated ECU")
            self.protected_data_policy = policy

        def handle_request(self, request):
            return UDSResponse(
                target_ecu_identifier=self.ecu.identifier,
                positive=True,
                payload=b"\x62\xf1\xa0UNEXPECTED-DATA",
            )

    analyzer = ProtectedDataVehicleAnalyzer(UnexpectedDataSimulator(), policy)

    assert analyzer.analyze(analyzer.simulator.ecu) == []
    assert analyzer.last_evidence.response_payload == b"\x62\xf1\xa0UNEXPECTED-DATA"


def test_misconfigured_protected_data_analyzer_emits_one_deterministic_finding():
    policy = DiagnosticDataPolicy(SIMULATED_PROTECTED_IDENTIFIER, True)
    simulator = SimulatedECU(
        ECU(0x7E0, "Simulated ECU"),
        policy,
        allow_unauthenticated_protected_data=True,
    )
    analyzer = ProtectedDataVehicleAnalyzer(simulator, policy)

    findings = analyzer.analyze(simulator.ecu)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "VEH-UDS-PROTECTED-DATA-UNAUTH"
    assert finding.category == "diagnostic-access-control"
    assert finding.source_tool == "vehicle-simulator"
    assert finding.cwe is None
    assert "exploit" not in finding.message.lower()
    assert "takeover" not in finding.message.lower()
    assert analyzer.last_evidence.response_payload == (
        b"\x62\xf1\xa0" + SIMULATED_PROTECTED_VALUE
    )


def test_vehicle_analyzer_does_not_flag_normal_f190_read():
    policy = DiagnosticDataPolicy(SIMULATED_VIN_IDENTIFIER, False)
    simulator = SimulatedECU(ECU(0x7E0, "Simulated ECU"), policy)
    analyzer = ProtectedDataVehicleAnalyzer(simulator, policy)

    assert analyzer.analyze(simulator.ecu) == []
    assert analyzer.last_evidence.response_payload == (
        b"\x62\xf1\x90" + SIMULATED_VIN_VALUE
    )


def test_uds_probe_records_exact_positive_request_and_response_values():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=SIMULATED_VIN_IDENTIFIER.to_bytes(2, byteorder="big"),
    )

    evidence = perform_uds_probe(simulator, request)

    assert evidence == VehicleAnalysisEvidence(
        target_ecu_identifier=0x7E0,
        service_id=0x22,
        request_payload=b"\xf1\x90",
        response_positive=True,
        response_payload=b"\x62\xf1\x90" + SIMULATED_VIN_VALUE,
        analysis_type="single-uds-probe",
    )


def test_uds_probe_records_deterministic_negative_response():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(target_ecu_identifier=0x7E0, service_id=0x10, payload=b"")

    evidence = perform_uds_probe(simulator, request, "unsupported-service-probe")

    assert evidence.target_ecu_identifier == 0x7E0
    assert evidence.service_id == 0x10
    assert evidence.request_payload == b""
    assert evidence.response_positive is False
    assert evidence.response_payload == b"\x7f\x10\x11"
    assert evidence.analysis_type == "unsupported-service-probe"


def test_uds_probe_does_not_alter_request_object():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=b"\xf1\x90",
    )

    perform_uds_probe(simulator, request)

    assert request == UDSRequest(
        target_ecu_identifier=0x7E0,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=b"\xf1\x90",
    )


def test_uds_probe_records_actual_response_for_wrong_ecu_target():
    simulator = SimulatedECU(ECU(identifier=0x7E0, name="Simulated ECU"))
    request = UDSRequest(
        target_ecu_identifier=0x7E1,
        service_id=READ_DATA_BY_IDENTIFIER,
        payload=b"\xf1\x90",
    )

    evidence = perform_uds_probe(simulator, request)

    assert evidence.target_ecu_identifier == 0x7E1
    assert evidence.response_positive is False
    assert evidence.response_payload == b"\x7f\x22\x31"


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


def test_finding_assessor_parses_valid_assessment():
    client = MockLLMClient(
        json.dumps(
            {
                "classification": "likely_vulnerability",
                "confidence": "medium",
                "rationale": "The scanner evidence indicates an unsafe copy.",
                "impact": "An attacker may corrupt memory.",
                "recommendations": ["Review bounds before copying input."],
            }
        )
    )
    finding = SecurityFinding(
        "RULE-1", "Unsafe copy", "WARNING", "ecu.c", 12, "memory-safety", "CWE-120", "semgrep"
    )

    assessment = LLMFindingAssessor(client).assess(finding, "char buffer[8];")

    assert assessment == FindingAssessment(
        classification="likely_vulnerability",
        confidence="medium",
        rationale="The scanner evidence indicates an unsafe copy.",
        impact="An attacker may corrupt memory.",
        recommendations=["Review bounds before copying input."],
    )


@pytest.mark.parametrize(
    "classification",
    [
        "confirmed_vulnerability",
        "likely_vulnerability",
        "needs_review",
        "likely_false_positive",
    ],
)
def test_finding_assessment_accepts_each_classification(classification):
    assessment = FindingAssessment(
        classification=classification,
        confidence="low",
        rationale="Needs analyst review.",
        impact="Impact is uncertain.",
        recommendations=[],
    )

    assert assessment.classification == classification


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_finding_assessment_accepts_each_confidence(confidence):
    assessment = FindingAssessment(
        classification="needs_review",
        confidence=confidence,
        rationale="Needs analyst review.",
        impact="Impact is uncertain.",
        recommendations=[],
    )

    assert assessment.confidence == confidence


def test_finding_assessor_rejects_malformed_response():
    assessor = LLMFindingAssessor(MockLLMClient("not-json"))

    with pytest.raises(FindingAssessmentParsingError):
        assessor.assess(SecurityFinding("R", "m", "LOW", "f.c", None, "cat", None, "tool"))


def test_finding_assessor_rejects_missing_required_field():
    response = json.dumps(
        {
            "classification": "needs_review",
            "confidence": "low",
            "rationale": "Review needed.",
            "impact": "Unknown.",
        }
    )

    with pytest.raises(FindingAssessmentParsingError):
        LLMFindingAssessor(MockLLMClient(response)).assess(
            SecurityFinding("R", "m", "LOW", "f.c", None, "cat", None, "tool")
        )


def test_finding_assessor_rejects_unexpected_extra_field():
    response = {
        "classification": "needs_review",
        "confidence": "low",
        "rationale": "Review needed.",
        "impact": "Unknown.",
        "recommendations": [],
        "execute_command": "rm -rf /",
    }

    with pytest.raises(FindingAssessmentParsingError):
        LLMFindingAssessor(MockLLMClient(json.dumps(response))).assess(
            SecurityFinding("R", "m", "LOW", "f.c", None, "cat", None, "tool")
        )


@pytest.mark.parametrize("recommendations", ["Review manually.", ["Review", 1]])
def test_finding_assessor_rejects_invalid_recommendations(recommendations):
    response = {
        "classification": "needs_review",
        "confidence": "low",
        "rationale": "Review needed.",
        "impact": "Unknown.",
        "recommendations": recommendations,
    }

    with pytest.raises(FindingAssessmentParsingError):
        LLMFindingAssessor(MockLLMClient(json.dumps(response))).assess(
            SecurityFinding("R", "m", "LOW", "f.c", None, "cat", None, "tool")
        )


@pytest.mark.parametrize(
    "field,value",
    [("classification", "invalid"), ("confidence", "critical")],
)
def test_finding_assessor_rejects_invalid_enum(field, value):
    response = {
        "classification": "needs_review",
        "confidence": "low",
        "rationale": "Review needed.",
        "impact": "Unknown.",
        "recommendations": [],
    }
    response[field] = value

    with pytest.raises(FindingAssessmentParsingError):
        LLMFindingAssessor(MockLLMClient(json.dumps(response))).assess(
            SecurityFinding("R", "m", "LOW", "f.c", None, "cat", None, "tool")
        )


def test_finding_assessor_preserves_recommendations():
    recommendations = ["Patch the input handling.", "Add a regression test."]
    response = json.dumps(
        {
            "classification": "confirmed_vulnerability",
            "confidence": "high",
            "rationale": "Evidence is conclusive.",
            "impact": "Memory corruption.",
            "recommendations": recommendations,
        }
    )

    assessment = LLMFindingAssessor(MockLLMClient(response)).assess(
        SecurityFinding("R", "m", "HIGH", "f.c", 3, "cat", "CWE-120", "tool")
    )

    assert assessment.recommendations == recommendations


def test_finding_assessor_prompt_includes_evidence_and_context():
    client = MockLLMClient(
        json.dumps(
            {
                "classification": "needs_review",
                "confidence": "low",
                "rationale": "Review needed.",
                "impact": "Unknown.",
                "recommendations": [],
            }
        )
    )
    finding = SecurityFinding(
        "RULE-42", "Unsafe diagnostic input", "ERROR", "diagnostic.c", 7,
        "input-validation", "CWE-20", "semgrep",
    )

    LLMFindingAssessor(client).assess(finding, "trusted source context")

    assert client.last_prompt is not None
    assert "OBSERVED EVIDENCE" in client.last_prompt
    assert "RULE-42" in client.last_prompt
    assert "Unsafe diagnostic input" in client.last_prompt
    assert "trusted source context" in client.last_prompt
    assert "INFERENCE" in client.last_prompt


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


def test_binary_analyzer_interface():
    with pytest.raises(TypeError):
        BinaryAnalyzer()

    class MinimalBinaryAnalyzer(BinaryAnalyzer):
        def analyze(self, target: str) -> list[SecurityFinding]:
            return [
                SecurityFinding(
                    rule_id="BIN-001",
                    message="Suspicious binary pattern",
                    severity="MEDIUM",
                    file=target,
                    line=None,
                    category="binary-analysis",
                    cwe=None,
                    source_tool="test_binary_analyzer",
                )
            ]

    findings = MinimalBinaryAnalyzer().analyze("fixtures/sample.bin")

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert isinstance(findings[0], SecurityFinding)
    assert findings[0].file == "fixtures/sample.bin"


def _compile_binary_fixture(source_name, output_path):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler is not installed")
    source_path = f"tests/fixtures/{source_name}"
    subprocess.run(
        [compiler, "-O0", source_path, "-o", str(output_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_binary_import_analyzer_detects_strcpy_fixture(tmp_path):
    binary_path = tmp_path / "binary_vulnerable"
    _compile_binary_fixture("binary_vulnerable.c", binary_path)

    analyzer = ImportedFunctionBinaryAnalyzer(ExternalToolRunner())
    findings = analyzer.analyze(str(binary_path))

    assert len(findings) == 1
    assert findings[0] == SecurityFinding(
        rule_id="BIN-MEM-UNSAFE-STRCPY",
        message=(
            "Potentially dangerous memory-unsafe function strcpy was detected "
            "in the binary imports."
        ),
        severity="MEDIUM",
        file=str(binary_path),
        line=None,
        category="binary-analysis",
        cwe="CWE-120",
        source_tool="nm",
    )
    assert analyzer.last_evidence == BinaryAnalysisEvidence(
        imported_symbol="___strcpy_chk",
        analysis_tool="nm",
        analysis_type="imported-symbol inspection",
    )


def test_binary_import_analyzer_ignores_binary_without_strcpy(tmp_path):
    binary_path = tmp_path / "binary_safe"
    _compile_binary_fixture("binary_safe.c", binary_path)

    analyzer = ImportedFunctionBinaryAnalyzer(ExternalToolRunner())
    findings = analyzer.analyze(str(binary_path))

    assert findings == []
    assert analyzer.last_evidence is None


def test_binary_import_analyzer_handles_missing_target_deterministically(tmp_path):
    missing_path = tmp_path / "does-not-exist"

    findings = ImportedFunctionBinaryAnalyzer(ExternalToolRunner()).analyze(
        str(missing_path)
    )

    assert findings == []


def test_binary_import_analyzer_rejects_symbol_name_prefix_false_positive():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(
        return_code=0,
        stdout="    _strcpy_wrapper\n",
        stderr="",
        timed_out=False,
    )

    findings = ImportedFunctionBinaryAnalyzer(runner).analyze("/tmp/fake-binary")

    assert findings == []


def test_binary_analysis_evidence_representation():
    evidence = BinaryAnalysisEvidence(
        imported_symbol="___strcpy_chk",
        analysis_tool="nm",
        analysis_type="imported-symbol inspection",
    )

    assert evidence.imported_symbol == "___strcpy_chk"
    assert evidence.analysis_tool == "nm"
    assert evidence.analysis_type == "imported-symbol inspection"


def test_binary_import_analyzer_retains_detected_symbol_in_evidence():
    runner = Mock(spec=ExternalToolRunner)
    runner.run.return_value = ExternalToolResult(
        return_code=0,
        stdout="___strcpy_chk\n",
        stderr="",
        timed_out=False,
    )

    findings = ImportedFunctionBinaryAnalyzer(runner).analyze("/tmp/fake-binary")

    assert len(findings) == 1
    assert findings[0] == SecurityFinding(
        rule_id="BIN-MEM-UNSAFE-STRCPY",
        message=(
            "Potentially dangerous memory-unsafe function strcpy was detected "
            "in the binary imports."
        ),
        severity="MEDIUM",
        file="/tmp/fake-binary",
        line=None,
        category="binary-analysis",
        cwe="CWE-120",
        source_tool="nm",
    )


def test_binary_analysis_context_contains_observed_evidence_and_limitations():
    finding = SecurityFinding(
        rule_id="BIN-MEM-UNSAFE-STRCPY",
        message="Potentially dangerous memory-unsafe function strcpy was detected in the binary imports.",
        severity="MEDIUM",
        file="/tmp/fake-binary",
        line=None,
        category="binary-analysis",
        cwe="CWE-120",
        source_tool="nm",
    )
    evidence = BinaryAnalysisEvidence(
        imported_symbol="___strcpy_chk",
        analysis_tool="nm",
        analysis_type="imported-symbol inspection",
    )

    context = format_binary_analysis_context(finding, evidence)

    assert "OBSERVED EVIDENCE" in context
    assert "rule_id=BIN-MEM-UNSAFE-STRCPY" in context
    assert "___strcpy_chk" in context
    assert "analysis_tool=nm" in context
    assert "analysis_type=imported-symbol inspection" in context
    assert "observed" in context.lower()
    assert "does not establish exploitability" in context


def test_finding_assessor_accepts_binary_analysis_context():
    finding = SecurityFinding(
        rule_id="BIN-MEM-UNSAFE-STRCPY",
        message="Potentially dangerous memory-unsafe function strcpy was detected in the binary imports.",
        severity="MEDIUM",
        file="/tmp/fake-binary",
        line=None,
        category="binary-analysis",
        cwe="CWE-120",
        source_tool="nm",
    )
    evidence = BinaryAnalysisEvidence(
        imported_symbol="___strcpy_chk",
        analysis_tool="nm",
        analysis_type="imported-symbol inspection",
    )
    client = MockLLMClient(
        json.dumps(
            {
                "classification": "likely_vulnerability",
                "confidence": "medium",
                "rationale": "Observed binary evidence points to a dangerous import.",
                "impact": "The binary imports a dangerous function.",
                "recommendations": ["Review the call path and replace unsafe string handling."],
            }
        )
    )

    assessment = LLMFindingAssessor(client).assess(
        finding,
        format_binary_analysis_context(finding, evidence),
    )

    assert assessment.classification == "likely_vulnerability"
    assert assessment.confidence == "medium"


def test_binary_import_analyzer_implements_binary_analyzer():
    analyzer = ImportedFunctionBinaryAnalyzer(ExternalToolRunner())

    assert isinstance(analyzer, BinaryAnalyzer)


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
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
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

    findings = SemgrepAnalyzer(runner, registry).analyze(
        "fixtures/ecu_vulnerable.c", "automotive"
    )

    runner.run.assert_called_once_with(
        "semgrep",
        [
            "scan",
            "--config",
            "/trusted/automotive.yml",
            "--json",
            "fixtures/ecu_vulnerable.c",
        ],
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
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
    runner.run.return_value = ExternalToolResult(
        0,
        '{"results":[{"check_id":"RULE-1","path":"ecu.c",'
        '"start":{"line":1},"extra":{"message":"Issue",'
        '"severity":"info","metadata":{}}}]}',
        "",
        False,
    )

    findings = SemgrepAnalyzer(runner, registry).analyze("ecu.c", "automotive")

    assert findings[0].cwe is None


@pytest.mark.parametrize("line", ["12", True])
def test_semgrep_analyzer_rejects_non_integer_line_metadata(line):
    runner = Mock(spec=ExternalToolRunner)
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
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
        SemgrepAnalyzer(runner, registry).analyze("ecu.c", "automotive")


def test_semgrep_analyzer_rejects_malformed_json():
    runner = Mock(spec=ExternalToolRunner)
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
    runner.run.return_value = ExternalToolResult(0, "not-json", "", False)

    with pytest.raises(SemgrepParsingError):
        SemgrepAnalyzer(runner, registry).analyze("ecu.c", "automotive")


def test_semgrep_analyzer_rejects_non_zero_exit_code():
    runner = Mock(spec=ExternalToolRunner)
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
    runner.run.return_value = ExternalToolResult(2, "", "invalid config", False)

    with pytest.raises(SemgrepExecutionError, match="2.*invalid config"):
        SemgrepAnalyzer(runner, registry).analyze("ecu.c", "automotive")


def test_semgrep_analyzer_rejects_timeout():
    runner = Mock(spec=ExternalToolRunner)
    registry = RulePackRegistry({"automotive": "/trusted/automotive.yml"})
    runner.run.return_value = ExternalToolResult(-1, "", "", True)

    with pytest.raises(SemgrepExecutionError, match="timed out"):
        SemgrepAnalyzer(runner, registry).analyze("ecu.c", "automotive")


def test_repository_semgrep_rule_detects_unsafe_strcpy():
    executable = shutil.which("semgrep")
    if executable is None:
        pytest.skip("semgrep executable is not installed")

    result = ExternalToolRunner().run(
        executable,
        [
            "scan",
            "--config",
            "rules/semgrep/automotive-c.yml",
            "--json",
            "tests/fixtures/ecu_vulnerable.c",
        ],
    )

    assert result.return_code == 0, result.stderr
    assert result.timed_out is False
    findings = json.loads(result.stdout)["results"]
    assert len(findings) == 1

    finding = findings[0]
    assert finding["check_id"].endswith("autosec-c-unsafe-strcpy")
    assert finding["path"].endswith("tests/fixtures/ecu_vulnerable.c")
    assert finding["start"]["line"] == 56
    assert finding["extra"]["severity"] == "ERROR"


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


def test_action_validator_allows_authorized_semgrep_rule_pack():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        allowed_parameter_values={
            "echo_security_tool": {"rule_pack": {"automotive"}}
        },
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"rule_pack": "automotive"},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is True
    assert result.code == "VALID"


@pytest.mark.parametrize("rule_pack", ["unknown", "../../malicious.yml", "/tmp/malicious.yml"])
def test_action_validator_rejects_unauthorized_semgrep_rule_pack(rule_pack):
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"fixtures/ecu_vulnerable.c"},
        allowed_parameter_values={
            "echo_security_tool": {"rule_pack": {"automotive"}}
        },
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="fixtures/ecu_vulnerable.c",
        parameters={"rule_pack": rule_pack},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "UNAUTHORIZED_PARAMETER"


def test_orchestrator_passes_authorized_rule_pack_to_semgrep_analyzer():
    analyzer = Mock(spec=SemgrepAnalyzer)
    analyzer.analyze.return_value = []
    tool = SemgrepSecurityTool(analyzer)
    registry = ToolRegistry()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    policy = SecurityPolicy(
        allowed_tools={"semgrep"},
        allowed_targets={"ecu.c"},
        allowed_parameter_values={"semgrep": {"rule_pack": {"automotive"}}},
    )
    action = AgentAction(
        tool_name="semgrep",
        target="ecu.c",
        parameters={"rule_pack": "automotive"},
    )

    AgentOrchestrator(state, registry, ActionValidator(), policy).execute(action)

    analyzer.analyze.assert_called_once_with("ecu.c", "automotive")


def test_action_validator_rejects_extra_semgrep_parameters():
    registry = ToolRegistry()
    registry.register(EchoSecurityTool())
    policy = SecurityPolicy(
        allowed_tools={"echo_security_tool"},
        allowed_targets={"ecu.c"},
        allowed_parameter_values={"echo_security_tool": {"rule_pack": {"automotive"}}},
    )
    action = AgentAction(
        tool_name="echo_security_tool",
        target="ecu.c",
        parameters={"rule_pack": "automotive", "config": "--dangerous"},
    )

    result = ActionValidator().validate(action, registry, policy)

    assert result.allowed is False
    assert result.code == "UNAUTHORIZED_PARAMETER"


@pytest.mark.parametrize("rule_pack", ["unknown", "../../malicious.yml", "/tmp/malicious.yml"])
def test_rejected_rule_pack_never_reaches_semgrep_execution(rule_pack):
    analyzer = Mock(spec=SemgrepAnalyzer)
    analyzer.analyze.return_value = []
    tool = SemgrepSecurityTool(analyzer)
    registry = ToolRegistry()
    registry.register(tool)
    state = AgentState(objective="Assess ECU", target="ecu.c")
    policy = SecurityPolicy(
        allowed_tools={"semgrep"},
        allowed_targets={"ecu.c"},
        allowed_parameter_values={"semgrep": {"rule_pack": {"automotive"}}},
    )
    action = AgentAction(
        tool_name="semgrep",
        target="ecu.c",
        parameters={"rule_pack": rule_pack},
    )

    updated_state = AgentOrchestrator(
        state, registry, ActionValidator(), policy
    ).execute(action)

    assert analyzer.analyze.call_count == 0
    assert updated_state.actions_taken == []
    assert "Action rejected (UNAUTHORIZED_PARAMETER)" in updated_state.observations[0]


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
