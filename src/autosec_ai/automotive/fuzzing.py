from dataclasses import dataclass
from enum import Enum

from .evidence import VehicleAnalysisEvidence
from .models import UDSRequest
from .simulator import READ_DATA_BY_IDENTIFIER, SimulatedECU


MAX_UDS_FUZZ_CASES = 32


class MutationType(Enum):
    """Closed set of supported deterministic mutation classes."""

    EMPTY_PAYLOAD = "empty-payload"
    TRUNCATED_DID = "truncated-did"
    VALID_DID = "valid-did"
    EXTRA_BYTE = "extra-byte"
    MAX_CLASSIC_CAN_PAYLOAD = "max-classic-can-payload"


@dataclass(frozen=True)
class UDSFuzzConfig:
    """Small bounded configuration for deterministic UDS case generation."""

    service_id: int
    data_identifier: int
    max_cases: int

    def __post_init__(self) -> None:
        if isinstance(self.service_id, bool) or not isinstance(self.service_id, int):
            raise TypeError("service_id must be an integer")
        if not 0x00 <= self.service_id <= 0xFF:
            raise ValueError("service_id must fit in one byte")
        if self.service_id != READ_DATA_BY_IDENTIFIER:
            raise ValueError(
                "current deterministic fuzz strategy supports only "
                "ReadDataByIdentifier"
            )
        if isinstance(self.data_identifier, bool) or not isinstance(
            self.data_identifier, int
        ):
            raise TypeError("data_identifier must be an integer")
        if not 0x0000 <= self.data_identifier <= 0xFFFF:
            raise ValueError("data_identifier must fit in two bytes")
        if isinstance(self.max_cases, bool) or not isinstance(self.max_cases, int):
            raise TypeError("max_cases must be an integer")
        if self.max_cases <= 0:
            raise ValueError("max_cases must be greater than zero")
        if self.max_cases > MAX_UDS_FUZZ_CASES:
            raise ValueError(f"max_cases must not exceed {MAX_UDS_FUZZ_CASES}")


@dataclass(frozen=True)
class UDSFuzzCase:
    """One deterministic UDS fuzz input, without security interpretation."""

    case_id: str
    service_id: int
    payload: bytes
    mutation_type: MutationType

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id:
            raise ValueError("case_id must be a non-empty string")
        if isinstance(self.service_id, bool) or not isinstance(self.service_id, int):
            raise TypeError("service_id must be an integer")
        if not 0x00 <= self.service_id <= 0xFF:
            raise ValueError("service_id must fit in one byte")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")
        if not isinstance(self.mutation_type, MutationType):
            raise TypeError("mutation_type must be a MutationType")


@dataclass(frozen=True)
class UDSFuzzEvidence:
    """Immutable observation from one executed deterministic fuzz case."""

    case_id: str
    target_ecu_identifier: int
    request_service_id: int
    request_payload: bytes
    response_positive: bool
    response_payload: bytes
    analysis_type: str
    mutation_type: MutationType

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id:
            raise ValueError("case_id must be a non-empty string")
        if not isinstance(self.analysis_type, str):
            raise TypeError("analysis_type must be a string")
        if not self.analysis_type:
            raise ValueError("analysis_type must be a non-empty string")
        if not isinstance(self.mutation_type, MutationType):
            raise TypeError("mutation_type must be a MutationType")


def generate_uds_fuzz_cases(config: UDSFuzzConfig) -> list[UDSFuzzCase]:
    """Generate a small fixed ordered set of malformed and boundary inputs."""
    did = config.data_identifier.to_bytes(2, byteorder="big")
    candidates = (
        UDSFuzzCase(
            "rdbi-empty",
            config.service_id,
            b"",
            MutationType.EMPTY_PAYLOAD,
        ),
        UDSFuzzCase(
            "rdbi-truncated-did",
            config.service_id,
            did[:1],
            MutationType.TRUNCATED_DID,
        ),
        UDSFuzzCase(
            "rdbi-valid-did",
            config.service_id,
            did,
            MutationType.VALID_DID,
        ),
        UDSFuzzCase(
            "rdbi-extra-byte",
            config.service_id,
            did + b"\x00",
            MutationType.EXTRA_BYTE,
        ),
        UDSFuzzCase(
            "rdbi-eight-byte",
            config.service_id,
            did + b"\x00" * 6,
            MutationType.MAX_CLASSIC_CAN_PAYLOAD,
        ),
    )
    return list(candidates[: config.max_cases])


class UDSFuzzer:
    """Execute bounded deterministic UDS cases against one in-memory ECU."""

    def __init__(self, simulator: SimulatedECU, config: UDSFuzzConfig) -> None:
        self.simulator = simulator
        self.config = config

    def run(self) -> list[UDSFuzzEvidence]:
        evidence: list[UDSFuzzEvidence] = []
        for case in generate_uds_fuzz_cases(self.config):
            request = UDSRequest(
                target_ecu_identifier=self.simulator.ecu.identifier,
                service_id=case.service_id,
                payload=case.payload,
            )
            response = self.simulator.handle_request(request)
            evidence.append(
                UDSFuzzEvidence(
                    case_id=case.case_id,
                    target_ecu_identifier=request.target_ecu_identifier,
                    request_service_id=request.service_id,
                    request_payload=request.payload,
                    response_positive=response.positive,
                    response_payload=response.payload,
                    analysis_type="deterministic-uds-fuzz-case",
                    mutation_type=case.mutation_type,
                )
            )
        return evidence