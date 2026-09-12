from dataclasses import dataclass, field


@dataclass
class AgentState:
    objective: str
    target: str
    actions_taken: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
