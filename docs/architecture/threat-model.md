# AutoSec-AI Prototype Threat Model

## 1. Scope

This threat model covers the frozen AutoSec-AI engineering prototype: LLM-generated investigation proposals, deterministic policy validation, registered security tools, external analyzer execution, normalized evidence, AI finding assessment, bounded investigation history, and terminal/JSON reporting.

It covers local controlled execution. There is no network-facing service, real vehicle interface, production deployment boundary, or persistent multi-user system in scope.

## 2. Protected Assets

- execution authority
- approved investigation targets
- approved tool parameters
- trusted Semgrep rule-pack mapping
- deterministic security evidence
- investigation history and feedback integrity
- policy configuration
- report presentation integrity

## 3. Trust Boundaries

### LLM to `AgentAction`

The LLM produces untrusted text. `AgentPlanner` parses it into a proposal but does not authorize it.

### Tool output to `FindingContext`

A registered result processor receives `ToolResult` data and creates normalized context. The processor is trusted application code; tool output remains analysis data rather than instructions.

### `FindingContext` to LLM assessor

Finding and evidence fields are serialized as structured untrusted input. Text inside evidence cannot change assessment rules, authorize tools, or create actions.

### Historical feedback to planner

Prior tool results, findings, assessments, and validation outcomes are included as untrusted feedback. A later proposal must cross `ActionValidator` again.

### CLI/application to configured trusted components

The application composition chooses the registered tool, target, processor, policy, and trusted rule-pack mapping. The CLI presents results and is not the source of authorization decisions.

## 4. Threat Actors and Untrusted Inputs

The prototype does not expose an internet-facing service. Relevant threats are hostile or malformed inputs crossing local trust boundaries:

- malformed or hostile LLM output
- prompt injection inside finding or evidence text
- hostile historical assessment text
- unauthorized tool proposals
- unauthorized targets
- unauthorized parameters
- excessive numeric or resource parameters
- arbitrary Semgrep configuration attempts
- malicious terminal/control characters in report content

## 5. Security Controls

| Threat | Implemented control |
|---|---|
| LLM proposes an unauthorized tool | `ActionValidator` checks registration and `SecurityPolicy.allowed_tools`. |
| LLM proposes an unauthorized target | `SecurityPolicy.allowed_targets` is checked before execution. |
| LLM supplies an unexpected parameter | Validator rejects parameter names not present in the configured allow-list. |
| LLM supplies an unauthorized parameter value | Validator checks exact allowed values. |
| LLM supplies an excessive numeric value | Validator applies configured numeric upper limits. |
| LLM attempts arbitrary Semgrep configuration | The source demo exposes only the logical `automotive` rule-pack name, resolved through `RulePackRegistry`; no arbitrary path or CLI arguments are accepted. |
| Shell injection through external analysis | `ExternalToolRunner` passes an executable and argument list to `subprocess.run`; production code does not use `shell=True`. |
| Prompt injection in evidence | `format_finding_context()` uses structured JSON and explicitly labels finding/evidence as untrusted data. |
| Hostile historical assessment authorizes a later action | Feedback states that assessments cannot authorize tools; every later proposal is independently validated. |
| Unbounded autonomous loop | `InvestigationRunConfig` limits runs to a maximum of 10 steps. |
| Non-success tool status is ignored | The bounded runner terminates with `TOOL_ERROR` for every executed status other than `success`. |
| Rejected action reaches a tool | `InvestigationOrchestrator` records a rejected step and does not call the tool. |
| Terminal escape/control injection | Terminal reporting strips ANSI and other control sequences before display. |
| Assessment is mistaken for deterministic evidence | Reports and models keep `SecurityFinding`/`FindingContext` separate from `FindingAssessment`. |

## 6. Residual Risks and Limitations

- There is no production sandbox around external tools.
- `SecurityPolicy` is mutable after construction if another component retains its reference.
- The application composition and trusted rule-pack mapping are assumed to be trusted.
- External scanner output is consumed as analyzer input and is not independently verified.
- Exceptions from tool execution, result processors, and assessors propagate rather than producing a normalized run result.
- The vehicle environment is simulated and cannot validate real ECU or network behavior.
- The default source demo uses deterministic mock LLM responses and does not test live provider behavior.
- Source analysis uses a narrow rule pack and the controlled processor keeps the first finding only.
- Binary analysis is imported-symbol inspection rather than full binary vulnerability analysis.
- There is no authentication, persistence, distributed execution, or production deployment control.

## 7. Security Invariants

- No proposed action executes before deterministic validation.
- LLM output never directly grants execution authority.
- Tool, target, and parameter authorization remain external to the LLM.
- AI assessment is not deterministic evidence of exploitability.
- Every autonomous iteration crosses validation independently.
- Autonomous execution is bounded.
- Trusted rule-pack filesystem paths come from application configuration, not the planner.
- Rejected actions do not execute tools.
- Historical evidence and assessments cannot modify policy.
- A non-success result from an executed tool terminates bounded execution with `TOOL_ERROR`.
