import argparse

from autosec_ai.agents.action import AgentAction
from autosec_ai.agents.bounded_investigation import (
    InvestigationRunResult,
    InvestigationTerminationReason,
)
from autosec_ai.agents.investigation import InvestigationState, InvestigationStep
from autosec_ai.reporting.investigation import (
    build_investigation_report,
    format_investigation_report,
    format_investigation_report_json,
)


def _build_demo_result() -> InvestigationRunResult:
    state = InvestigationState(
        objective="Present a controlled investigation record",
        target="simulated-ecu",
        steps=(
            InvestigationStep(
                step_number=1,
                proposed_action=AgentAction(
                    tool_name="simulated_observation",
                    target="simulated-ecu",
                    parameters={"mode": "demonstration"},
                ),
                validation_status="UNAUTHORIZED_TOOL",
                validation_allowed=False,
            ),
        ),
    )
    return InvestigationRunResult(
        state=state,
        termination_reason=InvestigationTerminationReason.ACTION_REJECTED,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autosec-ai",
        description="Present AutoSec-AI investigation records.",
    )
    subparsers = parser.add_subparsers(dest="command")
    demo = subparsers.add_parser(
        "report-demo",
        help="present a simulated / controlled demonstration report",
    )
    demo.add_argument(
        "--json",
        action="store_true",
        help="emit deterministic JSON instead of terminal text",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "report-demo":
        report = build_investigation_report(_build_demo_result())
        if args.json:
            print(format_investigation_report_json(report))
        else:
            print("SIMULATED / CONTROLLED DEMONSTRATION")
            print(format_investigation_report(report))
        return 0
    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())