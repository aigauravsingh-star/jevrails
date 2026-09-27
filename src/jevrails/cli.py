from __future__ import annotations

import argparse
import json
import sys

from .backends import JevBackend, NullDecisionBackend
from .eval import JsonlCase, evaluate_cases
from .guard import Guard
from .policy import CheckConfig, Policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jevrails")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan text with local and semantic guardrails.",
    )
    scan_parser.add_argument("path", nargs="?", help="File to scan. Reads stdin when omitted.")
    scan_parser.add_argument(
        "--jev",
        action="store_true",
        help="Use JevBackend.from_env() instead of local-only mode.",
    )
    scan_parser.add_argument(
        "--check",
        action="append",
        help="Enable only this check. May be repeated.",
    )
    scan_parser.add_argument(
        "--threshold",
        type=float,
        help="Override threshold for selected checks.",
    )
    scan_parser.add_argument(
        "--fail-open",
        action="store_true",
        help="Allow traffic if the decision backend fails.",
    )
    scan_parser.add_argument(
        "--max-approx-tokens",
        type=int,
        help="Enable approximate token limit check.",
    )
    scan_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")

    eval_parser = subparsers.add_parser("eval", help="Evaluate one check against a JSONL file.")
    eval_parser.add_argument("path", help="JSONL file with text and boolean label fields.")
    eval_parser.add_argument(
        "--check",
        required=True,
        help="Check id to evaluate, such as prompt_injection.",
    )
    eval_parser.add_argument("--text-field", default="text", help="JSONL text field name.")
    eval_parser.add_argument(
        "--label-field",
        default="label",
        help="JSONL boolean label field name.",
    )
    eval_parser.add_argument(
        "--threshold",
        type=float,
        help="Override threshold for the selected check.",
    )
    eval_parser.add_argument(
        "--jev",
        action="store_true",
        help="Use JevBackend.from_env() instead of local-only mode.",
    )
    eval_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")

    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "eval":
            return _eval(args)
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"jevrails: {exc}", file=sys.stderr)
        return 1
    return 1


def _scan(args: argparse.Namespace) -> int:
    text = _read_text(args.path)
    policy = (
        Policy.default()
        .with_fail_closed(not args.fail_open)
        .with_max_approx_tokens(args.max_approx_tokens)
    )

    if args.check:
        policy = policy.only(set(args.check))

    if args.threshold is not None:
        policy = _with_threshold(policy, args.threshold)

    backend = JevBackend.from_env() if args.jev else NullDecisionBackend()
    result = Guard(policy=policy, backend=backend).scan(text)
    indent = 2 if args.pretty else None
    print(json.dumps(result.to_dict(), indent=indent, sort_keys=True))
    return 0 if result.allowed else 2


def _eval(args: argparse.Namespace) -> int:
    policy = Policy.default().only({args.check})
    if args.threshold is not None:
        policy = _with_threshold(policy, args.threshold)
    backend = JevBackend.from_env() if args.jev else NullDecisionBackend()
    guard = Guard(policy=policy, backend=backend)

    cases: list[JsonlCase] = []
    with open(args.path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            cases.append(
                JsonlCase(
                    id=str(row.get("id", line_number)),
                    text=str(row[args.text_field]),
                    label=_parse_label(row[args.label_field], line_number=line_number),
                )
            )

    report = evaluate_cases(cases, guard, check_id=args.check)
    indent = 2 if args.pretty else None
    print(json.dumps(report.to_dict(), indent=indent, sort_keys=True))
    return 0


def _read_text(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    return sys.stdin.read()


def _parse_label(value: object, *, line_number: int) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "t", "yes", "y", "1", "positive"}:
            return True
        if normalized in {"false", "f", "no", "n", "0", "negative"}:
            return False
    raise ValueError(f"Line {line_number}: label must be a boolean, 0/1, or true/false string.")


def _with_threshold(policy: Policy, threshold: float) -> Policy:
    checks = {
        check_id: CheckConfig(
            enabled=config.enabled,
            threshold=threshold,
            action=config.action,
            severity=config.severity,
            shadow=config.shadow,
            params=config.params,
        )
        for check_id, config in policy.checks.items()
    }
    return Policy(
        checks=checks,
        fail_closed=policy.fail_closed,
        redact_replacement=policy.redact_replacement,
        max_approx_tokens=policy.max_approx_tokens,
    )


if __name__ == "__main__":
    raise SystemExit(main())
