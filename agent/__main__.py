"""Command line entry point: ``python -m agent example.com --provider gemini``."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import AuditAgent
from .providers import PROVIDERS, ChatModel, ModelError


def print_event(event):
    kind = event["type"]
    if kind == "start":
        print(f"Auditing {event['site']}", file=sys.stderr)
    elif kind == "thought":
        print(f"  [{event['step']}] {event['text'][:200]}", file=sys.stderr)
    elif kind == "tool_call":
        print(f"  [{event['step']}] -> {event['tool']} {json.dumps(event['args'])[:160]}", file=sys.stderr)
    elif kind == "tool_result":
        status = "ok" if event["ok"] else "error"
        print(f"  [{event['step']}] <- {event['tool']} {status}", file=sys.stderr)
    elif kind == "done":
        print(f"Finished ({event['stop_reason']})", file=sys.stderr)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m agent", description="Run the LLM-driven Brand AI-Readiness Audit agent")
    p.add_argument("site_url")
    p.add_argument("--provider", choices=sorted(PROVIDERS), default="gemini")
    p.add_argument("--model", help="Override the provider's default free model")
    p.add_argument("--max-pages", type=int, default=3)
    p.add_argument("--max-steps", type=int, default=16)
    p.add_argument("--stage-timeout", type=float, default=60.0)
    p.add_argument("--output", default="agent_audit_report.json")
    p.add_argument("--quiet", action="store_true", help="Do not print agent progress")
    args = p.parse_args(argv)

    try:
        model = ChatModel(args.provider, model=args.model)
    except ModelError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    agent = AuditAgent(
        model,
        max_steps=args.max_steps,
        max_pages=args.max_pages,
        stage_timeout=args.stage_timeout,
        on_event=None if args.quiet else print_event,
    )
    try:
        report = agent.run(args.site_url)
    except ModelError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out = Path(args.output)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(out)
    print("\n" + report["agent"]["summary"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
