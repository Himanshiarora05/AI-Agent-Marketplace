#!/usr/bin/env python3
"""Deterministic, bounded read-only runner for the Brand AI-Readiness Audit marketplace.

Runs technical discovery first, then trust and engagement audits, and finally composes
one report. Every subprocess has a hard stage timeout and the whole pipeline has a
hard wall-clock deadline, so a slow/unresponsive site cannot make the audit run
indefinitely. Failed or timed-out stages are surfaced as partial execution in the
final report rather than being silently treated as clean.
"""
import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TECH = ROOT / "skills/crawl-render-audit/scripts/check_technical.py"
TRUST = ROOT / "skills/freshness-corroboration/scripts/check_trust.py"
ENG = ROOT / "skills/engagement-audit/scripts/check_engagement.py"
COMPOSE = ROOT / "skills/audit-orchestrator/scripts/compose_report.py"


def run(cmd, timeout):
    """Run a child process with a hard timeout."""
    try:
        return subprocess.run(
            [sys.executable, *map(str, cmd)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=max(1.0, timeout),
        ), None
    except subprocess.TimeoutExpired as exc:
        return None, f"timed out after {timeout:.1f}s"


def stage(stage_name, cmd, output_path, stage_timeout, deadline, errors, timed_out):
    """Run one audit stage without allowing it to exceed the global deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        message = "global runtime deadline reached before stage started"
        errors.append(f"{stage_name}: {message}")
        timed_out.append(stage_name)
        return False

    allowed = min(float(stage_timeout), remaining)
    result, timeout_error = run(cmd, allowed)
    if timeout_error:
        errors.append(f"{stage_name}: {timeout_error}")
        timed_out.append(stage_name)
        return False

    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        errors.append(f"{stage_name}: exited with code {result.returncode}" + (f": {detail[-1000:]}" if detail else ""))
        return False

    if not Path(output_path).exists():
        errors.append(f"{stage_name}: completed without producing {output_path}")
        return False

    return True


def main():
    p = argparse.ArgumentParser(description="Run the complete Brand AI-Readiness Audit")
    p.add_argument("site_url")
    p.add_argument("--max-pages", type=int, default=6)
    p.add_argument("--current-year", type=int, default=None)
    p.add_argument("--mock-data")
    p.add_argument("--render-engagement", action="store_true")
    p.add_argument("--output", default="final_audit_report.json")
    p.add_argument("--stage-timeout", type=float, default=60.0,
                   help="Hard timeout in seconds for each audit stage (default: 60).")
    p.add_argument("--runtime-limit", type=float, default=240.0,
                   help="Hard wall-clock limit for the whole pipeline in seconds (default: 240).")
    args = p.parse_args()

    site = args.site_url if args.site_url.startswith(("http://", "https://")) else "https://" + args.site_url
    max_pages = max(1, min(args.max_pages, 6))
    stage_timeout = max(5.0, min(args.stage_timeout, args.runtime_limit))
    runtime_limit = max(30.0, args.runtime_limit)
    started = time.monotonic()
    deadline = started + runtime_limit
    errors = []
    timed_out = []

    with tempfile.TemporaryDirectory(prefix="brand-audit-") as td:
        td = Path(td)
        tech = td / "technical.json"
        trust = td / "trust.json"
        eng = td / "engagement.json"

        tech_ok = stage(
            "technical",
            [TECH, site, "--max-pages", str(max_pages), "--output", tech],
            tech, stage_timeout, deadline, errors, timed_out,
        )

        trust_cmd = [TRUST, site, "--max-pages", str(max_pages), "--output", trust]
        if tech_ok:
            trust_cmd += ["--technical", tech]
        if args.current_year is not None:
            trust_cmd += ["--current-year", str(args.current_year)]
        if args.mock_data:
            trust_cmd += ["--mock-data", args.mock_data]
        stage("trust", trust_cmd, trust, stage_timeout, deadline, errors, timed_out)

        eng_cmd = [ENG, site, "--max-pages", str(max_pages), "--output", eng]
        if tech_ok:
            eng_cmd += ["--technical", tech]
        if args.render_engagement:
            eng_cmd.append("--render")
        stage("engagement", eng_cmd, eng, stage_timeout, deadline, errors, timed_out)

        out = Path(args.output)
        compose_cmd = [
            COMPOSE, "--site", site,
            "--technical", tech,
            "--trust", trust,
            "--engagement", eng,
            "--output", out,
        ]
        result, timeout_error = run(compose_cmd, max(1.0, deadline - time.monotonic()))
        if timeout_error:
            print(f"ERROR: compose: {timeout_error}", file=sys.stderr)
            return 2
        if result.returncode != 0:
            print(result.stdout + result.stderr, file=sys.stderr)
            return result.returncode

        # Add transparent runtime metadata after composition.
        elapsed = round(time.monotonic() - started, 3)
        try:
            report = json.loads(out.read_text(encoding="utf-8"))
            execution = report.setdefault("execution", {})
            existing_errors = execution.get("errors", [])
            execution["errors"] = existing_errors + errors
            existing_missing = execution.get("missing_categories", [])
            for name in ("technical", "trust", "engagement"):
                if name in timed_out or (name in ("technical", "trust", "engagement") and not (td / f"{name}.json").exists()):
                    if name not in existing_missing:
                        existing_missing.append(name)
            execution["missing_categories"] = existing_missing
            execution["partial"] = bool(execution["partial"] or errors or existing_missing)
            execution["runtime_seconds"] = elapsed
            execution["runtime_limit_seconds"] = runtime_limit
            execution["stage_timeout_seconds"] = stage_timeout
            execution["timed_out_categories"] = timed_out
            execution["runtime_status"] = "within_limit" if elapsed <= runtime_limit else "deadline_exceeded"
            execution["note"] = (
                "All requested sub-audits completed within the bounded runtime."
                if not execution["partial"]
                else "Execution was partial or a stage failed/timed out. Missing categories are not treated as clean passes or given proactive suggestions."
            )
            out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except Exception as exc:
            print(f"ERROR: could not annotate runtime metadata: {exc}", file=sys.stderr)
            return 2

        print(out)
        if errors:
            print("WARNING: " + " | ".join(errors), file=sys.stderr)
        print(f"Runtime: {elapsed:.3f}s / limit {runtime_limit:.1f}s", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
