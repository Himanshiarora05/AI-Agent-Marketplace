# Live Website Smoke Tests

The marketplace is intended to run against unseen live websites, not only offline fixtures.
Use `run_live_smoke_tests.ps1` before submission to exercise the real entrypoint against
three public URLs and generate fresh reports under `reports/`.

The script:
- deletes any stale JSON reports before each run;
- audits each site through `skills/audit-orchestrator/scripts/run_audit.py`;
- uses a bounded 3-page sample;
- enforces a 60-second per-stage timeout and 240-second whole-pipeline deadline;
- verifies that the generated report identifies the requested site and includes runtime metadata.

These are smoke tests, not fixtures used by the audit logic. If the local network/DNS
blocks outbound access, the audit may record fetches as `unavailable`; that state should
not be interpreted as a target-site defect. Do not commit or submit stale reports from
an offline environment as evidence of a successful live crawl.
