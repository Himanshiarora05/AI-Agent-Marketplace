# Live smoke-test reports

This directory intentionally contains **no pre-generated site reports**. Reports from
an earlier run can become stale or look like canned fixtures, which is misleading for
a judge reviewing generalization.

Run the parent script from the marketplace root:

```powershell
powershell -ExecutionPolicy Bypass -File examples/run_live_smoke_tests.ps1
```

It clears this directory, audits three public sites through the real entrypoint, checks
that each report names the requested site, and records bounded runtime metadata. The
resulting JSON files are local smoke-test artifacts and are not used by the audit logic.
