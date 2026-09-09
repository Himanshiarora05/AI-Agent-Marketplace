# Adobe University Hackathon 2026 — Round 3 Rubric Mapping

This file provides traceability from the supplied Round 3 brief to the marketplace implementation. It does **not** claim that Adobe defines 34 rubric criteria. The supplied brief defines six evaluation criteria: Detection accuracy, Suggested-action quality, Output design, Skill-format & engineering hygiene, Marketplace composition, and Generalization.

| Adobe evaluation criterion | Where implemented | Verification evidence |
|---|---|---|
| Detection accuracy | `skills/crawl-render-audit`, `skills/freshness-corroboration`, `skills/engagement-audit` | `tests/test_all_rubric_cases.py` technical/trust/engagement cases; `tests/test_round3_polish.py` parity, redirects, page selection, entity confidence and deep-link cases |
| Suggested-action quality | `skills/*/SKILL.md`, `skills/audit-orchestrator/scripts/compose_report.py` | Report tests verify `suggested_action`, `priority`, `how_to_fix`; proactive recommendations are separately tagged |
| Output design | `skills/audit-orchestrator/scripts/compose_report.py` | `test_schema_conformity_and_scope`, `test_required_report_fields_are_preserved`, `test_composer_priority_actions_and_total_items` |
| Skill-format & engineering hygiene | `marketplace.json`, four skill folders, standard-library core, bounded/read-only scripts | `test_marketplace_has_exactly_one_entrypoint`, `test_skill_frontmatter_names_match_ids`; verifier checks manifest/schema; LF-normalized Python sources |
| Marketplace composition | `skills/audit-orchestrator` entrypoint composes technical → trust → engagement → final report | `run_audit.py` enforces the sequence and shares technical page scope with downstream skills; verifier runs the end-to-end pipeline |
| Generalization | Semantic crawl candidate selection, page-type awareness, formatting-aware fact parity, graceful failures, multi-page analysis | 48 core/hardening checks plus 20 Round 3 polish tests; no example site is hard-coded into the audit logic |

## Test traceability

`tests/test_all_rubric_cases.py` contains 48 focused checks: the first 28 are grouped under the project's internal `Rubric X.Y` labels, followed by hardening and polish regression cases. `tests/test_round3_polish.py` adds 20 further Round 3 generalization/polish checks. These are **test cases, not Adobe-defined rubric items**. Each test's docstring identifies the behavior it verifies, so a reviewer can search directly from the test to the implementation.

## Submission-level safety

The marketplace is recommend-only: it audits and reports, does not authenticate into sites, does not mutate live websites, uses bounded requests, and respects `robots.txt`. The Round 3 brief explicitly requires this operating model and a ZIP no larger than 50 MB.
