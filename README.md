# Brand AI-Readiness Audit - Agent Skill Marketplace

This Agent Skill Marketplace is a modular package containing four specialized agent skills designed to audit unseen websites for AI discoverability, factual trust, answerability, and on-site user engagement. The v1.4 pipeline adds bounded multi-page crawling, redirect/indexability/canonical analysis, page-type-aware structured-data quality, visible↔JSON-LD fact parity, rendered mobile geometry, semantic CTA classification, AI answerability and quote-readiness, deep-link context retention, entity-confidence signals, potential orphan detection, prioritized actions, and adversarial regression coverage.

The package follows the `agentskills.io` skill structure and is designed around the Adobe Hackathon Round 3 rubric, with bounded, read-only checks for unseen websites. The readiness index is an internal diagnostic only and is not an Adobe score.

---

## Directory Layout

```text
brand-ai-readiness-audit/
├── marketplace.json
├── README.md
├── RUBRIC_MAPPING.md
├── verify_marketplace.py
├── tests/
│   ├── test_all_rubric_cases.py
│   └── test_round3_polish.py
└── skills/
    ├── audit-orchestrator/
    │   ├── SKILL.md
    │   └── scripts/
    │       ├── compose_report.py
    │       └── run_audit.py
    ├── crawl-render-audit/
    │   ├── SKILL.md
    │   ├── references/
    │   │   └── discoverability_checklist.md
    │   └── scripts/
    │       └── check_technical.py
    ├── freshness-corroboration/
    │   ├── SKILL.md
    │   ├── references/
    │   │   └── freshness_corroboration_guide.md
    │   └── scripts/
    │       └── check_trust.py
    └── engagement-audit/
        ├── SKILL.md
        ├── references/
        │   └── engagement_principles.md
        └── scripts/
            └── check_engagement.py
```

---

## Skills Overview

### 1. Audit Orchestrator (`skills/audit-orchestrator`) [ENTRYPOINT]
* **Role**: Composes and coordinates the overall audit workflow.
* **Function**: 
  1. Runs the bounded technical crawl first and uses its representative URLs as the shared audit scope.
  2. Runs freshness/trust and engagement checks against those same representative deep links, preventing homepage-only blind spots.
  3. Runs `compose_report.py` to merge all findings into a standardized JSON report conforming to the required schema.
  4. **Rich Metadata & Scope**: Captures execution scope (`pages_checked`, `robots_checked`, `sitemap_checked`, `render_check`, `external_sources_checked`), finding categories, confidence ratings, affected page lists, and actionable `how_to_fix` instructions.
  5. **Proactive Improvements**: Adds category-level recommendations only when no critical/high defect is present. Proactive items are explicitly tagged and excluded from defect counts.
  6. Emits the final JSON report.

### 2. Crawl & Render Audit (`skills/crawl-render-audit`)
* **Role**: Technical crawlability, robots compliance, and AI discoverability auditor.
* **Function**:
  1. **Strict Robots.txt Compliance**: Uses `urllib.robotparser.RobotFileParser` to verify permission before fetching any URL. Disallowed targets abort fetching immediately to prevent policy violations. Scans for AI-specific crawler restrictions (`GPTBot`, `ClaudeBot`, `Google-Extended`, etc.).
  2. **XML Sitemap Parser & Index Follower**: Parses `sitemap.xml` and sitemap index files recursively via `xml.etree.ElementTree`, extracting URLs and `<lastmod>` timestamps.
  3. **Bounded Mini-Crawler**: Intelligently samples representative internal pages using URL, title/anchor semantics, schema hints, sitemap priority when available, same-domain rules, and a strict page budget.
  4. **Deep Schema.org Analysis**: Recursively extracts `@graph`, arrays, and nested schemas; validates property completeness (`Organization`, `Product`, `Article`, `FAQPage`, `BreadcrumbList`); identifies malformed vs. incomplete vs. valid schemas.
  5. **WCAG-Compliant Image Audit**: Distinguishes decorative images (`alt=""`, `role="presentation"`, spacer/icon files) from informative images, eliminating false positives on empty alt attributes.
  6. **Multi-Page Render Gap**: Renders the homepage plus up to three representative crawled pages and compares raw HTML facts with rendered DOM facts.
  7. **Indexability & Canonical Audit**: Checks meta/X-Robots noindex and canonical consistency, while recognizing that a missing canonical alone is not automatically a defect. Long/cross-host redirect chains are separately surfaced.
  8. **Visible ↔ Structured Fact Parity**: Detects conflicting prices, phones, emails, and other high-value machine facts between visible content and JSON-LD with formatting-aware normalization.
  9. **Mobile Geometry**: Uses a 390×844 viewport when Playwright is available to detect horizontal overflow and below-fold H1/CTA placement.
  10. **Mobile Viewport & Canvas Fallbacks**: Verifies responsive `<meta name="viewport">` tags and checks for machine-readable canvas fallbacks. Also records sampled internal-link graph/orphan signals.
* **Reference Guide**: [discoverability_checklist.md](skills/crawl-render-audit/references/discoverability_checklist.md)

### 3. Freshness & Corroboration (`skills/freshness-corroboration`)
* **Role**: Freshness, E-E-A-T credentials, and external web agreement auditor.
* **Function**:
  1. **Multi-Signal Freshness Model**: Synthesizes XML sitemap `<lastmod>`, Schema.org `dateModified`/`datePublished`, HTML `<meta>` timestamps, and in-page update notices alongside copyright footers. Avoids false positives on actively maintained sites that have not bumped copyright years.
  2. **Authoritative `sameAs` Entity Disambiguation**: Extracts verified external entity links from JSON-LD (Wikidata, Wikipedia, LinkedIn, Crunchbase) while strictly ignoring internal `@id` URIs. Flags entity ambiguity risks when naming collisions occur without disambiguation links.
  3. **Cross-Source Web Corroboration**: Queries the **Wikidata Entities Search API** and **Wikipedia Search API** to cross-verify headquarters locations, brand identity, and when available founding-year claims.
  4. **sameAs Sanity Validation**: Separates plausible knowledge/profile entity links from unsupported or suspicious sameAs targets before using them as disambiguation evidence. Accurately isolates regional codes (e.g. Canada as `CAN` vs California as `CA`) to prevent false contradictions.
  5. **Small Business Generalization Guard**: Recognizes that absence of Wikipedia/Wikidata entries is normal and expected for growing or niche brands, marking such cases as clean passes rather than defects.
  6. **E-E-A-T and Contact Transparency**: Audits author bylines, contact page links, corporate email, phone, and physical address disclosures.
* **Reference Guide**: [freshness_corroboration_guide.md](skills/freshness-corroboration/references/freshness_corroboration_guide.md)

### 4. Engagement Audit (`skills/engagement-audit`)
* **Role**: On-site user retention, readability, and navigation structure auditor.
* **Function**:
  1. **Heading Hierarchy & Value Hook**: Evaluates single `H1` placement and descriptive value propositions. Rendered geometry is used when Playwright is available.
  2. **Readability & Walls of Text**: Identifies unformatted paragraphs exceeding 100 words and detects excessive buzzwords or jargon.
  3. **Deep-Link Breadcrumb Auditing**: Verifies breadcrumb navigation structures (`nav[aria-label="breadcrumb"]`, `BreadcrumbList` schema) for visitors arriving via AI citations.
  4. **Intent-Classified CTAs**: Separates navigation links from conversion CTAs, then classifies purchase, demo, lead-generation, onboarding, pricing, download, learning, and navigation intents.
  5. **AI Answerability & Quote Readiness**: Scores identity, offer, audience, contact, and next-step clarity and separately estimates whether concise question→answer or definition content is easy to quote.
  6. **Deep-Link Context Retention**: Scores whether a visitor arriving directly on the page can retain brand context and continue through navigation, internal paths, breadcrumbs, and a meaningful CTA.
  7. **Dead-End Risk Detection**: Flags pages lacking primary header navigation, footers, or CTAs that strand users in dead ends.
  8. **Lightweight Performance & Clutter**: Calculates text-to-HTML ratios and monitors external script and stylesheet dependency bloat.
* **Reference Guide**: [engagement_principles.md](skills/engagement-audit/references/engagement_principles.md)

---

## How to Run an Audit

To perform a complete Brand AI-Readiness Audit against any live website:

```bash
# Recommended: deterministic end-to-end runner.
# It crawls first, shares the representative page set with trust + engagement,
# then emits one final report.
python skills/audit-orchestrator/scripts/run_audit.py https://example.com --max-pages 6 --output final_audit_report.json

# Optional: run the three skills individually when debugging.
python skills/crawl-render-audit/scripts/check_technical.py https://example.com --max-pages 6 --output tech.json
python skills/freshness-corroboration/scripts/check_trust.py https://example.com --technical tech.json --max-pages 6 --output trust.json
python skills/engagement-audit/scripts/check_engagement.py https://example.com --technical tech.json --max-pages 6 --output engage.json
python skills/audit-orchestrator/scripts/compose_report.py \
  --site "example.com" --technical tech.json --trust trust.json --engagement engage.json --output report.json
```

---

## Real-Website Smoke Testing

The marketplace is intended to run against unseen live websites, not only the offline fixtures used by the unit tests. Before submission, run the entrypoint against 2–3 real public URLs and inspect the generated JSON reports. A ready-to-use PowerShell smoke-test script is provided at `examples/run_live_smoke_tests.ps1`.

```powershell
# From the marketplace root
powershell -ExecutionPolicy Bypass -File examples/run_live_smoke_tests.ps1
```

The script clears stale JSON first, then writes fresh reports into `examples/reports/`. It also enforces a 60-second per-stage timeout and a 240-second whole-pipeline deadline. Network failures are recorded as `unavailable` rather than being misreported as anti-bot blocks. No pre-generated reports are shipped, because stale/canned site outputs are poor evidence of generalization.

## Runtime Bound

The entrypoint is deliberately bounded for the Round 3 `<5 minute` runtime guardrail.
`run_audit.py` enforces a hard 60-second timeout per audit stage and a hard 240-second
wall-clock deadline for the complete pipeline. The final report records
`runtime_seconds`, `runtime_limit_seconds`, `stage_timeout_seconds`, and any timed-out
categories under `execution`. A timeout or failed stage is marked as partial rather
than being presented as a clean audit.

The runtime cap is a safety bound, not a claim that every network target will finish
successfully. Actual runtime depends on network/server behavior; the included live
smoke-test script measures it on the machine where the submission is run.

## Verification and Automated Testing

The marketplace contains a dual-layer verification system directly runnable from the root:

```bash
# Runs the offline end-to-end audit server test AND the rubric/hardening suite plus the Round 3 polish/generalization suite
python verify_marketplace.py
```

### What `verify_marketplace.py` Tests:
1. **End-to-End Pipeline Execution**: Spins up an offline mock server serving test fixtures, executes all three sub-audits, runs the composer, and validates schema compliance.
2. **Signal Detection**: Verifies detection of AI crawler blocks, missing viewport tags, FAQ parity gaps, stale dates, E-E-A-T omissions, location contradictions, and navigation dead ends.
3. **Proactive Suggestions**: Confirms that clean runs generate appropriate proactive improvement suggestions.
4. **Core challenge-check suite (`tests/test_all_rubric_cases.py`)**: Executes 48 focused unit/regression checks across technical discoverability, trust/freshness, engagement, report composition, and hardening cases. The 34 historical core checks are not described as 34 Adobe rubric criteria; Adobe's supplied brief defines six evaluation criteria. (robots specificity, sitemap index recursion, malformed recoverable XML, WCAG decorative alt, multi-signal freshness weighting, Canada vs California disambiguation, page-type aware E-E-A-T, intent CTAs, breadcrumbs, and schema conformity).
5. **Round 3 Polish & Generalization Suite (`tests/test_round3_polish.py`)**: Executes 20 additional tests covering quote-readiness, deep-link scoring, semantic page selection, multi-page engagement isolation, schema/page mismatch, redirect-chain handling, formatting-aware fact parity, entity-confidence scoring, separate quote-readiness reporting, report priority actions, manifest integrity, and the internal diagnostic-score wording.

---

## Rubric Traceability

See `RUBRIC_MAPPING.md` for an auditable requirement-to-implementation-and-test map derived from the supplied Round 3 brief. It maps the brief's six evaluation criteria to concrete skills, scripts, and regression tests rather than relying on an unsupported “34/34 rubric criteria” claim.

## Portability & Engineering Hygiene

* **Core dependencies**: All core auditing scripts rely strictly on the Python 3 standard library. Playwright is an optional rendering enhancement. Install it only when you want verified rendered-vs-raw and mobile geometry checks: `pip install playwright` followed by `python -m playwright install chromium`. The marketplace does not bundle a virtual environment or `site-packages`.
* **Safety & Non-Invasiveness**: Read-only auditing. Strictly respects `robots.txt` disallow rules, enforces bounded crawl budgets, and applies generous 10-second network timeouts.
* **Package Hygiene**: Strictly conforms to the `<50MB` package limit, with clean Unix-style forward slashes and no `__pycache__` or operating system artifacts.
