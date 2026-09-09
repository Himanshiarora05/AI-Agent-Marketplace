---
name: audit-orchestrator
description: The entrypoint skill for the Brand AI-Readiness Audit marketplace. Orchestrates crawling, trust corroboration, and engagement analysis skills, compiling them into a single report.
license: MIT
compatibility: Requires Python 3.9+ with standard library. Optional Playwright is used for rendered checks when explicitly enabled.
allowed-tools: Python standard library subprocess, filesystem read/write in the sandbox, and the packaged sub-skill scripts only.
---

# Brand AI-Readiness Audit Orchestrator (Entrypoint)

## When to use
Use this skill as the main entrypoint to perform a complete Brand AI-Readiness Audit on a website. It automatically runs technical, trust, and engagement sub-audits, and outputs a single, validated JSON report conforming to the required schema.

For deterministic local execution, the packaged `scripts/run_audit.py` performs the same sequence and automatically feeds the technical crawler's bounded representative URLs into the trust and engagement skills. It is optional convenience tooling; the marketplace entrypoint remains this skill.

## Inputs
* `site_url` (string): The full absolute URL or domain of the website to audit (e.g. `https://example.com` or `example.com`).

## Procedure
1. Parse the input `site_url` to get the clean site domain (e.g., `example.com`).
2. Run the **Crawl & Render Audit** skill:
   * Execute `crawl-render-audit` with `site_url` as input.
   * Save the findings output list to `tech_findings.json`.
4. Run the **Freshness & Corroboration Audit** skill:
   * Execute `freshness-corroboration` with `site_url` and the technical audit JSON. Evaluate freshness and transparency per representative page; run external entity corroboration once on the primary page to avoid duplicate external queries.
   * Save the findings output list to `trust_findings.json`.
5. Run the **On-Site Engagement Audit** skill:
   * Execute `engagement-audit` with `site_url` and the technical audit JSON so its bounded `crawled_urls` become representative engagement/deep-link targets. Audit each selected page independently and preserve affected URLs.
   * Save the findings output list to `engagement_findings.json`.
6. Run the packaged report composer [compose_report.py](scripts/compose_report.py) to compile all findings, assign standardized sequential IDs (`F-XXX`), calculate severity summaries, and inject proactive suggestions where no critical/high defects are found:
   ```bash
   python skills/audit-orchestrator/scripts/compose_report.py \
     --site "<domain>" \
     --technical tech_findings.json \
     --trust trust_findings.json \
     --engagement engagement_findings.json \
     --output final_audit_report.json
   ```
6. **Perform Final LLM Synthesis & Review**:
   * Read `final_audit_report.json`.
   * Assess the overall status of the brand.
   * Verify that any proactive suggestions injected by the composer have `"proactive": true` and are relevant to the site.
7. Emit the final `final_audit_report.json` as the final skill execution output.

## Output
A single consolidated JSON audit report matching the schema below:
```json
{
  "site": "example.com",
  "audited_at": "2026-09-20T14:32:00Z",
  "scope": {
    "pages_checked": 6,
    "robots_checked": true,
    "sitemap_checked": true,
    "render_check": true,
    "external_sources_checked": 2
  },
  "summary": {
    "total_findings": 6,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "proactive_suggestions_count": 1
  },
  "findings": [
    {
      "id": "F-001",
      "title": "No JSON-LD structured data on product pages",
      "category": "technical",
      "severity": "high",
      "confidence": "high",
      "affected_pages": [
        "https://example.com/products"
      ],
      "evidence": "Crawled 6 pages; 0/6 contain schema.org markup.",
      "suggested_action": {
        "summary": "Add Product/Offer JSON-LD to every product page.",
        "priority": "high",
        "how_to_fix": "Embed Schema.org Product markup inside a <script type='application/ld+json'> block with name, description, and offers."
      }
    }
  ]
}
```
All required fields per finding (`id`, `title`, `category`, `severity`, `confidence`, `affected_pages`, `evidence`, `suggested_action` with `summary`, `priority`, `how_to_fix`) and summary metadata (`site`, `audited_at`, `scope`, counts-by-severity summary) must be present.

## References
* [Crawl & Render Audit Skills](../crawl-render-audit/SKILL.md) & [Discoverability Checklist](../crawl-render-audit/references/discoverability_checklist.md)
* [Freshness & Corroboration Skills](../freshness-corroboration/SKILL.md) & [Corroboration Guide](../freshness-corroboration/references/freshness_corroboration_guide.md)
* [On-Site Engagement Skills](../engagement-audit/SKILL.md) & [Engagement Principles](../engagement-audit/references/engagement_principles.md)
