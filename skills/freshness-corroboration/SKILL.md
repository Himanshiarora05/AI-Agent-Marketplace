---
name: freshness-corroboration
description: Audits a brand's freshness of content, E-E-A-T credentials, verifies consistency (agreement) of core facts across Wikipedia/Wikidata, and checks for naming collisions, and exposes an explainable entity-confidence signal.
license: MIT
allowed-tools: Python standard library filesystem/network read-only fetches; optional Playwright only for rendered checks.
compatibility: Requires Python 3.9+ with standard library and outbound network access for public Wikipedia and Wikidata APIs.
---

# Freshness & Corroboration Audit Skill

## When to use
Use this skill to identify issues related to stale content (such as outdated copyright footers or old publication dates), missing E-E-A-T author credentials, and discrepancies between site claims and external web sources. This also detects entity ambiguity (mistaken identity where multiple companies share the same name) which prevents AI models from trusting the brand's facts.

## Inputs
* `url` (string): The full absolute URL of the website to audit.
* `technical` (optional path): Technical audit JSON whose bounded `crawl_scope.crawled_urls` are used for per-page freshness/transparency checks.

## Procedure

The standalone entrypoint first checks robots.txt before fetching the target page. sameAs targets are sanity-checked before being accepted as entity anchors.
1. If a technical audit JSON is available, use its bounded representative URLs; evaluate freshness and transparency on each selected page. External corroboration is run only on the primary page to keep the audit bounded and avoid duplicate external queries.
2. Locate the packaged script [check_trust.py](scripts/check_trust.py).
3. Execute the script with the input URL:
   ```bash
   python skills/freshness-corroboration/scripts/check_trust.py <url> --output trust_findings.json
   ```
4. Read the generated `trust_findings.json` to inspect:
   * `brand_name`: Stated name of the brand.
   * `copyright`: Status and latest year found.
   * `year_mentions`: Frequency of year references (to see if the site content is active or stale).
   * `eeat_check`: Analysis of author links, publication dates, and corporate contact details.
   * `corroboration_check`: Comparison of page location elements against Wikidata API and Wikipedia Search API abstracts.
   * `ambiguity_check`: Name collisions and sameAs metadata warnings.
   * `entity_confidence`: Explainable confidence from domain/name alignment, authoritative sameAs, external matches, and contradictions.
5. **Compile findings**:
   * If copyright is stale or no copyright is found, create a finding for **Stale Copyright** (severity: `medium`).
   * If there are no mentions of the current/recent years, create a finding for **Stale Activity Signals** (severity: `medium`).
   * If E-E-A-T/contact details are missing, create a finding for **Missing E-E-A-T or Contact Transparency** (severity: `medium`).
   * If there is an external location discrepancy, create a finding for **Low Web Agreement / Fact Contradiction** (severity: `high`).
   * If the name is highly ambiguous and lacks `sameAs` metadata, create a finding for **Entity Ambiguity / Mistaken Identity Risk** (severity: `high`).
   * For each finding, provide the exact `evidence` found (citing the external source Checked e.g. Wikipedia Search API, Wikidata Entities Search, and its URL) and define a clear, mechanism-sound `suggested_action`.

## Output
An array of findings following the required schema. If no issues are found, return an empty list.

## References
* [Freshness & Corroboration Guide](references/freshness_corroboration_guide.md): In-depth guide on E-E-A-T signals, entity disambiguation, and Wikipedia/Wikidata cross-verification.


## Entity-confidence guardrails

Entity confidence is diagnostic, not a third-party verification claim. Absence of Wikipedia/Wikidata records is not itself a defect. Suspicious or unrelated `sameAs` links lower confidence rather than being treated as authoritative evidence.
