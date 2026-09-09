# Freshness & Corroboration Reference Guide

This reference document outlines the criteria for auditing a brand's freshness, consistency (agreement across the web), and entity disambiguation to build trust with AI assistants.

---

## 1. Multi-Signal Freshness & Activity Auditing

AI agents downrank or omit information if they suspect it is outdated, stale, or if the business is defunct. However, auditing freshness requires synthesizing **multiple independent signals** rather than penalizing a site solely for an unchanged copyright footer.

### Freshness Signals Evaluated
* **XML Sitemap Timestamps**:
  * Check `<lastmod>` timestamps in `sitemap.xml` for recent content additions or revisions.
* **Schema.org Structured Dates**:
  * Inspect `dateModified`, `datePublished`, and `uploadDate` inside `Article`, `BlogPosting`, `Product`, or `WebPage` JSON-LD schemas.
* **HTML `<meta>` Timestamps**:
  * Evaluate standard metadata timestamps: `article:modified_time`, `article:published_time`, `og:updated_time`, and `last-modified`.
* **In-Page Update Notices**:
  * Scan page copy for explicit freshness declarations (e.g. "Last updated on...", "Published: ...").
* **Copyright Notice Footer**:
  * Inspect copyright year declarations (e.g. "© 2018-2026 Brand Inc.").

### Evaluation Policy & False-Positive Guard
* **Multi-Signal Agreement**: If recent activity (within 12–18 months) is confirmed via Schema, Meta, or Sitemap timestamps, the site is classified as **Fresh**, even if the copyright footer displays an older year.
* **Stale Flagging Threshold**: A stale content finding (`severity: medium`) is only issued when all available signals indicate content has not been refreshed for >12–24 months, or when no temporal signals can be found to establish active maintenance.

---

## 2. Entity Ambiguity (Mistaken Identity Risk)

If a brand shares a common name or operates without structured entity links, AI models will struggle to isolate it from other organizations, leading to hallucinated attributes or misattributed reviews.

### Key Checks
* **Authoritative Schema.org `sameAs` Extraction**:
  * Extract verified external entity identifiers declared in `Organization` or `Brand` structured data.
  * Validate links against authoritative knowledge bases:
    * `wikidata.org` (e.g. `https://www.wikidata.org/wiki/Q...`)
    * `wikipedia.org`
    * `crunchbase.com`
    * `linkedin.com`
  * **Critical Distinction**: Substring matches for `"@id"` are **not** valid substitutes for `sameAs`. `@id` is an internal graph IRI, whereas `sameAs` explicitly points to external canonical entity graphs.
* **Naming Collision Assessment**:
  * If naming queries return multiple distinct entities across knowledge bases and the target site lacks `sameAs` links, issue a high-severity finding for **Entity Ambiguity / Mistaken Identity Risk**.

---

## 3. Web Agreement (External Fact Corroboration)

AI assistants synthesize facts from multiple web sources (e.g. Wikipedia, Wikidata, official registries). Discrepancies between on-page claims and authoritative external records cause AI trust penalties.

### Key Checks
* **Core Fact Extraction & Cross-Checking**:
  * Extract corporate headquarters location (state, city, country) from page text.
  * Cross-check against **Wikidata Search API** and **Wikipedia Search API** abstracts.
  * Standardize full names and state abbreviations (e.g., "California" <-> "CA", "Illinois" <-> "IL") with strict contextual address guards.
  * Accurately isolate country codes (e.g. Canada as `CAN`) from state abbreviations (e.g. California as `CA`) to avoid false contradiction flags.
* **Small / Niche Business Generalization Guard**:
  * If no external records are returned for a brand on Wikipedia or Wikidata, this is **normal and expected** for private, emerging, or local businesses.
  * Mark the corroboration check as **Pass** (`evidence: "No external search results found on Wikipedia or Wikidata. No contradictions detected."`), preventing penalization of small businesses.

---

## 4. E-E-A-T & Corporate Contact Transparency

Search models and LLM evaluators reward transparent authorship and verifiable contact credentials.

### Key Checks
* **Author Credits & Bylines**:
  * Check for explicit author bylines (`rel="author"`, author bio links, `Person` schema).
* **Corporate Navigation & Physical Credentials**:
  * Verify clear navigation paths to an About or Contact page.
  * Verify presence of direct customer communication channels: corporate email, telephone number, and physical office address.
