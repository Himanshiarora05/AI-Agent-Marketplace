# AI Discoverability Reference Checklist

This reference document outlines the technical criteria for auditing a brand website for AI assistant discoverability (being found, read, and cited).

---

## 1. Crawlability & Safety Compliance

AI crawlers must be able to retrieve page contents reliably, safely, and in compliance with web standards.

### Key Checks
* **Robots.txt Analysis & Strict Compliance**:
  * Verify if the audit crawler is permitted on the target URL using `urllib.robotparser.RobotFileParser`. If disallowed, the crawler **must abort fetching** to avoid policy violations.
  * Check if the site blocks all user-agents (`User-agent: *`) from crawling critical content (`Disallow: /`).
  * Check for blocks specifically targeting AI web crawlers:
    * `GPTBot` (OpenAI ChatGPT)
    * `ClaudeBot` (Anthropic Claude)
    * `Google-Extended` (Google Gemini training/search)
    * `Applebot-Extended` (Apple Intelligence)
    * `PerplexityBot` (Perplexity AI)
    * `Cohere-ai` (Cohere AI)
    * `Omgilibot` / `Omgili`
  * Verify if `Sitemap:` directives are present in `robots.txt` pointing to valid XML sitemaps.
* **XML Sitemap Discovery & Parsing**:
  * Locate XML sitemaps declared in `robots.txt` or standard `/sitemap.xml`.
  * Support both standard `<urlset>` sitemaps and nested `<sitemapindex>` files (recursively traversing child sitemaps).
  * Extract `<loc>` URLs and `<lastmod>` timestamps to assess content coverage and freshness.
* **Bounded Mini-Crawling**:
  * Intelligently sample 5–8 high-value internal pages (`/about`, `/contact`, `/pricing`, `/products`, `/faq`, `/blog`) to assess site-wide health beyond just the homepage.
  * Enforce strict same-domain boundaries, URL normalization (trailing slash, fragment, tracking parameters), and bounded request counts to prevent crawl traps.
* **Crawler Anti-Bot Challenges**:
  * Check if fetching the site using standard libraries returns `403 Forbidden`, `401 Unauthorized`, or Cloudflare / AWS WAF challenge pages.

---

## 2. JS-Render Gaps & Dynamic Fact Parity

Many real-time RAG (Retrieval-Augmented Generation) agents fetch web pages using simple HTTP libraries without executing JavaScript. If key facts are only loaded dynamically, AI agents cannot access them.

### Key Checks
* **Fact-Level Parity Audit**:
  * Compare crucial customer-facing facts in the raw HTTP GET response vs. a fully rendered headless browser DOM (via **Playwright**):
    * Phone numbers
    * Email addresses
    * Pricing figures
    * Official brand name and taglines
  * If critical facts exist in the rendered DOM but are absent in raw HTML, flag a **Critical JS-Render Gap**.
* **Text Ratio and SPA Containers**:
  * If the raw HTML body has minimal content (e.g., only `<div id="app"></div>` or `<div id="root"></div>`) while rendered view contains substantial text (>2x content expansion), flag as a **JS-Render Gap**.
* **Graceful Degradation**:
  * If headless browser execution is unavailable, evaluate heuristic indicators (low text count combined with high script counts or SPA containers) and issue appropriate heuristic warnings without pipeline crashes.

---

## 3. Deep Structured Data (Schema.org / JSON-LD)

Structured data enables AI agents to extract clean entity relations (facts, prices, specifications) without relying on fuzzy text heuristics.

### Key Checks
* **Robust JSON-LD Extraction**:
  * Handle multiple `<script type="application/ld+json">` blocks.
  * Correctly handle HTML entity references (`&amp;`, `&quot;`) without breaking JSON syntax.
  * Recursively parse `@graph` arrays and nested objects to discover all defined schemas.
* **Entity Typing & Completeness**:
  * **Organization / LocalBusiness**: Validate `name`, `url`, `address`, and authoritative `sameAs` links.
  * **Product / Offer**: Validate `name`, `description`, and `offers` (`price`, `priceCurrency`).
  * **FAQPage / Question**: Validate `mainEntity` with paired `acceptedAnswer` text.
  * **BreadcrumbList**: Validate `itemListElement` hierarchical trail.
  * **Article / BlogPosting**: Validate `headline`, `author`, and `datePublished` / `dateModified`.
* **Format Errors & Validation**:
  * Detect invalid JSON syntax, un-escaped control characters, or truncated script blocks.

---

## 4. Accessibility & Non-Text Media Auditing

Facts locked in opaque media formats cannot be parsed by AI text models.

### Key Checks
* **WCAG-Compliant Image Alternative Text**:
  * Accurately distinguish informative images from decorative images.
  * Do **NOT** flag decorative images (`alt=""`, `role="presentation"`, or spacer/icon files) as missing alt text.
  * Flag informative images lacking descriptive `alt` attributes.
* **Canvas Fallback Text**:
  * Check `<canvas>` elements for embedded fallback text or accompanying table descriptions. If canvas contains no fallback, flag as locked content.
* **FAQ Parity**:
  * Detect genuine FAQ sections in page text (headings, `<details>` accordions, or repeated Q&A blocks).
  * If FAQ text is present but lacks Schema.org `FAQPage` JSON-LD, recommend adding structured data for direct answer citation.
