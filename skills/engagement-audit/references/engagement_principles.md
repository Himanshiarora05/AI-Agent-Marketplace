# On-Site Engagement Reference Principles

This reference document outlines the criteria for auditing a website's on-site engagement (why visitors who arrive from AI citations or search engines stay, explore, and convert, rather than bouncing).

---

## 1. On-Site Orientation (Value Proposition & H1 Hierarchy)

When visitors land on a page (especially when deep-linked directly from an AI assistant response), they must immediately understand what the brand offers, who it is for, and what problem it solves.

### Key Checks
* **Single Descriptive H1 Above the Fold**:
  * Exactly one `<h1>` tag must be placed prominently above the fold.
  * Heading copy must clearly convey a descriptive value proposition (at least 3–8 words) rather than generic, single-word headers (e.g. "Platform" or "Home").
  * Multiple H1 tags dilute semantic focus and confuse assistive parsers.
* **Target Audience Clarity**:
  * The value proposition should clarify the intended audience or business use case.
* **Jargon & Buzzword Minimization**:
  * Excessive buzzwords (e.g., "hyper-scalable synergy", "disruptive paradigm shift", "game-changing next-gen solutions") obscure concrete value and trigger higher bounce rates from visitors seeking specific answers.

---

## 2. Context Retention & Navigation Flow

Visitors arriving via AI search citations lack the contextual roadmap of starting from the homepage. The destination page must provide structural support to prevent bounce.

### Key Checks
* **Deep-Link Breadcrumbs**:
  * Deep internal pages must feature breadcrumb trails (`<nav aria-label="breadcrumb">`, `.breadcrumb`, or Schema.org `BreadcrumbList`).
  * Breadcrumbs help AI-referred users immediately grasp where the landing page sits within the site hierarchy.
* **Intent-Classified Call-To-Action (CTA) Coverage**:
  * Rather than relying solely on generic links, audit pages for explicit, intent-classified CTAs:
    * **Commercial**: "Buy Now", "Order Now", "Add to Cart", "Checkout"
    * **Evaluation / Trial**: "Request a Demo", "Book a Demo", "Try Free", "Start Free Trial"
    * **Lead Generation**: "Contact Sales", "Get in Touch", "Schedule a Call"
    * **Onboarding**: "Sign Up", "Get Started", "Create Account"
    * **Pricing**: "View Pricing", "See Plans", "Compare Plans"
    * **Informational**: "Read Docs", "View Documentation", "Download Whitepaper"
* **Dead-End Avoidance**:
  * Check for presence of primary header navigation (`<header>`, `<nav>`) and global footers (`<footer>`). Pages with no navigation paths or zero CTAs trap users in dead ends and spike exit rates.

---

## 3. Readability & Content Hygiene

Cluttered layout and unformatted text walls repel human visitors and degrade LLM summarization quality.

### Key Checks
* **Paragraph Sizing & Scannability**:
  * Text should be structured into concise, easily scannable paragraphs (2–4 sentences each).
  * Flag "walls of text" (paragraphs containing >100 words without formatting, bullet points, or visual relief).
* **Text-to-Code Density**:
  * Calculate the text-to-HTML ratio. A ratio below 5–10% indicates bloated HTML templates, obsolete DOM wrappers, or excessive third-party tracking scripts.
* **Filler Content & SEO Boilerplate**:
  * Repetitive, keyword-stuffed footer texts designed for legacy search engines detract from brand authority and user experience.

---

## 4. Lightweight Performance Indicators

Fast page loading ensures that visitors arriving from mobile AI chats or web searches experience immediate responsiveness.

### Key Checks
* **Script & Style Dependencies**:
  * Track counts of external scripts (`<script src="...">`) and external stylesheets (`<link rel="stylesheet">`). Excessive external scripts (>30) increase time-to-interactive.
* **HTML Payload Size**:
  * Ensure raw HTML payload remains within reasonable limits (<500 KB) before media loading.
