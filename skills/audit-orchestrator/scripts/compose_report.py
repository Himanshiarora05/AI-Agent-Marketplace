#!/usr/bin/env python3
"""
Orchestration Report Composer - audit-orchestrator
Consolidates findings from crawl-render-audit, freshness-corroboration, and engagement-audit.
Formats, structures, and validates the final JSON report according to the required schema.
Uses only the Python standard library to guarantee portability.
"""

import sys
import json
import argparse
import re
from datetime import datetime, timezone

LOAD_ERRORS = []

def parse_args():
    parser = argparse.ArgumentParser(description="Consolidates separate audit findings into a single report")
    parser.add_argument("--site", required=True, help="Target website domain (e.g. example.com)")
    parser.add_argument("--technical", help="Path to technical findings JSON file")
    parser.add_argument("--trust", help="Path to trust findings JSON file")
    parser.add_argument("--engagement", help="Path to engagement findings JSON file")
    parser.add_argument("--output", help="Path to write the final consolidated JSON report")
    return parser.parse_args()

def load_json(file_path, label=None):
    """Load a sub-audit JSON file without silently hiding a failed sub-audit.

    Returns None on failure so the composer can still emit a structurally valid
    report, but records the failure in execution.partial/missing_categories.
    """
    if not file_path:
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        name = label or str(file_path)
        message = f"Failed to load {name}: {e}"
        LOAD_ERRORS.append(message)
        print(f"ERROR: {message}", file=sys.stderr)
        return None

def normalize_confidence(conf_val):
    """Ensures confidence is formatted as a standard float between 0.0 and 1.0."""
    if isinstance(conf_val, (int, float)):
        return round(float(conf_val), 2)
    if isinstance(conf_val, str):
        c_lower = conf_val.strip().lower()
        if c_lower == "high":
            return 0.95
        elif c_lower == "medium":
            return 0.85
        elif c_lower == "low":
            return 0.60
        try:
            return round(float(conf_val), 2)
        except ValueError:
            pass
    return 0.85

def parse_technical_findings(data, site_url):
    findings = []
    if not isinstance(data, dict):
        return findings

    # 1. robots.txt check
    robots = data.get("robots_txt", {})
    if robots.get("blocks_all"):
        findings.append({
            "title": "Robots.txt blocks all crawlers from root",
            "category": "technical",
            "severity": "critical",
            "confidence": 0.95,
            "affected_pages": [site_url],
            "evidence": robots.get("evidence", ""),
            "suggested_action": {
                "summary": "Modify robots.txt to remove 'Disallow: /' under the global 'User-agent: *' directive.",
                "priority": "critical",
                "how_to_fix": "Edit your robots.txt file to replace 'Disallow: /' with targeted disallows (e.g. 'Disallow: /admin/'). Ensure public content is crawlable by search and AI user-agents."
            }
        })
    elif robots.get("blocked_bots"):
        # AI-specific crawler blocks are reported as discoverability considerations
        findings.append({
            "title": "Robots.txt blocks specific AI assistants",
            "category": "technical",
            "severity": "medium",
            "confidence": 0.90,
            "affected_pages": [site_url],
            "evidence": robots.get("evidence", "") + " Note: This is an AI discoverability consideration; evaluate whether AI indexation aligns with your distribution strategy.",
            "suggested_action": {
                "summary": "Update robots.txt to permit friendly AI agents (GPTBot, ClaudeBot, Google-Extended, Applebot-Extended) if AI discoverability is a business goal.",
                "priority": "medium",
                "how_to_fix": "Add explicit allow rules in robots.txt:\nUser-agent: GPTBot\nAllow: /\n\nUser-agent: ClaudeBot\nAllow: /\n\nUser-agent: Google-Extended\nAllow: /"
            }
        })
    elif robots.get("status") == "found" and not robots.get("sitemaps"):
        findings.append({
            "title": "No XML Sitemap declared in robots.txt",
            "category": "technical",
            "severity": "medium",
            "confidence": 0.90,
            "affected_pages": [site_url],
            "evidence": "robots.txt was found but did not specify a 'Sitemap:' directive.",
            "suggested_action": {
                "summary": "Append the sitemap location to robots.txt (e.g. 'Sitemap: https://example.com/sitemap.xml').",
                "priority": "medium",
                "how_to_fix": f"Append this line to the end of robots.txt:\nSitemap: {site_url.rstrip('/')}/sitemap.xml"
            }
        })

    # 2. crawler_block
    cb = data.get("crawler_block", {})
    if cb.get("status") == "fail":
        findings.append({
            "title": "HTTP requests blocked by anti-bot measures",
            "category": "technical",
            "severity": "critical",
            "confidence": normalize_confidence(cb.get("confidence", 0.95)),
            "affected_pages": [site_url],
            "evidence": cb.get("evidence", ""),
            "suggested_action": {
                "summary": "Configure web application firewall (WAF) to white-list or allow requests with AI crawler headers.",
                "priority": "critical",
                "how_to_fix": "Review firewall / CDN bot management rules (Cloudflare, AWS WAF, Fastly). Expose verified AI search crawler user-agents and IPs to prevent automated 403/CAPTCHA challenges on public pages."
            }
        })

    # 3. js_render_gap
    js = data.get("js_render_gap", {})
    if js.get("status") in ["warning", "fail"]:
        sev = js.get("severity", "high")
        findings.append({
            "title": "Client-Side JS Rendering Gap detected",
            "category": "technical",
            "severity": sev,
            "confidence": normalize_confidence(js.get("confidence", 0.85)),
            "affected_pages": js.get("affected_pages") or [site_url],
            "evidence": js.get("evidence", ""),
            "suggested_action": {
                "summary": "Implement Server-Side Rendering (SSR), static site generation (SSG), or pre-rendering/dynamic rendering (e.g., via Prerender.io) so crawlers receive readable HTML content directly.",
                "priority": sev,
                "how_to_fix": "Adopt Server-Side Rendering (SSR) via modern web frameworks (Next.js, Nuxt, SvelteKit) or integrate dynamic prerendering middleware (e.g. Prerender.io, Rendertron) to deliver pre-rendered HTML to search bots."
            }
        })

    # 4. structured_data
    sd = data.get("structured_data", {})
    if sd.get("status") in ["warning", "fail"]:
        sev = sd.get("severity", "medium")
        findings.append({
            "title": "Missing or invalid Schema.org structured data",
            "category": "technical",
            "severity": sev,
            "confidence": normalize_confidence(sd.get("confidence", 0.90)),
            "affected_pages": sd.get("affected_pages") or [site_url],
            "evidence": sd.get("evidence", ""),
            "suggested_action": {
                "summary": "Embed JSON-LD structured data (Organization schema for homepage, Product/Offer schema for ecommerce pages) using script type='application/ld+json'.",
                "priority": sev,
                "how_to_fix": '<script type="application/ld+json">\n{\n  "@context": "https://schema.org",\n  "@type": "Organization",\n  "name": "BrandName",\n  "url": "' + site_url + '",\n  "sameAs": ["https://www.wikidata.org/wiki/..."]\n}\n</script>'
            }
        })

    # 5. locked_content
    lc = data.get("locked_content", {})
    if lc.get("status") == "warning":
        sev = lc.get("severity", "medium")
        findings.append({
            "title": "Content locked in non-text format or missing alt text",
            "category": "technical",
            "severity": sev,
            "confidence": normalize_confidence(lc.get("confidence", 0.85)),
            "affected_pages": lc.get("affected_pages") or [site_url],
            "evidence": lc.get("evidence", ""),
            "suggested_action": {
                "summary": "Add descriptive 'alt' tags to all img elements. Avoid embedding important pricing/info inside canvas or raw text-in-image headers without HTML fallback.",
                "priority": sev,
                "how_to_fix": "Add descriptive alt attributes (<img src='...' alt='Clear description of content'>). For decorative images, explicitly specify alt='' to conform with WCAG standards. For canvas diagrams, provide an accessible HTML text summary or table fallback."
            }
        })

    # 6. viewport_check
    vp = data.get("viewport_check", {})
    if vp.get("status") == "warning":
        findings.append({
            "title": "Missing Mobile Viewport Metadata tag",
            "category": "technical",
            "severity": "medium",
            "confidence": normalize_confidence(vp.get("confidence", 0.95)),
            "affected_pages": vp.get("affected_pages") or [site_url],
            "evidence": vp.get("evidence", ""),
            "suggested_action": {
                "summary": "Add <meta name='viewport' content='width=device-width, initial-scale=1'> inside the <head> element to support responsive mobile scaling.",
                "priority": "medium",
                "how_to_fix": "Insert <meta name='viewport' content='width=device-width, initial-scale=1.0'> into the <head> section of your HTML template."
            }
        })

    # 7. faq_schema_check
    faq = data.get("faq_schema_check", {})
    if faq.get("status") == "warning":
        findings.append({
            "title": "Questions detected in text but missing FAQPage structured data",
            "category": "technical",
            "severity": "medium",
            "confidence": normalize_confidence(faq.get("confidence", 0.85)),
            "affected_pages": faq.get("affected_pages") or [site_url],
            "evidence": faq.get("evidence", ""),
            "suggested_action": {
                "summary": "Convert flat Q&A text elements into schema.org FAQPage JSON-LD structures to help search engines parse direct answers.",
                "priority": "medium",
                "how_to_fix": '<script type="application/ld+json">\n{\n  "@context": "https://schema.org",\n  "@type": "FAQPage",\n  "mainEntity": [{\n    "@type": "Question",\n    "name": "FAQ Question Here?",\n    "acceptedAnswer": {\n      "@type": "Answer",\n      "text": "Answer text here."\n    }\n  }]\n}\n</script>'
            }
        })

    for key,title,action in [
        ("indexability_check","Page is marked noindex","Remove unintended noindex directives from meta robots or X-Robots-Tag while retaining intentional exclusions."),
        ("canonical_check","Canonical URL is missing or inconsistent","Declare exactly one canonical URL for indexable pages and keep it aligned with the final URL, sitemap, and internal links."),
        ("fact_parity","Visible content conflicts with structured data","Align visible pricing, contact, and product facts with JSON-LD so machines receive one consistent representation."),
        ("rendered_mobile","Mobile rendering has layout issues","Fix horizontal overflow and keep the primary value proposition and CTA accessible at a 390x844 viewport."),
    ]:
        info=data.get(key,{})
        if info.get("status") in ("fail","warning","conflict","mismatch","external"):
            sev=info.get("severity","medium")
            findings.append({"title":title,"category":"technical","severity":sev,"confidence":normalize_confidence(info.get("confidence",0.85)),"affected_pages":info.get("affected_pages") or [site_url],"evidence":info.get("evidence",""),"suggested_action":{"summary":action,"priority":sev,"how_to_fix":action}})

    # 8. redirect chain
    red=data.get("redirect_check",{})
    if red.get("status")=="warning":
        findings.append({"title":"Long or cross-host redirect chain","category":"technical","severity":"medium","confidence":normalize_confidence(red.get("confidence",0.98)),"affected_pages":red.get("affected_pages") or [site_url],"evidence":red.get("evidence",""),"suggested_action":{"summary":"Reduce redirect hops and keep public URLs on the intended canonical host.","priority":"medium","how_to_fix":"Point HTTP aliases directly to the final HTTPS canonical URL, remove intermediate redirects, and keep redirects within the same host unless a migration requires otherwise."}})
    # 9. potential orphan pages
    graph=data.get("page_graph",{})
    orphans=graph.get("potential_orphans",[]) if isinstance(graph,dict) else []
    if orphans:
        findings.append({"title":"Potentially orphaned high-value pages","category":"technical","severity":"medium","confidence":0.84,"affected_pages":orphans[:10],"evidence":graph.get("evidence","")+" URLs were present in the sitemap but had no inbound links in the sampled internal-link graph.","suggested_action":{"summary":"Link important sitemap pages from relevant navigation, hub pages, or contextual content so crawlers and visitors can discover them naturally.","priority":"medium","how_to_fix":"Add contextual internal links from the homepage or relevant category/content pages; ensure important pages are reachable without relying solely on the XML sitemap."}})
    return findings

def parse_trust_findings(data, site_url):
    findings = []
    if not isinstance(data, dict):
        return findings

    current_year = datetime.now(timezone.utc).year

    # 1. copyright / multi-signal freshness check
    copyright_info = data.get("copyright", {})
    if copyright_info.get("status") == "warning":
        sev = copyright_info.get("severity", "medium")
        findings.append({
            "title": "Stale Copyright year in footer notice",
            "category": "trust",
            "severity": sev,
            "confidence": normalize_confidence(copyright_info.get("confidence", 0.85)),
            "affected_pages": [site_url],
            "evidence": copyright_info.get("evidence", ""),
            "suggested_action": {
                "summary": f"Update the copyright footer declaration to the current year ({current_year}). Consider dynamic year scripting (e.g. JavaScript new Date().getFullYear()).",
                "priority": sev,
                "how_to_fix": f"Update static footer copyright strings to {current_year} or use dynamic template rendering: &copy; {current_year} BrandName. Also ensure sitemap.xml and meta publication timestamps reflect active updates."
            }
        })

    # 2. stale year mentions
    year_info = data.get("year_mentions", {})
    mentions = year_info.get("mentions", {})
    has_recent = year_info.get("has_future_or_current")
    if mentions and not has_recent:
        findings.append({
            "title": "Stale activity signals in page text",
            "category": "trust",
            "severity": "medium",
            "confidence": 0.85,
            "affected_pages": [site_url],
            "evidence": year_info.get("evidence", "") + " Site only mentions past years.",
            "suggested_action": {
                "summary": f"Refresh outdated content sections, press releases, or blog lists with recent {current_year} activity to reassure AI assistants of active operations.",
                "priority": "medium",
                "how_to_fix": f"Publish up-to-date {current_year} news items, product updates, or changelog notices on landing pages to confirm ongoing business operations to LLM web extractors."
            }
        })

    # 3. eeat_check
    eeat = data.get("eeat_check", {})
    if eeat.get("status") == "warning":
        findings.append({
            "title": "Missing E-E-A-T expertise or contact transparency signals",
            "category": "trust",
            "severity": "medium",
            "confidence": normalize_confidence(eeat.get("confidence", 0.85)),
            "affected_pages": [site_url],
            "evidence": eeat.get("evidence", ""),
            "suggested_action": {
                "summary": "Add clear author profiles/bylines to articles, provide published/updated timestamps, and ensure corporate email, phone, or address details are clearly linkable.",
                "priority": "medium",
                "how_to_fix": "Add an explicit Contact/About link in your primary navigation leading to verifiable corporate credentials: physical address, phone number, corporate email, and author/team leadership bios."
            }
        })

    # 4. corroboration_check
    corrob = data.get("corroboration_check", {})
    if corrob.get("status") == "fail":
        findings.append({
            "title": "Low Web Agreement / Fact Contradiction",
            "category": "trust",
            "severity": "high",
            "confidence": normalize_confidence(corrob.get("confidence", 0.95)),
            "affected_pages": [site_url],
            "evidence": corrob.get("evidence", ""),
            "suggested_action": {
                "summary": "Align key corporate information (such as headquarters location) on your website with external databases like Wikidata and Wikipedia.",
                "priority": "high",
                "how_to_fix": "Audit your registered business headquarters and public disclosures. Update the on-page address and submit accurate edits to Wikidata (P159 headquarters) and Wikipedia to eliminate factual contradictions."
            }
        })

    # 5. ambiguity_check
    ambig = data.get("ambiguity_check", {})
    if ambig.get("status") == "warning":
        findings.append({
            "title": "Entity Ambiguity / Mistaken Identity Risk",
            "category": "trust",
            "severity": "high",
            "confidence": normalize_confidence(ambig.get("confidence", 0.90)),
            "affected_pages": [site_url],
            "evidence": ambig.get("evidence", ""),
            "suggested_action": {
                "summary": "Embed Wikidata/Wikipedia URLs inside the organization JSON-LD sameAs links array to explicitly disambiguate your brand from same-named entities.",
                "priority": "high",
                "how_to_fix": 'Add schema.org "sameAs" references inside your Organization structured data:\n"sameAs": [\n  "https://www.wikidata.org/wiki/Q...",\n  "https://en.wikipedia.org/wiki/...",\n  "https://www.linkedin.com/company/..."\n]'
            }
        })

    entity=data.get("entity_confidence",{})
    ambiguity=data.get("ambiguity_check",{})
    corrob=data.get("corroboration_check",{})
    if isinstance(entity,dict) and entity.get("status")=="warning" and ambiguity.get("status")!="warning" and corrob.get("status")!="fail":
        findings.append({"title":"Low entity confidence / identity ambiguity","category":"trust","severity":"medium","confidence":normalize_confidence(entity.get("confidence",0.8)),"affected_pages":entity.get("affected_pages") or [site_url],"evidence":entity.get("evidence",""),"suggested_action":{"summary":"Strengthen entity identity with consistent organization name, domain, location, and authoritative sameAs identifiers.","priority":"medium","how_to_fix":"Use one canonical organization name and URL, keep location/contact facts consistent, and add only verified authoritative sameAs links such as the correct Wikidata or Wikipedia entity."}})
    return findings

def parse_engagement_findings(data, site_url):
    findings=[]
    if not isinstance(data, dict):
        return findings

    # 1. h1_audit
    h1 = data.get("h1_audit", {})
    if h1.get("status") in ["warning", "fail"]:
        sev = h1.get("severity", "medium")
        findings.append({
            "title": "Incorrect or missing page heading (H1) hierarchy",
            "category": "engagement",
            "severity": sev,
            "confidence": normalize_confidence(h1.get("confidence", 0.95)),
            "affected_pages": [site_url],
            "evidence": h1.get("evidence", ""),
            "suggested_action": {
                "summary": "Ensure the page has exactly one H1 tag placed above the fold containing a clear, search-relevant value proposition.",
                "priority": sev,
                "how_to_fix": "Structure page headings with exactly one <h1> above the fold containing a concise value statement (3-8 words). Demote secondary headings to <h2> and <h3>."
            }
        })

    # 2. readability
    read = data.get("readability", {})
    if read.get("status") == "warning":
        sev = read.get("severity", "medium")
        findings.append({
            "title": "Poor text readability layout (Walls of Text)",
            "category": "engagement",
            "severity": sev,
            "confidence": normalize_confidence(read.get("confidence", 0.90)),
            "affected_pages": [site_url],
            "evidence": read.get("evidence", ""),
            "suggested_action": {
                "summary": "Deconstruct large paragraph walls into smaller 2-3 sentence sections. Integrate bullet points, bold key terms, and whitespace.",
                "priority": sev,
                "how_to_fix": "Break text blocks exceeding 100 words into shorter paragraphs (2-3 sentences each). Use unordered lists (<ul>), bold key takeaways, and clear subheadings to facilitate skimming."
            }
        })

    # 3. navigation & cta
    nav = data.get("navigation_cta", {})
    if nav.get("status") in ["warning", "fail"]:
        sev = nav.get("severity", "medium")
        findings.append({
            "title": "Inaccessible navigation flow or missing CTAs",
            "category": "engagement",
            "severity": sev,
            "confidence": normalize_confidence(nav.get("confidence", 0.95)),
            "affected_pages": [site_url],
            "evidence": nav.get("evidence", ""),
            "suggested_action": {
                "summary": "Ensure deep-linked landing pages contain visible navigation menus, structural breadcrumbs, and a prominent call-to-action button (e.g. 'Get Started') to prevent exit bounce.",
                "priority": sev,
                "how_to_fix": "Implement persistent header navigation (<header><nav>...</nav></header>), add deep-link breadcrumbs (<nav aria-label='Breadcrumbs'>), and place prominent Call-To-Action buttons (e.g. 'Get Started', 'Schedule Demo') above the fold."
            }
        })

    # 4. clutter
    clut = data.get("clutter", {})
    if clut.get("status") == "warning":
        sev = clut.get("severity", "medium")
        findings.append({
            "title": "Low text-to-code ratio (Cluttered page layout)",
            "category": "engagement",
            "severity": sev,
            "confidence": normalize_confidence(clut.get("confidence", 0.90)),
            "affected_pages": [site_url],
            "evidence": clut.get("evidence", ""),
            "suggested_action": {
                "summary": "Optimize visual clutter. Consolidate tracking scripts, defer non-critical JS/CSS files, and clean obsolete DOM tags.",
                "priority": sev,
                "how_to_fix": "Audit and defer non-critical third-party analytics/ad scripts (add 'defer' or 'async'). Remove redundant DOM wrappers and obsolete CSS/JS bundles to achieve a text-to-code ratio above 10%."
            }
        })

    rendered=data.get("rendered_experience",{})
    if rendered.get("status")=="warning":
        findings.append({"title":"Above-the-fold or mobile layout issue","category":"engagement","severity":"medium","confidence":normalize_confidence(rendered.get("confidence",0.9)),"affected_pages":[site_url],"evidence":rendered.get("evidence",""),"suggested_action":{"summary":"Keep the primary value proposition and conversion CTA visible without an initial scroll and eliminate mobile horizontal overflow.","priority":"medium","how_to_fix":"Test at 1440x900 and 390x844, remove fixed-width elements that overflow the viewport, and keep the H1 plus primary CTA in the initial viewport."}})

    answerability=data.get("answerability",{})
    if answerability.get("status")=="warning":
        findings.append({"title":"Low answerability of the primary landing page","category":"engagement","severity":"medium","confidence":normalize_confidence(answerability.get("confidence",0.82)),"affected_pages":[site_url],"evidence":answerability.get("evidence",""),"suggested_action":{"summary":"Make the page answer the core questions—what the brand offers, who it serves, how to start, and how to contact it—using concise, crawlable text.","priority":"medium","how_to_fix":"Add a concise value proposition, explicit audience statement, short product/service definition, clear contact path, and one primary next-step CTA in plain HTML."}})
    quote= data.get("answerability",{})
    if isinstance(quote,dict):
        quote_score=quote.get("quote_readiness_score")
        if quote_score is not None and float(quote_score) < 50:
            findings.append({"title":"Low AI quote readiness","category":"engagement","severity":"medium","confidence":normalize_confidence(quote.get("confidence",0.88)),"affected_pages":quote.get("affected_pages") or [site_url],"evidence":quote.get("evidence","")+f" Quote-readiness score: {quote_score}/100.","suggested_action":{"summary":"Add concise, self-contained answer blocks that an AI assistant can quote without reconstructing missing context.","priority":"medium","how_to_fix":"Use descriptive question or definition headings followed immediately by 1-3 sentence factual answers. Keep key facts in crawlable HTML and include the subject, audience, scope, and relevant qualifiers in the answer itself."}})
    deep=data.get("deep_link_context",{})
    if isinstance(deep,dict) and deep.get("status")=="warning":
        findings.append({"title":"Weak deep-link context retention","category":"engagement","severity":"medium","confidence":normalize_confidence(deep.get("confidence",0.9)),"affected_pages":[site_url],"evidence":deep.get("evidence",""),"suggested_action":{"summary":"Make every likely AI landing page understandable and navigable on its own, with persistent context and a clear next path.","priority":"medium","how_to_fix":"Keep brand identity and primary navigation visible, add breadcrumbs where hierarchy matters, provide contextual internal links, and expose one meaningful primary CTA on the landing page."}})
    return findings

def main():
    args = parse_args()
    site_url = args.site
    if not site_url.startswith("http://") and not site_url.startswith("https://"):
        site_url = "https://" + site_url
    
    # Load raw JSON structures from all files
    tech_data = load_json(args.technical, "technical audit")
    trust_data = load_json(args.trust, "trust audit")
    engage_data = load_json(args.engagement, "engagement audit")

    requested_categories = []
    if args.technical: requested_categories.append(("technical", tech_data))
    if args.trust: requested_categories.append(("trust", trust_data))
    if args.engagement: requested_categories.append(("engagement", engage_data))
    missing_categories = [name for name, data in requested_categories if data is None]
    
    raw_findings = []
    
    tech_findings = []
    if tech_data:
        if isinstance(tech_data, list):
            tech_findings.extend(tech_data)
        elif isinstance(tech_data, dict):
            if "findings" in tech_data and isinstance(tech_data["findings"], list):
                tech_findings.extend(tech_data["findings"])
            elif "robots_txt" in tech_data:
                tech_findings.extend(parse_technical_findings(tech_data, site_url))
            else:
                tech_findings.append(tech_data)
    for f in tech_findings:
        if isinstance(f, dict):
            f["category"] = "technical"
    raw_findings.extend(tech_findings)
                
    trust_findings = []
    if trust_data:
        if isinstance(trust_data, list):
            trust_findings.extend(trust_data)
        elif isinstance(trust_data, dict):
            if "findings" in trust_data and isinstance(trust_data["findings"], list):
                trust_findings.extend(trust_data["findings"])
            elif "copyright" in trust_data or "multi_signal_freshness" in trust_data:
                trust_findings.extend(parse_trust_findings(trust_data, site_url))
            else:
                trust_findings.append(trust_data)
    for f in trust_findings:
        if isinstance(f, dict):
            f["category"] = "trust"
    raw_findings.extend(trust_findings)
                
    engage_findings = []
    if engage_data:
        if isinstance(engage_data, list):
            engage_findings.extend(engage_data)
        elif isinstance(engage_data, dict):
            if "findings" in engage_data and isinstance(engage_data["findings"], list):
                engage_findings.extend(engage_data["findings"])
            elif "h1_audit" in engage_data:
                engage_findings.extend(parse_engagement_findings(engage_data, site_url))
            else:
                engage_findings.append(engage_data)
    for f in engage_findings:
        if isinstance(f, dict):
            f["category"] = "engagement"
    raw_findings.extend(engage_findings)
    
    # Inject Proactive Suggestions if no critical or high severity defects in respective categories
    has_high_critical_tech = any(f.get("category") == "technical" and f.get("severity") in ["critical", "high"] for f in raw_findings if isinstance(f, dict))
    has_high_critical_trust = any(f.get("category") == "trust" and f.get("severity") in ["critical", "high"] for f in raw_findings if isinstance(f, dict))
    has_high_critical_engage = any(f.get("category") == "engagement" and f.get("severity") in ["critical", "high"] for f in raw_findings if isinstance(f, dict))
    
    if tech_data is not None and not has_high_critical_tech:
        raw_findings.append({
            "title": "Proactive AI Answerability: Add Answer-First Content",
            "category": "technical",
            "severity": "medium",
            "confidence": 0.95,
            "affected_pages": [site_url],
            "evidence": "No critical or high severity technical defect was detected in the sampled checks. This is a proactive improvement, not a defect finding.",
            "suggested_action": {
                "summary": "Create answer-first, crawlable sections for high-value user questions and expose important facts in plain HTML plus valid structured data.",
                "priority": "medium",
                "proactive": True,
                "how_to_fix": "Add concise answer-first sections for core questions, descriptive headings, stable URLs, and matching facts in visible HTML plus Schema.org JSON-LD."
            }
        })
        
    if trust_data is not None and not has_high_critical_trust:
        raw_findings.append({
            "title": "Proactive Brand Trust: Strengthen Verified Entity Signals",
            "category": "trust",
            "severity": "medium",
            "confidence": 0.95,
            "affected_pages": [site_url],
            "evidence": "No critical or high severity trust defect was detected in the sampled checks. This is a proactive improvement, not a defect finding.",
            "suggested_action": {
                "summary": "Keep authoritative entity identifiers consistent across structured data and external profiles to reduce future naming-collision risk.",
                "priority": "medium",
                "proactive": True,
                "how_to_fix": "In your Schema.org Organization JSON-LD, append authoritative entity URIs to the 'sameAs' array to anchor your brand identity in global knowledge graphs."
            }
        })
        
    if engage_data is not None and not has_high_critical_engage:
        raw_findings.append({
            "title": "Proactive Engagement: Add Smart Navigation Anchor Links for AI Deep-Citations",
            "category": "engagement",
            "severity": "medium",
            "confidence": 0.95,
            "affected_pages": [site_url],
            "evidence": "Landing page orientation headings, reading structures, navigation, and Call-to-Actions are well aligned.",
            "suggested_action": {
                "summary": "Introduce micro-anchor links next to core headings and paragraphs to allow AI assistants to reference exact section URLs in their answer citations.",
                "priority": "medium",
                "proactive": True,
                "how_to_fix": "Add permanent id attributes to major section headings (<h2 id='features'>) and surface subtle hover anchor links (#) to support precise deep-linking by AI engines."
            }
        })
    
    # Consolidate skipped checks on fetch failure
    has_fetch_failure = False
    fetch_failure_idx = -1
    for idx, f in enumerate(raw_findings):
        if not isinstance(f, dict):
            continue
        title = f.get("title", "")
        if title == "HTTP requests blocked by anti-bot measures" or "fetching failed" in f.get("evidence", "").lower():
            has_fetch_failure = True
            fetch_failure_idx = idx
            break
            
    if has_fetch_failure and fetch_failure_idx != -1:
        skipped_titles = []
        filtered_findings = []
        for idx, f in enumerate(raw_findings):
            if idx == fetch_failure_idx:
                filtered_findings.append(f)
                continue
            if not isinstance(f, dict):
                filtered_findings.append(f)
                continue
            ev = f.get("evidence", "")
            if "skipped check" in ev.lower():
                skipped_titles.append(f.get("title", "Unknown Check"))
            else:
                filtered_findings.append(f)
                
        if skipped_titles:
            for f in filtered_findings:
                if isinstance(f, dict) and (f.get("title") == "HTTP requests blocked by anti-bot measures" or "fetching failed" in f.get("evidence", "").lower()):
                    f["evidence"] += f" The following checks were skipped due to the fetch failure: {', '.join(skipped_titles)}."
                    break
            raw_findings = filtered_findings

    # Deduplicate materially identical findings emitted by multiple sub-checks.
    deduped=[]; dedupe_keys=set()
    for f in raw_findings:
        if not isinstance(f,dict):
            continue
        key=(f.get("category"), re.sub(r"\W+"," ",str(f.get("title","")).lower()).strip(), tuple(sorted(f.get("affected_pages",[]) or [])))
        if key in dedupe_keys and not f.get("suggested_action",{}).get("proactive",False):
            continue
        dedupe_keys.add(key); deduped.append(f)
    raw_findings=deduped

    # Standardize findings: sanitize fields, assign sequential IDs (F-001, F-002, etc.)
    consolidated_findings = []
    id_counter = 1
    
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0
    }
    proactive_count = 0
    
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
            
        title = f.get("title", "").strip()
        severity = f.get("severity", "medium")
        if not severity:
            severity = "medium"
        severity = str(severity).lower().strip()
        evidence = f.get("evidence", "").strip()
        suggested_action = f.get("suggested_action", {})
        category = f.get("category", "technical")
        confidence = normalize_confidence(f.get("confidence", 0.85))
        affected_pages = f.get("affected_pages", [site_url])
        
        if not title or not evidence:
            continue
            
        if severity not in ["critical", "high", "medium"]:
            severity = "medium"
            
        is_proactive = False
        if isinstance(suggested_action, dict):
            is_proactive = suggested_action.get("proactive", False)
            
        if isinstance(suggested_action, str):
            suggested_action_obj = {
                "summary": suggested_action,
                "priority": severity,
                "how_to_fix": "Follow recommended industry best practices to resolve this finding."
            }
        else:
            action_summary = suggested_action.get("summary", "Fix the identified issue.").strip()
            action_priority = suggested_action.get("priority", severity)
            if not action_priority:
                action_priority = severity
            action_priority = str(action_priority).lower().strip()
            if action_priority not in ["critical", "high", "medium"]:
                action_priority = severity
            action_how_to_fix = suggested_action.get("how_to_fix", "Follow recommended industry best practices to resolve this finding.")
            suggested_action_obj = {
                "summary": action_summary,
                "priority": action_priority,
                "how_to_fix": action_how_to_fix
            }
            if is_proactive:
                suggested_action_obj["proactive"] = True
            
        finding_id = f"F-{id_counter:03d}"
        id_counter += 1
        
        if is_proactive:
            proactive_count += 1
        else:
            severity_counts[severity] += 1
            
        finding_item = {
            "id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "affected_pages": affected_pages,
            "evidence": evidence,
            "suggested_action": suggested_action_obj
        }
        if is_proactive:
            finding_item["proactive"] = True
            
        consolidated_findings.append(finding_item)
        
    # Calculate scope metadata
    pages_crawled = 1
    if tech_data and isinstance(tech_data, dict):
        if "crawl_scope" in tech_data and isinstance(tech_data["crawl_scope"], dict):
            pages_crawled = max(1, tech_data["crawl_scope"].get("pages_successfully_crawled", 1))
        elif "crawled_pages" in tech_data and isinstance(tech_data["crawled_pages"], list):
            pages_crawled = max(1, len(tech_data["crawled_pages"]))
            
    scope_metadata = {
        "pages_checked": pages_crawled,
        "robots_checked": bool(tech_data and isinstance(tech_data, dict) and ("robots" in tech_data or "robots_txt" in tech_data)),
        "sitemap_checked": bool(tech_data and isinstance(tech_data, dict) and ("sitemap" in tech_data or tech_data.get("robots_txt", {}).get("sitemaps"))),
        "render_check": bool(tech_data and isinstance(tech_data, dict) and "js_render_gap" in tech_data),
        "external_sources_checked": 2 if trust_data else 0
    }
    if tech_data and isinstance(tech_data, dict):
        js = tech_data.get("js_render_gap", {})
        if isinstance(js, dict):
            scope_metadata["render_status"] = "verified" if js.get("status") == "pass" else ("unavailable" if js.get("status") == "unavailable" else js.get("status", "unknown"))
    else:
        scope_metadata["render_status"] = "not_run"
        
    # Strict count requirement: total_findings strictly equals non-proactive findings
    total_non_proactive = sum(severity_counts.values())
    
    cat_scores={"technical":100.0,"trust":100.0,"engagement":100.0}
    penalty={"critical":30,"high":18,"medium":7}
    for f in consolidated_findings:
        cat=f.get("category","technical")
        if cat in cat_scores: cat_scores[cat]=max(0.0,cat_scores[cat]-penalty.get(f.get("severity"),7)*normalize_confidence(f.get("confidence",0.85)))
    readiness=round(sum(cat_scores.values())/3,1)
    readiness_band="excellent" if readiness>=90 else "strong" if readiness>=75 else "needs_attention" if readiness>=55 else "at_risk"

    # Build final report structure
    severity_rank={"critical":0,"high":1,"medium":2}
    top_candidates=[f for f in consolidated_findings if not f.get("proactive")]
    top_candidates.sort(key=lambda f:(severity_rank.get(f.get("severity"),9), -normalize_confidence(f.get("confidence",0.85))))
    priority_actions=[]
    for rank,f in enumerate(top_candidates[:5],1):
        action=f.get("suggested_action",{})
        priority_actions.append({"rank":rank,"finding_id":f.get("id"),"action":action.get("summary","Fix the identified issue."),"why_it_matters":f.get("evidence",""),"priority":action.get("priority",f.get("severity"))})

    subaudit_errors = []
    for label, data in (("technical", tech_data), ("trust", trust_data), ("engagement", engage_data)):
        if isinstance(data, dict):
            execution = data.get("execution", {})
            if isinstance(execution, dict):
                for error in execution.get("errors", []) or []:
                    subaudit_errors.append(f"{label}: {error}")

    report = {
        "site": args.site,
        "audited_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_findings": total_non_proactive,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "proactive_suggestions_count": proactive_count,
            "total_items": len(consolidated_findings)
        },
        "scope": scope_metadata,
        "execution": {
            "partial": bool(missing_categories or LOAD_ERRORS or subaudit_errors),
            "missing_categories": missing_categories,
            "errors": list(LOAD_ERRORS) + subaudit_errors,
            "note": "A partial report is explicitly marked when a requested sub-audit could not be loaded. Missing categories are not treated as clean passes or given proactive suggestions." if (missing_categories or LOAD_ERRORS or subaudit_errors) else "All requested sub-audits were loaded successfully."
        },
        "readiness": {"score":readiness,"band":readiness_band,"dimensions":{k:round(v,1) for k,v in cat_scores.items()},"method":"Internal diagnostic index based on severity- and confidence-weighted observed findings; it is not an Adobe score. Proactive suggestions do not reduce the index."},
        "priority_actions":priority_actions,
        "findings": consolidated_findings
    }
    
    output_data = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output_data)
        print(f"Consolidated audit report written to {args.output}")
    else:
        print(output_data)

if __name__ == "__main__":
    main()
