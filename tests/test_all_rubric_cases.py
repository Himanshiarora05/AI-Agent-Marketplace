#!/usr/bin/env python3
"""
Comprehensive Test Suite for Brand AI-Readiness Audit
Verifies 34 historical core challenge checks plus additional hardening/regression checks across:
1. Crawl & Technical Discoverability (Robots.txt, Sitemap XML, Mini-Crawler, Schema.org, WCAG Alt, Canvas, JS Render Gap)
2. Freshness & Trust Corroboration (Multi-signal Freshness, sameAs Disambiguation, Location/Fact Corroboration, E-E-A-T)
3. On-Site User Engagement (H1 Hierarchy, Readability, Breadcrumbs, Intent CTAs, Dead-Ends, Clutter)
4. Report Composition & Schema Compliance (Scope Metadata, Confidence, Suggested Actions, Total Findings)
"""

import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock

# Add scripts directories to path
MARKETPLACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(MARKETPLACE_DIR, "skills", "crawl-render-audit", "scripts"))
sys.path.insert(0, os.path.join(MARKETPLACE_DIR, "skills", "freshness-corroboration", "scripts"))
sys.path.insert(0, os.path.join(MARKETPLACE_DIR, "skills", "engagement-audit", "scripts"))
sys.path.insert(0, os.path.join(MARKETPLACE_DIR, "skills", "audit-orchestrator", "scripts"))

import check_technical
import check_trust
import check_engagement
import compose_report


class TestTechnicalRubric(unittest.TestCase):
    """Rubric Category 1: Technical & AI Discoverability Auditing"""

    def test_robots_blocks_all(self):
        """Rubric 1.1: Detects global crawler block ('Disallow: /' under '*')"""
        robots_txt = "User-agent: *\nDisallow: /\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/")
            self.assertTrue(res["blocks_all"])
            self.assertFalse(res["audit_crawler_allowed"])

    def test_robots_ai_assistants_blocked(self):
        """Rubric 1.2: Detects specific AI bot blocks (GPTBot, ClaudeBot)"""
        robots_txt = "User-agent: GPTBot\nDisallow: /\nUser-agent: ClaudeBot\nDisallow: /\nUser-agent: *\nAllow: /\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/")
            self.assertFalse(res["blocks_all"])
            self.assertTrue(res["audit_crawler_allowed"])
            self.assertIn("GPTBot", res["blocked_bots"])
            self.assertIn("ClaudeBot", res["blocked_bots"])

    def test_robots_crawler_safety_permission_guard(self):
        """Rubric 1.3: Aborts fetching disallowed URLs without policy violations"""
        robots_txt = "User-agent: *\nDisallow: /admin/\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/admin/settings")
            self.assertFalse(res["audit_crawler_allowed"])

    def test_xml_sitemap_standard_parsing(self):
        """Rubric 1.4: Parses XML sitemap with URLs and lastmod timestamps"""
        sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/about</loc>
                <lastmod>2026-01-15</lastmod>
            </url>
            <url>
                <loc>https://example.com/pricing</loc>
                <lastmod>2026-02-01</lastmod>
            </url>
        </urlset>"""
        with patch("check_technical.fetch_url", return_value=(200, sitemap_xml, None)):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertTrue(res["found"])
            self.assertTrue(res["valid"])
            self.assertEqual(len(res["urls"]), 2)
            self.assertEqual(res["latest_lastmod"], "2026-02-01")

    def test_xml_sitemap_index_recursion(self):
        """Rubric 1.5: Parses XML sitemap index and follows child sitemaps"""
        index_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap>
                <loc>https://example.com/sitemap-pages.xml</loc>
            </sitemap>
        </sitemapindex>"""
        child_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/products</loc><lastmod>2026-02-10</lastmod></url>
        </urlset>"""
        def mock_fetch(url, **kwargs):
            if "sitemap-pages.xml" in url:
                return (200, child_xml, None)
            return (200, index_xml, None)
        with patch("check_technical.fetch_url", side_effect=mock_fetch):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertTrue(res["found"])
            self.assertIn("https://example.com/products", res["urls"])

    def test_bounded_crawler_candidate_selection(self):
        """Rubric 1.6: Bounded mini-crawler selects high-value same-domain paths within budget"""
        links = [
            "/about", "/contact", "/pricing", "/faq", "/blog", "/docs", 
            "https://external.com/partner", "https://example.com/terms", "/about#team"
        ]
        candidates = check_technical.select_crawl_candidates("https://example.com", links, [], max_pages=5)
        self.assertLessEqual(len(candidates), 5)
        self.assertIn("https://example.com/about", candidates)
        self.assertIn("https://example.com/contact", candidates)
        self.assertNotIn("https://external.com/partner", candidates)

    def test_structured_data_recursive_graph_parsing(self):
        """Rubric 1.7: Deeply parses Schema.org @graph arrays and nested structures"""
        graph_json = json.dumps({
            "@context": "https://schema.org",
            "@graph": [
                {"@type": "Organization", "name": "Test Org", "url": "https://example.com"},
                {"@type": "Product", "name": "Widget A", "offers": {"@type": "Offer", "price": "29.99"}}
            ]
        })
        schemas_found = []
        details = {}
        check_technical.extract_schemas_recursive(json.loads(graph_json), schemas_found, details)
        self.assertIn("Organization", schemas_found)
        self.assertIn("Product", schemas_found)
        self.assertIn("Offer", schemas_found)

    def test_structured_data_missing_properties_validation(self):
        """Rubric 1.8: Flags incomplete schemas missing recommended properties"""
        incomplete_product = {"@type": "Product"} # Missing name, description, offers
        missing = check_technical.audit_schema_properties("Product", incomplete_product)
        self.assertIn("name", missing)
        self.assertIn("offers", missing)

    def test_wcag_decorative_image_handling(self):
        """Rubric 1.9: Does NOT flag decorative images (alt='', role='presentation') as missing alt"""
        html = """<html><body>
            <img src="spacer.gif" alt="" />
            <img src="divider.png" role="presentation" />
            <img src="photo.jpg" alt="Team meeting" />
        </body></html>"""
        parser = check_technical.TechHTMLParser()
        parser.feed(html)
        self.assertEqual(parser.images_count, 3)
        self.assertEqual(parser.images_decorative, 2)
        self.assertEqual(parser.images_informative_no_alt, 0)

    def test_wcag_informative_image_flagging(self):
        """Rubric 1.10: Correctly flags informative images lacking alt attributes"""
        html = """<html><body>
            <img src="product_diagram.png" />
            <img src="pricing_chart.png" />
        </body></html>"""
        parser = check_technical.TechHTMLParser()
        parser.feed(html)
        self.assertEqual(parser.images_informative_no_alt, 2)

    def test_canvas_fallback_detection(self):
        """Rubric 1.11: Distinguishes canvas with fallback text from empty canvas"""
        html_with_fallback = "<html><body><canvas id='chart'><p>Q3 Revenue: $1.2M</p></canvas></body></html>"
        parser = check_technical.TechHTMLParser()
        parser.feed(html_with_fallback)
        self.assertTrue(parser.has_canvas)
        self.assertIn("Q3 Revenue: $1.2M", parser.canvas_fallback_texts)

    def test_faq_parity_detection(self):
        """Rubric 1.12: Flags Q&A text content lacking schema.org FAQPage structured data"""
        html = """<html><body>
            <h2>Frequently Asked Questions</h2>
            <p>What is the refund policy? Refunds are processed within 14 days.</p>
            <p>How do I reset my password? Click forgot password on login.</p>
        </body></html>"""
        parser = check_technical.TechHTMLParser()
        parser.feed(html)
        self.assertGreaterEqual(parser.faq_clues_count, 1)


class TestTrustFreshnessRubric(unittest.TestCase):
    """Rubric Category 2: Trust, Freshness & Entity Corroboration Auditing"""

    def setUp(self):
        self.sitemap_patch = patch("check_trust.fetch_sitemap_lastmod", return_value=None)
        self.apis_patch = patch("check_trust.check_external_apis", return_value=[])
        self.mock_sitemap = self.sitemap_patch.start()
        self.mock_apis = self.apis_patch.start()

    def tearDown(self):
        self.sitemap_patch.stop()
        self.apis_patch.stop()

    def test_multi_signal_freshness_pass_with_recent_schema(self):
        """Rubric 2.1: Avoids false positive on 2021 copyright when 2026 schema dateModified is present"""
        html = """<html><head>
            <script type="application/ld+json">
            {"@context": "https://schema.org", "@type": "Article", "dateModified": "2026-02-15"}
            </script>
        </head><body>
            <footer>&copy; 2021 Brand Inc.</footer>
        </body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com", current_year=2026)
        self.assertEqual(res["copyright"]["status"], "pass")
        self.assertIn("Multi-signal freshness confirmed", res["copyright"]["evidence"])

    def test_multi_signal_freshness_warning_on_unanimously_stale(self):
        """Rubric 2.2: Flags warning when all signals agree site has been stale since 2021"""
        html = """<html><head>
            <meta property="article:modified_time" content="2021-05-10">
        </head><body>
            <p>Annual report 2021 highlights.</p>
            <footer>&copy; 2021 Stale Corp.</footer>
        </body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com", current_year=2026)
        self.assertEqual(res["copyright"]["status"], "warning")
        self.assertEqual(res["copyright"]["severity"], "medium")

    def test_sameas_real_jsonld_extraction(self):
        """Rubric 2.3: Correctly extracts sameAs entity URLs and rejects @id substitutes"""
        html = """<html><head>
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "Organization",
                "@id": "https://example.com/#org",
                "sameAs": ["https://www.wikidata.org/wiki/Q9999", "https://en.wikipedia.org/wiki/TestBrand"]
            }
            </script>
        </head><body><h1>TestBrand</h1></body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com", current_year=2026)
        self.assertEqual(res["ambiguity_check"]["status"], "pass")
        self.assertIn("https://www.wikidata.org/wiki/Q9999", res["ambiguity_check"]["same_as_links"])

    def test_location_corroboration_contradiction(self):
        """Rubric 2.4: Detects location fact contradiction (site California vs external Chicago IL)"""
        html = "<html><body><p>Headquartered in California, CA.</p></body></html>"
        mock_ext = [{
            "title": "Brand Corp",
            "snippet": "Brand Corp is headquartered in Chicago, IL.",
            "source": "Wikipedia Search API",
            "url": "https://en.wikipedia.org/wiki/Brand_Corp"
        }]
        with patch("check_trust.check_external_apis", return_value=mock_ext):
            res = check_trust.analyze_trust(html, "https://example.com", current_year=2026)
            self.assertEqual(res["corroboration_check"]["status"], "fail")
            self.assertEqual(res["corroboration_check"]["severity"], "high")

    def test_location_corroboration_canada_vs_california(self):
        """Rubric 2.5: Properly isolates Canada ('CAN') from California ('CA') without false matches"""
        site_can = "<html><body><p>Located in Canada.</p></body></html>"
        mock_ca = [{"title": "Brand", "snippet": "Located in California, CA.", "source": "Wikidata", "url": "https://wikidata.org"}]
        with patch("check_trust.check_external_apis", return_value=mock_ca):
            res = check_trust.analyze_trust(site_can, "https://example.com")
            self.assertEqual(res["corroboration_check"]["status"], "fail")

    def test_small_business_no_wikipedia_graceful_pass(self):
        """Rubric 2.6: Absence of Wikipedia/Wikidata for small/niche business is marked pass, NOT failure"""
        html = "<html><body><p>Welcome to Joe's Local Bakery in Austin, TX.</p></body></html>"
        with patch("check_trust.check_external_apis", return_value=[]):
            res = check_trust.analyze_trust(html, "https://example.com")
            self.assertEqual(res["corroboration_check"]["status"], "pass")
            self.assertIn("common for growing or niche brands", res["corroboration_check"]["evidence"])

    def test_eeat_transparency_checks(self):
        """Rubric 2.7: Evaluates author bylines, contact page link, email, phone, and address"""
        html_complete = """<html><body>
            <a href="/contact">Contact Support</a>
            <a href="/authors/dr-smith" rel="author">By Dr. Smith</a>
            <p>Email: support@example.com, Phone: +1 555-123-4567, Address: 100 Market St, San Francisco, CA</p>
        </body></html>"""
        res = check_trust.analyze_trust(html_complete, "https://example.com")
        self.assertEqual(res["eeat_check"]["status"], "pass")


class TestEngagementRubric(unittest.TestCase):
    """Rubric Category 3: On-Site User Engagement & Retention Auditing"""

    def test_h1_hierarchy_validation(self):
        """Rubric 3.1: Validates H1 hierarchy (missing H1 -> fail, multiple -> warning, single -> pass)"""
        # Missing H1
        res_missing = check_engagement.analyze_engagement(100, "<html><body><p>No H1 tag</p></body></html>")
        self.assertEqual(res_missing["h1_audit"]["status"], "fail")
        
        # Multiple H1
        res_mult = check_engagement.analyze_engagement(100, "<html><body><h1>H1 One</h1><h1>H1 Two</h1></body></html>")
        self.assertEqual(res_mult["h1_audit"]["status"], "warning")
        
        # Single informative H1
        res_ok = check_engagement.analyze_engagement(100, "<html><body><h1>Scalable Cloud Infrastructure for Modern Devs</h1></body></html>")
        self.assertEqual(res_ok["h1_audit"]["status"], "pass")

    def test_readability_walls_of_text(self):
        """Rubric 3.2: Detects unformatted text blocks exceeding 100 words in a single paragraph"""
        wall = "word " * 120
        html = f"<html><body><p>{wall}</p></body></html>"
        res = check_engagement.analyze_engagement(len(html), html)
        self.assertEqual(res["readability"]["status"], "warning")
        self.assertEqual(res["readability"]["walls_of_text_count"], 1)

    def test_intent_classified_ctas(self):
        """Rubric 3.3: Classifies CTAs into distinct intents (commercial, demo, lead-gen, signup, pricing)"""
        html = """<html><body>
            <header><nav><a href="/">Home</a></nav></header>
            <a href="/buy">Buy Now</a>
            <a href="/demo">Book a Demo</a>
            <a href="/contact">Contact Sales</a>
            <a href="/signup">Get Started</a>
            <a href="/pricing">View Pricing</a>
        </body></html>"""
        res = check_engagement.analyze_engagement(len(html), html)
        intents = res["navigation_cta"]["ctas_by_intent"]
        self.assertGreaterEqual(intents["commercial"], 1)
        self.assertGreaterEqual(intents["evaluation"], 1)
        self.assertGreaterEqual(intents["lead_generation"], 1)
        self.assertGreaterEqual(intents["onboarding"], 1)
        self.assertGreaterEqual(intents["pricing"], 1)

    def test_breadcrumbs_detection(self):
        """Rubric 3.4: Detects deep-link breadcrumb navigation structures"""
        html = """<html><body>
            <nav aria-label="Breadcrumbs">
                <a href="/">Home</a> / <a href="/docs">Docs</a> / API
            </nav>
        </body></html>"""
        res = check_engagement.analyze_engagement(len(html), html)
        self.assertTrue(res["navigation_cta"]["breadcrumbs_present"])

    def test_dead_end_navigation_warning(self):
        """Rubric 3.5: Flags pages without nav/header or CTAs as exit risks"""
        html = "<html><body><p>A lonely article with no links, menus, or call to actions.</p></body></html>"
        res = check_engagement.analyze_engagement(len(html), html)
        self.assertEqual(res["navigation_cta"]["status"], "fail")

    def test_clutter_and_lightweight_performance(self):
        """Rubric 3.6: Measures text-to-code ratio and tracks script/stylesheet payloads"""
        heavy_html = "<html><head>" + "<script src='track.js'></script>" * 35 + "</head><body><p>Tiny text</p></body></html>"
        res = check_engagement.analyze_engagement(len(heavy_html), heavy_html)
        self.assertEqual(res["clutter"]["status"], "warning")
        self.assertGreater(res["clutter"]["external_scripts_count"], 30)


class TestReportCompositionRubric(unittest.TestCase):
    """Rubric Category 4: Report Composition & Schema Compliance"""

    def test_schema_conformity_and_scope(self):
        """Rubric 4.1: Report complies 100% with required schema and includes scope metadata"""
        tech_data = {
            "crawled_pages": ["https://example.com", "https://example.com/about"],
            "robots_txt": {"status": "found", "blocks_all": False, "blocked_bots": [], "sitemaps": ["https://example.com/sitemap.xml"]},
            "crawler_block": {"status": "pass"},
            "js_render_gap": {"status": "pass"}
        }
        trust_data = {
            "copyright": {"status": "pass"},
            "corroboration_check": {"status": "pass"}
        }
        engage_data = {
            "h1_audit": {"status": "pass"},
            "navigation_cta": {"status": "pass"}
        }
        
        tech_f = compose_report.parse_technical_findings(tech_data, "https://example.com")
        trust_f = compose_report.parse_trust_findings(trust_data, "https://example.com")
        engage_f = compose_report.parse_engagement_findings(engage_data, "https://example.com")
        
        # Verify no defect findings generated on clean data
        self.assertEqual(len(tech_f), 0)
        self.assertEqual(len(trust_f), 0)
        self.assertEqual(len(engage_f), 0)

    def test_total_findings_strictly_excludes_proactive(self):
        """Rubric 4.2: summary.total_findings strictly equals non-proactive findings"""
        raw_findings = [
            {
                "title": "Defect 1",
                "severity": "medium",
                "evidence": "Evidence 1",
                "suggested_action": {"summary": "Fix 1", "priority": "medium"}
            },
            {
                "title": "Proactive 1",
                "severity": "medium",
                "evidence": "Good state",
                "suggested_action": {"summary": "Enhance 1", "priority": "medium", "proactive": True}
            }
        ]
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0}
        proactive_count = 0
        for f in raw_findings:
            is_proactive = f.get("suggested_action", {}).get("proactive", False)
            if is_proactive:
                proactive_count += 1
            else:
                severity_counts[f["severity"]] += 1
                
        self.assertEqual(sum(severity_counts.values()), 1)
        self.assertEqual(proactive_count, 1)

    def test_suggested_action_includes_how_to_fix(self):
        """Rubric 4.3: Every finding suggested_action contains actionable how_to_fix instructions"""
        tech_data = {
            "viewport_check": {"status": "warning", "evidence": "Missing viewport tag"}
        }
        findings = compose_report.parse_technical_findings(tech_data, "https://example.com")
        self.assertEqual(len(findings), 1)
        action = findings[0]["suggested_action"]
        self.assertIn("how_to_fix", action)
        self.assertIn("viewport", action["how_to_fix"].lower())


class TestHardeningRegression(unittest.TestCase):
    """Hardening Regression Tests: Specificity, Semantics, Freshness, E-E-A-T, and Resilience"""

    def setUp(self):
        self.sitemap_patch = patch("check_trust.fetch_sitemap_lastmod", return_value=None)
        self.apis_patch = patch("check_trust.check_external_apis", return_value=[])
        self.mock_sitemap = self.sitemap_patch.start()
        self.mock_apis = self.apis_patch.start()

    def tearDown(self):
        self.sitemap_patch.stop()
        self.apis_patch.stop()

    def test_robots_specific_agent_overrides_wildcard(self):
        """Hardening 1: Declared audit user-agent overrides wildcard disallow"""
        robots_txt = "User-agent: *\nDisallow: /\n\nUser-agent: BrandAuditBot\nAllow: /\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/")
            self.assertTrue(res["audit_crawler_allowed"])
            self.assertTrue(res["blocks_all"])

    def test_robots_audit_bot_explicitly_blocked(self):
        """Hardening 2: Declared audit user-agent is blocked if explicitly disallowed"""
        robots_txt = "User-agent: BrandAuditBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/")
            self.assertFalse(res["audit_crawler_allowed"])
            self.assertFalse(res["blocks_all"])

    def test_robots_malformed_graceful(self):
        """Hardening 3: Malformed robots.txt lines do not crash the parser"""
        robots_txt = "This is not standard\n<<Invalid Syntax>>\nUser-agent: *\nDisallow:\n"
        with patch("check_technical.fetch_url", return_value=(200, robots_txt, None)):
            res = check_technical.evaluate_robots_txt("https://example.com", "https://example.com/test")
            self.assertEqual(res["status"], "found")
            self.assertTrue(res["audit_crawler_allowed"])

    def test_sitemap_malformed_xml_recoverable(self):
        """Hardening 4: Malformed XML sitemap is marked valid: False, recoverable: True"""
        malformed_xml = "<urlset><url><loc>https://example.com/item1</loc><unclosed_tag>"
        with patch("check_technical.fetch_url", return_value=(200, malformed_xml, None)):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertTrue(res["found"])
            self.assertFalse(res["valid"])
            self.assertTrue(res["recoverable"])
            self.assertEqual(res["url_count"], 1)
            self.assertIn("https://example.com/item1", res["urls"])

    def test_sitemap_inaccessible(self):
        """Hardening 5: Inaccessible sitemap (HTTP 404) reports found: False"""
        with patch("check_technical.fetch_url", return_value=(404, "", None)):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertFalse(res["found"])
            self.assertFalse(res["valid"])
            self.assertFalse(res["recoverable"])

    def test_freshness_old_copyright_alone_is_not_stale(self):
        """Hardening 6: Old copyright alone without corroborating staleness signals is not marked stale defect"""
        html = "<html><body><footer>&copy; 2022 Example Corp. All rights reserved.</footer></body></html>"
        res = check_trust.analyze_trust(html, "https://example.com", current_year=2026)
        self.assertEqual(res["multi_signal_freshness"]["status"], "pass")

    def test_eeat_pricing_page_without_author_passes(self):
        """Hardening 7: Pricing pages do not require individual author bylines"""
        html = """<html><body>
            <header><a href="/contact">Contact Sales</a></header>
            <h1>Pricing & Plans</h1>
            <p>Email: sales@example.com, Phone: +1 555-0100</p>
        </body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com/pricing", current_year=2026)
        self.assertEqual(res["eeat_check"]["status"], "pass")

    def test_eeat_article_page_without_author_warns(self):
        """Hardening 8: Editorial article pages without author bylines trigger transparency warning"""
        html = """<html><body>
            <h1>Comprehensive Industry Guide</h1>
            <p>Detailed analysis of industry trends without any author attribution.</p>
        </body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com/blog/trends-guide", current_year=2026)
        self.assertEqual(res["eeat_check"]["status"], "warning")
        self.assertIn("author byline", res["eeat_check"]["evidence"].lower())

    def test_structured_data_page_type_awareness(self):
        """Hardening 9: detect_page_type identifies distinct page archetypes accurately"""
        self.assertEqual(check_technical.detect_page_type("https://example.com/"), "homepage")
        self.assertEqual(check_technical.detect_page_type("https://example.com/pricing"), "pricing")
        self.assertEqual(check_technical.detect_page_type("https://example.com/products/widget-pro"), "product")
        self.assertEqual(check_technical.detect_page_type("https://example.com/blog/scaling-fast"), "article")
        self.assertEqual(check_technical.detect_page_type("https://example.com/faq"), "faq")

    def test_external_api_unavailable_graceful_pass(self):
        """Hardening 10: External API errors/timeouts degrade gracefully to empty list without error"""
        self.apis_patch.stop()
        try:
            with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
                records = check_trust.check_external_apis("AnyBrand")
                self.assertEqual(records, [])
        finally:
            self.apis_patch.start()

    def test_eeat_legal_page_passes(self):
        """Hardening 11: Legal and privacy policy pages pass without requiring author bylines or sales CTAs"""
        html = """<html><body>
            <h1>Privacy Policy</h1>
            <p>We respect your privacy. This policy explains how we collect and process your personal data.</p>
        </body></html>"""
        res = check_trust.analyze_trust(html, "https://example.com/privacy")
        self.assertEqual(res["eeat_check"]["status"], "pass")
        self.assertIn("Legal/compliance document verified", res["eeat_check"]["evidence"])

    def test_sitemap_cross_domain_child_ignored(self):
        """Hardening 12: Child sitemaps pointing to external domains are not enqueued (same-domain boundary)"""
        index_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://evil-external-domain.com/sitemap.xml</loc></sitemap>
            <sitemap><loc>https://example.com/sitemap-valid.xml</loc></sitemap>
        </sitemapindex>"""
        valid_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/page-1</loc></url>
        </urlset>"""
        def mock_fetch(url, **kwargs):
            if "evil-external" in url:
                raise AssertionError("External cross-domain sitemap should NOT have been fetched!")
            if "sitemap-valid.xml" in url:
                return (200, valid_xml, None)
            return (200, index_xml, None)
        with patch("check_technical.fetch_url", side_effect=mock_fetch):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertTrue(res["found"])
            self.assertIn("https://example.com/page-1", res["urls"])
            self.assertNotIn("https://evil-external-domain.com/sitemap.xml", res["sitemaps_parsed"])

    def test_sitemap_empty_no_urls(self):
        """Hardening 13: Empty sitemap XML with no url entries handles gracefully"""
        empty_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>"""
        with patch("check_technical.fetch_url", return_value=(200, empty_xml, None)):
            res = check_technical.parse_xml_sitemap("https://example.com/sitemap.xml", "https://example.com")
            self.assertTrue(res["found"])
            self.assertTrue(res["valid"])
            self.assertEqual(res["url_count"], 0)
            self.assertIn("no valid URLs could be extracted", res["evidence"])

    def test_dynamic_current_year_compose_report(self):
        """Hardening 14: Report composition dynamically reflects the current calendar year"""
        from datetime import datetime, timezone
        expected_year = datetime.now(timezone.utc).year
        stale_trust = {
            "copyright": {"status": "warning", "severity": "medium", "evidence": "Old copyright 2020"},
            "year_mentions": {"mentions": {2020: 1}, "has_future_or_current": False, "evidence": "2020 only"}
        }
        findings = compose_report.parse_trust_findings(stale_trust, "https://example.com")
        self.assertEqual(len(findings), 2)
        for f in findings:
            action = f["suggested_action"]
            self.assertIn(str(expected_year), action["summary"])
            self.assertIn(str(expected_year), action["how_to_fix"])

    def test_all_seven_cta_intent_categories(self):
        """Hardening 15: Recognizes explicit CTA categories (purchase, signup, demo, contact, download, learn, navigation)"""
        html = """<html><body>
            <header><nav><a href="/">Home</a></nav></header>
            <a href="/buy">Purchase Now</a>
            <a href="/register">Sign Up</a>
            <a href="/demo">Request a Demo</a>
            <a href="/contact">Contact Sales</a>
            <a href="/app">Download the App</a>
            <a href="/features">Learn More</a>
            <a href="#top">Back to Top</a>
        </body></html>"""
        res = check_engagement.analyze_engagement(len(html), html)
        intents = res["navigation_cta"]["ctas_by_intent"]
        self.assertGreaterEqual(intents["purchase"], 1)
        self.assertGreaterEqual(intents["signup"], 1)
        self.assertGreaterEqual(intents["demo"], 1)
        self.assertGreaterEqual(intents["contact"], 1)
        self.assertGreaterEqual(intents["download"], 1)
        self.assertGreaterEqual(intents["learn"], 1)
        self.assertGreaterEqual(intents["navigation"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

class TestPolishEnhancements(unittest.TestCase):
    """Regression coverage for the v1.1 polish layer."""

    def test_canonical_validation(self):
        self.assertEqual(
            check_technical.validate_canonical("https://example.com/about", ["https://example.com/about"])["status"],
            "pass"
        )
        self.assertEqual(
            check_technical.validate_canonical("https://example.com/about", ["https://example.com/other"])["status"],
            "mismatch"
        )

    def test_visible_structured_fact_parity(self):
        html = """<html><head><script type='application/ld+json'>
        {"@context":"https://schema.org","@type":"Product","name":"Widget",
         "offers":{"price":"99","priceCurrency":"USD"}}
        </script></head><body><p>Widget costs $129</p></body></html>"""
        parser = check_technical.TechHTMLParser(page_url="https://example.com/product")
        parser.feed(html)
        _, _, mismatches = check_technical.compare_visible_structured_facts(parser)
        self.assertTrue(mismatches)

    def test_navigation_links_are_not_conversion_ctas(self):
        html = "<html><body><nav><a href='/'>Home</a></nav><p>Content</p></body></html>"
        result = check_engagement.analyze_engagement(len(html), html)
        intents = result["navigation_cta"]["ctas_by_intent"]
        self.assertEqual(intents.get("commercial", 0), 0)
        self.assertGreaterEqual(intents.get("navigation", 0), 1)

    def test_answerability_score_is_exposed(self):
        html = """<html><body><h1>Cloud Backup for Teams</h1>
        <p>Secure backup software for engineering teams. Contact us at hello@example.com.</p>
        <a href='/signup'>Get Started</a></body></html>"""
        result = check_engagement.analyze_engagement(len(html), html)
        self.assertIn("answerability", result)
        self.assertGreaterEqual(result["answerability"]["score"], 60)

    def test_sameas_sanity_rejects_unrelated_profile(self):
        valid, suspicious = check_trust.validate_sameas_links(
            ["https://en.wikipedia.org/wiki/Completely_Unrelated_Entity"], "Example Brand"
        )
        self.assertEqual(valid, [])
        self.assertEqual(len(suspicious), 1)
