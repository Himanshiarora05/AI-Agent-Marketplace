import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in [
    ROOT / 'skills' / 'crawl-render-audit' / 'scripts',
    ROOT / 'skills' / 'engagement-audit' / 'scripts',
    ROOT / 'skills' / 'freshness-corroboration' / 'scripts',
    ROOT / 'skills' / 'audit-orchestrator' / 'scripts',
]:
    sys.path.insert(0, str(p))

import check_technical
import check_engagement
import check_trust
import compose_report


class TestAIReadinessPolish(unittest.TestCase):
    def test_fact_normalization_avoids_phone_format_false_positive(self):
        html = '''<html><body><p>Call +1 (555) 123-4567</p>
        <script type="application/ld+json">{"@type":"Organization","telephone":"+15551234567"}</script></body></html>'''
        p = check_technical.TechHTMLParser('https://example.com'); p.feed(html)
        _, _, mismatches = check_technical.compare_visible_structured_facts(p)
        self.assertFalse(any(x['fact'] == 'phones' for x in mismatches))

    def test_price_normalization_avoids_decimal_false_positive(self):
        html = '''<html><body><p>Price: $99.00</p>
        <script type="application/ld+json">{"@type":"Offer","price":"99","priceCurrency":"USD"}</script></body></html>'''
        p = check_technical.TechHTMLParser('https://example.com'); p.feed(html)
        _, _, mismatches = check_technical.compare_visible_structured_facts(p)
        self.assertFalse(any(x['fact'] == 'prices' for x in mismatches))

    def test_semantic_candidate_selection_uses_anchor_text(self):
        selected = check_technical.select_crawl_candidates(
            'https://example.com/',
            ['/plans-and-billing', '/solutions', '/company'],
            [],
            max_pages=4,
            page_metadata={
                'https://example.com/plans-and-billing': {'anchor_text':'See pricing'},
                'https://example.com/solutions': {'anchor_text':'Explore solutions'},
                'https://example.com/company': {'anchor_text':'About our company'},
            }
        )
        self.assertIn('https://example.com/plans-and-billing', selected)
        self.assertIn('https://example.com/solutions', selected)

    def test_schema_page_mismatch_is_exposed(self):
        mismatch = check_technical.schema_page_mismatch('product', ['Organization'])
        self.assertTrue(mismatch)
        self.assertIn('product', [x.lower() for x in mismatch])

    def test_schema_quality_is_explainable(self):
        q = check_technical.schema_quality('product', ['Product'], {})
        self.assertEqual(q['score'], 100)
        self.assertEqual(q['missing'], [])

    def test_redirect_analysis_clean(self):
        r = check_technical.analyze_redirect_chain('https://example.com/', {'_final_url':'https://example.com/','_redirect_chain':[]})
        self.assertEqual(r['status'], 'pass')
        self.assertEqual(r['hops'], 0)

    def test_redirect_analysis_warns_long_chain(self):
        chain=[{'from':'https://example.com/','to':'https://example.com/a','status':301},
               {'from':'https://example.com/a','to':'https://example.com/b','status':302},
               {'from':'https://example.com/b','to':'https://example.com/','status':301}]
        r=check_technical.analyze_redirect_chain('https://example.com/', {'_final_url':'https://example.com/','_redirect_chain':chain})
        self.assertEqual(r['status'],'warning')
        self.assertEqual(r['hops'],3)

    def test_answerability_has_quote_readiness(self):
        html='''<title>Acme Analytics Platform</title><h1>Acme Analytics Platform for Retail Teams</h1>
        <p>Acme is a software platform that helps retail teams understand customer demand.</p>
        <p>Who is Acme for? Acme is designed for retail teams and growing businesses.</p>
        <p>Contact sales at sales@example.com.</p><a href="/start">Get Started</a>'''
        r=check_engagement.analyze_engagement(len(html),html)
        self.assertIn('quote_readiness_score',r['answerability'])
        self.assertGreaterEqual(r['answerability']['quote_readiness_score'],50)

    def test_deep_link_context_score(self):
        html='''<title>Acme Product</title><header><nav><a href="/">Home</a><a href="/pricing">Pricing</a></nav></header>
        <nav aria-label="Breadcrumbs"><a href="/">Home</a><a href="/products">Products</a></nav>
        <h1>Acme Product</h1><p>Acme is a product for teams.</p><a href="/start">Get Started</a><footer>Acme</footer>'''
        r=check_engagement.analyze_engagement(len(html),html)
        self.assertGreaterEqual(r['deep_link_context']['score'],90)

    def test_semantic_cta_exploration_is_detected(self):
        intents=check_engagement.classify_cta('Explore solutions','/solutions',False)
        self.assertIn('learn',intents)

    def test_entity_confidence_is_present(self):
        html='''<title>Example Analytics</title><meta name="description" content="Example Analytics platform for teams.">
        <script type="application/ld+json">{"@type":"Organization","name":"Example Analytics","url":"https://example.com","sameAs":["https://www.wikidata.org/wiki/Q123"]}</script>'''
        def no_external(_): return []
        r=check_trust.analyze_trust(html,'https://example.com',current_year=2026,external_apis_fn=no_external)
        self.assertIn('entity_confidence',r)
        self.assertIn('score',r['entity_confidence'])

    def test_entity_confidence_warning_on_conflict(self):
        html='<title>Mock Brand</title><p>Headquartered in California.</p>'
        def external(_): return [{'title':'Mock Brand','snippet':'Headquartered in Illinois.','source':'Wikipedia Search API','url':'https://en.wikipedia.org/wiki/Mock_Brand'}]
        r=check_trust.analyze_trust(html,'https://mockbrand.example',current_year=2026,external_apis_fn=external)
        self.assertEqual(r['corroboration_check']['status'],'fail')
        self.assertEqual(r['entity_confidence']['status'],'warning')

    def test_composer_priority_actions_and_total_items(self):
        with tempfile.TemporaryDirectory() as d:
            tech=Path(d)/'t.json'; trust=Path(d)/'r.json'; eng=Path(d)/'e.json'; out=Path(d)/'o.json'
            tech.write_text(json.dumps({'robots_txt':{'status':'found','blocks_all':False,'blocked_bots':[],'sitemaps':[],'evidence':'ok'},'crawler_block':{'status':'pass','evidence':'ok'},'structured_data':{'status':'pass','evidence':'ok'},'crawl_scope':{'pages_successfully_crawled':2},'redirect_check':{'status':'warning','evidence':'3 hops','confidence':.98},'page_graph':{'potential_orphans':['https://example.com/pricing'],'evidence':'one orphan'},'fact_parity':{'status':'pass'},'canonical_check':{'status':'pass'}}))
            trust.write_text(json.dumps({'copyright':{'status':'pass'},'multi_signal_freshness':{'status':'pass'},'eeat_check':{'status':'pass'},'corroboration_check':{'status':'pass'},'ambiguity_check':{'status':'pass'},'entity_confidence':{'status':'pass'}}))
            eng.write_text(json.dumps({'h1_audit':{'status':'pass'},'readability':{'status':'pass'},'navigation_cta':{'status':'pass'},'clutter':{'status':'pass'},'answerability':{'status':'warning','evidence':'low answerability','confidence':.88},'deep_link_context':{'status':'warning','evidence':'weak deep link','confidence':.9}}))
            import subprocess
            subprocess.check_call([sys.executable,str(ROOT/'skills/audit-orchestrator/scripts/compose_report.py'),'--site','example.com','--technical',str(tech),'--trust',str(trust),'--engagement',str(eng),'--output',str(out)])
            report=json.loads(out.read_text())
            self.assertIn('priority_actions',report)
            self.assertEqual(report['summary']['total_items'],len(report['findings']))
            self.assertEqual(report['summary']['total_findings'],sum(report['summary'][k] for k in ('critical','high','medium')))

    def test_required_report_fields_are_preserved(self):
        f={'id':'F-001','title':'Example','category':'technical','severity':'high','evidence':'Evidence','suggested_action':{'summary':'Fix it','priority':'high','how_to_fix':'Do X'}}
        self.assertEqual(set(f),{'id','title','category','severity','evidence','suggested_action'})

    def test_no_fake_adobe_score_language(self):
        text=(ROOT/'README.md').read_text().lower()
        self.assertIn('internal diagnostic',text)

    def test_marketplace_has_exactly_one_entrypoint(self):
        m=json.loads((ROOT/'marketplace.json').read_text())
        entries=[x for x in m['skills'] if x.get('entrypoint') is True]
        self.assertEqual(len(entries),1)

    def test_skill_frontmatter_names_match_ids(self):
        m=json.loads((ROOT/'marketplace.json').read_text())
        for item in m['skills']:
            text=(ROOT/item['path']/ 'SKILL.md').read_text()
            first=text.split('---',2)[1]
            import re
            match=re.search(r'^name:\s*([^\n]+)',first,re.M)
            self.assertIsNotNone(match)
            self.assertEqual(match.group(1).strip(),item['id'])

    def test_engagement_multi_page_isolates_deep_link_failure(self):
        pages={
            'https://example.com/':'<html><header><nav><a href="/pricing">Pricing</a></nav></header><h1>Acme Cloud Backup for Teams</h1><p>Secure backup software for teams.</p><a href="/start">Get Started</a><footer>Acme</footer></html>',
            'https://example.com/article':'<html><body><h1>Old article</h1><p>'+('word '*120)+'</p></body></html>'
        }
        def fetch(u):
            h=pages[u]; return len(h),h
        r=check_engagement.analyze_engagement_pages(list(pages),fetch_fn=fetch,max_pages=6)
        self.assertEqual(r['pages_checked'],2)
        self.assertIn('https://example.com/article',r['readability']['affected_pages'])
        self.assertIn('page_reports',r)

    def test_composer_has_separate_quote_readiness_signal(self):
        data={'answerability':{'status':'pass','score':100,'quote_readiness_score':20,'confidence':.9,'evidence':'answerability good'}}
        fs=compose_report.parse_engagement_findings(data,'https://example.com')
        self.assertEqual(len(fs),1)
        self.assertIn('quote readiness',fs[0]['title'].lower())

    def test_trust_multi_page_preserves_page_level_freshness(self):
        pages={
            'https://example.com/':'<html><head><title>Acme</title></head><body><p>Updated on: September 2026</p><a href="/contact">Contact</a><p>hello@example.com</p></body></html>',
            'https://example.com/article':'<html><head><title>Old Acme Article</title><script type="application/ld+json">{"@type":"Article","dateModified":"2021-01-01"}</script></head><body><p>Published on: January 2021</p><p>© 2021 Acme</p></body></html>'
        }
        import check_trust
        from unittest.mock import patch
        def fake_fetch(u):
            return pages[u], None
        with patch.object(check_trust, 'fetch_page_with_headers', side_effect=fake_fetch), patch.object(check_trust, 'robots_allows', return_value=True), patch.object(check_trust, 'fetch_sitemap_lastmod', return_value=None):
            r=check_trust.analyze_trust_pages(list(pages), current_year=2026, primary_external=lambda _brand: [], max_pages=6)
        self.assertEqual(r['pages_checked'],2)
        self.assertIn('https://example.com/article', r['multi_signal_freshness']['affected_pages'])
        self.assertEqual(len(r['page_reports']),2)


if __name__=='__main__':
    unittest.main(verbosity=2)

    def test_composer_marks_missing_subaudit_as_partial(self):
        """A failed/missing sub-audit must be visible and must not receive a fake proactive pass."""
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            tech = Path(td) / "technical.json"
            tech.write_text(json.dumps({"robots_txt": {}, "crawl_scope": {"pages_successfully_crawled": 1}, "js_render_gap": {"status": "unavailable"}}), encoding="utf-8")
            result = subprocess.run([
                sys.executable, compose_report.__file__, "--site", "https://example.com",
                "--technical", str(tech), "--trust", str(Path(td) / "missing-trust.json"),
                "--output", str(Path(td) / "report.json")
            ], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0)
            report = json.loads((Path(td) / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["execution"]["partial"])
            self.assertIn("trust", report["execution"]["missing_categories"])
            self.assertFalse(any(f.get("category") == "trust" and f.get("proactive") for f in report["findings"]))

    def test_network_failure_is_unavailable_not_antibot(self):
        """A status-0 transport failure is not falsely reported as crawler blocking."""
        html = ""
        with patch("check_technical.fetch", return_value=(0, "temporary dns failure", {"_error": "Temporary failure in name resolution"})):
            result = check_technical.audit_site("https://example.com")
            self.assertEqual(result["crawler_block"]["status"], "unavailable")
            self.assertNotIn("anti-bot", result["crawler_block"]["evidence"].lower())
