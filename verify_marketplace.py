#!/usr/bin/env python3
"""
Verification Script for Brand AI-Readiness Audit Marketplace
Launches an offline mock HTTP server, executes the audit pipeline end-to-end,
and validates findings output against the required schema.
Can be executed directly from the marketplace root:
    python verify_marketplace.py
"""

import http.server
import socketserver
import threading
import subprocess
import json
import os
import sys
import time
import re
import zipfile
from unittest.mock import patch, MagicMock

PORT = 8999
MOCK_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Mock Brand Page | Enterprise Solutions</title>
</head>
<body>
    <h1>Mock Brand</h1>
    <h1>Another H1 tag</h1> <!-- multiple H1 warning -->
    
    <p>This is a paragraph containing a lot of text designed to look like a wall of text so that our engagement audit script detects it properly. We need to exceed 100 words in this single paragraph block to trigger the warning. Let's add some sentences about search visibility, AI assistant discovery, user experience, site readability, and layout optimization. We will continue writing to reach the threshold limit. Crawlers fetch content, indexes store it, and LLMs summarize it. A clean website structure with proper heading hierarchies, descriptive link text, and prominent Call-to-Action elements ensures visitors don't bounce. This is word number eighty, ninety, and now we are well over one hundred words in this paragraph.</p>
    
    <p>Short paragraph is fine.</p>
    
    <!-- We have questions to trigger FAQ missing check -->
    <p>What is Mock Brand's main offering? Mock Brand provides enterprise logistics. How do I contact Mock Brand? You can reach us at contact@mockbrand.com.</p>
    
    <!-- Location mentions California to conflict with Chicago IL mock external search -->
    <p>Our office is located in California, CA.</p>
    
    <img src="logo.png"> <!-- missing alt warning -->
    <img src="banner.jpg" alt="Company Banner"> <!-- fine -->
    <canvas id="graphCanvas"></canvas> <!-- canvas warning -->
    
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "Organization",
      "name": "Mock Brand",
      "url": "https://localhost:8999/search?q=mock&ref=footer"
    }
    </script>
    
    <footer>
        <p>© 2021 Mock Brand LLC. All rights reserved.</p> <!-- stale copyright warning (current is 2026) -->
    </footer>
</body>
</html>
"""

MOCK_ROBOTS = """User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: *
Disallow: /private-admin/
"""

class MockHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(MOCK_ROBOTS.encode('utf-8'))
        elif self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(MOCK_HTML.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            
    def log_message(self, format, *args):
        pass # Suppress logging to keep console clean

def run_server():
    handler = MockHTTPHandler
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        httpd.serve_forever()

def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def clean_generated_artifacts(marketplace_dir):
    for root,dirs,files in os.walk(marketplace_dir, topdown=False):
        for name in files:
            if name.endswith('.pyc'):
                try: os.remove(os.path.join(root,name))
                except OSError: pass
        for name in dirs:
            if name == '__pycache__':
                try:
                    import shutil; shutil.rmtree(os.path.join(root,name))
                except OSError: pass


def validate_package_structure(marketplace_dir):
    manifest_path=os.path.join(marketplace_dir,'marketplace.json')
    assert os.path.isfile(manifest_path), 'Missing top-level marketplace.json'
    with open(manifest_path,encoding='utf-8') as f: manifest=json.load(f)
    assert isinstance(manifest.get('skills'),list) and manifest['skills'], 'Manifest must list skills'
    entries=[x for x in manifest['skills'] if x.get('entrypoint') is True]
    assert len(entries)==1, 'Manifest must have exactly one entrypoint'
    ids=set()
    for item in manifest['skills']:
        sid=item.get('id'); rel=item.get('path')
        assert sid and sid not in ids, f'Invalid/duplicate skill id: {sid}'
        ids.add(sid)
        skill_dir=os.path.join(marketplace_dir,rel)
        skill_file=os.path.join(skill_dir,'SKILL.md')
        assert os.path.isdir(skill_dir), f'Missing skill directory: {rel}'
        assert os.path.isfile(skill_file), f'Missing SKILL.md: {rel}'
        text=open(skill_file,encoding='utf-8').read()
        assert text.startswith('---'), f'{sid}: missing YAML frontmatter'
        fm=text.split('---',2)[1]
        m=re.search(r'^name:\s*([^\n]+)',fm,re.M)
        d=re.search(r'^description:\s*(.+)',fm,re.M)
        assert m and m.group(1).strip()==sid, f'{sid}: frontmatter name must match manifest id'
        assert d and d.group(1).strip(), f'{sid}: missing description'
    readme=os.path.join(marketplace_dir,'README.md')
    assert os.path.isfile(readme), 'Missing root README.md'
    assert os.path.isfile(os.path.join(marketplace_dir,'RUBRIC_MAPPING.md')), 'Missing rubric traceability map'
    for root,dirs,files in os.walk(marketplace_dir):
        assert '__pycache__' not in root, f'Package contains __pycache__: {root}'
        for name in files:
            assert not name.endswith('.pyc'), f'Package contains compiled artifact: {name}'
    return True


def test_audit():
    # Start the mock server in a daemon thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1) # Wait for server to start
    
    target_url = f"http://localhost:{PORT}/"
    os.environ["BRAND_AUDIT_LOCAL_FIXTURE"] = str(PORT)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(base_dir, "skills")):
        marketplace_dir = base_dir
        workspace_dir = base_dir
    else:
        workspace_dir = base_dir
        marketplace_dir = os.path.join(base_dir, "brand-ai-readiness-audit")
    
    clean_generated_artifacts(marketplace_dir)
    validate_package_structure(marketplace_dir)
    print('Marketplace package structure validation: PASS!')

    # Paths to outputs
    tech_out = "tech_findings.json"
    trust_out = "trust_findings.json"
    engage_out = "engagement_findings.json"
    final_report_out = "final_audit_report.json"
    
    # Generate mock corroboration fixture if missing
    mock_corrob_created = False
    mock_corrob_path = os.path.join(workspace_dir, "mock_corroboration.json")
    if not os.path.exists(mock_corrob_path):
        mock_data = {
            "external_records": [
                {
                    "title": "Mock Brand Chicago LLC",
                    "snippet": "Mock Brand Chicago is a logistics firm headquartered in Chicago, Illinois. Led by CEO John Smith.",
                    "source": "Wikipedia Search API",
                    "url": "https://en.wikipedia.org/wiki/Mock_Brand_Chicago"
                }
            ]
        }
        with open(mock_corrob_path, "w", encoding="utf-8") as f:
            json.dump(mock_data, f, indent=2)
        mock_corrob_created = True
    
    try:
        # 0. Unit test the fact-level JS render gap logic
        print("Unit testing fact-level JS render gap...")
        mock_html = "<html><head><title>Mock Site</title></head><body><h1>Mock Site</h1></body></html>"
        
        # Pre-inject playwright mocks into sys.modules to prevent ModuleNotFoundError
        mock_playwright = MagicMock()
        mock_sync = mock_playwright.sync_playwright
        mock_p = mock_sync.return_value.__enter__.return_value
        mock_browser = mock_p.chromium.launch.return_value
        mock_page = mock_browser.new_context.return_value.new_page.return_value
        mock_page.content.return_value = "<html><body><h1>Mock Brand</h1><p>Contact us at +1 555-555-0199 or price is $99</p></body></html>"
        mock_page.locator.return_value.inner_text.return_value = "Mock Brand Contact us at +1 555-555-0199 or price is $99"
        
        sys.modules["playwright"] = mock_playwright
        sys.modules["playwright.sync_api"] = mock_playwright
        
        sys.path.append(os.path.join(marketplace_dir, "skills", "crawl-render-audit", "scripts"))
        import check_technical
        
        check_technical.playwright_available = True
        
        findings = check_technical.analyze_technical(target_url)
        # Clean up sys.modules so it doesn't leak into subsequent real runs
        sys.modules.pop("playwright", None)
        sys.modules.pop("playwright.sync_api", None)
        check_technical.playwright_available = False # reset
        
        assert "js_render_gap" in findings
        print("Fact-level JS render gap unit test: PASS!")

        # 0.1 Unit test California vs Canada location matching
        sys.path.append(os.path.join(marketplace_dir, "skills", "freshness-corroboration", "scripts"))
        import check_trust
        
        print("Unit testing Canada vs California location conflict...")
        site_html_canada = "<html><body><p>Our office is located in Canada.</p></body></html>"
        mock_external_ca = [
            {
                "title": "Mock Brand",
                "snippet": "Mock Brand is located in California, CA.",
                "source": "Wikipedia Search API",
                "url": "https://en.wikipedia.org/wiki/Mock_Brand"
            }
        ]
        with patch("check_trust.check_external_apis", return_value=mock_external_ca):
            res = check_trust.analyze_trust(site_html_canada, "http://localhost")
            corrob = res.get("corroboration_check", {})
            assert corrob.get("status") == "fail", f"Expected conflict status 'fail', got {corrob.get('status')}"
            assert "Fact contradiction detected" in corrob.get("evidence"), "Should report location contradiction evidence"
            print("Canada (site) vs California (external) conflict check: PASS!")
            
        site_html_ca = "<html><body><p>Our office is located in California, CA.</p></body></html>"
        mock_external_canada = [
            {
                "title": "Mock Brand",
                "snippet": "Mock Brand is located in Canada.",
                "source": "Wikipedia Search API",
                "url": "https://en.wikipedia.org/wiki/Mock_Brand"
            }
        ]
        with patch("check_trust.check_external_apis", return_value=mock_external_canada):
            res = check_trust.analyze_trust(site_html_ca, "http://localhost")
            corrob = res.get("corroboration_check", {})
            assert corrob.get("status") == "fail", f"Expected conflict status 'fail', got {corrob.get('status')}"
            assert "Fact contradiction detected" in corrob.get("evidence"), "Should report location contradiction evidence"
            print("California (site) vs Canada (external) conflict check: PASS!")

        # 1. Run technical check
        tech_cmd = f'python "{os.path.join(marketplace_dir, "skills", "crawl-render-audit", "scripts", "check_technical.py")}" {target_url} --output {tech_out}'
        print(f"Running Technical Audit: {tech_cmd}")
        code, out, err = run_command(tech_cmd)
        if code != 0:
            print(f"Technical Audit Failed!\nErr: {err}")
            return False
            
        with open(tech_out, 'r', encoding='utf-8') as f:
            tech_data = json.load(f)
        assert tech_data["structured_data"]["status"] != "fail", f"Structured data check failed: {tech_data['structured_data']['evidence']}"
        assert "Organization" in tech_data["structured_data"]["schemas_found"], "Expected Organization schema to be parsed successfully"
        print("Structured data ampersand regression test: PASS!")
            
        # 2. Run trust check
        trust_cmd = f'python "{os.path.join(marketplace_dir, "skills", "freshness-corroboration", "scripts", "check_trust.py")}" {target_url} --current-year 2026 --mock-data "{mock_corrob_path}" --output {trust_out}'
        print(f"Running Trust Audit: {trust_cmd}")
        code, out, err = run_command(trust_cmd)
        if code != 0:
            print(f"Trust Audit Failed!\nErr: {err}")
            return False
            
        # 3. Run engagement check
        engage_cmd = f'python "{os.path.join(marketplace_dir, "skills", "engagement-audit", "scripts", "check_engagement.py")}" {target_url} --output {engage_out}'
        print(f"Running Engagement Audit: {engage_cmd}")
        code, out, err = run_command(engage_cmd)
        if code != 0:
            print(f"Engagement Audit Failed!\nErr: {err}")
            return False
            
        # 4. Run composer
        compose_cmd = f'python "{os.path.join(marketplace_dir, "skills", "audit-orchestrator", "scripts", "compose_report.py")}" --site "localhost" --technical {tech_out} --trust {trust_out} --engagement {engage_out} --output {final_report_out}'
        print(f"Running Orchestrator Composer: {compose_cmd}")
        code, out, err = run_command(compose_cmd)
        if code != 0:
            print(f"Composer Failed!\nErr: {err}")
            return False
            
        # 5. Validate Output Schema
        with open(final_report_out, 'r', encoding='utf-8') as f:
            report = json.load(f)
            
        print("\n--- Final Consolidated Report Preview ---")
        print(json.dumps(report, indent=2))
        print("----------------------------------------\n")
        
        # Schema assertions
        assert report["site"] == "localhost", "Site name mismatch"
        assert "audited_at" in report, "Missing audited_at"
        assert "summary" in report, "Missing summary"
        assert "findings" in report, "Missing findings"
        
        summary = report["summary"]
        assert "total_findings" in summary, "Missing total_findings in summary"
        assert "critical" in summary, "Missing critical in summary"
        assert "high" in summary, "Missing high in summary"
        assert "medium" in summary, "Missing medium in summary"
        assert "proactive_suggestions_count" in summary, "Missing proactive_suggestions_count in summary"
        assert "total_items" in summary, "Missing total_items in summary"
        assert "priority_actions" in report, "Missing priority_actions"
        
        findings = report["findings"]
        assert len(findings) == summary["total_items"], "Total item count mismatch"
        assert summary["total_findings"] == summary["critical"] + summary["high"] + summary["medium"], "Defect severity counts do not sum to total_findings"
        assert summary["total_items"] == summary["total_findings"] + summary["proactive_suggestions_count"], "Total findings count mismatch"
        
        finding_titles = [f["title"] for f in findings]
        print(f"Captured Finding Titles: {finding_titles}")
        
        # Verify signal findings exist
        assert "Missing Mobile Viewport Metadata tag" in finding_titles, "Missing Viewport check finding"
        assert "Questions detected in text but missing FAQPage structured data" in finding_titles, "Missing FAQ check finding"
        assert "Missing E-E-A-T expertise or contact transparency signals" in finding_titles, "Missing EEAT check finding"
        assert "Low Web Agreement / Fact Contradiction" in finding_titles, "Missing Corroboration check finding"
        assert "Entity Ambiguity / Mistaken Identity Risk" in finding_titles, "Missing Ambiguity check finding"
        
        for idx, f in enumerate(findings):
            assert "id" in f, f"Finding {idx} missing id"
            assert f["id"].startswith("F-"), f"Finding {idx} has invalid ID prefix"
            assert "title" in f, f"Finding {idx} missing title"
            assert "severity" in f, f"Finding {idx} missing severity"
            assert f["severity"] in ["critical", "high", "medium"], f"Finding {idx} has invalid severity"
            assert "evidence" in f, f"Finding {idx} missing evidence"
            assert "suggested_action" in f, f"Finding {idx} missing suggested_action"
            assert "summary" in f["suggested_action"], f"Finding {idx} suggested_action missing summary"
            assert "priority" in f["suggested_action"], f"Finding {idx} suggested_action missing priority"
            
        print("Schema and signal assertions: PASS!")
        
        # 6. Test Proactive Suggestions Injection on Clean Reports
        print("\n--- Testing Proactive Suggestions Injection on Clean Data ---")
        clean_tech = "clean_tech.json"
        clean_trust = "clean_trust.json"
        clean_engage = "clean_engage.json"
        clean_report = "clean_report.json"
        
        # Write clean mock data (no critical/high findings)
        with open(clean_tech, "w") as f:
            json.dump({"viewport_check": {"status": "pass", "evidence": "OK"}, "js_render_gap": {"status": "pass", "evidence": "OK"}}, f)
        with open(clean_trust, "w") as f:
            json.dump({"copyright": {"status": "pass", "evidence": "OK"}}, f)
        with open(clean_engage, "w") as f:
            json.dump({"h1_audit": {"status": "pass", "evidence": "OK"}}, f)
            
        clean_compose_cmd = f'python "{os.path.join(marketplace_dir, "skills", "audit-orchestrator", "scripts", "compose_report.py")}" --site "clean.com" --technical {clean_tech} --trust {clean_trust} --engagement {clean_engage} --output {clean_report}'
        code, out, err = run_command(clean_compose_cmd)
        
        with open(clean_report, 'r', encoding='utf-8') as f:
            rep = json.load(f)
            
        clean_findings = rep["findings"]
        print(f"Clean Run Finding Titles: {[f['title'] for f in clean_findings]}")
        
        # Verify counts structure on clean run
        assert rep["summary"]["total_findings"] == 0, f"Expected 0 total defect findings on clean run, got {rep['summary']['total_findings']}"
        assert rep["summary"]["proactive_suggestions_count"] == 3, f"Expected 3 proactive suggestions on clean run, got {rep['summary']['proactive_suggestions_count']}"
        
        # Verify proactive suggestions are present and tagged
        proactive_titles = [f["title"] for f in clean_findings if f["suggested_action"].get("proactive") is True]
        assert len(proactive_titles) == 3, f"Expected 3 proactive suggestions, found {len(proactive_titles)}"
        assert "Proactive AI Answerability: Add Answer-First Content" in proactive_titles
        assert "Proactive Brand Trust: Strengthen Verified Entity Signals" in proactive_titles
        assert "Proactive Engagement: Add Smart Navigation Anchor Links for AI Deep-Citations" in proactive_titles
        print("Proactive Suggestions Injection: PASS!")
        
        # 7. Run comprehensive rubric + polish/generalization suites
        for test_file in ["test_all_rubric_cases.py", "test_round3_polish.py"]:
            test_path=os.path.join(marketplace_dir,"tests",test_file)
            if os.path.exists(test_path):
                print(f"\n--- Running {test_file} ---")
                code,out,err=run_command(f'python "{test_path}"')
                if code != 0:
                    print(f"Test suite failed: {test_file}\nErr: {err}\nOut: {out}")
                    return False
                print(f"{test_file}: ALL PASS!")
        
        # Cleanup clean mock files
        for f in [clean_tech, clean_trust, clean_engage, clean_report]:
            if os.path.exists(f):
                os.remove(f)
                
        clean_generated_artifacts(marketplace_dir)
        print("\nAll verification suites passed successfully!")
        return True
    except AssertionError as ae:
        print(f"Verification Failed: {ae}")
        return False
    finally:
        clean_generated_artifacts(marketplace_dir)
        # Clean up temporary JSONs
        for f in [tech_out, trust_out, engage_out, final_report_out]:
            if os.path.exists(f):
                os.remove(f)
        if mock_corrob_created and os.path.exists(mock_corrob_path):
            os.remove(mock_corrob_path)

if __name__ == '__main__':
    success = test_audit()
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
