#!/usr/bin/env python3
"""
Engagement Audit Script - engagement-audit
Audits heading hierarchies, readability, deep-link breadcrumbs,
intent-classified Call-To-Action (CTA) elements, dead-end risks,
audience clarity, jargon density, and lightweight performance metrics.
Uses only the Python standard library to guarantee portability.
"""

import sys
import urllib.request
import urllib.parse
import json
import re
import urllib.robotparser
from html.parser import HTMLParser
import argparse
import os
import ipaddress
import socket
import time
from contextlib import contextmanager


EXECUTION_ERRORS = []

# --- Politeness: per-host request spacing, honoring robots.txt Crawl-delay ---
MIN_REQUEST_INTERVAL = 0.5  # seconds, floor even when robots.txt is silent
_LAST_REQUEST_TS = {}
_HOST_CRAWL_DELAY = {}

def _note_crawl_delay(host, seconds):
    """Record a Crawl-delay learned from robots.txt for a host, if larger than what's known."""
    if not host or not seconds:
        return
    host = host.lower()
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return
    _HOST_CRAWL_DELAY[host] = max(_HOST_CRAWL_DELAY.get(host, 0.0), seconds)

def _respect_rate_limit(url):
    """Sleep just long enough to keep requests to the same host politely spaced,
    using the larger of a small default floor and any robots.txt Crawl-delay."""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        host = ""
    if not host:
        return
    delay = max(MIN_REQUEST_INTERVAL, _HOST_CRAWL_DELAY.get(host, 0.0))
    now = time.monotonic()
    last = _LAST_REQUEST_TS.get(host)
    if last is not None:
        wait = delay - (now - last)
        if wait > 0:
            time.sleep(wait)
    _LAST_REQUEST_TS[host] = time.monotonic()

def _record_execution_error(context, exc):
    message = f"{context}: {type(exc).__name__}: {str(exc)[:240]}"
    EXECUTION_ERRORS.append(message)
    return message

def _validate_public_http_url(url):
    """Allow only HTTP(S) targets whose hostname resolves to public IP space."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not allowed")
    host = parsed.hostname.rstrip(".").lower()
    blocked_names = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "0.0.0.0"}
    # The verifier uses a deliberately isolated local fixture. This opt-in is
    # never enabled by normal audits and is restricted to the verifier's port.
    test_target = os.environ.get("BRAND_AUDIT_LOCAL_FIXTURE")
    if test_target and host in {"localhost", "127.0.0.1"} and str(parsed.port or 80) == test_target:
        return True
    if host in blocked_names or host.endswith(".local") or host.endswith(".localhost"):
        raise ValueError(f"Blocked non-public hostname: {host}")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                                       type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"Hostname resolution failed: {host}") from exc
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    for addr in addresses:
        mapped = getattr(addr, "ipv4_mapped", None)
        check_addr = mapped or addr
        if (check_addr.is_private or check_addr.is_loopback or check_addr.is_link_local or
                check_addr.is_unspecified or check_addr.is_multicast or check_addr.is_reserved):
            raise ValueError(f"Blocked non-public IP address for {host}: {check_addr}")
    return True


def _is_public_ip(ip_obj):
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    check_addr = mapped or ip_obj
    return not (check_addr.is_private or check_addr.is_loopback or check_addr.is_link_local or
                check_addr.is_unspecified or check_addr.is_multicast or check_addr.is_reserved)


@contextmanager
def _guarded_dns():
    """Pin the DNS resolution used for the live connection to the same public-IP-only
    rule enforced by _validate_public_http_url. This removes the TOCTOU window a
    DNS-rebinding attack could exploit between validation and the socket actually
    connecting, since it is the same resolution call that is filtered and reused."""
    original_getaddrinfo = socket.getaddrinfo

    def _filtered_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        infos = original_getaddrinfo(host, port, family, type, proto, flags)
        # Mirror the same isolated local-fixture opt-in used by
        # _validate_public_http_url so the verifier's local test server keeps working.
        test_target = os.environ.get("BRAND_AUDIT_LOCAL_FIXTURE")
        if test_target and str(host).lower() in {"localhost", "127.0.0.1"} and str(port) == test_target:
            return infos
        safe = []
        for info in infos:
            try:
                addr_obj = ipaddress.ip_address(info[4][0].split('%')[0])
            except ValueError:
                continue
            if _is_public_ip(addr_obj):
                safe.append(info)
        if not safe:
            raise socket.gaierror(f"DNS resolution for {host} returned no public IP addresses")
        return safe

    socket.getaddrinfo = _filtered_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


class EngagementHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_h1 = False
        self.in_h2 = False
        self.in_paragraph = False
        self.in_nav = False
        self.nav_depth = 0
        self.in_script_or_style = False
        self.in_a = False
        self.in_button = False
        self.current_interactive_tag = ""
        self.current_interactive_href = ""
        self.current_interactive_role = ""
        self.current_interactive_text = []
        
        self.h1_texts = []
        self.h2_texts = []
        self.title_text = ""
        self.meta_description = ""
        self.in_title = False
        self.paragraphs = []
        self.current_paragraph = []
        
        # Interactive elements (buttons, links, inputs)
        self.interactive_elements = []
        self.links = []
        
        # Navigation & Structure
        self.has_nav = False
        self.has_header = False
        self.has_footer = False
        self.has_breadcrumbs = False
        
        # Performance & Tag Counts
        self.total_elements = 0
        self.raw_html_length = 0
        self.total_text_length = 0
        self.external_scripts_count = 0
        self.inline_scripts_count = 0
        self.stylesheets_count = 0
        self.images_count = 0
        self.forms_count = 0
        
    def handle_starttag(self, tag, attrs):
        self.total_elements += 1
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()
        
        if tag_lower == 'script':
            self.in_script_or_style = True
            if attrs_dict.get('src'):
                self.external_scripts_count += 1
            else:
                self.inline_scripts_count += 1
        elif tag_lower == 'style':
            self.in_script_or_style = True
        elif tag_lower == 'title':
            self.in_title = True
        elif tag_lower == 'meta':
            name=(attrs_dict.get('name') or attrs_dict.get('property') or '').lower()
            if name == 'description': self.meta_description=attrs_dict.get('content','').strip()
        elif tag_lower == 'link':
            rel = attrs_dict.get('rel', '').lower()
            if 'stylesheet' in rel:
                self.stylesheets_count += 1
        elif tag_lower == 'img':
            self.images_count += 1
        elif tag_lower == 'form':
            self.forms_count += 1
        elif tag_lower == 'h1':
            self.in_h1 = True
        elif tag_lower == 'h2':
            self.in_h2 = True
        elif tag_lower == 'p':
            self.in_paragraph = True
            self.current_paragraph = []
        elif (tag_lower == 'nav' or 
              attrs_dict.get('role') == 'navigation' or 
              'nav' in attrs_dict.get('class', '').lower() or 
              'navigation' in attrs_dict.get('id', '').lower()):
            self.in_nav = True
            self.nav_depth += 1
            self.has_nav = True
            aria_label = attrs_dict.get('aria-label', '').lower()
            if 'breadcrumb' in aria_label:
                self.has_breadcrumbs = True
        elif tag_lower == 'header':
            self.has_header = True
        elif tag_lower == 'footer':
            self.has_footer = True
            
        # Detect interactive CTA targets (<button>, <a>, <input type=submit>, role=button)
        role = attrs_dict.get('role', '').lower()
        if tag_lower in ['button', 'a'] or role == 'button' or (tag_lower == 'input' and attrs_dict.get('type') in ['submit', 'button']):
            self.current_interactive_tag = tag_lower
            self.current_interactive_href = attrs_dict.get('href', '')
            self.current_interactive_role = role
            self.current_interactive_text = []
            
            # Check for title, value, or aria-label attributes
            label = attrs_dict.get('aria-label') or attrs_dict.get('title') or attrs_dict.get('value')
            if label:
                self.current_interactive_text.append(label)
                
            if tag_lower == 'a':
                self.in_a = True
            elif tag_lower == 'button':
                self.in_button = True
                
        # Check breadcrumbs by class/id/microdata
        cls_id = (attrs_dict.get('class', '') + " " + attrs_dict.get('id', '') + " " + attrs_dict.get('itemtype', '')).lower()
        if 'breadcrumb' in cls_id:
            self.has_breadcrumbs = True

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in ['script', 'style']:
            self.in_script_or_style = False
        elif tag_lower == 'title':
            self.in_title = False
        elif tag_lower == 'h1':
            self.in_h1 = False
        elif tag_lower == 'h2':
            self.in_h2 = False
        elif tag_lower == 'p':
            self.in_paragraph = False
            p_text = " ".join(self.current_paragraph).strip()
            if p_text:
                self.paragraphs.append(p_text)
            self.current_paragraph = []
        elif tag_lower == 'nav':
            self.nav_depth=max(0,self.nav_depth-1)
            self.in_nav=self.nav_depth>0
        elif tag_lower in ['a', 'button']:
            if tag_lower == 'a':
                self.in_a = False
            elif tag_lower == 'button':
                self.in_button = False
                
            full_text = " ".join(self.current_interactive_text).strip()
            elem_obj = {
                "tag": self.current_interactive_tag,
                "href": self.current_interactive_href,
                "text": full_text,
                "role": self.current_interactive_role,
                "is_navigation": self.nav_depth > 0 or self.current_interactive_href.lower() in ["/", "/home", "index.html"]
            }
            self.interactive_elements.append(elem_obj)
            if tag_lower == 'a':
                self.links.append(elem_obj)

    def handle_data(self, data):
        self.raw_html_length += len(data)
        if not self.in_script_or_style:
            stripped = data.strip()
            if stripped:
                self.total_text_length += len(stripped)
            
            if self.in_title:
                self.title_text += data.strip() + ' '
            if self.in_h1:
                self.h1_texts.append(data.strip())
            elif self.in_h2:
                self.h2_texts.append(data.strip())
            elif self.in_paragraph:
                self.current_paragraph.append(data.strip())
                
            if self.in_a or self.in_button:
                self.current_interactive_text.append(data.strip())


def fetch_page(url, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"):
    """Fetch a public HTTP(S) page and validate every redirect destination."""
    tracker = None
    try:
        _validate_public_http_url(url)
        _respect_rate_limit(url)
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9'
            }
        )
        class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
            def __init__(self):
                super().__init__(); self.chain=[]
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                self.chain.append({'from':req.full_url,'to':newurl,'status':code})
                _validate_public_http_url(newurl)
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        tracker=SafeRedirectHandler()
        opener=urllib.request.build_opener(tracker)
        with _guarded_dns(), opener.open(req, timeout=10) as response:
            _validate_public_http_url(response.geturl())
            html = response.read(2 * 1024 * 1024 + 1)
            if len(html) > 2 * 1024 * 1024:
                html = html[:2 * 1024 * 1024]
            encoding = response.info().get_content_charset() or 'utf-8'
            return len(html), html.decode(encoding, errors='replace')
    except Exception as e:
        message=_record_execution_error(f"Page fetch blocked/failed for {url}", e)
        return 0, f"Error: {message}"


# Intent categories for Call to Actions
CTA_INTENT_PATTERNS = {
    "commercial": [
        r'\bbuy\s+now\b', r'\border\s+now\b', r'\bcheckout\b', r'\badd\s+to\s+cart\b',
        r'\bpurchase\b', r'\bshop\s+now\b', r'\bsubscribe\b'
    ],
    "purchase": [
        r'\bbuy\s+now\b', r'\border\s+now\b', r'\bcheckout\b', r'\badd\s+to\s+cart\b',
        r'\bpurchase\b', r'\bshop\s+now\b', r'\bsubscribe\b'
    ],
    "evaluation": [
        r'\brequest\s+a?\s*demo\b', r'\bbook\s+a?\s*demo\b', r'\btry\s+free\b',
        r'\bstart\s+free\s+trial\b', r'\bfree\s+trial\b', r'\btry\s+it\s+free\b'
    ],
    "demo": [
        r'\brequest\s+a?\s*demo\b', r'\bbook\s+a?\s*demo\b', r'\btry\s+free\b',
        r'\bstart\s+free\s+trial\b', r'\bfree\s+trial\b', r'\btry\s+it\s+free\b'
    ],
    "lead_generation": [
        r'\bcontact\s+sales\b', r'\bcontact\s+us\b', r'\bget\s+in\s+touch\b',
        r'\btalk\s+to\s+sales\b', r'\bschedule\s+a?\s*call\b', r'\breach\s+out\b', r'\btalk\b', r'\bconnect\b', r'\brequest\b.*\bquote\b'
    ],
    "contact": [
        r'\bcontact\s+sales\b', r'\bcontact\s+us\b', r'\bget\s+in\s+touch\b',
        r'\btalk\s+to\s+sales\b', r'\bschedule\s+a?\s*call\b', r'\breach\s+out\b', r'\btalk\b', r'\bconnect\b', r'\brequest\b.*\bquote\b'
    ],
    "onboarding": [
        r'\bsign\s+up\b', r'\bget\s+started\b', r'\bjoin\s+free\b',
        r'\bcreate\s+account\b', r'\bregister\b', r'\bstart\s+now\b', r'\btry\s+(?:it|the\s+platform)\b', r'\bjoin\s+us\b'
    ],
    "signup": [
        r'\bsign\s+up\b', r'\bget\s+started\b', r'\bjoin\s+free\b',
        r'\bcreate\s+account\b', r'\bregister\b', r'\bstart\s+now\b', r'\btry\s+(?:it|the\s+platform)\b', r'\bjoin\s+us\b'
    ],
    "pricing": [
        r'\bview\s+pricing\b', r'\bsee\s+pricing\b', r'\bpricing\s+plans\b',
        r'\bcompare\s+plans\b', r'\bsee\s+plans\b', r'\bpricing\b'
    ],
    "download": [
        r'\bdownload\b', r'\bget\s+the\s+app\b', r'\binstall\b', r'\bdownload\s+whitepaper\b'
    ],
    "learn": [
        r'\blearn\s+more\b', r'\bread\s+more\b', r'\bexplore\s+features\b',
        r'\bhow\s+it\s+works\b', r'\bsee\s+how\b', r'\bexplore\b', r'\bdiscover\b', r'\bsee\s+(?:what|why)\b'
    ],
    "navigation": [
        r'\bback\s+to\s+top\b', r'\bhome\b', r'\bmenu\b', r'\bprevious\b', r'\bnext\b'
    ],
    "informational": [
        r'\bread\s+docs?\b', r'\bview\s+documentation\b', r'\blearn\s+more\b',
        r'\bexplore\s+features\b', r'\bdownload\s+whitepaper\b'
    ]
}

BUZZWORDS = [
    "synergy", "paradigm shift", "hyper-scalable", "next-gen", "disruptive",
    "cutting-edge", "game-changing", "holistic", "mission-critical", "best-of-breed",
    "revolutionary", "seamless integration", "world-class", "innovative solutions"
]

AUDIENCE_TARGET_PATTERNS = [
    r'\bfor\s+(?:developers|engineers|designers|enterprises|businesses|teams|creators|startups|retailers|students|homeowners|patients|doctors)\b',
    r'\bbuilt\s+for\s+[a-z\s]{3,25}\b',
    r'\bdesigned\s+for\s+[a-z\s]{3,25}\b',
    r'\btailored\s+(?:for|to)\s+[a-z\s]{3,25}\b'
]


def classify_cta(elem_text, elem_href, is_navigation=False):
    combined=(elem_text+" "+elem_href).lower()
    matched=[]
    for intent,patterns in CTA_INTENT_PATTERNS.items():
        if is_navigation and intent!="navigation": continue
        if any(re.search(p,combined,re.I) for p in patterns): matched.append(intent)
    if is_navigation and not matched and re.search(r'\b(home|menu|next|previous|back to top)\b',combined): matched.append("navigation")
    return matched



def _norm_words(text):
    return re.sub(r'\s+', ' ', text or '').strip()


def _question_answer_pairs(text):
    """Extract simple question→answer windows without pretending to understand semantics."""
    text=_norm_words(text)
    pairs=[]
    for m in re.finditer(r'([^.!?]{8,160}\?)\s+([^.!?]{20,320}[.!?])', text):
        q=m.group(1).strip(); a=m.group(2).strip()
        if len(q.split())>=3 and len(a.split())>=4:
            pairs.append({'question':q,'answer':a})
    return pairs


def _answerability_analysis(parser, ctas_found):
    h1=_norm_words(' '.join(parser.h1_texts)); title=_norm_words(parser.title_text)
    body=_norm_words(' '.join(parser.paragraphs))
    combined=' '.join([title,h1,parser.meta_description,body[:5000]])
    lower=combined.lower()
    identity=bool(h1 and len(h1.split())>=3) or bool(title and len(title.split())>=4)
    offer=bool(re.search(r'\b(product|service|platform|software|tool|app|solution|agency|consulting|marketplace|store|shop)\b', lower))
    audience=bool(re.search(r'\b(for|built for|designed for|used by|serves|help(?:s)?|teams?|businesses|developers|creators|students|customers)\b[^.]{0,100}', lower))
    contact=bool(re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', combined, re.I) or re.search(r'\b(contact|support|sales|call us|email us|phone)\b', lower))
    next_step=bool(ctas_found) or bool(re.search(r'\b(get started|buy|book|request|schedule|sign up|start|try|download|contact|explore|learn more|subscribe|apply|join)\b', lower))
    questions=_question_answer_pairs(combined)
    # Quote-ready: concise explicit answers near question-like headings, or short declarative definition sentences.
    quote_ready=[]
    for pair in questions:
        if 5 <= len(pair['answer'].split()) <= 55: quote_ready.append(pair)
    definition=bool(re.search(r'\b[A-Z][A-Za-z0-9& .-]{2,50}\s+(?:is|helps|provides|offers|enables)\s+[^.]{15,180}[.]', combined))
    quote_score=min(100, round((len(quote_ready)>0)*50 + (definition)*30 + (identity and offer)*20))
    checks={'identity':identity,'offer':offer,'audience':audience,'contact':contact,'next_step':next_step}
    score=round(sum(checks.values())/len(checks)*100)
    status='warning' if score<60 or quote_score<50 else 'pass'
    return {'status':status,'score':score,'checks':checks,'quote_readiness_score':quote_score,'quote_ready_pairs':quote_ready[:5], 'confidence':0.88,'severity':'medium','evidence':f'Answerability score {score}/100; quote-readiness {quote_score}/100. Checks cover identity, offer, audience, contact path, and next step.'}


def _deep_link_analysis(parser, ctas_found):
    """Estimate whether a visitor landing directly on this page can retain context and continue."""
    brand_context=bool(parser.h1_texts or parser.title_text or parser.meta_description)
    nav=bool(parser.has_nav or parser.has_header)
    breadcrumb=bool(parser.has_breadcrumbs)
    internal_links=len([x for x in parser.links if x.get('href')])
    meaningful_ctas=len([x for x in ctas_found if not x.get('is_navigation')])
    footer=parser.has_footer
    points={'brand_context':25,'navigation':25,'breadcrumb':15,'internal_paths':15,'primary_cta':15,'footer':5}
    checks={'brand_context':brand_context,'navigation':nav,'breadcrumb':breadcrumb,'internal_paths':internal_links>=2,'primary_cta':meaningful_ctas>=1,'footer':footer}
    score=sum(points[k] for k,v in checks.items() if v)
    status='warning' if score<60 else 'pass'
    missing=[k.replace('_',' ') for k,v in checks.items() if not v]
    evidence=f'Deep-link context retention score {score}/100. ' + ('Missing: '+', '.join(missing)+'.' if missing else 'Brand context, navigation, internal paths, and conversion path are present.')
    return {'status':status,'score':score,'checks':checks,'confidence':0.9,'severity':'medium','evidence':evidence}

def analyze_engagement(raw_len, html_content, rendered_metrics=None, mobile_metrics=None):
    parser = EngagementHTMLParser()
    parser.feed(html_content)
    
    # 1. Evaluate H1 Headings
    h1_count = len(parser.h1_texts)
    h1_val = " ".join(parser.h1_texts).strip()
    
    h1_status = "pass"
    h1_evidence = f"Found {h1_count} H1 tags."
    h1_severity = None
    h1_confidence = 0.95
    
    if h1_count == 0:
        h1_status = "fail"
        h1_severity = "high"
        h1_evidence += " Missing core heading on the landing page, which hurts above-the-fold orientation."
    elif h1_count > 1:
        h1_status = "warning"
        h1_severity = "medium"
        h1_evidence += " Multiple H1 tags can dilute the page's primary theme."
    elif len(h1_val.split()) < 3:
        h1_status = "warning"
        h1_severity = "medium"
        h1_evidence += f" H1 heading is too short ('{h1_val}'), failing to convey clear brand value."
        
    # 2. Analyze Readability, Walls of Text, and Jargon Density
    walls_of_text = []
    total_words = 0
    full_text = " ".join(parser.paragraphs)
    
    for idx, p in enumerate(parser.paragraphs):
        words = p.split()
        total_words += len(words)
        if len(words) > 100:
            walls_of_text.append({"index": idx, "word_count": len(words), "text": p[:60] + "..."})
            
    # Buzzword / jargon analysis: requires multiple buzzwords to flag
    buzzwords_found = []
    for bz in BUZZWORDS:
        matches = re.findall(r'\b' + re.escape(bz) + r'\b', full_text, re.IGNORECASE)
        if matches:
            buzzwords_found.append(f"{bz} ({len(matches)}x)")
            
    readability_status = "pass"
    readability_evidence = f"Total paragraph words: {total_words}. Found {len(walls_of_text)} 'wall of text' paragraphs (>100 words)."
    readability_severity = None
    readability_confidence = 0.9
    
    if len(walls_of_text) > 0:
        readability_status = "warning"
        readability_severity = "medium"
        readability_evidence += " Large unformatted text blocks reduce reader retention and confuse AI summary parsers."
        if buzzwords_found:
            readability_evidence += f" Jargon/buzzwords detected: {', '.join(buzzwords_found[:4])}."
    elif len(buzzwords_found) >= 4:
        readability_status = "warning"
        readability_severity = "medium"
        readability_evidence += f" High buzzword/jargon concentration detected ({', '.join(buzzwords_found[:5])}), which obscures clear value propositions for human users and LLMs."
        
    # 3. Audience clarity + AI answerability / quote readiness
    audience_text=(h1_val + " " + full_text[:1500]).lower()
    audience_clues=[]
    for pat in AUDIENCE_TARGET_PATTERNS:
        audience_clues.extend(re.findall(pat, audience_text, re.IGNORECASE))
    audience_clarity="clear" if audience_clues else ("somewhat_clear" if len(h1_val.split())>=4 else "unclear")
    # CTA list is not yet built here; use textual next-step signals first, then refine below.
    provisional_ctas=[]
    answerability=_answerability_analysis(parser, provisional_ctas)

    # 4. Context Retention (CTAs, Breadcrumbs & Navigation)
    ctas_found = []
    ctas_by_intent = {k: [] for k in CTA_INTENT_PATTERNS.keys()}
    
    internal_links_count = 0
    external_links_count = 0
    parent_links_count = 0
    
    for elem in parser.interactive_elements:
        href = elem["href"].lower()
        text = elem["text"].strip()
        
        if href.startswith("http") and not href.startswith("javascript"):
            external_links_count += 1
        elif href:
            internal_links_count += 1
            if href in ['/', '/home', 'index.html', '../']:
                parent_links_count += 1
            
        intents = classify_cta(text, href, elem.get("is_navigation",False))
        if intents:
            ctas_found.append({"text": text, "href": elem["href"], "intents": intents, "tag": elem["tag"], "is_navigation": elem.get("is_navigation",False)})
            for it in intents:
                ctas_by_intent[it].append(text or href)
                
    answerability=_answerability_analysis(parser, ctas_found)
    deep_link=_deep_link_analysis(parser, ctas_found)

    navigation_status = "pass"
    navigation_evidence = (
        f"Header/Nav element present: {parser.has_nav}. Footer element present: {parser.has_footer}. "
        f"CTAs found: {len(ctas_found)}."
    )
    navigation_severity = None
    navigation_confidence = 0.95
    
    # Dead-End analysis: page with zero navigation and zero CTAs
    if not parser.has_nav and not parser.has_header:
        navigation_status = "fail"
        navigation_severity = "high"
        navigation_evidence += " Lack of clear navigation menu makes it difficult for visitors arriving via deep links to explore the site."
    elif len(ctas_found) == 0:
        navigation_status = "warning"
        navigation_severity = "medium"
        navigation_evidence += " No explicit Call-To-Action (CTA) found. Pages ending in dead ends increase bounce rates."
    else:
        active_intents = [f"{k} ({len(v)})" for k, v in ctas_by_intent.items() if v]
        if active_intents:
            navigation_evidence += f" CTA intents covered: {', '.join(active_intents)}."
            
    if parser.has_breadcrumbs:
        navigation_evidence += " Structural breadcrumbs detected for deep orientation."
        
    # 5. Text-to-HTML Ratio & Lightweight Performance Signals
    ratio = (parser.total_text_length / raw_len) if raw_len > 0 else 0
    html_kb = raw_len / 1024.0
    
    clutter_status = "pass"
    clutter_evidence = f"Text-to-HTML ratio is {ratio:.1%}."
    clutter_severity = None
    clutter_confidence = 0.9
    
    if ratio < 0.05:
        clutter_status = "warning"
        clutter_severity = "medium"
        clutter_evidence += f" Very low text ratio ({ratio:.1%}). Page might contain excessive boilerplate code, tracking scripts, or ad widgets."
        if parser.external_scripts_count > 15:
            clutter_evidence += f" High external script count ({parser.external_scripts_count} scripts)."
    elif parser.external_scripts_count > 30 or html_kb > 600:
        clutter_status = "warning"
        clutter_severity = "medium"
        clutter_evidence += f" Bloated payload detected ({html_kb:.1f} KB HTML, {parser.external_scripts_count} scripts). Heavy initial load increases bounce rates for referred visitors."
        
    rendered_audit={"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"No browser-rendered geometry supplied."}
    if rendered_metrics:
        issues=[]
        for m in rendered_metrics:
            if m.get("h1_top_px") is not None and m["h1_top_px"]>900: issues.append(f"{m['url']}: H1 begins below the initial 900px viewport ({m['h1_top_px']}px).")
            if m.get("cta_top_px") is not None and m["cta_top_px"]>900: issues.append(f"{m['url']}: primary CTA begins below the initial viewport ({m['cta_top_px']}px).")
            if m.get("horizontal_overflow_px",0)>8: issues.append(f"{m['url']}: horizontal overflow of {m['horizontal_overflow_px']}px.")
        rendered_audit={"status":"warning" if issues else "pass","severity":"medium","confidence":0.9,"evidence":" ".join(issues) if issues else "Rendered geometry shows the primary H1/CTA within the desktop viewport and no significant horizontal overflow."}

    return {
        "h1_audit": {
            "status": h1_status,
            "severity": h1_severity,
            "confidence": h1_confidence,
            "h1_count": h1_count,
            "h1_text": h1_val,
            "evidence": h1_evidence
        },
        "readability": {
            "status": readability_status,
            "severity": readability_severity,
            "confidence": readability_confidence,
            "paragraph_count": len(parser.paragraphs),
            "walls_of_text_count": len(walls_of_text),
            "buzzwords_detected": buzzwords_found,
            "audience_clarity": audience_clarity,
            "evidence": readability_evidence
        },
        "navigation_cta": {
            "status": navigation_status,
            "severity": navigation_severity,
            "confidence": navigation_confidence,
            "internal_links": internal_links_count,
            "external_links": external_links_count,
            "parent_links": parent_links_count,
            "ctas_detected": len(ctas_found),
            "ctas_by_intent": {k: len(v) for k, v in ctas_by_intent.items()},
            "breadcrumbs_present": parser.has_breadcrumbs,
            "evidence": navigation_evidence
        },
        "answerability": answerability,
        "deep_link_context": deep_link,
        "rendered_experience": rendered_audit,
        "clutter": {
            "status": clutter_status,
            "severity": clutter_severity,
            "confidence": clutter_confidence,
            "ratio": ratio,
            "html_size_kb": round(html_kb, 1),
            "total_dom_elements": parser.total_elements,
            "script_tags_count": parser.external_scripts_count + parser.inline_scripts_count,
            "external_scripts_count": parser.external_scripts_count,
            "stylesheets_count": parser.stylesheets_count,
            "images_count": parser.images_count,
            "forms_count": parser.forms_count,
            "evidence": clutter_evidence
        }
    }



def _status_rank(status):
    return {"fail": 3, "warning": 2, "unavailable": 1, "pass": 0}.get(status or "pass", 0)

def _aggregate_page_metric(page_reports, key, site_url):
    reports=[r for r in page_reports if isinstance(r.get(key), dict)]
    if not reports:
        return {"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"No page-level results available.","affected_pages":[]}
    worst=max(reports, key=lambda r:_status_rank(r[key].get("status")))
    affected=[]
    for r in reports:
        m=r[key]
        if m.get("status") in ("warning","fail"):
            affected.append(r["url"])
    evidence_parts=[]
    for r in reports:
        ev=r[key].get("evidence")
        if ev:
            evidence_parts.append(f"{r['url']}: {ev}")
    out=dict(worst[key])
    out["affected_pages"]=affected
    out["evidence"]=f"Checked {len(reports)} representative page(s). " + " ".join(evidence_parts[:8])
    return out

def analyze_engagement_pages(page_urls, max_pages=6, fetch_fn=None, render=False):
    EXECUTION_ERRORS.clear()
    """Audit a bounded set of representative URLs and aggregate engagement signals.

    Each page is analyzed independently so an excellent homepage cannot hide a poor
    AI-citation landing page. The returned page_reports preserve page-level evidence.
    """
    fetch=fetch_fn or fetch_page
    urls=[]
    for u in page_urls or []:
        if not u: continue
        u=urllib.parse.urldefrag(u)[0]
        if not u.startswith(("http://","https://")): continue
        if u not in urls: urls.append(u)
        if len(urls)>=max(1,min(max_pages,6)): break
    if not urls:
        return {"page_reports":[],"pages_checked":0,"status":"unavailable","evidence":"No representative URLs supplied."}
    page_reports=[]
    for u in urls:
        if fetch_fn:
            raw_len,html=fetch(u)
        else:
            raw_len,html=fetch_page(u)
        if not raw_len:
            page_reports.append({"url":u,"status":"unavailable","h1_audit":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":f"Page fetch failed: {html}"},"readability":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetch failed."},"navigation_cta":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetch failed."},"answerability":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetch failed."},"deep_link_context":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetch failed."},"clutter":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetch failed."}})
            continue
        rendered_metrics=None; mobile_metrics=None; render_error=None
        if render:
            rendered_metrics,mobile_metrics,render_error=render_engagement_metrics(u)
        r=analyze_engagement(raw_len,html,rendered_metrics=rendered_metrics,mobile_metrics=mobile_metrics)
        r["url"]=u
        if render_error: r.setdefault("rendered_experience",{})["render_error"]=render_error
        page_reports.append(r)
    aggregate={"page_reports":page_reports,"pages_checked":len(page_reports),"audited_urls":[r["url"] for r in page_reports]}
    for key in ("h1_audit","readability","navigation_cta","rendered_experience","clutter","answerability","deep_link_context"):
        aggregate[key]=_aggregate_page_metric(page_reports,key,urls[0])
    # Keep a compact aggregate of CTA intents for the marketplace report.
    cta_counts={}
    for r in page_reports:
        for k,v in (r.get("navigation_cta",{}).get("ctas_by_intent",{}) or {}).items():
            cta_counts[k]=cta_counts.get(k,0)+int(v or 0)
    aggregate["navigation_cta"]["ctas_by_intent"]=cta_counts
    aggregate["evidence"]=f"Multi-page engagement audit checked {len(page_reports)} representative page(s); findings retain affected URLs so deep-link weaknesses are not hidden by homepage health."
    return aggregate

def robots_allows(url, user_agent="BrandAuditBot"):
    p=urllib.parse.urlparse(url); robots_url=f"{p.scheme}://{p.netloc}/robots.txt"
    try:
        _validate_public_http_url(url)
        _respect_rate_limit(robots_url)
        req=urllib.request.Request(robots_url,headers={"User-Agent":user_agent})
        with _guarded_dns(), urllib.request.urlopen(req,timeout=5) as resp: content=resp.read(65536).decode("utf-8",errors="replace")
        rp=urllib.robotparser.RobotFileParser(); rp.parse(content.splitlines())
        try:
            _note_crawl_delay(p.hostname, rp.crawl_delay(user_agent) or rp.crawl_delay("*"))
        except Exception:
            pass
        return rp.can_fetch(user_agent,url)
    except Exception as e:
        _record_execution_error(f"robots.txt check failed for {url}", e)
        return True

def render_engagement_metrics(url):
    try: from playwright.sync_api import sync_playwright
    except ImportError: return None,None,"Playwright module not found"
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True); page=browser.new_page(viewport={"width":1440,"height":900}); page.goto(url,wait_until="domcontentloaded",timeout=8000)
            try: page.wait_for_load_state("networkidle",timeout=2500)
            except Exception as e: _record_execution_error("Render network-idle wait failed", e)
            h=page.locator("h1").first.bounding_box() if page.locator("h1").count() else None; c=page.locator("a,button").filter(has_text=re.compile(r"(get started|buy now|book .*demo|request .*demo|contact sales|start free trial|sign up|explore|discover|learn more|talk to|schedule|try .*free|request .*quote)",re.I)); cb=c.first.bounding_box() if c.count() else None
            metric={"url":url,"h1_top_px":round(h["y"],1) if h else None,"cta_top_px":round(cb["y"],1) if cb else None,"horizontal_overflow_px":max(0,int(page.evaluate("document.documentElement.scrollWidth-window.innerWidth")))}
            mobile=browser.new_page(viewport={"width":390,"height":844},is_mobile=True); mobile.goto(url,wait_until="domcontentloaded",timeout=8000); overflow=max(0,int(mobile.evaluate("document.documentElement.scrollWidth-window.innerWidth"))); browser.close()
            return [metric],{"horizontal_overflow_px":overflow},None
    except Exception as e: return None,None,str(e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Audits page layout and navigation structure for user engagement")
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--pages", help="Comma-separated representative URLs to audit in addition to the target")
    parser.add_argument("--technical", help="Technical audit JSON; uses its bounded crawled_urls as representative pages")
    parser.add_argument("--max-pages", type=int, default=6, help="Maximum representative pages to audit")
    parser.add_argument("--render", action="store_true", help="Run Playwright geometry checks per representative page when available")
    parser.add_argument("--output", help="Path to write output JSON")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    if not robots_allows(url):
        report={"robots_gate":{"status":"blocked","evidence":"Target URL is disallowed by robots.txt; engagement audit did not fetch the page."},"h1_audit":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"readability":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"navigation_cta":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"rendered_experience":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"clutter":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"answerability":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."},"deep_link_context":{"status":"unavailable","severity":"medium","confidence":1.0,"evidence":"Skipped due to robots.txt."}}
    else:
        urls=[url]
        if args.technical:
            try:
                td=json.loads(open(args.technical,encoding="utf-8").read())
                urls += td.get("crawl_scope",{}).get("crawled_urls",[])
            except Exception as e: _record_execution_error("Render network-idle wait failed", e)
        if args.pages:
            urls += [x.strip() for x in args.pages.split(",") if x.strip()]
        # Preserve first occurrence and same-domain URLs only.
        seen=set(); selected=[]; base=urllib.parse.urlparse(url).netloc.lower()
        for u in urls:
            u=urllib.parse.urldefrag(u)[0]
            try:
                if urllib.parse.urlparse(u).netloc.lower()!=base: continue
            except Exception as e:
                _record_execution_error("Engagement URL candidate skipped", e)
                continue
            if u not in seen:
                seen.add(u); selected.append(u)
        report=analyze_engagement_pages(selected,max_pages=args.max_pages,render=args.render) if len(selected)>1 or args.technical or args.pages else None
        if report is None:
            raw_len,html=fetch_page(url)
            if not raw_len:
                report={"robots_gate":{"status":"allowed","evidence":"robots.txt allowed the target URL."},"h1_audit":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":f"Page fetching failed: {html}"},"readability":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."},"navigation_cta":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."},"answerability":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."},"deep_link_context":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."},"rendered_experience":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."},"clutter":{"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"Page fetching failed."}}
            else:
                rendered_metrics,mobile_metrics,render_error=render_engagement_metrics(url)
                report=analyze_engagement(raw_len,html,rendered_metrics=rendered_metrics,mobile_metrics=mobile_metrics)
                report["rendered_experience"]["render_error"]=render_error

    report.setdefault("execution", {"partial": False, "errors": []})
    report["execution"]["partial"] = bool(report["execution"].get("partial") or EXECUTION_ERRORS)
    report["execution"]["errors"] = list(report["execution"].get("errors", [])) + list(EXECUTION_ERRORS)
    output_data=json.dumps(report,indent=2)
    if args.output:
        with open(args.output,"w",encoding="utf-8") as f: f.write(output_data)
        print(f"Engagement audit written to {args.output}")
    else: print(output_data)
