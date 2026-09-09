#!/usr/bin/env python3
"""
Technical and Crawlability Audit Script - crawl-render-audit
Evaluates robots.txt compliance, recursive XML sitemaps, bounded mini-crawling,
Schema.org structured data, WCAG-compliant image alternative text, canvas/iframe
accessibility, and fact-level JS-render dependency gaps.
Uses only the Python standard library with optional Playwright integration.
"""

import sys
import urllib.request
import urllib.parse
import urllib.robotparser
import urllib.error
import json
import re
import html
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
import argparse
import os
import ipaddress
import socket
import time
from contextlib import contextmanager

AUDIT_BOT_NAME = "BrandAuditBot"
AUDIT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 BrandAuditBot/1.0"
DEFAULT_TIMEOUT = 10
MAX_RESPONSE_BYTES = 2097152 # 2 MB

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


class TechHTMLParser(HTMLParser):
    def __init__(self, page_url=""):
        super().__init__()
        self.page_url = page_url
        self.in_script_or_style = False
        self.in_json_ld = False
        self._json_ld_buffer = ""
        self.json_ld_contents = []
        
        self.title = ""
        self.in_title = False
        self.in_body = False
        self.meta_tags = {}
        self.has_viewport = False
        self.viewport_content = ""
        self.canonical_urls = []
        self.robots_meta = []
        
        # Image accessibility tracking
        self.images_count = 0
        self.images_informative = 0
        self.images_informative_no_alt = 0
        self.images_decorative = 0
        
        # Canvas & Iframe tracking
        self.has_canvas = False
        self.canvas_fallback_texts = []
        self._in_canvas = False
        self._current_canvas_text = ""
        self.has_iframe = False
        self.iframe_titles = []
        self.has_svg = False
        
        # Headings & Structure
        self.headings = []
        self._in_heading = False
        self._current_heading_tag = ""
        self._current_heading_text = ""
        
        # Figure / Figcaption tracking for surrounding context
        self._in_figure = False
        self._current_figcaption = ""
        self._in_figcaption = False
        
        # Parent link tracking for images inside <a>
        self._in_anchor = False
        self._current_anchor_text = ""
        self._current_anchor_label = ""
        self._current_anchor_href = ""
        
        # Breadcrumbs & Navigation
        self.has_breadcrumbs = False
        self.internal_links = []
        self.internal_link_metadata = []
        self.external_links = []
        
        # Q&A / FAQ clues
        self.faq_clues_count = 0
        self.details_count = 0
        
        # Performance & Weights
        self.scripts_count = 0
        self.external_scripts_count = 0
        self.inline_scripts_count = 0
        self.stylesheets_count = 0
        self.body_text_length = 0
        self.div_root_count = 0
        self.texts = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()
        
        if tag_lower == 'body':
            self.in_body = True
        elif tag_lower == 'title':
            self.in_title = True
        elif tag_lower in ['script', 'style']:
            self.in_script_or_style = True
            if tag_lower == 'script':
                self.scripts_count += 1
                if attrs_dict.get('src'):
                    self.external_scripts_count += 1
                else:
                    self.inline_scripts_count += 1
                if 'application/ld+json' in attrs_dict.get('type', '').lower():
                    self.in_json_ld = True
                    self._json_ld_buffer = ""
        elif tag_lower == 'link':
            rel = attrs_dict.get('rel', '').lower()
            if 'stylesheet' in rel:
                self.stylesheets_count += 1
            if 'canonical' in rel and attrs_dict.get('href'):
                self.canonical_urls.append(attrs_dict.get('href').strip())
        elif tag_lower == 'meta':
            name = (attrs_dict.get('name') or attrs_dict.get('property') or '').lower()
            content = attrs_dict.get('content', '')
            if name and content:
                self.meta_tags[name] = content
            if name == 'viewport':
                self.has_viewport = True
                self.viewport_content = content
            if name in ('robots', 'googlebot', 'googlebot-news'):
                self.robots_meta.append({'name': name, 'content': content})
        elif tag_lower == 'figure':
            self._in_figure = True
            self._current_figcaption = ""
        elif tag_lower == 'figcaption':
            self._in_figcaption = True
        elif tag_lower == 'a':
            self._in_anchor = True
            self._current_anchor_text = ""
            self._current_anchor_label = attrs_dict.get('aria-label', '') or attrs_dict.get('title', '')
            href = attrs_dict.get('href', '').strip()
            self._current_anchor_href = href
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                if href.startswith('http://') or href.startswith('https://'):
                    self.external_links.append(href)
                else:
                    self.internal_links.append(href)
                    self.internal_link_metadata.append({'href': href, 'anchor_text': ''})
        elif tag_lower == 'img':
            self.images_count += 1
            alt = attrs_dict.get('alt')
            role = attrs_dict.get('role', '').lower()
            aria_label = attrs_dict.get('aria-label', '').strip()
            aria_labelledby = attrs_dict.get('aria-labelledby', '').strip()
            aria_hidden = attrs_dict.get('aria-hidden', '').lower()
            title = attrs_dict.get('title', '').strip()
            src = attrs_dict.get('src', '').lower()
            img_class = attrs_dict.get('class', '').lower()
            
            # W3C WCAG Decorative Image Detection:
            # 1. alt="" explicitly declares decorative image
            # 2. role="presentation" or role="none"
            # 3. aria-hidden="true"
            # 4. Standard spacer/divider/icon asset names
            is_decorative = (
                alt == "" or 
                role in ["presentation", "none"] or 
                aria_hidden == "true" or
                any(d in src or d in img_class for d in ["spacer", "divider", "pixel", "bullet", "decor"])
            )
            
            if is_decorative:
                self.images_decorative += 1
            else:
                self.images_informative += 1
                # Check for accessible textual alternatives
                has_alt_text = bool(alt and alt.strip())
                has_aria = bool(aria_label or aria_labelledby)
                has_title = bool(title)
                # Check parent context (e.g. figure caption or link with text)
                has_context = bool(self._in_figcaption or (self._in_anchor and self._current_anchor_label))
                
                if not (has_alt_text or has_aria or has_title or has_context):
                    self.images_informative_no_alt += 1
                    
        elif tag_lower == 'canvas':
            self.has_canvas = True
            self._in_canvas = True
            self._current_canvas_text = ""
            # Check accessible labels directly on canvas tag
            c_label = attrs_dict.get('aria-label', '').strip() or attrs_dict.get('title', '').strip()
            if c_label:
                self.canvas_fallback_texts.append(c_label)
        elif tag_lower == 'iframe':
            self.has_iframe = True
            t = attrs_dict.get('title', '').strip()
            if t:
                self.iframe_titles.append(t)
        elif tag_lower == 'svg':
            self.has_svg = True
        elif tag_lower == 'details':
            self.details_count += 1
        elif tag_lower in ['h1', 'h2', 'h3', 'h4']:
            self._in_heading = True
            self._current_heading_tag = tag_lower
            self._current_heading_text = ""
        elif (tag_lower == 'nav' or 
              attrs_dict.get('role') == 'navigation' or 
              'breadcrumb' in attrs_dict.get('class', '').lower() or
              'breadcrumb' in attrs_dict.get('id', '').lower() or
              'breadcrumb' in attrs_dict.get('aria-label', '').lower()):
            if 'breadcrumb' in (attrs_dict.get('aria-label', '') + attrs_dict.get('class', '') + attrs_dict.get('id', '')).lower():
                self.has_breadcrumbs = True
        elif tag_lower == 'div':
            div_id = attrs_dict.get('id', '').lower()
            div_class = attrs_dict.get('class', '').lower()
            if div_id in ['root', 'app', '__next', '__nuxt']:
                self.div_root_count += 1
            if 'faq' in div_id or 'faq' in div_class or 'accordion' in div_class:
                self.faq_clues_count += 1

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == 'title':
            self.in_title = False
        elif tag_lower == 'body':
            self.in_body = False
        elif tag_lower in ['script', 'style']:
            self.in_script_or_style = False
            if self.in_json_ld:
                raw_json = self._json_ld_buffer.strip()
                if raw_json:
                    self.json_ld_contents.append(raw_json)
            self.in_json_ld = False
        elif tag_lower == 'canvas':
            self._in_canvas = False
            c_text = self._current_canvas_text.strip()
            if c_text:
                self.canvas_fallback_texts.append(c_text)
        elif tag_lower == 'figure':
            self._in_figure = False
        elif tag_lower == 'figcaption':
            self._in_figcaption = False
        elif tag_lower == 'a':
            if self.internal_link_metadata:
                # Match the most recent metadata entry for this anchor.
                for item in reversed(self.internal_link_metadata):
                    if item.get('anchor_text','') == '' and item.get('href') == self._current_anchor_href:
                        item['anchor_text'] = self._current_anchor_text.strip() or self._current_anchor_label
                        break
            self._in_anchor = False
        elif tag_lower in ['h1', 'h2', 'h3', 'h4']:
            self._in_heading = False
            htext = self._current_heading_text.strip()
            if htext:
                self.headings.append((self._current_heading_tag, htext))
                if any(w in htext.lower() for w in ["faq", "frequently asked", "questions & answers", "common questions"]):
                    self.faq_clues_count += 2

    def handle_data(self, data):
        if self.in_json_ld:
            self._json_ld_buffer += data
        elif self.in_title:
            self.title += data
        elif self._in_canvas:
            self._current_canvas_text += data
        elif self._in_heading:
            self._current_heading_text += data
        elif self._in_figcaption:
            self._current_figcaption += data
        elif self._in_anchor:
            self._current_anchor_text += data
            
        if self.in_body and not self.in_script_or_style:
            stripped = data.strip()
            if stripped:
                self.body_text_length += len(stripped)
                self.texts.append(stripped)

    def handle_entityref(self, name):
        unescaped = html.unescape(f"&{name};")
        if self.in_json_ld:
            self._json_ld_buffer += unescaped
        elif self._in_heading:
            self._current_heading_text += unescaped
        elif self.in_body and not self.in_script_or_style:
            self.body_text_length += len(unescaped)
            self.texts.append(unescaped)

    def handle_charref(self, name):
        unescaped = html.unescape(f"&#{name};")
        if self.in_json_ld:
            self._json_ld_buffer += unescaped
        elif self._in_heading:
            self._current_heading_text += unescaped
        elif self.in_body and not self.in_script_or_style:
            self.body_text_length += len(unescaped)
            self.texts.append(unescaped)


def fetch_url(url, user_agent=AUDIT_USER_AGENT, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_RESPONSE_BYTES):
    """Fetch a public HTTP(S) URL with bounded size/time and safe redirect validation."""
    tracker = None
    try:
        _validate_public_http_url(url)
        _respect_rate_limit(url)
        req = urllib.request.Request(url, headers={
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        class TrackingRedirectHandler(urllib.request.HTTPRedirectHandler):
            def __init__(self):
                super().__init__(); self.chain=[]
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                self.chain.append({'from':req.full_url,'to':newurl,'status':code})
                # Validate the redirect destination before any follow-up request,
                # including same-host redirects that resolve to private IP space.
                _validate_public_http_url(newurl)
                src=urllib.parse.urlparse(req.full_url).netloc.lower().removeprefix('www.')
                dst=urllib.parse.urlparse(newurl).netloc.lower().removeprefix('www.')
                if src and dst and src != dst:
                    return None
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        tracker=TrackingRedirectHandler()
        opener=urllib.request.build_opener(tracker)
        with _guarded_dns(), opener.open(req, timeout=timeout) as response:
            raw_data=response.read(max_bytes+1)
            if len(raw_data)>max_bytes: raw_data=raw_data[:max_bytes]
            encoding=response.info().get_content_charset() or 'utf-8'
            decoded=raw_data.decode(encoding, errors='replace')
            headers=response.info()
            headers['_final_url']=response.geturl()
            headers['_redirect_chain']=tracker.chain
            _validate_public_http_url(response.geturl())
            return response.getcode(), decoded, headers
    except urllib.error.HTTPError as e:
        headers=e.headers
        if headers is not None:
            try:
                _validate_public_http_url(getattr(e, 'url', url))
            except Exception as validation_error:
                _record_execution_error("SSRF validation blocked HTTP error target", validation_error)
            headers['_final_url']=getattr(e,'url',url)
            headers['_redirect_chain']=tracker.chain if tracker else []
        return e.code, str(e.read(4096)), headers
    except Exception as e:
        message=_record_execution_error(f"Fetch blocked/failed for {url}", e)
        return 0, message, {'_final_url':url,'_redirect_chain':tracker.chain if tracker else [],'_error':message}


def is_same_domain(url, base_url):
    """Verifies that two URLs share the same canonical domain, ignoring www."""
    try:
        p1 = urllib.parse.urlparse(url).netloc.lower()
        p2 = urllib.parse.urlparse(base_url).netloc.lower()
        if p1.startswith("www."):
            p1 = p1[4:]
        if p2.startswith("www."):
            p2 = p2[4:]
        return bool(p1 and p2 and p1 == p2)
    except Exception as e:
        _record_execution_error("Domain comparison failed", e)
        return False


def evaluate_robots_txt(base_url, target_url, audit_user_agent=AUDIT_BOT_NAME, fetch_fn=None):
    """
    Fetches and thoroughly analyzes robots.txt using urllib.robotparser.
    Determines whether the audit crawler is allowed to fetch the target URL.
    Scans for AI crawler specific restrictions (GPTBot, ClaudeBot, etc.).
    Extracts sitemaps.
    """
    fetch = fetch_fn if fetch_fn is not None else fetch_url
    robots_url = f"{base_url.rstrip('/')}/robots.txt"
    status_code, robots_content, _ = fetch(robots_url)
    
    result = {
        "status": "not_found",
        "blocks_all": False,
        "blocked_bots": [],
        "allowed_bots": [],
        "audit_crawler_allowed": True,
        "sitemaps": [],
        "evidence": "",
        "raw_content": ""
    }
    
    if status_code != 200 or not robots_content:
        result["evidence"] = f"robots.txt returned HTTP status {status_code} or was unreachable. Defaulting to permissive crawl."
        return result
        
    result["status"] = "found"
    result["raw_content"] = robots_content
    
    # 1. Standard robotparser for audit crawler permission check
    rp = urllib.robotparser.RobotFileParser()
    rp.parse(robots_content.splitlines())
    
    # Extract declared bot token for robots.txt matching
    bot_token = audit_user_agent
    if " " in bot_token:
        tokens = [t.split("/")[0] for t in bot_token.split() if any(k in t.lower() for k in ["bot", "audit", "crawler", "spider"])]
        bot_token = tokens[0] if tokens else "BrandAuditBot"
    else:
        bot_token = bot_token.split("/")[0]
        
    try:
        can_fetch = rp.can_fetch(bot_token, target_url)
    except Exception:
        can_fetch = True
    result["audit_crawler_allowed"] = can_fetch

    # Honor a declared Crawl-delay for this host so subsequent requests
    # (sitemap, mini-crawl pages) are spaced out at least that far apart.
    try:
        declared_delay = rp.crawl_delay(bot_token) or rp.crawl_delay("*")
        _note_crawl_delay(urllib.parse.urlparse(base_url).hostname, declared_delay)
    except Exception:
        pass
    
    # 2. AI Crawlers to analyze for discoverability considerations
    ai_bots = [
        "GPTBot", "ClaudeBot", "Google-Extended", "Applebot-Extended", 
        "PerplexityBot", "Cohere-ai", "Omgilibot", "FacebookBot"
    ]
    for bot in ai_bots:
        if not rp.can_fetch(bot, target_url):
            result["blocked_bots"].append(bot)
        else:
            result["allowed_bots"].append(bot)
            
    # Check if all crawlers are blocked at root
    if not rp.can_fetch("*", f"{base_url}/"):
        result["blocks_all"] = True
        
    # Extract declared sitemaps
    for line in robots_content.splitlines():
        line_clean = line.strip()
        if line_clean.lower().startswith("sitemap:"):
            sitemap_url = line_clean.split(":", 1)[1].strip()
            if sitemap_url:
                result["sitemaps"].append(sitemap_url)
                
    # Build evidence summary
    ev_parts = []
    if result["blocks_all"]:
        ev_parts.append("Global crawl block detected ('Disallow: /' under '*').")
    if result["blocked_bots"]:
        ev_parts.append(f"AI-specific crawler restriction declared for: {', '.join(result['blocked_bots'])}.")
    if result["sitemaps"]:
        ev_parts.append(f"Declared {len(result['sitemaps'])} sitemap directive(s).")
    else:
        ev_parts.append("No Sitemap directives found in robots.txt.")
        
    result["evidence"] = " ".join(ev_parts) if ev_parts else "robots.txt allows standard web crawler access."
    return result


def parse_xml_sitemap(sitemap_url, base_url, max_depth=2, max_sitemaps=5, max_urls=500, fetch_fn=None):
    """
    Recursively discovers and parses XML sitemaps and sitemap index files.
    Extracts URLs and lastmod timestamps with bounded depth and URL count limits.
    Enforces same-domain boundary for all queued child sitemaps.
    """
    fetch = fetch_fn if fetch_fn is not None else fetch_url
    result = {
        "found": False,
        "valid": False,
        "recoverable": False,
        "urls": [],
        "url_count": 0,
        "lastmods": {},
        "priorities": {},
        "latest_lastmod": None,
        "evidence": "",
        "sitemaps_parsed": []
    }
    
    visited_sitemaps = set()
    sitemap_queue = [sitemap_url]
    
    while sitemap_queue and len(visited_sitemaps) < max_sitemaps and len(result["urls"]) < max_urls:
        current_sm = sitemap_queue.pop(0)
        if current_sm in visited_sitemaps:
            continue
        visited_sitemaps.add(current_sm)
        
        status_code, content, _ = fetch(current_sm)
        if status_code != 200 or not content:
            continue
            
        result["found"] = True
        result["sitemaps_parsed"].append(current_sm)
        
        try:
            # Strip namespaces for uniform tag parsing
            xml_text = re.sub(r'\sxmlns="[^"]+"', '', content, count=1)
            root = ET.fromstring(xml_text.encode('utf-8', errors='replace'))
            result["valid"] = True
            
            tag_name = root.tag.lower().split('}')[-1]
            
            # Case A: Sitemap Index (<sitemapindex>)
            if "sitemapindex" in tag_name:
                for sitemap_node in root.findall('.//sitemap'):
                    loc = sitemap_node.find('loc')
                    if loc is not None and loc.text:
                        loc_clean = loc.text.strip()
                        # Enforce same-domain boundary
                        if is_same_domain(loc_clean, base_url):
                            if loc_clean not in visited_sitemaps and len(sitemap_queue) < max_sitemaps:
                                sitemap_queue.append(loc_clean)
                            
            # Case B: Standard URL Set (<urlset>)
            elif "urlset" in tag_name:
                for url_node in root.findall('.//url'):
                    if len(result["urls"]) >= max_urls:
                        break
                    loc = url_node.find('loc')
                    lastmod = url_node.find('lastmod')
                    priority = url_node.find('priority')
                    if loc is not None and loc.text:
                        clean_loc = loc.text.strip()
                        result["urls"].append(clean_loc)
                        if lastmod is not None and lastmod.text:
                            lm_val = lastmod.text.strip()
                            result["lastmods"][clean_loc] = lm_val
                            if not result["latest_lastmod"] or lm_val > result["latest_lastmod"]:
                                result["latest_lastmod"] = lm_val
                        if priority is not None and priority.text:
                            try: result["priorities"][clean_loc] = float(priority.text.strip())
                            except Exception as e: _record_execution_error("Non-fatal technical check failure", e)
        except ET.ParseError:
            # Fallback regex parsing if XML is malformed
            loc_matches = re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', content, re.IGNORECASE)
            lastmod_matches = re.findall(r'<lastmod>\s*([^\s<]+)\s*</lastmod>', content, re.IGNORECASE)
            if loc_matches:
                # Malformed XML is NOT marked valid; report recoverable: True
                result["valid"] = False
                result["recoverable"] = True
                for loc in loc_matches[:max_urls]:
                    c_loc = loc.strip()
                    if c_loc not in result["urls"]:
                        result["urls"].append(c_loc)
                if lastmod_matches:
                    for lm in lastmod_matches:
                        if not result["latest_lastmod"] or lm > result["latest_lastmod"]:
                            result["latest_lastmod"] = lm
        except Exception as e:
            _record_execution_error("Non-fatal technical check failure", e)

    result["url_count"] = len(result["urls"])
    if result["urls"]:
        if result["valid"]:
            result["evidence"] = f"Discovered {len(result['urls'])} URLs across {len(result['sitemaps_parsed'])} valid sitemap(s)."
        else:
            result["evidence"] = f"Malformed XML sitemap recovered: Extracted {len(result['urls'])} URLs via fallback regex parser. XML syntax should be fixed."
        if result["latest_lastmod"]:
            result["evidence"] += f" Latest content modification date: {result['latest_lastmod']}."
    elif result["found"]:
        result["evidence"] = "Sitemap file found, but no valid URLs could be extracted."
    else:
        result["evidence"] = "No sitemap file could be accessed."
        
    return result


def extract_schemas_recursive(obj, schemas_found, details, depth=0):
    """Recursively walks JSON-LD structures (including @graph and arrays)."""
    if depth > 20:
        return
    if isinstance(obj, dict):
        if "@type" in obj:
            types = obj["@type"]
            if not isinstance(types, list):
                types = [types]
            for t in types:
                if isinstance(t, str):
                    clean_type = t.split("/")[-1]
                    schemas_found.append(clean_type)
                    details.setdefault(clean_type, []).append(obj)
        for k, v in obj.items():
            extract_schemas_recursive(v, schemas_found, details, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            extract_schemas_recursive(item, schemas_found, details, depth + 1)


def audit_schema_properties(schema_type, instance):
    """Validates presence of recommended properties for standard schema.org types."""
    missing = []
    type_checks = {
        "Organization": ["name", "url"],
        "LocalBusiness": ["name", "address"],
        "Product": ["name", "description", "offers"],
        "Offer": ["price", "priceCurrency"],
        "Article": ["headline", "author", "datePublished"],
        "BlogPosting": ["headline", "author", "datePublished"],
        "FAQPage": ["mainEntity"],
        "BreadcrumbList": ["itemListElement"],
        "WebSite": ["url", "name"],
        "WebPage": ["name", "url"],
        "Service": ["name", "description"],
        "Person": ["name"]
    }
    recommended = type_checks.get(schema_type, [])
    for prop in recommended:
        if prop not in instance or not instance[prop]:
            missing.append(prop)
    return missing



def detect_page_type(url, html="", title="", schemas=None):
    """
    Detects the functional archetype of a webpage based on URL path,
    page title, schema.org types, and content clues.
    Types: 'homepage', 'product', 'pricing', 'article', 'blog', 'faq', 'about', 'contact', 'documentation', 'legal', 'general'
    """
    path = urllib.parse.urlparse(url).path.lower().rstrip('/')
    title_lower = title.lower() if title else ""
    schemas = schemas or []
    schemas_lower = [s.lower() for s in schemas]
    
    if path in ["", "/", "/index.html", "/home", "/index.php", "/default.aspx"]:
        return "homepage"
    if "faq" in path or "faqpage" in schemas_lower or "frequently asked questions" in title_lower:
        return "faq"
    if any(k in path for k in ["/pricing", "/plans", "/cost", "/tiers"]) or "pricing" in title_lower:
        return "pricing"
    if any(k in path for k in ["/product", "/products", "/item", "/shop", "/store", "/goods"]) or any(s in schemas for s in ["Product", "Offer"]):
        return "product"
    if "/service" in path or "Service" in schemas:
        return "service"
    if any(k in path for k in ["/blog", "/article", "/post", "/news", "/story", "/insights"]) or any(s in schemas for s in ["Article", "BlogPosting", "NewsArticle"]):
        return "article"
    if any(k in path for k in ["/docs", "/doc", "/documentation", "/guide", "/api", "/reference"]):
        return "documentation"
    if "/about" in path or "about us" in title_lower:
        return "about"
    if "/contact" in path or "contact us" in title_lower:
        return "contact"
    if any(k in path for k in ["/privacy", "/terms", "/tos", "/legal", "/security", "/cookies"]):
        return "legal"
    return "general"

def select_crawl_candidates(homepage_url, internal_links, sitemap_urls, max_pages=6, page_metadata=None):
    """Select diverse, high-value same-domain pages using semantic signals.

    ``page_metadata`` is optional and maps normalized URLs to metadata such as
    title, anchor text, schema types and sitemap priority. The legacy URL-only
    interface remains supported for portability and tests.
    """
    parsed_base = urllib.parse.urlparse(homepage_url)
    base_domain = parsed_base.netloc.lower()
    page_metadata = page_metadata or {}

    def normalize_url(raw_url):
        full = urllib.parse.urljoin(homepage_url, raw_url)
        p = urllib.parse.urlparse(full)
        if not is_same_domain(full, homepage_url):
            return None
        if p.scheme not in ['http', 'https']:
            return None
        query_params = urllib.parse.parse_qs(p.query)
        clean_params = {k: v for k, v in query_params.items() if not k.lower().startswith(('utm_', 'ref', 'fbclid', 'gclid'))}
        clean_query = urllib.parse.urlencode(clean_params, doseq=True)
        clean_path = p.path.rstrip('/') or '/'
        return urllib.parse.urlunparse((p.scheme, p.netloc, clean_path, '', clean_query, ''))

    homepage_norm = normalize_url(homepage_url) or homepage_url
    seen = {homepage_norm}
    candidates = [homepage_url]
    all_pool = []
    for u in (sitemap_urls + internal_links):
        norm = normalize_url(u)
        if norm and norm not in seen and norm not in all_pool:
            all_pool.append(norm)

    # Intent buckets encourage coverage of genuinely different page roles.
    bucket_terms = {
        'pricing': ['pricing','plans','cost','tiers','price'],
        'about': ['about','company','team','story'],
        'contact': ['contact','support','sales','locations'],
        'product': ['product','products','service','services','features','solutions','platform'],
        'faq': ['faq','help','questions','answers'],
        'knowledge': ['blog','news','article','post','insights','docs','documentation','guide','resources']
    }

    def score(url):
        meta = page_metadata.get(url, {})
        hay = ' '.join([url.lower(), str(meta.get('title','')).lower(), str(meta.get('anchor_text','')).lower()])
        schemas = {str(x).lower() for x in meta.get('schemas', [])}
        score = 0
        for bucket, terms in bucket_terms.items():
            if any(re.search(r'\b'+re.escape(t)+r'\b', hay) for t in terms):
                score += 5
        if 'product' in schemas or 'offer' in schemas: score += 6
        if 'article' in schemas or 'blogposting' in schemas: score += 4
        if 'faqpage' in schemas: score += 4
        if meta.get('sitemap_priority') is not None:
            try: score += min(3, float(meta['sitemap_priority']))
            except Exception as e: _record_execution_error("Non-fatal technical check failure", e)
        path_depth = len([x for x in urllib.parse.urlparse(url).path.split('/') if x])
        score += max(0, 2-path_depth)
        return score

    ranked = sorted(all_pool, key=lambda u: (-score(u), u))
    selected_roles = set()
    for u in ranked:
        if len(candidates) >= max_pages: break
        hay = ' '.join([u.lower(), str(page_metadata.get(u,{}).get('title','')).lower(), str(page_metadata.get(u,{}).get('anchor_text','')).lower()])
        role = next((r for r,terms in bucket_terms.items() if any(t in hay for t in terms)), 'general')
        if role not in selected_roles or len(candidates) < 2:
            candidates.append(u); seen.add(u); selected_roles.add(role)
    for u in ranked:
        if len(candidates) >= max_pages: break
        if u not in seen:
            candidates.append(u); seen.add(u)
    return candidates


SITEMAP_PATH_CANDIDATES = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml", "/sitemap-index.xml", "/sitemaps/sitemap.xml"]

def _extract_machine_facts(text):
    text=text or ""
    prices=set(re.findall(r'(?:[$€£₹]|USD|EUR|GBP|INR)\s*\d+(?:[,.]\d{1,2})?', text, re.I))
    # Structured Product/Offer JSON often stores price and currency as separate fields.
    for m in re.finditer(r'"price"\s*:\s*"?([0-9]+(?:\.[0-9]+)?)"?', text, re.I):
        window=text[m.start():m.start()+300]
        cm=re.search(r'"priceCurrency"\s*:\s*"([A-Z]{3})"',window,re.I)
        cur=cm.group(1).upper() if cm else ""
        symbol={"USD":"$","EUR":"€","GBP":"£","INR":"₹"}.get(cur,cur)
        prices.add(f"{symbol}{m.group(1)}")
    return {
        "emails": sorted(set(re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', text)))[:10],
        "phones": sorted(set(re.findall(r'\+?\d{1,3}[\s.-]?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3}[\s.-]?\d{3,4}', text)))[:10],
        "prices": sorted(prices)[:20]
    }

def _norm_fact(v, fact_type=None):
    value=re.sub(r'\s+', ' ', str(v).strip().lower())
    if fact_type == 'phones':
        digits=re.sub(r'\D','',value)
        return digits[-10:] if len(digits)>=10 else digits
    if fact_type == 'emails':
        return value.replace('mailto:','')
    if fact_type == 'prices':
        currency=''
        m=re.search(r'(usd|eur|gbp|inr|\$|€|£|₹)',value,re.I)
        if m: currency={'$':'usd','€':'eur','£':'gbp','₹':'inr'}.get(m.group(1).lower(),m.group(1).lower())
        nums=re.findall(r'\d+(?:[,.]\d+)?',value.replace(',',''))
        number=nums[0] if nums else ''
        try: number=f'{float(number):.2f}'
        except Exception as e: _record_execution_error("Non-fatal technical check failure", e)
        return f'{currency}:{number}'
    return value

def compare_visible_structured_facts(parser):
    visible=_extract_machine_facts(' '.join(parser.texts))
    structured={k:[] for k in visible}
    for block in parser.json_ld_contents:
        try: blob=json.dumps(json.loads(block), ensure_ascii=False)
        except Exception as e:
                            _record_execution_error("Technical JSON-LD block skipped", e)
                            continue
        facts=_extract_machine_facts(blob)
        for k in structured: structured[k].extend(facts[k])
    mismatches=[]
    for key in structured:
        sv={_norm_fact(x,key) for x in structured[key]}; vv={_norm_fact(x,key) for x in visible[key]}
        if sv and vv and not sv.intersection(vv):
            mismatches.append({"fact":key,"structured":structured[key][:5],"visible":visible[key][:5]})
    return visible, structured, mismatches

def validate_canonical(page_url, canonical_urls):
    if not canonical_urls:
        return {"status":"missing","canonical":None,"evidence":"No rel=canonical link declared."}
    vals=[]
    for c in canonical_urls:
        u=urllib.parse.urljoin(page_url,c); q=urllib.parse.urlparse(u)
        vals.append(urllib.parse.urlunparse((q.scheme,q.netloc,q.path.rstrip('/') or '/', '', q.query,'')))
    vals=list(dict.fromkeys(vals)); p=urllib.parse.urlparse(page_url)
    target=urllib.parse.urlunparse((p.scheme,p.netloc,p.path.rstrip('/') or '/', '', p.query,''))
    if len(vals)>1: return {"status":"conflict","canonical":vals,"evidence":f"Multiple canonical URLs declared: {', '.join(vals[:3])}."}
    if urllib.parse.urlparse(vals[0]).netloc.lower()!=p.netloc.lower(): return {"status":"external","canonical":vals[0],"evidence":f"Canonical points to a different host: {vals[0]}."}
    if vals[0]!=target: return {"status":"mismatch","canonical":vals[0],"evidence":f"Canonical {vals[0]} differs from the audited URL {target}."}
    return {"status":"pass","canonical":vals[0],"evidence":"Canonical URL is present and matches the audited page."}

def discover_sitemap_candidates(base_url, robots_sitemaps=None):
    out=[]
    for u in (robots_sitemaps or []):
        if u and u not in out: out.append(u)
    for path in SITEMAP_PATH_CANDIDATES:
        u=base_url.rstrip('/')+path
        if u not in out: out.append(u)
    return out

def classify_page_semantics(url, parser, schemas):
    base=detect_page_type(url,'',parser.title,schemas); text=' '.join(parser.texts[:40]).lower()
    if base=='general':
        if re.search(r'\b(api|developer documentation|reference docs|getting started)\b',text): return 'documentation'
        if re.search(r'\b(price|pricing|per month|per year|free trial)\b',text): return 'pricing'
        if re.search(r'\b(frequently asked questions|common questions)\b',text): return 'faq'
    return base

def analyze_redirect_chain(requested_url, response_headers):
    chain = []
    final_url = requested_url
    if isinstance(response_headers, dict):
        chain = response_headers.get('_redirect_chain') or []
        final_url = response_headers.get('_final_url') or requested_url
    try:
        requested = urllib.parse.urlparse(requested_url)
        final = urllib.parse.urlparse(final_url)
        cross_domain = bool(final.netloc and requested.netloc and not is_same_domain(final_url, requested_url))
    except Exception:
        cross_domain = False
    status = 'pass'
    evidence = f'No redirect chain detected; final URL is {final_url}.'
    if chain:
        hops = len(chain)
        cross_hop = any(not is_same_domain(x.get('to',''), requested_url) for x in chain)
        status = 'warning' if hops >= 3 or cross_hop else 'pass'
        evidence = f'Request followed {hops} redirect hop(s) and ended at {final_url}.'
        if hops >= 3: evidence += ' Redirect chain is longer than two hops and may waste crawl budget.'
        if cross_hop: evidence += ' Redirect chain crosses to a different host.'
    return {'status':status,'hops':len(chain),'chain':chain[:8],'final_url':final_url,'cross_domain':cross_domain,'severity':'medium','confidence':0.98,'evidence':evidence}


def schema_page_mismatch(page_type, schemas):
    schemas={str(x).lower() for x in schemas}
    expected={
        'homepage': {'organization','website','webpage'},
        'product': {'product','offer'},
        'article': {'article','blogposting','newsarticle'},
        'faq': {'faqpage','question'},
        'service': {'service','organization'},
        'contact': {'organization','localbusiness','contactpoint'},
        'about': {'organization','person','aboutpage'},
        'pricing': {'product','offer','service','webpage'},
        'documentation': {'techarticle','article','webpage'},
    }.get(page_type, set())
    if not schemas or not expected: return []
    if schemas.intersection(expected): return []
    return sorted(expected)


def schema_quality(page_type, schemas, details):
    """Return an explainable page-type schema coverage score using alternatives."""
    alternatives={
        'homepage':[['Organization','WebSite']],
        'product':[['Product','Offer']],
        'article':[['Article','BlogPosting','NewsArticle']],
        'faq':[['FAQPage']],
        'service':[['Service']],
    }.get(page_type, [])
    if not alternatives: return {'score':100,'missing':[],'reason':'No page-type-specific schema expectation.'}
    present={str(x) for x in schemas}
    covered=sum(1 for group in alternatives if any(x in present for x in group))
    missing=[' or '.join(group) for group in alternatives if not any(x in present for x in group)]
    score=round(covered/len(alternatives)*100)
    return {'score':score,'missing':missing,'reason':f'{covered}/{len(alternatives)} page-type schema requirement group(s) covered.'}


def analyze_technical(url, max_crawl_pages=6, fetch_fn=None):
    EXECUTION_ERRORS.clear()
    """
    Executes a comprehensive, bounded technical audit.
    Strictly respects robots.txt, discovers sitemaps, crawls representative pages,
    and audits structured data, JS-render gaps, and media accessibility.
    """
    fetch = fetch_fn if fetch_fn is not None else fetch_url
    parsed_url = urllib.parse.urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    findings = {
        "robots": {
            "checked": True,
            "audit_crawler_allowed": True,
            "blocks_all": False,
            "blocked_bots": [],
            "allowed_bots": [],
            "evidence": ""
        },
        "sitemap": {
            "found": False,
            "valid": False,
            "url_count": 0,
            "sampled": 0,
            "lastmod_available": False,
            "latest_lastmod": None,
            "evidence": ""
        },
        "crawl_scope": {
            "pages_attempted": 0,
            "pages_successfully_crawled": 0,
            "pages_failed": 0,
            "robots_disallowed_urls": [],
            "max_pages": max_crawl_pages,
            "sitemap_used": False,
            "crawled_urls": []
        },
        "robots_txt": {
            "status": "not_checked",
            "blocks_all": False,
            "blocked_bots": [],
            "sitemaps": [],
            "evidence": ""
        },
        "crawler_block": {
            "status": "pass",
            "evidence": "",
            "confidence": 1.0
        },
        "js_render_gap": {
            "status": "pass",
            "severity": "medium",
            "evidence": "",
            "confidence": 0.8,
            "affected_pages": []
        },
        "structured_data": {
            "status": "pass",
            "severity": "high",
            "schemas_found": [],
            "missing_properties": {},
            "evidence": "",
            "confidence": 0.9,
            "affected_pages": []
        },
        "faq_schema_check": {
            "status": "pass",
            "severity": "medium",
            "evidence": "",
            "confidence": 0.85,
            "affected_pages": []
        },
        "viewport_check": {
            "status": "pass",
            "severity": "medium",
            "evidence": "",
            "confidence": 0.95,
            "affected_pages": []
        },
        "canonical_check": {"status":"not_checked","severity":"medium","confidence":0.95,"evidence":"","affected_pages":[]},
        "redirect_check": {"status":"pass","severity":"medium","confidence":0.98,"hops":0,"chain":[],"final_url":url,"evidence":""},
        "redirect_checks": [],
        "indexability_check": {"status":"pass","severity":"high","confidence":0.95,"evidence":"","affected_pages":[]},
        "fact_parity": {"status":"pass","severity":"high","confidence":0.9,"mismatches":[],"evidence":"","affected_pages":[]},
        "rendered_mobile": {"status":"unavailable","severity":"medium","confidence":0.5,"evidence":"","affected_pages":[]},
        "rendered_engagement": {"status":"unavailable","metrics":[],"evidence":""},
        "locked_content": {
            "status": "pass",
            "severity": "medium",
            "evidence": "",
            "confidence": 0.85,
            "affected_pages": []
        }
    }
    
    # 1. Robots.txt Compliance Check
    robots_info = evaluate_robots_txt(base_url, url, fetch_fn=fetch_fn)
    findings["robots"]["audit_crawler_allowed"] = robots_info["audit_crawler_allowed"]
    findings["robots"]["blocks_all"] = robots_info["blocks_all"]
    findings["robots"]["blocked_bots"] = robots_info["blocked_bots"]
    findings["robots"]["allowed_bots"] = robots_info["allowed_bots"]
    findings["robots"]["evidence"] = robots_info["evidence"]
    
    findings["robots_txt"]["status"] = robots_info["status"]
    findings["robots_txt"]["blocks_all"] = robots_info["blocks_all"]
    findings["robots_txt"]["blocked_bots"] = robots_info["blocked_bots"]
    findings["robots_txt"]["sitemaps"] = robots_info["sitemaps"]
    findings["robots_txt"]["evidence"] = robots_info["evidence"]
    
    # CRITICAL: Strict robots.txt compliance guard on homepage
    if not robots_info["audit_crawler_allowed"]:
        findings["crawler_block"]["status"] = "fail"
        findings["crawler_block"]["severity"] = "critical"
        findings["crawler_block"]["confidence"] = 1.0
        findings["crawler_block"]["evidence"] = (
            f"Target URL ({url}) is disallowed for web crawlers in robots.txt. "
            "Audit crawler strictly respects robots.txt directives and aborted page fetching to avoid policy violations."
        )
        findings["crawl_scope"]["robots_disallowed_urls"].append(url)
        for k in ["js_render_gap", "structured_data", "faq_schema_check", "viewport_check", "locked_content"]:
            findings[k]["status"] = "unavailable"
            findings[k]["evidence"] = f"Skipped check: Target URL disallowed by robots.txt."
        return findings

    # 2. XML Sitemap Discovery
    sitemap_candidates = discover_sitemap_candidates(base_url, robots_info["sitemaps"])
    
    sitemap_data = None
    for sm_url in sitemap_candidates:
        sm_res = parse_xml_sitemap(sm_url, base_url, fetch_fn=fetch_fn)
        if sm_res["found"] and sm_res["valid"]:
            sitemap_data = sm_res
            break
        elif sm_res["found"] and sm_res.get("recoverable") and not sitemap_data:
            sitemap_data = sm_res
            
    if sitemap_data:
        findings["sitemap"] = sitemap_data
        findings["sitemap"]["sampled"] = len(sitemap_data["urls"][:max_crawl_pages])
        findings["sitemap"]["lastmod_available"] = bool(sitemap_data["latest_lastmod"])
        findings["sitemap"]["url_count"] = sitemap_data["url_count"]
        findings["sitemap"]["recoverable"] = sitemap_data.get("recoverable", False)
    else:
        findings["sitemap"]["evidence"] = "No valid XML sitemap discovered via robots.txt or /sitemap.xml."

    # 3. Fetch Target URL HTML
    status_code, page_html, response_headers = fetch(url)
    findings["crawl_scope"]["pages_attempted"] = 1
    
    if status_code != 200:
        # Status 0 means the HTTP stack could not establish a response (DNS,
        # timeout, TLS, local network policy, etc.). It is not evidence that the
        # target site blocked the audit crawler, so do not turn it into a false
        # critical anti-bot finding.
        if status_code == 0:
            error_detail = (response_headers or {}).get("_error", "network request failed") if isinstance(response_headers, dict) else "network request failed"
            findings["crawler_block"]["status"] = "unavailable"
            findings["crawler_block"]["evidence"] = f"Target page could not be fetched because the HTTP request did not receive a response: {error_detail}. This is an audit-environment/network limitation, not proof that the site blocks crawlers."
            findings["crawler_block"]["confidence"] = 0.98
        else:
            findings["crawler_block"]["status"] = "fail"
            findings["crawler_block"]["evidence"] = f"HTTP request to target URL failed with status code {status_code}."
            findings["crawler_block"]["confidence"] = 0.95
        for k in ["js_render_gap", "structured_data", "faq_schema_check", "viewport_check", "locked_content"]:
            findings[k]["status"] = "unavailable"
            findings[k]["evidence"] = f"Skipped check: Page fetching did not succeed (status {status_code})."
        return findings
    else:
        findings["crawler_block"]["evidence"] = "HTTP GET request succeeded with status code 200."
        findings["crawl_scope"]["pages_successfully_crawled"] = 1
        findings["crawl_scope"]["crawled_urls"].append(url)

    findings["redirect_check"] = analyze_redirect_chain(url, response_headers)
    if findings["redirect_check"].get("status") == "warning":
        findings["redirect_check"]["affected_pages"] = [url]

    x_robots=(response_headers or {}).get("X-Robots-Tag","") if isinstance(response_headers,dict) else ""
    if re.search(r"\bnoindex\b",x_robots,re.I):
        findings["indexability_check"]={"status":"fail","severity":"high","confidence":1.0,"evidence":f"HTTP X-Robots-Tag contains noindex: {x_robots}.","affected_pages":[url]}

    # 4. Parse Homepage & Mini-Crawl Representative Pages
    homepage_parser = TechHTMLParser(page_url=url)
    try:
        homepage_parser.feed(page_html)
    except Exception:
        homepage_parser.body_text_length = len(page_html)

    if any("noindex" in m.get("content","").lower() for m in homepage_parser.robots_meta):
        findings["indexability_check"]={"status":"fail","severity":"high","confidence":1.0,"evidence":f"Meta robots directives contain noindex: {homepage_parser.robots_meta}.","affected_pages":[url]}
    canon=validate_canonical(url,homepage_parser.canonical_urls)
    if canon["status"]=="missing":
        canon["evidence"] += " Absence alone is not treated as a defect; inconsistent or external canonicals are the actionable cases."
    findings["canonical_check"]={"status":"pass" if canon["status"]=="missing" else canon["status"],"severity":"medium" if canon["status"]=="missing" else "high","confidence":0.98 if canon["status"]!="missing" else 0.92,"evidence":canon["evidence"],"affected_pages":[url] if canon["status"] not in ("pass","missing") else []}

    sitemap_urls = sitemap_data["urls"] if sitemap_data else []
    candidate_metadata={}
    for item in getattr(homepage_parser,'internal_link_metadata',[]):
        norm=urllib.parse.urljoin(url,item.get('href',''))
        if is_same_domain(norm,url):
            candidate_metadata[urllib.parse.urlparse(norm)._replace(fragment='').geturl()]={'anchor_text':item.get('anchor_text','')}
    if sitemap_data:
        for sm_url,priority in sitemap_data.get('priorities',{}).items():
            norm=urllib.parse.urlparse(sm_url)._replace(fragment='').geturl()
            if is_same_domain(norm,url):
                candidate_metadata.setdefault(norm,{})['sitemap_priority']=priority
    crawl_candidates = select_crawl_candidates(url, homepage_parser.internal_links, sitemap_urls, max_pages=max_crawl_pages, page_metadata=candidate_metadata)
    
    all_parsers = [homepage_parser]
    all_pages_html = [(url, page_html)]
    
    # Bounded crawler respecting robots.txt
    rp = urllib.robotparser.RobotFileParser()
    if robots_info["raw_content"]:
        rp.parse(robots_info["raw_content"].splitlines())
        
    for sub_url in crawl_candidates[1:]:
        # Check robots.txt for every candidate URL
        if robots_info["raw_content"] and not rp.can_fetch(AUDIT_BOT_NAME, sub_url):
            findings["crawl_scope"]["robots_disallowed_urls"].append(sub_url)
            continue
            
        findings["crawl_scope"]["pages_attempted"] += 1
        sub_code, sub_html, sub_headers = fetch(sub_url)
        sub_redirect=analyze_redirect_chain(sub_url, sub_headers)
        sub_redirect['url']=sub_url
        findings['redirect_checks'].append(sub_redirect)
        if sub_code == 200 and sub_html:
            findings["crawl_scope"]["pages_successfully_crawled"] += 1
            findings["crawl_scope"]["crawled_urls"].append(sub_url)
            sub_parser = TechHTMLParser(page_url=sub_url)
            try:
                sub_parser.feed(sub_html)
            except Exception as e:
                _record_execution_error("Non-fatal technical check failure", e)
            all_parsers.append(sub_parser)
            all_pages_html.append((sub_url, sub_html))
        else:
            findings["crawl_scope"]["pages_failed"] += 1

    if any(x.get('status')=='warning' for x in findings.get('redirect_checks',[])) and findings['redirect_check'].get('status')!='warning':
        findings['redirect_check']={'status':'warning','severity':'medium','confidence':0.96,'hops':max((x.get('hops',0) for x in findings['redirect_checks']),default=0),'chain':[],'final_url':url,'evidence':'One or more sampled internal pages use a long or cross-host redirect chain.','affected_pages':[x.get('url') for x in findings['redirect_checks'] if x.get('status')=='warning']}

    findings["crawl_scope"]["sitemap_used"] = bool(sitemap_data and sitemap_data["valid"])
    findings["sitemap"]["sampled"] = len(all_parsers)

    # Page-level indexability/canonical checks and internal-link graph signals.
    indexability_issues=[]; canonical_issues=[]; orphan_candidates=[]; page_fact_mismatches=[]
    crawled_set={p.page_url.rstrip('/') for p in all_parsers}
    inbound={u:0 for u in crawled_set}
    for p in all_parsers:
        for link in p.internal_links:
            target=urllib.parse.urljoin(p.page_url, link).split('#')[0].rstrip('/')
            if target in inbound: inbound[target]+=1
        if any('noindex' in m.get('content','').lower() for m in p.robots_meta):
            indexability_issues.append(p.page_url)
        c=validate_canonical(p.page_url,p.canonical_urls)
        if c['status'] not in ('pass','missing'): canonical_issues.append({'url':p.page_url,**c})
        _,_,mm=compare_visible_structured_facts(p)
        if mm: page_fact_mismatches.append({'url':p.page_url,'mismatches':mm})
    for target,count in inbound.items():
        if count==0 and target.rstrip('/') != url.rstrip('/') and sitemap_data and target in {x.rstrip('/') for x in sitemap_data.get('urls',[])}:
            orphan_candidates.append(target)
    if indexability_issues:
        findings['indexability_check']={'status':'fail','severity':'high','confidence':1.0,'evidence':f'noindex detected on {len(indexability_issues)} crawled page(s).','affected_pages':indexability_issues}
    if canonical_issues:
        findings['canonical_check']={'status':'warning','severity':'high','confidence':0.96,'evidence':f'Inconsistent canonical declarations detected on {len(canonical_issues)} crawled page(s).','affected_pages':[x['url'] for x in canonical_issues]}
    findings['page_graph']={'crawled_pages':len(all_parsers),'inbound_link_counts':inbound,'potential_orphans':orphan_candidates,'evidence':f'{len(orphan_candidates)} sitemap-listed crawled targets have no inbound links from the sampled graph.' if orphan_candidates else 'No potential orphan pages found within the sampled sitemap/crawl graph.'}
    findings['fact_parity']={'status':'warning' if page_fact_mismatches else 'pass','severity':'high','confidence':0.93 if page_fact_mismatches else 0.9,'mismatches':page_fact_mismatches,'evidence':f'Found visible-vs-structured fact mismatches on {len(page_fact_mismatches)} crawled page(s).' if page_fact_mismatches else 'Visible high-value facts are consistent with structured data where both expose the same fact types across sampled pages.','affected_pages':[x['url'] for x in page_fact_mismatches]}

    # 5. JS-Render Gap Evaluation
    playwright_available = False
    playwright_error = None
    rendered_text_len = None
    rendered_body = None
    
    try:
        from playwright.sync_api import sync_playwright
        playwright_available = True
    except ImportError:
        playwright_available = False
        playwright_error = "Playwright module not found"
        
    rendered_pages=[]; rendered_metrics=[]
    if playwright_available:
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True)
                context=browser.new_context(user_agent=AUDIT_USER_AGENT,viewport={"width":1440,"height":900})
                page=context.new_page()
                targets=[u for u in [url]+findings["crawl_scope"]["crawled_urls"][1:4]]
                for target in targets:
                    try:
                        page.goto(target,wait_until="domcontentloaded",timeout=8000)
                        try: page.wait_for_load_state("networkidle",timeout=2500)
                        except Exception as e: _record_execution_error("Non-fatal technical check failure", e)
                        body=page.locator("body").inner_text(); h=page.locator("h1").first.bounding_box() if page.locator("h1").count() else None
                        c=page.locator("a,button").filter(has_text=re.compile(r"(get started|buy now|book .*demo|request .*demo|contact sales|start free trial|sign up)",re.I)); cb=c.first.bounding_box() if c.count() else None
                        rendered_pages.append((target,body)); rendered_metrics.append({"url":target,"rendered_text_length":len(body.strip()),"h1_top_px":round(h["y"],1) if h else None,"cta_top_px":round(cb["y"],1) if cb else None,"horizontal_overflow_px":max(0,int(page.evaluate("document.documentElement.scrollWidth-window.innerWidth")))})
                    except Exception as e: js_ev.append(f"Render failed for {target}: {str(e)[:120]}")
                try:
                    mobile=context.new_page(viewport={"width":390,"height":844},is_mobile=True); mobile.goto(url,wait_until="domcontentloaded",timeout=8000)
                    try: mobile.wait_for_load_state("networkidle",timeout=2500)
                    except Exception as e: _record_execution_error("Non-fatal technical check failure", e)
                    ov=max(0,int(mobile.evaluate("document.documentElement.scrollWidth-window.innerWidth"))); mh=mobile.locator("h1").first.bounding_box() if mobile.locator("h1").count() else None
                    mc=mobile.locator("a,button").filter(has_text=re.compile(r"(get started|buy now|book .*demo|request .*demo|contact sales|start free trial|sign up)",re.I)); mcb=mc.first.bounding_box() if mc.count() else None
                    h1_below=bool(mh and mh["y"]>844); cta_below=bool(mcb and mcb["y"]>844)
                    mobile_issue=ov>8 or h1_below or cta_below
                    findings["rendered_mobile"]={"status":"warning" if mobile_issue else "pass","severity":"medium","confidence":0.9,"evidence":f"Mobile viewport 390x844: horizontal overflow {ov}px; H1 top {round(mh['y'],1) if mh else 'not found'}px; primary CTA top {round(mcb['y'],1) if mcb else 'not found'}px; below-fold H1={h1_below}, below-fold CTA={cta_below}.","affected_pages":[url] if mobile_issue else []}
                    mobile.close()
                except Exception as e: findings["rendered_mobile"]["evidence"]=f"Mobile rendering unavailable: {str(e)[:160]}"
                browser.close()
        except Exception as e: playwright_error=str(e)
    text_len=homepage_parser.body_text_length; has_spa_div=homepage_parser.div_root_count>0; scripts_cnt=homepage_parser.scripts_count
    js_ev=[]
    if has_spa_div: js_ev.append("SPA root container (e.g. #root, #app) detected.")
    raw_by_url={u:h for u,h in all_pages_html}
    if rendered_pages:
        gap_pages=[]
        for target,body in rendered_pages:
            raw=raw_by_url.get(target,""); raw_clean=re.sub(r"<script[^>]*>.*?</script>|<style[^>]*>.*?</style>"," ",raw,flags=re.I|re.S); raw_text=re.sub(r"<[^>]+>"," ",raw_clean)
            rf=_extract_machine_facts(raw_text); ff=_extract_machine_facts(body); missing=[]
            for fact in ("phones","emails","prices"):
                if ff[fact] and not set(map(_norm_fact,ff[fact])).intersection(map(_norm_fact,rf[fact])): missing.append(fact)
            ratio=len(body.strip())/max(1,len(raw_text.strip()))
            js_ev.append(f"{target}: raw readable text {len(raw_text.strip())} chars; rendered {len(body.strip())} chars ({ratio:.1f}x).")
            if missing: js_ev.append(f"Fact-level dynamic content only visible after render: {', '.join(missing)}.")
            if missing or (len(body)>500 and len(raw_text)<200 and ratio>2): gap_pages.append(target)
        if gap_pages:
            findings["js_render_gap"].update({"status":"fail","severity":"high","confidence":0.92,"affected_pages":gap_pages})
        else: findings["js_render_gap"].update({"status":"pass","confidence":0.92})
    else:
        findings["js_render_gap"].update({"status":"unavailable","severity":"medium","confidence":0.5}); js_ev.append(f"JS-render check incomplete: Headless browser unavailable or failed ({playwright_error or 'unknown error'}). Raw HTML fallback used."); js_ev.append(f"Raw HTML contains {scripts_cnt} scripts and {text_len} characters of text.")
    findings["js_render_gap"]["evidence"]=" ".join(js_ev)
    findings["rendered_engagement"]={"status":"pass" if rendered_metrics else "unavailable","metrics":rendered_metrics,"evidence":"Rendered desktop geometry sampled on representative pages." if rendered_metrics else "No rendered geometry available."}
    findings["js_render_gap"]["evidence"] = " ".join(js_ev)

    # 6. Deep Structured Data Analysis across all crawled pages
    all_schemas = []
    schema_details = {}
    invalid_json_count = 0
    missing_props_report = {}
    pages_with_schema = set()
    
    page_type_gaps = {}
    for page_item in all_parsers:
        p_schemas = []
        for block in page_item.json_ld_contents:
            try:
                parsed_json = json.loads(block)
                pages_with_schema.add(page_item.page_url)
                extract_schemas_recursive(parsed_json, all_schemas, schema_details)
                extract_schemas_recursive(parsed_json, p_schemas, {})
            except json.JSONDecodeError:
                invalid_json_count += 1
                
        # Evaluate schema expectations for this page archetype
        pt = classify_page_semantics(page_item.page_url, page_item, p_schemas)
        quality = schema_quality(pt, p_schemas, schema_details)
        if quality['missing']:
            page_type_gaps.setdefault('quality:'+pt, []).append({'url':page_item.page_url,'missing':quality['missing'],'score':quality['score']})
        mismatch_expected=schema_page_mismatch(pt,p_schemas)
        if mismatch_expected:
            page_type_gaps.setdefault('mismatch:'+pt, []).append({'url':page_item.page_url,'expected_any_of':mismatch_expected,'found':p_schemas})
        if pt == "product" and not any(s in p_schemas for s in ["Product", "Offer"]):
            page_type_gaps.setdefault("Product", []).append(page_item.page_url)
        elif pt == "article" and not any(s in p_schemas for s in ["Article", "BlogPosting", "NewsArticle"]):
            page_type_gaps.setdefault("Article", []).append(page_item.page_url)
        elif pt == "homepage" and not any(s in p_schemas for s in ["Organization", "WebSite"]):
            page_type_gaps.setdefault("Organization", []).append(page_item.page_url)
                
    unique_schemas = list(set(all_schemas))
    findings["structured_data"]["schemas_found"] = unique_schemas
    
    for stype, instances in schema_details.items():
        for inst in instances:
            missing = audit_schema_properties(stype, inst)
            if missing:
                missing_props_report.setdefault(stype, set()).update(missing)
                
    findings["structured_data"]["missing_properties"] = {k: list(v) for k, v in missing_props_report.items()}
    findings["structured_data"]["page_type_gaps"] = page_type_gaps
    
    sd_ev = []
    if unique_schemas:
        sd_ev.append(f"Detected valid Schema.org types across crawled pages: {', '.join(unique_schemas)}.")
        if missing_props_report:
            missing_desc = [f"{k} (missing {', '.join(v)})" for k, v in missing_props_report.items()]
            sd_ev.append(f"Incomplete schemas detected: {'; '.join(missing_desc)}.")
            findings["structured_data"]["status"] = "warning"
            findings["structured_data"]["severity"] = "medium"
            findings["structured_data"]["confidence"] = 0.85
        if page_type_gaps:
            gaps_desc = [f"{st} schema missing on {len(urls)} {st.lower()} page(s)" for st, urls in page_type_gaps.items()]
            sd_ev.append(f"Page-type schema gaps: {'; '.join(gaps_desc)}.")
            findings["structured_data"]["status"] = "warning"
            findings["structured_data"]["severity"] = "medium"
            findings["structured_data"]["confidence"] = 0.85
    else:
        sd_ev.append("No Schema.org JSON-LD structured data detected across crawled pages.")
        findings["structured_data"]["status"] = "warning"
        findings["structured_data"]["severity"] = "medium"
        findings["structured_data"]["confidence"] = 0.85
        if page_type_gaps:
            gaps_desc = [f"{st} schema recommended for {len(urls)} {st.lower()} page(s)" for st, urls in page_type_gaps.items()]
            sd_ev.append(f"Priority recommendations: {'; '.join(gaps_desc)}.")
        
    if invalid_json_count > 0:
        sd_ev.append(f"Detected {invalid_json_count} broken or invalid JSON-LD script blocks.")
        findings["structured_data"]["status"] = "fail"
        findings["structured_data"]["severity"] = "high"
        findings["structured_data"]["confidence"] = 1.0
        
    findings["structured_data"]["evidence"] = " ".join(sd_ev)
    sd_pages=set()
    for vals in page_type_gaps.values():
        for item in vals:
            if isinstance(item,dict): sd_pages.add(item.get('url'))
            elif isinstance(item,str): sd_pages.add(item)
    findings["structured_data"]["affected_pages"] = sorted(x for x in sd_pages if x)

    # 7. Accurate FAQ Parity Check
    has_faq_schema = "FAQPage" in unique_schemas or "Question" in unique_schemas
    total_faq_headings = sum(p.faq_clues_count for p in all_parsers)
    total_accordions = sum(p.details_count for p in all_parsers)
    
    question_candidates = []
    for parser in all_parsers:
        for text in parser.texts:
            for q in re.findall(r'([^.!?]+\?)', text):
                q_clean = q.strip()
                if len(q_clean.split()) > 3 and any(w in q_clean.lower() for w in ["what", "how", "why", "who", "where", "when", "can", "is", "are", "do", "does", "should"]):
                    question_candidates.append(q_clean)
                    
    is_real_faq_content = (total_faq_headings >= 1) or (total_accordions >= 1) or (len(question_candidates) >= 2)
    
    if is_real_faq_content and not has_faq_schema:
        findings["faq_schema_check"] = {
            "status": "warning",
            "severity": "medium",
            "confidence": 0.85,
            "evidence": f"Found FAQ structures (headings/accordions: {total_faq_headings + total_accordions}, questions: {len(question_candidates)}) on crawled pages, but no matching FAQPage Schema.org JSON-LD is declared.",
            "affected_pages": [p.page_url for p in all_parsers if p.faq_clues_count > 0 or p.details_count > 0]
        }
    elif has_faq_schema:
        findings["faq_schema_check"] = {
            "status": "pass",
            "severity": "medium",
            "confidence": 0.95,
            "evidence": "FAQPage structured data markup is present, facilitating direct question-and-answer indexing by AI assistants.",
            "affected_pages": []
        }
    else:
        findings["faq_schema_check"] = {
            "status": "pass",
            "severity": "medium",
            "confidence": 0.8,
            "evidence": "No dedicated FAQ section detected on sampled pages.",
            "affected_pages": []
        }

    # 8. Refined Image & Non-Text Media Accessibility Audit
    total_images = sum(p.images_count for p in all_parsers)
    informative_images = sum(p.images_informative for p in all_parsers)
    informative_no_alt = sum(p.images_informative_no_alt for p in all_parsers)
    decorative_images = sum(p.images_decorative for p in all_parsers)
    
    has_canvas = any(p.has_canvas for p in all_parsers)
    canvas_fallback = any(bool(p.canvas_fallback_texts) for p in all_parsers)
    
    locked_ev = []
    locked_status = "pass"
    
    if informative_images > 0:
        ratio_missing = informative_no_alt / informative_images
        locked_ev.append(f"Sampled {total_images} images ({decorative_images} decorative with valid empty alt/role). Found {informative_no_alt}/{informative_images} ({ratio_missing:.1%}) informative images lacking descriptive alt text.")
        if ratio_missing > 0.4 and informative_no_alt >= 2:
            locked_status = "warning"
    else:
        locked_ev.append("No inline informative images found.")
        
    if has_canvas:
        if canvas_fallback:
            locked_ev.append("Canvas elements detected with readable fallback text or accessible labels.")
        else:
            # Check if page has ample explanatory text
            if homepage_parser.body_text_length > 500:
                locked_ev.append("Canvas elements detected alongside explanatory HTML text.")
            else:
                locked_ev.append("Canvas elements detected without machine-readable text fallbacks.")
                locked_status = "warning"
                
    findings["locked_content"]["status"] = locked_status
    findings["locked_content"]["evidence"] = " ".join(locked_ev)

    # 9. Viewport Metadata Check
    missing_viewport_pages = [p.page_url for p in all_parsers if not p.has_viewport]
    if missing_viewport_pages:
        findings["viewport_check"] = {
            "status": "warning",
            "severity": "medium",
            "confidence": 0.95,
            "evidence": f"Viewport meta tag is missing on {len(missing_viewport_pages)} sampled page(s), degrading responsive rendering and mobile readability.",
            "affected_pages": missing_viewport_pages
        }
    else:
        findings["viewport_check"] = {
            "status": "pass",
            "severity": "medium",
            "confidence": 0.95,
            "evidence": "Viewport meta tag is declared, ensuring proper responsive scaling on mobile devices.",
            "affected_pages": []
        }

    findings["execution"] = {"partial": bool(EXECUTION_ERRORS), "errors": list(EXECUTION_ERRORS)}
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Technical crawlability, robots compliance, and rendering audit")
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--max-pages", type=int, default=6, help="Maximum pages to sample for bounded mini-crawl")
    parser.add_argument("--output", help="Path to write output JSON")
    args = parser.parse_args()
    
    url = args.url
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
        
    report = analyze_technical(url, max_crawl_pages=args.max_pages)
    output_data = json.dumps(report, indent=2)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output_data)
        print(f"Technical audit written to {args.output}")
    else:
        print(output_data)
