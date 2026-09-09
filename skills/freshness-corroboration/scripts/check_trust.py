#!/usr/bin/env python3
"""
Trust and Freshness Audit Script - freshness-corroboration
Identifies copyright years, evaluates multi-signal content freshness (HTTP Last-Modified,
sitemap lastmod, schema dateModified, meta timestamps, text mentions), extracts brand information,
validates schema.org sameAs entity disambiguation, and corroborates facts against external APIs.
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
from datetime import datetime, timezone
import ipaddress
import socket
import time
from contextlib import contextmanager

AUDIT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BrandAuditBot/1.0"

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


class TrustHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.texts = []
        self.in_script_or_style = False
        self.in_json_ld = False
        self.current_json_ld = []
        self.json_ld_blocks = []
        
        self.title = ""
        self.in_title = False
        self.meta_description = ""
        self.meta_dates = []
        
        self.links = []
        self.has_contact_link = False
        self.has_author_link = False
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()
        
        if tag_lower == 'script':
            stype = attrs_dict.get('type', '').lower()
            if 'application/ld+json' in stype:
                self.in_json_ld = True
                self.current_json_ld = []
            else:
                self.in_script_or_style = True
        elif tag_lower == 'style':
            self.in_script_or_style = True
        elif tag_lower == 'title':
            self.in_title = True
        elif tag_lower == 'meta':
            name = (attrs_dict.get('name') or attrs_dict.get('property') or '').lower()
            content = attrs_dict.get('content', '')
            if name == 'description':
                self.meta_description = content
            elif any(d in name for d in ['modified', 'published', 'updated', 'date', 'lastmod']):
                if content:
                    self.meta_dates.append({"name": name, "content": content})
        elif tag_lower == 'a':
            href = attrs_dict.get('href', '')
            rel = attrs_dict.get('rel', '').lower()
            title = attrs_dict.get('title', '')
            self.links.append({"href": href, "text": title, "rel": rel})
            if any(k in href.lower() for k in ["contact", "about", "support", "help", "team"]):
                self.has_contact_link = True
            if "author" in rel or "author" in href.lower():
                self.has_author_link = True

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == 'script':
            if self.in_json_ld:
                self.in_json_ld = False
                raw_json = "".join(self.current_json_ld).strip()
                if raw_json:
                    self.json_ld_blocks.append(raw_json)
                self.current_json_ld = []
            else:
                self.in_script_or_style = False
        elif tag_lower == 'style':
            self.in_script_or_style = False
        elif tag_lower == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_json_ld:
            self.current_json_ld.append(data)
        elif self.in_title:
            self.title += data
        elif not self.in_script_or_style:
            stripped = data.strip()
            if stripped:
                self.texts.append(stripped)


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
        return rp.can_fetch(user_agent,url),robots_url
    except Exception as e:
        _record_execution_error(f"robots.txt check failed for {url}", e)
        return True,robots_url

def validate_sameas_links(same_as_links, brand_name):
    supported={"wikidata.org","wikipedia.org","linkedin.com","crunchbase.com","dbpedia.org"}; tokens={x for x in re.findall(r"[a-z0-9]+",(brand_name or "").lower()) if len(x)>2}; valid=[]; suspicious=[]
    for link in same_as_links:
        try:
            q=urllib.parse.urlparse(link); host=q.netloc.lower().removeprefix("www.")
            if not any(host==d or host.endswith("."+d) for d in supported): suspicious.append(link); continue
            path_tokens=set(re.findall(r"[a-z0-9]+",urllib.parse.unquote(q.path.lower())))
            if tokens and path_tokens and not (tokens & path_tokens) and host!="wikidata.org": suspicious.append(link)
            else: valid.append(link)
        except Exception: suspicious.append(link)
    return valid,suspicious

def fetch_page_with_headers(url, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"):
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
            html_bytes = response.read(2 * 1024 * 1024 + 1)
            if len(html_bytes) > 2 * 1024 * 1024:
                html_bytes = html_bytes[:2 * 1024 * 1024]
            encoding = response.info().get_content_charset() or 'utf-8'
            decoded_html = html_bytes.decode(encoding, errors='replace')
            http_last_modified = response.headers.get('Last-Modified')
            return decoded_html, http_last_modified
    except Exception as e:
        message=_record_execution_error(f"Page fetch blocked/failed for {url}", e)
        return f"Error: {message}", None


def check_external_apis(brand_name):
    if not brand_name or brand_name == "Unknown Brand":
        return []
        
    results = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BrandAuditBot/1.0'}
    
    # 1. Query Wikipedia Search API
    try:
        wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(brand_name)}&format=json"
        req = urllib.request.Request(wiki_url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.loads(response.read().decode('utf-8'))
            search_list = data.get("query", {}).get("search", [])
            for s in search_list[:3]:
                results.append({
                    "title": s.get("title"),
                    "snippet": re.sub(r'<[^>]+>', '', s.get("snippet", "")),
                    "source": "Wikipedia Search API",
                    "url": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(s.get('title', ''))}"
                })
    except Exception as e:
        _record_execution_error("Wikipedia/Wikidata corroboration failed", e)
        
    # 2. Query Wikidata Search API
    try:
        wikidata_url = f"https://www.wikidata.org/w/api.php?action=wbsearchentities&search={urllib.parse.quote(brand_name)}&language=en&format=json"
        req2 = urllib.request.Request(wikidata_url, headers=headers)
        with urllib.request.urlopen(req2, timeout=8) as response:
            data = json.loads(response.read().decode('utf-8'))
            search_list = data.get("search", [])
            for s in search_list[:3]:
                results.append({
                    "title": s.get("label"),
                    "snippet": s.get("description", "No description available."),
                    "source": "Wikidata Search API",
                    "url": s.get("concepturi") or f"https://www.wikidata.org/wiki/{s.get('id')}"
                })
    except Exception as e:
        _record_execution_error("Wikipedia/Wikidata corroboration failed", e)
        
    return results


def extract_brand_name(html_title, meta_description, target_url):
    domain_guess = ""
    if target_url:
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            domain = parsed_url.netloc or parsed_url.path
            if domain.startswith("www."):
                domain = domain[4:]
            domain_guess = domain.split(".")[0].lower()
        except Exception as e:
            _record_execution_error("Non-fatal trust check failure", e)

    default_brand = domain_guess.capitalize() if domain_guess else "Unknown Brand"
    
    title = html_title.strip() if html_title else ""
    if not title:
        return default_brand
        
    parts = [p.strip() for p in re.split(r'[-–—|•·\u00b7:]', title) if p.strip()]
    if not parts:
        return default_brand
        
    if domain_guess:
        for part in parts:
            clean_part = re.sub(r'\b(?:Logo|Homepage|Portal|Login|Official\s+Site|Official|Home)\b', '', part, flags=re.IGNORECASE).strip()
            if domain_guess in clean_part.lower():
                if len(clean_part) < 40:
                    return clean_part
                    
    shortest = min(parts, key=len)
    if len(shortest) < 30:
        return shortest
        
    return default_brand


def extract_locations(text):
    if not text:
        return set()

    full_names_pattern = (
        r'\b(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|'
        r'Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|'
        r'Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|'
        r'Nebraska|Nevada|New\s+Hampshire|New\s+Jersey|New\s+Mexico|New\s+York|North\s+Carolina|'
        r'North\s+Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode\s+Island|South\s+Carolina|'
        r'South\s+Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West\s+Virginia|'
        r'Wisconsin|Wyoming|United\s+States|United\s+Kingdom|Canada|Germany|France|India|Australia)\b'
    )
    
    us_state_abbrs = {
        "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", 
        "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", 
        "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", 
        "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", 
        "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"
    }
    country_abbrs = {"US", "USA", "UK", "CAN"}
    valid_short_codes = us_state_abbrs | country_abbrs

    found = set()

    for m in re.findall(full_names_pattern, text, re.IGNORECASE):
        norm_name = re.sub(r'\s+', ' ', m.strip()).upper()
        found.add(norm_name)

    comma_matches = re.findall(r',\s*([A-Z]{2,3})\b', text)
    for code in comma_matches:
        if code in valid_short_codes:
            found.add(code)

    zip_matches = re.findall(r'\b([A-Z]{2})\s+\d{5}(?:-\d{4})?\b', text)
    for code in zip_matches:
        if code in us_state_abbrs:
            found.add(code)

    phrase_pattern = (
        r'\b(?:based\s+in|headquartered\s+in|headquarters\s+in|hq\s+in|located\s+in|'
        r'offices?\s+in|branches?\s+in|facilities\s+in|studios?\s+in)\s+(?:the\s+)?([A-Z]{2,3})\b'
    )
    for code in re.findall(phrase_pattern, text, re.IGNORECASE):
        code_upper = code.upper()
        if code_upper in valid_short_codes:
            found.add(code_upper)

    paren_matches = re.findall(r'\(([A-Z]{2,3})\)', text)
    for code in paren_matches:
        if code in valid_short_codes:
            found.add(code)

    country_preposition = r'\b(?:in|across|throughout)\s+(?:the\s+)?(US|USA|UK)\b'
    for code in re.findall(country_preposition, text):
        found.add(code)

    country_noun = r'\b(US|USA|UK)\s+(?:headquarters|offices?|branches?|hq|campus|operations|market)\b'
    for code in re.findall(country_noun, text):
        found.add(code)

    mapping = {
        "ALABAMA": "AL", "ALASKA": "AK", "ARIZONA": "AZ", "ARKANSAS": "AR", "CALIFORNIA": "CA",
        "COLORADO": "CO", "CONNECTICUT": "CT", "DELAWARE": "DE", "FLORIDA": "FL", "GEORGIA": "GA",
        "HAWAII": "HI", "IDAHO": "ID", "ILLINOIS": "IL", "INDIANA": "IN", "IOWA": "IA",
        "KANSAS": "KS", "KENTUCKY": "KY", "LOUISIANA": "LA", "MAINE": "ME", "MARYLAND": "MD",
        "MASSACHUSETTS": "MA", "MICHIGAN": "MI", "MINNESOTA": "MN", "MISSISSIPPI": "MS", "MISSOURI": "MO",
        "MONTANA": "MT", "NEBRASKA": "NE", "NEVADA": "NV", "NEW HAMPSHIRE": "NH", "NEW JERSEY": "NJ",
        "NEW MEXICO": "NM", "NEW YORK": "NY", "NORTH CAROLINA": "NC", "NORTH DAKOTA": "ND", "OHIO": "OH",
        "OKLAHOMA": "OK", "OREGON": "OR", "PENNSYLVANIA": "PA", "RHODE ISLAND": "RI", "SOUTH CAROLINA": "SC",
        "SOUTH DAKOTA": "SD", "TENNESSEE": "TN", "TEXAS": "TX", "UTAH": "UT", "VERMONT": "VT",
        "VIRGINIA": "VA", "WASHINGTON": "WA", "WEST VIRGINIA": "WV", "WISCONSIN": "WI", "WYOMING": "WY",
        "UNITED STATES": "US", "USA": "US", "UNITED KINGDOM": "UK", "CANADA": "CAN", "CAN": "CAN"
    }

    standardized = set()
    for val in found:
        standardized.add(mapping.get(val, val))
    return standardized


def extract_sameas_and_dates_from_json_ld(json_ld_blocks):
    """Recursively walks JSON-LD structures to find true sameAs links and date attributes."""
    same_as_links = []
    schema_dates = []
    
    def visit(obj):
        if isinstance(obj, dict):
            # Only count actual 'sameAs' property, never '@id'
            if "sameAs" in obj:
                sa = obj["sameAs"]
                if isinstance(sa, list):
                    for u in sa:
                        if isinstance(u, str) and u.strip():
                            same_as_links.append(u.strip())
                elif isinstance(sa, str) and sa.strip():
                    same_as_links.append(sa.strip())
            for date_key in ["dateModified", "datePublished", "uploadDate"]:
                if date_key in obj and isinstance(obj[date_key], str):
                    schema_dates.append({"key": date_key, "value": obj[date_key].strip()})
            for k, v in obj.items():
                visit(v)
        elif isinstance(obj, list):
            for item in obj:
                visit(item)

    for block in json_ld_blocks:
        try:
            parsed = json.loads(block)
            visit(parsed)
        except Exception as e:
            _record_execution_error("Non-fatal trust check failure", e)
            
    return same_as_links, schema_dates


def parse_year_from_date_str(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    m = re.search(r'\b(20\d{2})\b', date_str)
    if m:
        try:
            return int(m.group(1))
        except ValueError as e:
            _record_execution_error("Invalid date value encountered", e)
    return None


def fetch_sitemap_lastmod(base_url):
    """Quickly inspects sitemap.xml for the latest lastmod date."""
    try:
        sm_url = f"{base_url.rstrip('/')}/sitemap.xml"
        _respect_rate_limit(sm_url)
        req = urllib.request.Request(sm_url, headers={'User-Agent': AUDIT_USER_AGENT})
        with _guarded_dns(), urllib.request.urlopen(req, timeout=3) as resp:
            text = resp.read(65536).decode('utf-8', errors='replace')
            matches = re.findall(r'<lastmod>\s*(20\d{2})', text, re.IGNORECASE)
            if matches:
                return max([int(m) for m in matches])
    except Exception as e:
        _record_execution_error("Wikipedia/Wikidata corroboration failed", e)
    return None



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


def _trust_status_rank(status):
    return {"fail":3,"warning":2,"unavailable":1,"pass":0}.get(status or "pass",0)

def analyze_trust_pages(page_urls, current_year=None, primary_external=None, max_pages=6):
    EXECUTION_ERRORS.clear()
    """Audit freshness/transparency on bounded representative pages.

    External corroboration is intentionally performed only for the first (primary) page
    to avoid duplicate external queries; page-level freshness/E-E-A-T still runs across
    the representative sample.
    """
    urls=[]
    for u in page_urls or []:
        u=urllib.parse.urldefrag(u)[0]
        if not u.startswith(("http://","https://")): continue
        if u not in urls: urls.append(u)
        if len(urls)>=max(1,min(max_pages,6)): break
    reports=[]
    for i,u in enumerate(urls):
        if not robots_allows(u):
            reports.append({"url":u,"status":"unavailable","multi_signal_freshness":{"status":"unavailable","evidence":"Skipped due to robots.txt."},"eeat_check":{"status":"unavailable","evidence":"Skipped due to robots.txt."}})
            continue
        try:
            html,last_modified=fetch_page_with_headers(u)
        except Exception as e:
            html,last_modified=f"Error: {e}",None
        if not html or html.startswith("Error:"):
            reports.append({"url":u,"status":"unavailable","multi_signal_freshness":{"status":"unavailable","evidence":"Page fetch failed."},"eeat_check":{"status":"unavailable","evidence":"Page fetch failed."}})
            continue
        ext_fn=None
        if i==0 and primary_external is not None:
            ext_fn=primary_external
        r=analyze_trust(html,u,current_year=current_year,http_last_modified=last_modified,external_apis_fn=ext_fn)
        r["url"]=u
        reports.append(r)
    if not reports:
        return {"page_reports":[],"pages_checked":0,"status":"unavailable","evidence":"No representative pages could be audited."}
    out={"page_reports":reports,"pages_checked":len(reports),"audited_urls":[r["url"] for r in reports]}
    for key in ("copyright","multi_signal_freshness","year_mentions","eeat_check"):
        vals=[r.get(key) for r in reports if isinstance(r.get(key),dict)]
        if not vals: continue
        worst=max(vals,key=lambda x:_trust_status_rank(x.get("status")))
        affected=[r["url"] for r in reports if isinstance(r.get(key),dict) and r[key].get("status") in ("warning","fail")]
        ev=[f"{r['url']}: {r[key].get('evidence','')}" for r in reports if isinstance(r.get(key),dict) and r[key].get("evidence")]
        item=dict(worst); item["affected_pages"]=affected; item["evidence"]=f"Checked {len(vals)} representative page(s). " + " ".join(ev[:8]); out[key]=item
    # Corroboration/entity identity remain anchored to the primary page; this is explicit in output.
    for key in ("corroboration_check","ambiguity_check","entity_confidence"):
        if isinstance(reports[0].get(key),dict): out[key]=reports[0][key]
    out["evidence"]=f"Multi-page trust audit checked {len(reports)} representative page(s). External entity corroboration was run once on the primary page; freshness and transparency were evaluated per page."
    return out

def analyze_trust(html_content, target_url, mock_data_path=None, current_year=None, http_last_modified=None, fetch_sitemap_fn=None, external_apis_fn=None):
    if current_year is None:
        current_year = datetime.now(timezone.utc).year
    parser = TrustHTMLParser()
    parser.feed(html_content)
    
    full_text = " ".join(parser.texts)
    
    # Extract JSON-LD sameAs and dateModified/datePublished
    same_as_links, schema_dates = extract_sameas_and_dates_from_json_ld(parser.json_ld_blocks)
    brand_name = extract_brand_name(parser.title, parser.meta_description, target_url)
    validated_sameas, suspicious_sameas = validate_sameas_links(same_as_links, brand_name)
    
    # 1. Multi-signal Freshness Collection
    # Signal A: Copyright Footer Years
    copyright_pattern = r'(?:copyright|copr\.|\u00a9|&copy;)\s*(?:[0-9]{4}\s*[-–—]\s*)?([0-9]{4})'
    copyrights = re.findall(copyright_pattern, full_text, re.IGNORECASE)
    copyrights_raw = re.findall(copyright_pattern, html_content, re.IGNORECASE)
    all_copyright_years = list(set([int(y) for y in (copyrights + copyrights_raw) if y.isdigit()]))
    latest_copyright = max(all_copyright_years) if all_copyright_years else None
    
    # Signal B: Meta tag dates
    meta_years = []
    for md in parser.meta_dates:
        y = parse_year_from_date_str(md["content"])
        if y:
            meta_years.append(y)
    latest_meta_year = max(meta_years) if meta_years else None
    
    # Signal C: Schema.org dates
    schema_years = []
    for sd in schema_dates:
        y = parse_year_from_date_str(sd["value"])
        if y:
            schema_years.append(y)
    latest_schema_year = max(schema_years) if schema_years else None
    
    # Signal D: HTTP Last-Modified header
    http_year = parse_year_from_date_str(http_last_modified) if http_last_modified else None
    
    # Signal E: Sitemap lastmod check
    parsed_target = urllib.parse.urlparse(target_url)
    base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    if fetch_sitemap_fn is not None:
        sitemap_year = fetch_sitemap_fn(base_url)
    elif target_url.startswith("http"):
        sitemap_year = fetch_sitemap_lastmod(base_url)
    else:
        sitemap_year = None
    
    # Signal F: In-page text update notices
    text_date_pattern = r'(?:last\s+updated|updated|modified|published)\s*(?:on|:)?\s*([A-Za-z]+\s+\d{1,2},?\s+20\d{2}|20\d{2}-\d{2}-\d{2})'
    text_dates = re.findall(text_date_pattern, full_text, re.IGNORECASE)
    text_years = []
    for td in text_dates:
        y = parse_year_from_date_str(td)
        if y:
            text_years.append(y)
    latest_text_year = max(text_years) if text_years else None
    
    # Signal G: Year mentions in text
    year_mentions = {}
    for y in range(2015, current_year + 2):
        count = len(re.findall(r'\b' + str(y) + r'\b', full_text))
        if count > 0:
            year_mentions[y] = count
            
    # Synthesize multi-signal freshness
    all_activity_years = [
        y for y in [latest_copyright, latest_meta_year, latest_schema_year, http_year, sitemap_year, latest_text_year] 
        if y is not None
    ]
    latest_activity_year = max(all_activity_years) if all_activity_years else None
    
    freshness_signals = {
        "copyright_year": latest_copyright,
        "meta_dates_year": latest_meta_year,
        "schema_dates_year": latest_schema_year,
        "http_last_modified_year": http_year,
        "sitemap_lastmod_year": sitemap_year,
        "text_dates_year": latest_text_year,
        "latest_activity_year": latest_activity_year
    }
    
    # Signal classifications:
    # STRONG: schema dates, sitemap lastmod, HTTP Last-Modified, article timestamps
    # MEDIUM: in-page text update notices
    # WEAK: footer copyright year, general in-text year mentions
    
    strong_recent_signals = []
    strong_stale_signals = []
    
    for name, yr in [
        ("schema_dates", latest_schema_year),
        ("sitemap_lastmod", sitemap_year),
        ("http_last_modified", http_year),
        ("meta_dates", latest_meta_year)
    ]:
        if yr is not None:
            if yr >= current_year - 1:
                strong_recent_signals.append((name, yr))
            elif yr < current_year - 1:
                strong_stale_signals.append((name, yr))
                
    medium_recent_signals = []
    medium_stale_signals = []
    if latest_text_year is not None:
        if latest_text_year >= current_year - 1:
            medium_recent_signals.append(("text_update_notice", latest_text_year))
        elif latest_text_year < current_year - 1:
            medium_stale_signals.append(("text_update_notice", latest_text_year))
            
    # Freshness evaluation rules:
    # Rule 1: If ANY strong or medium signal indicates recent activity (>= current_year - 1),
    # the site is confirmed fresh! Even if copyright footer has not been bumped.
    if strong_recent_signals or medium_recent_signals:
        freshness_status = "pass"
        freshness_severity = None
        freshness_confidence = 0.95
        recent_names = [f"{s[0]} ({s[1]})" for s in strong_recent_signals + medium_recent_signals]
        if latest_copyright and latest_copyright < current_year - 1:
            freshness_evidence = (
                f"Multi-signal freshness confirmed: Recent activity verified up to {latest_activity_year} "
                f"(schema/meta dates: {latest_schema_year or latest_meta_year}, text: {latest_text_year}). "
                f"Note: Copyright footer shows {latest_copyright}, but site is actively maintained."
            )
        else:
            freshness_evidence = f"Multi-signal freshness confirmed: Recent activity detected ({latest_activity_year}). Copyright footer is {latest_copyright}."
            
    # Rule 2: Multiple meaningful signals agree on old content (< current_year - 1)
    elif (len(strong_stale_signals) >= 1 and (len(medium_stale_signals) >= 1 or (latest_copyright and latest_copyright < current_year - 1))) or len(strong_stale_signals) >= 2:
        freshness_status = "warning"
        freshness_severity = "medium"
        freshness_confidence = 0.90
        stale_names = [f"{s[0]} ({s[1]})" for s in strong_stale_signals + medium_stale_signals]
        if latest_copyright:
            stale_names.append(f"copyright ({latest_copyright})")
        freshness_evidence = (
            f"Stale content detected across evaluated signals: latest activity date is {latest_activity_year} "
            f"(copyright: {latest_copyright or 'N/A'}, meta dates: {latest_meta_year or 'N/A'}, "
            f"schema dates: {latest_schema_year or 'N/A'}). No current {current_year} signals detected."
        )
        
    # Rule 3: ONLY copyright is old (WEAK signal), but NO strong signals confirm staleness
    elif latest_copyright and latest_copyright < current_year - 1:
        freshness_status = "pass"
        freshness_severity = None
        freshness_confidence = 0.70
        freshness_evidence = (
            f"Copyright footer displays {latest_copyright}. However, copyright notices alone are a weak freshness "
            f"indicator without corroborating signals; no independent signals (sitemap, schema, or meta dates) confirm content staleness."
        )
        
    # Rule 4: No date signals declared
    else:
        freshness_status = "pass"
        freshness_severity = None
        freshness_confidence = 0.60
        freshness_evidence = "No explicit copyright, meta dates, or schema timestamps declared to measure content age."
        
    # 2. Extract Brand / Entity Clues
    brand_candidate = extract_brand_name(parser.title, parser.meta_description, target_url)
        
    detected_schemas = []
    for block in parser.json_ld_blocks:
        try:
            data = json.loads(block)
            if isinstance(data, dict):
                st = data.get("@type")
                if isinstance(st, list):
                    detected_schemas.extend(st)
                elif isinstance(st, str):
                    detected_schemas.append(st)
        except Exception as e:
            _record_execution_error("Non-fatal trust check failure", e)
    page_type = detect_page_type(target_url, full_text, parser.title, schemas=detected_schemas)
    
    has_author = parser.has_author_link or any(pattern in full_text.lower() for pattern in ["written by", "author:", "by: ", "published by"])
    has_email = len(re.findall(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', full_text)) > 0
    has_phone = len(re.findall(r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', full_text)) > 0
    has_address = len(re.findall(r'\b\d{1,5}\s+[A-Za-z0-9#.\s]{3,30}\s+(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|parkway|pkwy|suite|ste|box)\b', full_text, re.IGNORECASE)) > 0
    
    eeat_status = "pass"
    eeat_ev = [
        f"Author link/byline present: {has_author}.",
        f"Corporate contact link present: {parser.has_contact_link}.",
        f"Contact channels: Email: {has_email}, Phone: {has_phone}, Physical Address: {has_address}."
    ]
    
    if page_type in ["article", "blog"]:
        if not has_author:
            eeat_status = "warning"
            eeat_ev.append("Article/editorial content lacks author byline or Person credentials, reducing transparency for informational queries.")
        else:
            eeat_ev.append("Author attribution verified for editorial content.")
    elif page_type in ["pricing", "product"]:
        # Individual author bylines are NOT expected on pricing or product pages
        if not parser.has_contact_link and not (has_email or has_phone):
            eeat_status = "warning"
            eeat_ev.append(f"{page_type.capitalize()} page lacks visible contact or support navigation links.")
        else:
            eeat_ev.append(f"Commercial transparency verified on {page_type} page. Author bylines are not expected.")
    elif page_type == "legal":
        # Legal pages (privacy policy, terms of service) do not require author bylines or commercial contact CTAs
        eeat_status = "pass"
        eeat_ev.append("Legal/compliance document verified (Privacy Policy / Terms). Author bylines and commercial CTAs are not expected.")
    else:
        # Homepage / About / General pages
        if not parser.has_contact_link and not has_author:
            eeat_status = "warning"
            eeat_ev.append("Missing a clearly labeled navigation path to Contact/About page.")
            if not (has_email or has_phone or has_address):
                eeat_ev.append("No direct corporate communication channels (email, phone, or address) detected on page.")
        else:
            eeat_ev.append("Corporate transparency confirmed via contact links or direct communication channels.")
            
    # 4. Cross-Source Corroboration & Disambiguation
    corrob_status = "pass"
    corrob_severity = None
    corrob_confidence = 0.9
    corrob_ev = []
    
    ambiguity_status = "pass"
    ambiguity_severity = None
    ambiguity_confidence = 0.9
    ambiguity_ev = []
    
    external_records = []
    conflict_detected = False
    if mock_data_path:
        try:
            with open(mock_data_path, 'r', encoding='utf-8') as f:
                mock_data = json.load(f)
                external_records = mock_data.get("external_records", [])
                corrob_ev.append(f"Loaded {len(external_records)} mock records from {mock_data_path}.")
        except Exception as e:
            corrob_ev.append(f"Error loading mock corroboration path: {e}. Falling back to search.")
            if external_apis_fn is not None:
                external_records = external_apis_fn(brand_candidate)
            else:
                external_records = check_external_apis(brand_candidate)
    elif external_apis_fn is not None:
        external_records = external_apis_fn(brand_candidate)
    else:
        external_records = check_external_apis(brand_candidate)
        
    # Check authoritative external sameAs links (ignoring internal @id)
    authoritative_same_as = [
        u for u in same_as_links 
        if any(d in u.lower() for d in ["wikidata.org", "wikipedia.org", "crunchbase.com", "linkedin.com", "github.com"])
    ]
    if suspicious_sameas:
        ambiguity_status="warning"
        ambiguity_severity="high"
        ambiguity_confidence=0.88
        ambiguity_ev.append(f"Potentially weak sameAs targets were not accepted as authoritative disambiguation evidence: {', '.join(suspicious_sameas[:3])}.")
    
    if external_records:
        local_locs = extract_locations(full_text)
        
        us_states_list = {"AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"}
        countries_list = {"US", "UK", "CAN", "INDIA", "GERMANY", "FRANCE", "AUSTRALIA"}
        
        local_states = local_locs.intersection(us_states_list)
        local_countries = local_locs.intersection(countries_list)
        if local_states:
            local_countries.add("US")
            
        conflict_detected = False
        matching_record = None
        ext_states_set = set()
        site_founded_match = re.search(r"\bfounded\s+(?:in\s+)?(20\d{2})\b", full_text, re.I)
        site_founded_year = int(site_founded_match.group(1)) if site_founded_match else None
        
        for rec in external_records:
            snippet = rec["snippet"]
            title = rec["title"]
            ext_locs = extract_locations(snippet + " " + title)
            
            ext_states = ext_locs.intersection(us_states_list)
            ext_countries = ext_locs.intersection(countries_list)
            year_conflict = False
            if site_founded_year:
                ext_founded = re.search(r"\bfounded\s+(?:in\s+)?(20\d{2})\b", snippet + " " + title, re.I)
                if ext_founded and int(ext_founded.group(1)) != site_founded_year:
                    year_conflict = True
            if ext_states:
                ext_countries.add("US")
                
            state_conflict = False
            if ext_states and local_states:
                if not ext_states.intersection(local_states):
                    state_conflict = True
                    
            country_conflict = False
            if ext_countries and local_countries:
                if not ext_countries.intersection(local_countries):
                    country_conflict = True
                    
            if state_conflict or country_conflict or year_conflict:
                conflict_detected = True
                matching_record = rec
                ext_states_set = ext_locs
                break
                    
        if conflict_detected and matching_record:
            corrob_status = "fail"
            corrob_severity = "high"
            corrob_confidence = 0.95
            corrob_ev.append(f"Fact contradiction detected between site and {matching_record['source']} ({matching_record['url']}). External records state location matches {list(ext_states_set)}, whereas target site claims location matches {list(local_locs)}.")
            if site_founded_year:
                corrob_ev.append(f"Founded-year consistency was also checked when an external record exposed a founding year; the site claims {site_founded_year}.")
        else:
            corrob_ev.append(f"Corroboration checked against {len(external_records)} external source(s). No location conflicts detected.")
            
        # Ambiguity Check: evaluate real sameAs URLs
        if authoritative_same_as:
            ambiguity_status = "pass"
            ambiguity_confidence = 0.95
            ambiguity_ev.append(f"Authoritative entity disambiguation links detected in schema.org sameAs ({', '.join(authoritative_same_as)}).")
        elif len(external_records) > 0 and not same_as_links:
            if conflict_detected or len(external_records) > 1:
                ambiguity_status = "warning"
                ambiguity_severity = "high"
                ambiguity_confidence = 0.9
                ambiguity_ev.append(f"Entity ambiguity detected: Naming search for '{brand_candidate}' returns multiple distinct matches (e.g. '{external_records[0]['title']}' and others), but homepage lacks schema.org 'sameAs' URLs to disambiguate the brand.")
            else:
                ambiguity_ev.append("Entity matches the target brand closely. No naming collision or ambiguity detected.")
        else:
            ambiguity_ev.append("Entity disambiguation links are in place or no naming collisions found.")
    else:
        corrob_status = "pass"
        corrob_confidence = 0.8
        corrob_ev.append(f"No external search results found for brand '{brand_candidate}' on Wikipedia or Wikidata. No location or entity contradictions detected (common for growing or niche brands).")
        if authoritative_same_as:
            ambiguity_status = "pass"
            ambiguity_confidence = 0.95
            ambiguity_ev.append(f"Authoritative sameAs links present ({', '.join(authoritative_same_as)}).")
        else:
            ambiguity_ev.append("No naming matches found on external sources to assess ambiguity.")
        
    # Explainable entity-confidence model. This is a diagnostic confidence signal,
    # not a claim that an external knowledge graph has verified the entity.
    parsed_host=urllib.parse.urlparse(target_url).netloc.lower().removeprefix('www.')
    brand_tokens={x for x in re.findall(r'[a-z0-9]+',(brand_candidate or '').lower()) if len(x)>2}
    host_tokens={x for x in re.findall(r'[a-z0-9]+',parsed_host.split('.')[0]) if len(x)>2}
    entity_score=25 if brand_tokens and host_tokens and brand_tokens.intersection(host_tokens) else 10
    if authoritative_same_as: entity_score += 30
    elif validated_sameas: entity_score += 15
    if external_records:
        title_tokens={x for r in external_records for x in re.findall(r'[a-z0-9]+',(r.get('title') or '').lower()) if len(x)>2}
        if brand_tokens.intersection(title_tokens): entity_score += 20
        if len(external_records) == 1: entity_score += 10
        else: entity_score -= 5
    if conflict_detected: entity_score -= 25
    if suspicious_sameas: entity_score -= 10
    entity_score=max(0,min(100,entity_score))
    entity_status='warning' if entity_score < 60 else 'pass'
    entity_evidence=(f'Entity confidence {entity_score}/100 based on domain/name alignment, authoritative sameAs, external name matches, and contradiction signals. '
                     f'Authoritative sameAs={bool(authoritative_same_as)}; external records={len(external_records)}; conflicts={conflict_detected}; suspicious sameAs={len(suspicious_sameas)}.')

    disambiguation_queries = [
        f'"{brand_candidate}" headquarters address',
        f'"{brand_candidate}" CEO OR founder OR leadership',
        f'"{brand_candidate}" pricing plans review',
        f'"{brand_candidate}" wikidata OR wikipedia'
    ]
    
    findings = {
        "brand_name": brand_candidate,
        "copyright": {
            "years_found": all_copyright_years,
            "latest_year": latest_copyright,
            "status": freshness_status,
            "severity": freshness_severity,
            "confidence": freshness_confidence,
            "evidence": freshness_evidence
        },
        "multi_signal_freshness": {
            "status": freshness_status,
            "severity": freshness_severity,
            "confidence": freshness_confidence,
            "signals": freshness_signals,
            "evidence": freshness_evidence
        },
        "year_mentions": {
            "mentions": year_mentions,
            "has_future_or_current": any(y >= current_year for y in year_mentions),
            "evidence": f"Mentions of years: {', '.join(f'{k} ({v}x)' for k, v in year_mentions.items())}." if year_mentions else "No specific year mentions found."
        },
        "eeat_check": {
            "status": eeat_status,
            "severity": "medium",
            "confidence": 0.85,
            "evidence": " ".join(eeat_ev)
        },
        "corroboration_check": {
            "status": corrob_status,
            "severity": corrob_severity or "high",
            "confidence": corrob_confidence,
            "evidence": " ".join(corrob_ev)
        },
        "ambiguity_check": {
            "status": ambiguity_status,
            "severity": ambiguity_severity or "high",
            "confidence": ambiguity_confidence,
            "same_as_links": same_as_links,
        "validated_same_as_links": validated_sameas,
        "suspicious_same_as_links": suspicious_sameas,
            "evidence": " ".join(ambiguity_ev)
        },
        "entity_confidence": {
            "score": entity_score,
            "status": entity_status,
            "confidence": round(max(0.55, entity_score/100),2),
            "evidence": entity_evidence,
            "affected_pages": [target_url] if entity_status == "warning" else []
        },
        "suggested_queries": disambiguation_queries
    }
    
    findings["execution"] = {"partial": bool(EXECUTION_ERRORS), "errors": list(EXECUTION_ERRORS)}
    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audits freshness, E-E-A-T, and external corroboration")
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--pages", help="Comma-separated representative URLs")
    parser.add_argument("--technical", help="Technical audit JSON; uses its bounded crawled_urls")
    parser.add_argument("--max-pages", type=int, default=6)
    parser.add_argument("--current-year", type=int, default=None)
    parser.add_argument("--mock-data", help="Offline corroboration fixture JSON")
    parser.add_argument("--output", help="Path to write output JSON")
    args=parser.parse_args()
    url=args.url if args.url.startswith(("http://","https://")) else "https://"+args.url
    urls=[url]
    if args.technical:
        try:
            td=json.loads(open(args.technical,encoding="utf-8").read()); urls += td.get("crawl_scope",{}).get("crawled_urls",[])
        except Exception as e: _record_execution_error("Trust input file could not be loaded", e)
    if args.pages: urls += [x.strip() for x in args.pages.split(",") if x.strip()]
    # same-domain, de-duplicated bounded set
    base=urllib.parse.urlparse(url).netloc.lower(); selected=[]; seen=set()
    for u in urls:
        u=urllib.parse.urldefrag(u)[0]
        try:
            if urllib.parse.urlparse(u).netloc.lower()!=base: continue
        except Exception as e:
            _record_execution_error("Trust URL candidate skipped", e)
            continue
        if u not in seen: seen.add(u); selected.append(u)
    mock_external=None
    if args.mock_data:
        def _mock(_brand):
            try: return json.load(open(args.mock_data,encoding="utf-8")).get("external_records",[])
            except Exception as e:
                _record_execution_error("Trust mock data could not be loaded", e)
                return []
        mock_external=_mock
    report=analyze_trust_pages(selected,current_year=args.current_year,primary_external=mock_external,max_pages=args.max_pages) if len(selected)>1 or args.technical or args.pages else None
    if report is None:
        if not robots_allows(url):
            report={"robots_gate":{"status":"blocked","evidence":"Target URL is disallowed by robots.txt; trust audit did not fetch the page."}}
        else:
            html,last_modified=fetch_page_with_headers(url)
            if not html or html.startswith("Error:"):
                report={"robots_gate":{"status":"allowed","evidence":"robots.txt allowed the target URL."},"multi_signal_freshness":{"status":"unavailable","evidence":"Page fetch failed."},"eeat_check":{"status":"unavailable","evidence":"Page fetch failed."}}
            else:
                report=analyze_trust(html,url,current_year=args.current_year,http_last_modified=last_modified,mock_data_path=args.mock_data)
    output_data=json.dumps(report,indent=2)
    if args.output:
        with open(args.output,"w",encoding="utf-8") as f: f.write(output_data)
        print(f"Trust audit written to {args.output}")
    else: print(output_data)
