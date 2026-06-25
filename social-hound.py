#!/usr/bin/env python3

from __future__ import annotations

import csv
import datetime as dt
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import textwrap
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    print("[FATAL] pip install requests"); raise

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[FATAL] pip install beautifulsoup4"); raise

try:
    import dns.resolver, dns.exception
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.syntax import Syntax
    from rich.text import Text
    from rich.rule import Rule
    from rich.live import Live
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False

try:
    import pyfiglet
    FIGLET_OK = True
except ImportError:
    FIGLET_OK = False

APP_NAME      = "SOCIAL HOUND"
APP_VERSION   = "1"
DEFAULT_TIMEOUT = 12
DEFAULT_UA    = f"SocialHound/{APP_VERSION} (OSINT audit)"
REPORTS_DIR   = "reports"
MAX_HTML_READ = 2_000_000
MAX_BODY_PREVIEW = 3000

C_CRIMSON   = "bold red"
C_BONE      = "bold white"
C_DIM_BONE  = "white"
C_AMBER     = "bold yellow"
C_SHADOW    = "dim white"
C_ACCENT    = "bright_red"
C_GOOD      = "bold green"
C_WARN      = "bold yellow"
C_BAD       = "bold red"
C_INFO      = "bold cyan"

console = Console(highlight=False) if RICH_OK else None

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?\d{1,3}[\s\-().]*)?(?:\(?\d{2,4}\)?[\s\-().]*){2,5}\d{2,4}(?!\w)"
)
JS_ENDPOINT_RE = re.compile(
    r'(?:"|\')'
    r'(/(?:api|v\d|graphql|admin|auth|login|signup|user|users|account|accounts|'
    r'internal|private|dashboard|panel|upload|download|search|config|settings|'
    r'token|session|oauth|callback|reset|profile|billing|webhook|docs)[^"\']*)'
    r'(?:"|\')',
    re.IGNORECASE,
)

SECRETS_PATTERNS: Dict[str, re.Pattern] = {
    "AWS Access Key"   : re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret"       : re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'),
    "Generic API Key"  : re.compile(r'(?i)api[_\-]?key["\'\s:=]+["\'][a-zA-Z0-9_\-]{20,60}["\']'),
    "Bearer Token"     : re.compile(r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*'),
    "Private Key PEM"  : re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "Slack Token"      : re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}'),
    "GitHub Token"     : re.compile(r'gh[oprstu]_[A-Za-z0-9]{36,}'),
    "Google API Key"   : re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Stripe Key"       : re.compile(r'(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24,}'),
    "JWT"              : re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    "Twilio SID"       : re.compile(r'AC[0-9a-f]{32}'),
    "Sendgrid Key"     : re.compile(r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}'),
    "Mailgun Key"      : re.compile(r'key-[0-9a-zA-Z]{32}'),
    "Password in URL"  : re.compile(r'(?i)(?:password|passwd|pwd)["\'\s:=]+["\'][^"\']{4,}["\']'),
    "Internal IP"      : re.compile(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
}

SOCIAL_HINTS = {
    "twitter.com","x.com","facebook.com","linkedin.com","instagram.com",
    "youtube.com","t.me","github.com","gitlab.com","discord.gg",
    "medium.com","threads.net","tiktok.com","reddit.com","mastodon.social",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security","Content-Security-Policy","X-Frame-Options",
    "X-Content-Type-Options","Referrer-Policy","Permissions-Policy",
    "Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

COMMON_DNS_TYPES  = ["A","AAAA","MX","NS","TXT","CNAME","SOA"]
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 25:"SMTP", 53:"DNS", 80:"HTTP", 110:"POP3",
    143:"IMAP", 443:"HTTPS", 465:"SMTPS", 587:"SMTP Submission",
    993:"IMAPS", 995:"POP3S", 1433:"MSSQL", 1521:"Oracle", 3306:"MySQL",
    3389:"RDP", 5432:"PostgreSQL", 6379:"Redis", 8000:"HTTP Alt",
    8080:"HTTP Proxy/App", 8443:"HTTPS Alt", 9200:"Elasticsearch", 27017:"MongoDB",
}

SAFE_DISCOVERY_PATHS = [
    "/","/robots.txt","/sitemap.xml","/security.txt","/.well-known/security.txt",
    "/login","/signin","/dashboard","/admin","/api","/api/v1","/api/v2",
    "/graphql","/docs","/swagger","/openapi.json","/help",
    "/terms","/privacy","/contact","/.env","/.git/config",
]

COMMON_SUBDOMAINS = [
    "www","mail","webmail","dev","test","staging","api","admin","portal",
    "dashboard","beta","cdn","static","m","mobile","app","status","vpn",
    "git","jira","confluence","jenkins","grafana","kibana","smtp","pop","imap",
]

# Username check platform list
USERNAME_PLATFORMS: List[Dict[str, str]] = [
    {"name":"GitHub",       "url":"https://github.com/{u}",                    "miss":"Not Found"},
    {"name":"GitLab",       "url":"https://gitlab.com/{u}",                    "status":"404"},
    {"name":"Twitter/X",    "url":"https://x.com/{u}",                         "miss":"This account doesn't exist"},
    {"name":"Instagram",    "url":"https://www.instagram.com/{u}/",             "miss":"Sorry, this page"},
    {"name":"Reddit",       "url":"https://www.reddit.com/user/{u}",            "miss":"Sorry, nobody on Reddit"},
    {"name":"HackerNews",   "url":"https://news.ycombinator.com/user?id={u}",   "miss":"No such user"},
    {"name":"DEV.to",       "url":"https://dev.to/{u}",                         "status":"404"},
    {"name":"Medium",       "url":"https://medium.com/@{u}",                    "miss":"This page is not available"},
    {"name":"TryHackMe",    "url":"https://tryhackme.com/p/{u}",                "miss":"404"},
    {"name":"HackTheBox",   "url":"https://app.hackthebox.com/users/profile/{u}","miss":""},
    {"name":"Keybase",      "url":"https://keybase.io/{u}",                     "status":"404"},
    {"name":"Pastebin",     "url":"https://pastebin.com/u/{u}",                 "status":"404"},
    {"name":"npm",          "url":"https://www.npmjs.com/~{u}",                 "status":"404"},
    {"name":"PyPI",         "url":"https://pypi.org/user/{u}/",                 "status":"404"},
    {"name":"Gravatar",     "url":"https://en.gravatar.com/{u}",                "status":"404"},
    {"name":"Twitch",       "url":"https://www.twitch.tv/{u}",                  "miss":"Hmm, that page is unavailable"},
    {"name":"YouTube",      "url":"https://www.youtube.com/@{u}",               "miss":"This channel doesn't exist"},
]

def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def _print(markup: str) -> None:
    if RICH_OK: console.print(markup)
    else: print(re.sub(r'\[.*?\]','', markup))


def _clr(markup: str) -> str:
    """Strip Rich markup for plain fallback."""
    return re.sub(r'\[.*?\]', '', markup)

def feed_hit(label: str, value: str = "", indent: int = 0) -> None:
    pad = "  " * indent
    if RICH_OK:
        val_part = f"  [dim white]{value}[/dim white]" if value else ""
        console.print(f"{pad}[bold red]◉[/bold red] [bold white]{label}[/bold white]{val_part}")
    else:
        print(f"{pad}◉ {label}  {value}")

def feed_miss(label: str, value: str = "", indent: int = 0) -> None:
    pad = "  " * indent
    if RICH_OK:
        val_part = f"  [dim]{value}[/dim]" if value else ""
        console.print(f"{pad}[dim]◌ {label}{val_part}[/dim]")
    else:
        print(f"{pad}◌ {label}  {value}")

def feed_info(label: str, value: str = "", indent: int = 0) -> None:
    pad = "  " * indent
    if RICH_OK:
        val_part = f"  [dim white]{value}[/dim white]" if value else ""
        console.print(f"{pad}[cyan]▸[/cyan] [white]{label}[/white]{val_part}")
    else:
        print(f"{pad}▸ {label}  {value}")

def feed_warn(label: str, value: str = "", indent: int = 0) -> None:
    pad = "  " * indent
    if RICH_OK:
        val_part = f"  [dim yellow]{value}[/dim yellow]" if value else ""
        console.print(f"{pad}[bold yellow]⚠[/bold yellow] [yellow]{label}[/yellow]{val_part}")
    else:
        print(f"{pad}⚠ {label}  {value}")

def feed_err(label: str, value: str = "", indent: int = 0) -> None:
    pad = "  " * indent
    if RICH_OK:
        val_part = f"  [dim red]{value}[/dim red]" if value else ""
        console.print(f"{pad}[bold red]✘[/bold red] [red]{label}[/red]{val_part}")
    else:
        print(f"{pad}✘ {label}  {value}")

def feed_section(title: str) -> None:
    """Section header — crimson rule with title."""
    if RICH_OK:
        console.print(Rule(f"[bold red]{title}[/bold red]", style="red"))
    else:
        print(f"\n{'─'*60} {title}")

def feed_blank() -> None:
    if RICH_OK: console.print()
    else: print()

def feed_kv(key: str, val: Any, indent: int = 1, hit: bool = True) -> None:
    """Generic key→value feed line, auto-detects hit/miss."""
    v = str(val) if val is not None else ""
    if not v or v in ("None","{}","[]",""):
        feed_miss(key, "—", indent=indent)
    elif hit:
        feed_hit(key, v[:120], indent=indent)
    else:
        feed_info(key, v[:120], indent=indent)

def feed_list(label: str, items: List[Any], indent: int = 1, max_show: int = 20) -> None:
    """Print a list with a header count then each item."""
    if not items:
        feed_miss(label, "none found", indent=indent)
        return
    feed_hit(label, f"({len(items)} found)", indent=indent)
    for item in items[:max_show]:
        if RICH_OK:
            console.print(f"{'  '*(indent+1)}[dim white]·[/dim white] [white]{str(item)[:110]}[/white]")
        else:
            print(f"{'  '*(indent+1)}· {str(item)[:110]}")
    if len(items) > max_show:
        feed_info(f"… {len(items)-max_show} more (see saved report)", indent=indent+1)

def info(msg: str)  -> None: feed_info(msg)
def good(msg: str)  -> None: feed_hit(msg)
def warn(msg: str)  -> None: feed_warn(msg)
def bad(msg: str)   -> None: feed_err(msg)
def hint(msg: str)  -> None: feed_info(msg, indent=1)
def divider(label: str = "") -> None: feed_section(label) if label else feed_blank()

def live_status(msg: str) -> None:
    if RICH_OK:
        console.print(f"  [dim]· {msg}[/dim]", end="\r")
    else:
        print(f"  · {msg}", end="\r", flush=True)

def pretty_json(data: Any) -> None:
    raw = json.dumps(data, indent=2, default=str)
    if RICH_OK:
        console.print(Syntax(raw, "json", theme="monokai", word_wrap=True))
    else:
        print(raw)

NOIR_BANNER_PLAIN = r"""
  ███████╗ ██████╗  ██████╗██╗ █████╗ ██╗     
  ██╔════╝██╔═══██╗██╔════╝██║██╔══██╗██║     
  ███████╗██║   ██║██║     ██║███████║██║     
  ╚════██║██║   ██║██║     ██║██╔══██║██║     
  ███████║╚██████╔╝╚██████╗██║██║  ██║███████╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝
  ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
  ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
  ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
  ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
  ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
"""

def print_banner() -> None:
    if RICH_OK:
        console.print(f"[bold red]{NOIR_BANNER_PLAIN}[/bold red]")
        console.print(Panel(
            Text.from_markup(
                f"[bold white]Open Source / Author : Nethound[/bold white]  [dim white]v{APP_VERSION}[/dim white]\n"
                "[dim white]OSINT · RECON · ASSET AUDIT[/dim white]\n"
                "[bold red]USE ONLY ON TARGETS YOU OWN OR ARE AUTHORIZED TO TEST[/bold red]"
            ),
            border_style="red",
            padding=(0, 4),
        ))
    else:
        print(NOIR_BANNER_PLAIN)
        print(f"SOCIAL HOUND {APP_VERSION} — OSINT TOOLKIT")
        print("USE ONLY ON TARGETS YOU OWN OR ARE AUTHORIZED TO TEST")
        print("─" * 70)

MENU_ITEMS = [
    ("01", "IP Intelligence & Geolocation",    "ip"),
    ("02", "DNS Recon",                        "dns"),
    ("03", "RDAP Network Lookup",              "rdap"),
    ("04", "ASN / BGP Route Intelligence",     "asn"),   # NEW
    ("05", "TLS Certificate Analysis",         "tls"),
    ("06", "WHOIS Intelligence",               "whois"),
    ("07", "Port Exposure Scan",               "ports"),
    ("08", "Website Fingerprint Scan",         "web"),
    ("09", "Security Header Audit",            "headers"),
    ("10", "JS Secrets Scanner",               "secrets"),  # NEW
    ("11", "Safe Web Crawl Engine",            "crawl"),
    ("12", "Subdomain Discovery Engine",       "subdomains"),
    ("13", "Robots + Sitemap Analysis",        "robots"),
    ("14", "Safe Path Discovery",              "paths"),
    ("15", "Username Intelligence",            "username"),  # NEW
    ("16", "Full OSINT Audit (ALL-IN-ONE)",    "full"),
    ("17", "Batch Target Processing",          "batch"),
    ("──", "──────────────────────────────",  ""),
    ("18", "Show Last Report",                 "show"),
    ("19", "Save JSON Report",                 "json"),
    ("20", "Save HTML Report",                 "html"),
    ("21", "Export Findings CSV",              "csv"),
    ("00", "Exit",                             "exit"),
]

def print_menu() -> None:
    if not RICH_OK:
        for num, label, _ in MENU_ITEMS:
            print(f"  [{num}] {label}")
        return

    table = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    table.add_column("num",   style="bold red",   width=4)
    table.add_column("label", style="white",      width=38)
    table.add_column("num2",  style="bold red",   width=4)
    table.add_column("label2",style="white",      width=38)

    visible = [(n,l) for n,l,_ in MENU_ITEMS if n != "──"]
    # pair them up
    for i in range(0, len(visible), 2):
        n1, l1 = visible[i]
        if i+1 < len(visible):
            n2, l2 = visible[i+1]
        else:
            n2, l2 = "", ""
        table.add_row(f"[{n1}]", l1, f"[{n2}]" if n2 else "", l2)

    console.print(Panel(
        table,
        title="[bold red]◈  SOCIAL HOUND CONTROL PANEL  ◈[/bold red]",
        border_style="red",
        padding=(0,1),
    ))

def ensure_reports_dir() -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)

def slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value[:120] or "report"

def request_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA})
    return s

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value: return value
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value

def host_from_input(value: str) -> str:
    parsed = urllib.parse.urlparse(normalize_url(value.strip()))
    host = parsed.hostname or value.strip()
    return host.strip().strip("/")

def is_ip(value: str) -> bool:
    try: ipaddress.ip_address(value); return True
    except Exception: return False

def root_netloc(netloc: str) -> str:
    if ":" in netloc: netloc = netloc.split(":")[0]
    return netloc.lower().strip(".")

def same_domain(base_netloc: str, candidate_url: str) -> bool:
    try:
        c    = urllib.parse.urlparse(candidate_url)
        base = root_netloc(base_netloc)
        cand = root_netloc(c.netloc)
        return cand == base or cand.endswith("." + base)
    except Exception: return False

def absolute_url(base: str, href: str) -> str:
    return urllib.parse.urljoin(base, href.strip())

def maps_links(lat: Any, lon: Any) -> Dict[str, str]:
    if lat in (None,"") or lon in (None,""): return {}
    return {
        "google_maps":   f"https://www.google.com/maps?q={lat},{lon}",
        "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}",
    }

def normalize_header_name(name: str) -> str:
    return "-".join(p.capitalize() for p in name.split("-"))

def progress_iter(items: List[Any], description: str = "Working"):
    if not RICH_OK:
        for item in items: yield item
        return
    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold red"),
        TextColumn("[bold white]{task.description}[/bold white]"),
        BarColumn(bar_width=30, style="red", complete_style="bold red"),
        TimeElapsedColumn(),
        console=console,
    ) as p:
        task = p.add_task(description, total=len(items))
        for item in items:
            yield item
            p.advance(task)

def detect_technologies(headers: Dict[str,str], html_text: str, final_url: str) -> List[str]:
    detected: Set[str] = set()
    lh = {k.lower(): str(v).lower() for k,v in headers.items()}
    hl = html_text.lower()
    server   = lh.get("server","")
    x_pow    = lh.get("x-powered-by","")
    via      = lh.get("via","")

    if "cloudflare" in server or "cf-ray" in lh: detected.add("Cloudflare")
    if "nginx"      in server: detected.add("nginx")
    if "apache"     in server: detected.add("Apache")
    if "iis"        in server: detected.add("Microsoft IIS")
    if "varnish"    in (via+server): detected.add("Varnish")
    if "php"        in (x_pow+hl): detected.add("PHP")
    if "express"    in x_pow: detected.add("Express")
    if "asp.net"    in x_pow: detected.add("ASP.NET")
    if "wordpress"  in hl or "/wp-content/" in hl: detected.add("WordPress")
    if "woocommerce"in hl: detected.add("WooCommerce")
    if "shopify"    in hl: detected.add("Shopify")
    if "__next"     in hl or "_next/" in hl: detected.add("Next.js")
    if "react"      in hl or "data-reactroot" in hl: detected.add("React")
    if "vue"        in hl or "__vue__" in hl: detected.add("Vue.js")
    if "angular"    in hl or "ng-app" in hl: detected.add("Angular")
    if "jquery"     in hl: detected.add("jQuery")
    if "bootstrap"  in hl: detected.add("Bootstrap")
    if "drupal"     in hl: detected.add("Drupal")
    if "joomla"     in hl: detected.add("Joomla")
    if urllib.parse.urlparse(final_url).scheme == "https": detected.add("HTTPS")
    return sorted(detected)

def analyze_cookies(headers: Dict[str,str], cookies) -> List[Dict[str,Any]]:
    results = []
    raw = headers.get("Set-Cookie","").lower()
    for c in cookies:
        results.append({
            "name":          c.name,
            "value_preview": c.value[:20],
            "secure_hint":   "secure"   in raw,
            "httponly_hint": "httponly" in raw,
            "samesite_hint": "samesite" in raw,
        })
    return results

def rate_security(web: Dict[str,Any], tls: Dict[str,Any]) -> Dict[str,Any]:
    score = 100
    findings: List[Dict[str,str]] = []

    missing = web.get("missing_security_headers", [])
    if missing:
        score -= min(40, len(missing)*4)
        findings.append({"severity":"medium","issue":f"Missing headers: {', '.join(missing)}"})

    for c in web.get("cookie_analysis",[]):
        if not c.get("secure_hint"):
            score -= 3
            findings.append({"severity":"medium","issue":f"Cookie '{c['name']}' may lack Secure flag"})

    sc = web.get("status_code")
    if isinstance(sc,int) and sc >= 400:
        score -= 5
        findings.append({"severity":"low","issue":f"HTTP {sc} response"})

    tv = str(tls.get("tls_version") or "")
    if tv:
        if "TLSv1.3" in tv: pass
        elif "TLSv1.2" in tv: score -= 3
        else:
            score -= 15
            findings.append({"severity":"high","issue":f"Outdated TLS: {tv}"})

    csp = (web.get("security_headers") or {}).get("Content-Security-Policy","") or ""
    if "unsafe-inline" in csp.lower():
        score -= 5
        findings.append({"severity":"low","issue":"CSP contains unsafe-inline"})

    grade = "A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F"
    return {"score": max(0,min(100,score)), "grade": grade, "findings": findings}

def asn_bgp_lookup(target: str) -> Dict[str,Any]:
    """
    Uses bgpview.io public API to resolve ASN info, announced prefixes,
    peers, and upstreams for a given IP or hostname.
    """
    host = host_from_input(target)
    ip_value = host

    if not is_ip(host):
        try:
            ip_value = socket.gethostbyname(host)
        except Exception as e:
            return {"input":target,"error":f"DNS resolve failed: {e}"}

    sess = request_session()
    result: Dict[str,Any] = {"input":target,"host":host,"ip":ip_value}

    try:
        r = sess.get(f"https://api.bgpview.io/ip/{urllib.parse.quote(ip_value)}", timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            d = r.json().get("data",{})
            prefixes = d.get("prefixes",[])
            rir = d.get("rir_allocation",{})
            result["rir"] = {
                "name":         rir.get("rir_name"),
                "country_code": rir.get("country_code"),
                "prefix":       rir.get("prefix"),
                "date_allocated": rir.get("date_allocated"),
            }
            if prefixes:
                p0 = prefixes[0]
                asn_info = p0.get("asn",{})
                result["asn"]    = asn_info.get("asn")
                result["asn_name"] = asn_info.get("name")
                result["asn_description"] = asn_info.get("description")
                result["asn_country_code"] = asn_info.get("country_code")
                result["prefix"] = p0.get("prefix")
                result["prefix_name"] = p0.get("name")
                result["all_prefixes"] = [
                    {"prefix": px.get("prefix"), "asn": (px.get("asn") or {}).get("asn")}
                    for px in prefixes[:20]
                ]
        else:
            result["ip_prefix_error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["ip_prefix_error"] = str(e)

    asn_num = result.get("asn")
    if asn_num:
        try:
            r2 = sess.get(f"https://api.bgpview.io/asn/{asn_num}", timeout=DEFAULT_TIMEOUT)
            if r2.status_code == 200:
                d2 = r2.json().get("data",{})
                result["asn_detail"] = {
                    "name":          d2.get("name"),
                    "description":   d2.get("description"),
                    "website":       d2.get("website"),
                    "looking_glass": d2.get("looking_glass"),
                    "traffic_estimation": d2.get("traffic_estimation"),
                    "traffic_ratio":      d2.get("traffic_ratio"),
                    "owner_address":      d2.get("owner_address"),
                }
        except Exception as e:
            result["asn_detail_error"] = str(e)

        # peers
        try:
            r3 = sess.get(f"https://api.bgpview.io/asn/{asn_num}/peers", timeout=DEFAULT_TIMEOUT)
            if r3.status_code == 200:
                d3 = r3.json().get("data",{})
                result["ipv4_peers"] = [
                    {"asn": p.get("asn"), "name": p.get("name"), "country": p.get("country_code")}
                    for p in d3.get("ipv4_peers",[])[:20]
                ]
                result["ipv6_peers"] = [
                    {"asn": p.get("asn"), "name": p.get("name"), "country": p.get("country_code")}
                    for p in d3.get("ipv6_peers",[])[:10]
                ]
        except Exception as e:
            result["peers_error"] = str(e)

        # upstreams
        try:
            r4 = sess.get(f"https://api.bgpview.io/asn/{asn_num}/upstreams", timeout=DEFAULT_TIMEOUT)
            if r4.status_code == 200:
                d4 = r4.json().get("data",{})
                result["ipv4_upstreams"] = [
                    {"asn": u.get("asn"), "name": u.get("name"), "country": u.get("country_code")}
                    for u in d4.get("ipv4_upstreams",[])[:10]
                ]
        except Exception as e:
            result["upstreams_error"] = str(e)

        # announced prefixes
        try:
            r5 = sess.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes", timeout=DEFAULT_TIMEOUT)
            if r5.status_code == 200:
                d5 = r5.json().get("data",{})
                result["announced_ipv4_prefixes"] = [
                    {"prefix": px.get("prefix"), "name": px.get("name")}
                    for px in d5.get("ipv4_prefixes",[])[:30]
                ]
                result["announced_ipv6_prefixes"] = [
                    {"prefix": px.get("prefix"), "name": px.get("name")}
                    for px in d5.get("ipv6_prefixes",[])[:10]
                ]
        except Exception as e:
            result["prefixes_error"] = str(e)

    return result

def scan_js_secrets(target: str, max_js_files: int = 20) -> Dict[str,Any]:
    """Fetch the page, collect JS file URLs, then scan each for known secret patterns."""
    url   = normalize_url(target)
    sess  = request_session()
    found_secrets: List[Dict[str,Any]] = []
    scanned_files: List[str] = []
    errors: List[str] = []

    # get main page
    try:
        resp = sess.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        html_text = resp.text[:MAX_HTML_READ]
    except Exception as e:
        return {"url":url,"error":str(e)}

    soup = BeautifulSoup(html_text, "html.parser")
    js_urls: Set[str] = set()

    # collect inline script content
    for tag in soup.find_all("script"):
        if not tag.get("src"):
            inline = tag.get_text()
            if len(inline) > 50:
                for secret_name, pattern in SECRETS_PATTERNS.items():
                    for match in pattern.finditer(inline):
                        found_secrets.append({
                            "source": "inline-script",
                            "type":   secret_name,
                            "match_preview": match.group(0)[:80],
                        })
        else:
            js_url = absolute_url(url, tag["src"])
            js_urls.add(js_url)

    # also grep page HTML itself
    for secret_name, pattern in SECRETS_PATTERNS.items():
        for match in pattern.finditer(html_text):
            found_secrets.append({
                "source": "page-html",
                "type":   secret_name,
                "match_preview": match.group(0)[:80],
            })

    # fetch and scan JS files
    for js_url in list(js_urls)[:max_js_files]:
        live_status(f"Scanning {js_url[:60]}…")
        try:
            jr = sess.get(js_url, timeout=DEFAULT_TIMEOUT)
            scanned_files.append(js_url)
            for secret_name, pattern in SECRETS_PATTERNS.items():
                for match in pattern.finditer(jr.text):
                    found_secrets.append({
                        "source": js_url,
                        "type":   secret_name,
                        "match_preview": match.group(0)[:80],
                    })
        except Exception as e:
            errors.append(f"{js_url}: {e}")

    if RICH_OK: console.print("" + " "*80, end="\r")  # clear live line

    # deduplicate
    seen: Set[str] = set()
    deduped: List[Dict[str,Any]] = []
    for s in found_secrets:
        key = s["type"] + s["match_preview"][:30]
        if key not in seen:
            seen.add(key)
            deduped.append(s)

    return {
        "url":            url,
        "js_files_scanned": scanned_files,
        "total_js_files": len(js_urls),
        "secrets_found":  deduped,
        "secrets_count":  len(deduped),
        "scan_errors":    errors[:20],
        "note":           "Match previews are truncated. Verify before acting.",
    }

def username_intelligence(username: str) -> Dict[str,Any]:
    """
    Check username across hacker/dev/social platforms.
    Uses HTTP status codes + body heuristics.
    """
    username = username.strip().lower()
    sess = request_session()
    sess.headers.update({"User-Agent":
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    })

    found:   List[Dict[str,Any]] = []
    missing: List[str]           = []
    errors:  List[str]           = []

    for platform in progress_iter(USERNAME_PLATFORMS, f"Hunting [{username}]"):
        p_url = platform["url"].replace("{u}", urllib.parse.quote(username))
        live_status(f"Checking {platform['name']}…")
        try:
            r = sess.get(p_url, timeout=10, allow_redirects=True)
            body = r.text[:4000]

            miss_str    = platform.get("miss","")
            miss_status = platform.get("status","")

            hit = False
            if miss_status:
                hit = (str(r.status_code) != miss_status)
            elif miss_str:
                hit = (r.status_code < 400) and (miss_str.lower() not in body.lower())
            else:
                hit = r.status_code < 400

            if hit:
                found.append({
                    "platform": platform["name"],
                    "url":      p_url,
                    "status":   r.status_code,
                })
                good(f"FOUND  {platform['name']:15s}  {p_url}")
            else:
                missing.append(platform["name"])
        except Exception as e:
            errors.append(f"{platform['name']}: {e}")

    if RICH_OK: console.print("" + " "*80, end="\r")

    return {
        "username":        username,
        "platforms_checked": len(USERNAME_PLATFORMS),
        "accounts_found":  found,
        "found_count":     len(found),
        "not_found":       missing,
        "errors":          errors[:20],
        "generated_at":    now_iso(),
        "note":            "Results are heuristic. Manual verification is recommended.",
    }

def geolocate_ip_or_host(target: str) -> Dict[str,Any]:
    host = host_from_input(target)
    ip_value = host
    if not is_ip(host):
        try: ip_value = socket.gethostbyname(host)
        except Exception as e: return {"input":target,"host":host,"error":str(e)}
    try:
        r = request_session().get(f"https://ipwho.is/{urllib.parse.quote(ip_value)}", timeout=DEFAULT_TIMEOUT)
        data = r.json()
    except Exception as e:
        return {"input":target,"host":host,"ip":ip_value,"error":str(e)}

    return {
        "input":target,"host":host,"ip":ip_value,
        "success":data.get("success"),"type":data.get("type"),
        "continent":data.get("continent"),"country":data.get("country"),
        "country_code":data.get("country_code"),"region":data.get("region"),
        "city":data.get("city"),"latitude":data.get("latitude"),
        "longitude":data.get("longitude"),"postal":data.get("postal"),
        "capital":data.get("capital"),
        "flag":(data.get("flag") or {}).get("emoji") if isinstance(data.get("flag"),dict) else None,
        "connection":data.get("connection",{}),"timezone":data.get("timezone",{}),
        "maps":maps_links(data.get("latitude"),data.get("longitude")),
        "note":"IP geolocation is approximate.",
    }

def rdap_lookup(target: str) -> Dict[str,Any]:
    host = host_from_input(target)
    ip_value = host
    if not is_ip(host):
        try: ip_value = socket.gethostbyname(host)
        except Exception as e: return {"input":target,"host":host,"error":str(e)}
    try:
        r = request_session().get(f"https://rdap.org/ip/{urllib.parse.quote(ip_value)}", timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200: return {"input":target,"ip":ip_value,"error":f"HTTP {r.status_code}"}
        data = r.json()
    except Exception as e:
        return {"input":target,"ip":ip_value,"error":str(e)}
    entities = [{"handle":e.get("handle"),"roles":e.get("roles")} for e in data.get("entities",[])[:10]]
    return {
        "input":target,"host":host,"ip":ip_value,
        "name":data.get("name"),"handle":data.get("handle"),
        "country":data.get("country"),"start_address":data.get("startAddress"),
        "end_address":data.get("endAddress"),"port43":data.get("port43"),
        "entities":entities,
    }

def dns_lookup(target: str) -> Dict[str,Any]:
    host = host_from_input(target)
    result: Dict[str,Any] = {"host":host,"records":{}}
    if not DNS_OK: return {**result,"error":"dnspython not installed"}
    for rtype in COMMON_DNS_TYPES:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=8)
            result["records"][rtype] = [str(a).strip() for a in answers]
        except Exception as e:
            result["records"][rtype] = {"error":str(e)}
    try: result["resolved_ipv4"] = socket.gethostbyname(host)
    except Exception as e: result["resolved_ipv4"] = {"error":str(e)}
    try:
        dnskey = dns.resolver.resolve(host,"DNSKEY",lifetime=8)
        result["dnssec_dnskey"] = [str(a).strip() for a in dnskey]
    except Exception as e:
        result["dnssec_dnskey"] = {"error":str(e)}
    return result

def whois_lookup(target: str) -> Dict[str,Any]:
    host = host_from_input(target)
    if is_ip(host): return {"target":target,"host":host,"error":"Use RDAP for IPs."}
    if not WHOIS_OK: return {"target":target,"host":host,"error":"python-whois not installed"}
    try:
        data = whois_lib.whois(host)
    except Exception as e:
        return {"target":target,"host":host,"error":str(e)}
    return {
        "target":target,"host":host,
        "domain_name":data.get("domain_name"),"registrar":data.get("registrar"),
        "whois_server":data.get("whois_server"),
        "creation_date":str(data.get("creation_date")),
        "expiration_date":str(data.get("expiration_date")),
        "updated_date":str(data.get("updated_date")),
        "name_servers":data.get("name_servers"),"emails":data.get("emails"),
        "status":data.get("status"),"dnssec":data.get("dnssec"),
    }

def tls_inspect(target: str, port: int = 443) -> Dict[str,Any]:
    host = host_from_input(target)
    ctx  = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                version= ssock.version()
    except Exception as e:
        return {"host":host,"port":port,"error":str(e)}
    subject = dict(x[0] for x in cert.get("subject",[]))
    issuer  = dict(x[0] for x in cert.get("issuer",[]))
    return {
        "host":host,"port":port,"tls_version":version,"cipher":cipher,
        "subject":subject,"issuer":issuer,
        "serial_number":cert.get("serialNumber"),
        "not_before":cert.get("notBefore"),"not_after":cert.get("notAfter"),
        "subject_alt_names":cert.get("subjectAltName",[]),
    }

def port_scan(target: str, timeout: float = 1.2) -> Dict[str,Any]:
    host = host_from_input(target)
    results = []
    for port, service in COMMON_PORTS.items():
        live_status(f"Probing {host}:{port} ({service})…")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    banner = None
                    try:
                        sock.settimeout(0.8)
                        if port in (80,8080,8000):
                            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
                            banner = sock.recv(120).decode(errors="replace").strip()
                        elif port in (21,25,110,143):
                            banner = sock.recv(120).decode(errors="replace").strip()
                    except Exception: pass
                    results.append({"port":port,"service":service,"banner_preview":banner})
        except Exception: pass
    if RICH_OK: console.print("" + " "*80, end="\r")
    return {"host":host,"ports_scanned":list(COMMON_PORTS.keys()),"open_ports":results}

def fetch_page(url: str) -> Dict[str,Any]:
    url = normalize_url(url)
    try:
        r = request_session().get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except Exception as e:
        return {"url":url,"error":str(e)}
    headers_norm = {normalize_header_name(k):v for k,v in dict(r.headers).items()}
    security  = {h: headers_norm.get(h) for h in SECURITY_HEADERS}
    missing   = [h for h,v in security.items() if not v]
    html_text = r.text[:MAX_HTML_READ]
    soup      = BeautifulSoup(html_text,"html.parser")
    title     = soup.title.get_text(strip=True) if soup.title else None
    metas: Dict[str,str] = {}
    for m in soup.find_all("meta"):
        name    = m.get("name") or m.get("property") or m.get("http-equiv")
        content = m.get("content")
        if name and content and len(metas)<60: metas[name]=content
    return {
        "input_url":url,"final_url":r.url,"status_code":r.status_code,
        "server":headers_norm.get("Server"),"content_type":headers_norm.get("Content-Type"),
        "title":title,"headers":headers_norm,"security_headers":security,
        "missing_security_headers":missing,"meta":metas,
        "cookie_analysis":analyze_cookies(headers_norm,r.cookies),
        "technologies":detect_technologies(headers_norm,html_text,r.url),
        "html_preview":html_text[:MAX_BODY_PREVIEW],
    }

def inspect_robots_and_sitemap(target: str) -> Dict[str,Any]:
    url    = normalize_url(target)
    parsed = urllib.parse.urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    result: Dict[str,Any] = {
        "base":base,"robots_url":base+"/robots.txt",
        "sitemap_url":base+"/sitemap.xml","robots":{},"sitemaps":[],"urls":[],
    }
    try:
        rr = request_session().get(base+"/robots.txt", timeout=DEFAULT_TIMEOUT)
        result["robots"]["status_code"] = rr.status_code
        result["robots"]["preview"]     = rr.text[:2000]
        sitemaps, allow, disallow, uas  = [],[],[],[]
        for line in rr.text.splitlines():
            ll = line.strip().lower()
            if ll.startswith("sitemap:"):   sitemaps.append(line.split(":",1)[1].strip())
            elif ll.startswith("allow:"):   allow.append(line.split(":",1)[1].strip())
            elif ll.startswith("disallow:"): disallow.append(line.split(":",1)[1].strip())
            elif ll.startswith("user-agent:"): uas.append(line.split(":",1)[1].strip())
        result["robots"]["declared_sitemaps"] = sitemaps[:50]
        result["robots"]["allow"]      = allow[:100]
        result["robots"]["disallow"]   = disallow[:100]
        result["robots"]["user_agents"]= uas[:50]
    except Exception as e:
        result["robots"]["error"] = str(e)

    sm_candidates = result["robots"].get("declared_sitemaps",[]) + [base+"/sitemap.xml"]
    seen: Set[str] = set()
    for sm in sm_candidates:
        if sm in seen: continue
        seen.add(sm)
        try:
            sr = request_session().get(sm, timeout=DEFAULT_TIMEOUT)
            item = {"url":sm,"status_code":sr.status_code}
            if sr.status_code==200 and "<loc>" in sr.text:
                locs = re.findall(r"<loc>(.*?)</loc>", sr.text, re.I|re.S)
                item["urls"] = [html.unescape(x.strip()) for x in locs[:200]]
                result["urls"].extend(item["urls"])
            result["sitemaps"].append(item)
        except Exception as e:
            result["sitemaps"].append({"url":sm,"error":str(e)})
    result["urls"] = sorted(set(result["urls"]))[:500]
    return result

def extract_page_artifacts(base_url: str, html_text: str) -> Dict[str,Any]:
    soup      = BeautifulSoup(html_text,"html.parser")
    emails    = sorted(set(EMAIL_RE.findall(html_text)))
    phones    = sorted(set(p.strip() for p in PHONE_RE.findall(html_text) if len(re.sub(r"\D","",p))>=7))
    all_links: Set[str]=set(); social: Set[str]=set(); js: Set[str]=set()
    css: Set[str]=set(); docs: Set[str]=set(); endpoints: Set[str]=set()
    for tag in soup.find_all(["a","script","link"]):
        href = tag.get("href") or tag.get("src")
        if not href: continue
        full   = absolute_url(base_url, href)
        parsed = urllib.parse.urlparse(full)
        host   = parsed.netloc.lower(); path = parsed.path.lower()
        all_links.add(full)
        if any(h in host for h in SOCIAL_HINTS): social.add(full)
        if path.endswith(".js"):  js.add(full)
        if path.endswith(".css"): css.add(full)
        if any(path.endswith(e) for e in [".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".txt",".csv"]):
            docs.add(full)
    for m in JS_ENDPOINT_RE.findall(html_text): endpoints.add(m)
    return {
        "emails":emails[:100],"phones":phones[:100],"links":sorted(all_links)[:700],
        "social_links":sorted(social)[:100],"js_files":sorted(js)[:150],
        "css_files":sorted(css)[:150],"public_documents":sorted(docs)[:150],
        "js_endpoints":sorted(endpoints)[:250],
    }

class CrawlSettings:
    def __init__(self,max_pages=10,same_domain_only=True,delay_seconds=0.75,
                 respect_robots=True,include_query_variants=False):
        self.max_pages=max_pages; self.same_domain_only=same_domain_only
        self.delay_seconds=delay_seconds; self.respect_robots=respect_robots
        self.include_query_variants=include_query_variants
    def as_dict(self): return self.__dict__

def can_fetch(url: str) -> Tuple[bool, Optional[str]]:
    parsed = urllib.parse.urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = urllib.robotparser.RobotFileParser()
    try: rp.set_url(robots_url); rp.read(); return rp.can_fetch(DEFAULT_UA, url), robots_url
    except Exception: return True, robots_url

def crawl_site(start_url: str, settings: CrawlSettings) -> Dict[str,Any]:
    start_url      = normalize_url(start_url)
    base_netloc    = urllib.parse.urlparse(start_url).netloc
    visited: Set[str] = set(); queue: deque[str] = deque([start_url])
    page_summaries=[]; emails:Set[str]=set(); phones:Set[str]=set()
    social:Set[str]=set(); docs:Set[str]=set(); js:Set[str]=set()
    css:Set[str]=set(); endpoints:Set[str]=set()

    while queue and len(visited) < settings.max_pages:
        url = queue.popleft()
        norm = url.split("#")[0]
        if not settings.include_query_variants:
            p = urllib.parse.urlparse(norm)
            norm = urllib.parse.urlunparse((p.scheme,p.netloc,p.path,"","",""))
        if norm in visited: continue
        if settings.same_domain_only and not same_domain(base_netloc, norm): continue
        if settings.respect_robots:
            allowed, rb = can_fetch(norm)
            if not allowed:
                page_summaries.append({"url":norm,"skipped":True,"reason":f"robots.txt"})
                visited.add(norm); continue
        live_status(f"Crawling {norm[:70]}…")
        try:
            r = request_session().get(norm, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            ct = r.headers.get("Content-Type","")
            if "text/html" not in ct.lower():
                page_summaries.append({"url":norm,"final_url":r.url,"status_code":r.status_code,"note":"non-HTML"})
                visited.add(norm); time.sleep(settings.delay_seconds); continue
            html_text = r.text[:MAX_HTML_READ]
            soup      = BeautifulSoup(html_text,"html.parser")
            title     = soup.title.get_text(strip=True) if soup.title else None
            artifacts = extract_page_artifacts(r.url, html_text)
            page_summaries.append({
                "url":norm,"final_url":r.url,"status_code":r.status_code,"title":title,
                "emails_found":artifacts["emails"][:20],"phones_found":artifacts["phones"][:20],
                "social_links_found":artifacts["social_links"][:20],
                "documents_found":artifacts["public_documents"][:20],
                "js_endpoints_found":artifacts["js_endpoints"][:20],
            })
            emails.update(artifacts["emails"]); phones.update(artifacts["phones"])
            social.update(artifacts["social_links"]); docs.update(artifacts["public_documents"])
            js.update(artifacts["js_files"]); css.update(artifacts["css_files"])
            endpoints.update(artifacts["js_endpoints"])
            for link in artifacts["links"]:
                if settings.same_domain_only and not same_domain(base_netloc,link): continue
                if link not in visited and len(queue)<settings.max_pages*12: queue.append(link)
        except Exception as e:
            page_summaries.append({"url":norm,"error":str(e)})
        visited.add(norm); time.sleep(settings.delay_seconds)

    if RICH_OK: console.print("" + " "*80, end="\r")
    return {
        "start_url":start_url,"pages_visited":len(visited),"page_summaries":page_summaries,
        "emails":sorted(emails)[:300],"phones":sorted(phones)[:300],
        "social_links":sorted(social)[:300],"public_documents":sorted(docs)[:300],
        "js_files":sorted(js)[:300],"css_files":sorted(css)[:300],
        "js_endpoints":sorted(endpoints)[:300],"settings":settings.as_dict(),
    }

def discover_paths(base_url: str) -> Dict[str,Any]:
    base_url = normalize_url(base_url).rstrip("/")
    found = []
    for path in SAFE_DISCOVERY_PATHS:
        url = base_url + path
        live_status(f"Probing {path}…")
        try:
            r = request_session().get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if r.status_code < 500:
                found.append({
                    "path":path,"status_code":r.status_code,"final_url":r.url,
                    "content_type":r.headers.get("Content-Type"),
                    "content_length":r.headers.get("Content-Length"),
                })
        except Exception as e:
            found.append({"path":path,"error":str(e)})
    if RICH_OK: console.print("" + " "*80, end="\r")
    return {"base_url":base_url,"checked_paths":SAFE_DISCOVERY_PATHS,"results":found}

def subdomain_discovery(target: str) -> Dict[str,Any]:
    domain = host_from_input(target)
    found: List[Dict[str,Any]]=[]; seen: Set[str]=set()
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        live_status(f"Resolving {fqdn}…")
        try:
            ip = socket.gethostbyname(fqdn)
            if fqdn not in seen:
                seen.add(fqdn)
                found.append({"source":"dns_wordlist","subdomain":fqdn,"ip":ip})
        except Exception: pass

    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        r   = request_session().get(url, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            for item in r.json()[:500]:
                for line in (item.get("name_value") or "").splitlines():
                    line = line.strip().lower()
                    if "*" in line: continue
                    if (line.endswith("."+domain) or line==domain) and line not in seen:
                        seen.add(line)
                        resolved = None
                        try: resolved = socket.gethostbyname(line)
                        except Exception: pass
                        found.append({"source":"crt.sh","subdomain":line,"ip":resolved})
    except Exception as e:
        found.append({"source":"crt.sh","error":str(e)})

    if RICH_OK: console.print("" + " "*80, end="\r")
    found_sorted = sorted([x for x in found if "subdomain" in x], key=lambda x: x["subdomain"])
    return {"domain":domain,"found_subdomains":found_sorted[:500],"count":len(found_sorted)}

def combined_audit(target: str, max_pages: int = 8) -> Dict[str,Any]:
    started = time.time()
    host = host_from_input(target)
    url  = normalize_url(target)
    web  = fetch_page(url)
    tls  = tls_inspect(target)
    return {
        "generated_at":now_iso(),"target_input":target,"host":host,"url":url,
        "geolocation":  geolocate_ip_or_host(target),
        "asn_bgp":      asn_bgp_lookup(target),
        "rdap":         rdap_lookup(target),
        "whois":        whois_lookup(target),
        "dns":          dns_lookup(target),
        "tls":          tls,
        "web":          web,
        "robots_sitemap": inspect_robots_and_sitemap(url),
        "path_discovery": discover_paths(url),
        "subdomains":   subdomain_discovery(target),
        "ports":        port_scan(target),
        "js_secrets":   scan_js_secrets(url),
        "crawl":        crawl_site(url, CrawlSettings(max_pages=max_pages,same_domain_only=True,
                                                       delay_seconds=0.75,respect_robots=True)),
        "security_rating": rate_security(web, tls),
        "scan_duration_seconds": round(time.time()-started, 2),
    }

# Each display_* function streams findings line-by-line as ◉/◌/▸/⚠/✘
# so the terminal feels alive and operator-like.

def display_geo(result: Dict[str,Any]) -> None:
    feed_section("IP INTELLIGENCE · GEOLOCATION")
    if result.get("error"):
        feed_err("Lookup failed", result["error"]); return
    feed_hit("host",    result.get("host",""))
    feed_hit("ip",      result.get("ip",""))
    flag = result.get("flag") or ""
    country = f"{flag} {result.get('country','')} ({result.get('country_code','')})" if result.get("country") else ""
    if country: feed_hit("country", country)
    if result.get("region"):  feed_hit("region",   result["region"])
    if result.get("city"):    feed_hit("city",      result["city"])
    if result.get("postal"):  feed_info("postal",   result["postal"])
    if result.get("latitude"):
        feed_info("coords", f"{result['latitude']}, {result['longitude']}")
    conn = result.get("connection") or {}
    if conn.get("isp"):  feed_info("isp",  conn["isp"])
    if conn.get("org"):  feed_info("org",  conn["org"])
    if conn.get("asn"):  feed_info("asn",  str(conn["asn"]))
    tz = result.get("timezone") or {}
    if tz.get("id"):     feed_info("timezone", f"{tz['id']}  UTC{tz.get('utc','')}")
    maps = result.get("maps") or {}
    if maps.get("google_maps"): feed_info("google maps", maps["google_maps"])
    feed_warn("note", "geolocation is approximate — may reflect ISP location")

def display_dns(result: Dict[str,Any]) -> None:
    feed_section("DNS RECON")
    if result.get("error"):
        feed_err("DNS failed", result["error"]); return
    feed_info("host", result.get("host",""))
    if result.get("resolved_ipv4") and not isinstance(result["resolved_ipv4"], dict):
        feed_hit("resolved ipv4", result["resolved_ipv4"])
    records = result.get("records", {})
    for rtype, rdata in records.items():
        if isinstance(rdata, dict):  # error dict
            feed_miss(rtype, rdata.get("error","no record"))
        elif isinstance(rdata, list) and rdata:
            feed_hit(rtype, "")
            for rec in rdata[:10]:
                feed_info(rtype, rec[:100], indent=1)
        else:
            feed_miss(rtype)
    dnssec = result.get("dnssec_dnskey")
    if isinstance(dnssec, list) and dnssec:
        feed_hit("DNSSEC", f"{len(dnssec)} key(s) found")
    else:
        feed_miss("DNSSEC", "no DNSKEY found")

def display_rdap(result: Dict[str,Any]) -> None:
    feed_section("RDAP NETWORK LOOKUP")
    if result.get("error"):
        feed_err("RDAP failed", result["error"]); return
    feed_kv("ip",            result.get("ip"))
    feed_kv("name",          result.get("name"))
    feed_kv("handle",        result.get("handle"))
    feed_kv("country",       result.get("country"))
    feed_kv("start address", result.get("start_address"))
    feed_kv("end address",   result.get("end_address"))
    feed_kv("port43",        result.get("port43"))
    entities = result.get("entities", [])
    if entities:
        feed_hit("entities", f"({len(entities)} found)")
        for e in entities[:10]:
            roles = ", ".join(e.get("roles") or [])
            feed_info(e.get("handle","?"), roles, indent=1)

def display_asn(result: Dict[str,Any]) -> None:
    feed_section("ASN / BGP ROUTE INTELLIGENCE")
    if result.get("error"):
        feed_err("Lookup failed", result["error"]); return

    feed_hit("ip",      result.get("ip",""))
    feed_kv("asn",      result.get("asn"))
    feed_kv("asn name", result.get("asn_name"))
    feed_kv("desc",     result.get("asn_description"))
    feed_kv("country",  result.get("asn_country_code"))
    feed_kv("prefix",   result.get("prefix"))

    rir = result.get("rir") or {}
    if any(rir.values()):
        feed_blank(); feed_section("RIR ALLOCATION")
        feed_kv("rir",       rir.get("name"))
        feed_kv("country",   rir.get("country_code"))
        feed_kv("allocated", rir.get("date_allocated"))

    detail = result.get("asn_detail") or {}
    if any(detail.values()):
        feed_blank(); feed_section("ASN DETAIL")
        feed_kv("website",      detail.get("website"))
        feed_kv("looking glass",detail.get("looking_glass"))
        feed_kv("traffic est.", detail.get("traffic_estimation"))
        feed_kv("traffic ratio",detail.get("traffic_ratio"))

    peers = result.get("ipv4_peers",[])
    if peers:
        feed_blank(); feed_section(f"IPV4 BGP PEERS  ({len(peers)} shown)")
        for p in peers[:20]:
            feed_info(f"AS{p.get('asn','')}",
                      f"{p.get('name','')[:40]}  [{p.get('country','')}]", indent=1)

    ups = result.get("ipv4_upstreams",[])
    if ups:
        feed_blank(); feed_section(f"IPV4 UPSTREAMS  ({len(ups)} found)")
        for u in ups[:10]:
            feed_info(f"AS{u.get('asn','')}",
                      f"{u.get('name','')[:40]}  [{u.get('country','')}]", indent=1)

    prefixes = result.get("announced_ipv4_prefixes",[])
    if prefixes:
        feed_blank(); feed_section(f"ANNOUNCED PREFIXES  ({len(prefixes)} shown)")
        for px in prefixes[:15]:
            feed_info(px.get("prefix",""), px.get("name","")[:60], indent=1)

def display_tls(result: Dict[str,Any]) -> None:
    feed_section("TLS CERTIFICATE ANALYSIS")
    if result.get("error"):
        feed_err("TLS handshake failed", result["error"]); return
    feed_hit("version", result.get("tls_version",""))
    cipher = result.get("cipher") or ()
    if cipher: feed_hit("cipher", f"{cipher[0]}  {cipher[2]}b" if len(cipher)>2 else str(cipher))
    subj = result.get("subject") or {}
    feed_kv("common name", subj.get("commonName"))
    feed_kv("org",         subj.get("organizationName"))
    feed_kv("country",     subj.get("countryName"))
    iss = result.get("issuer") or {}
    feed_kv("issuer",      iss.get("organizationName"))
    feed_kv("not before",  result.get("not_before"))
    feed_kv("not after",   result.get("not_after"))
    sans = result.get("subject_alt_names",[])
    feed_list("subject alt names", [f"{t}:{v}" for t,v in sans], max_show=15)

def display_whois(result: Dict[str,Any]) -> None:
    feed_section("WHOIS INTELLIGENCE")
    if result.get("error"):
        feed_err("WHOIS failed", result["error"]); return
    feed_kv("domain",      result.get("domain_name"))
    feed_kv("registrar",   result.get("registrar"))
    feed_kv("whois server",result.get("whois_server"))
    feed_kv("created",     result.get("creation_date"))
    feed_kv("expires",     result.get("expiration_date"))
    feed_kv("updated",     result.get("updated_date"))
    feed_kv("dnssec",      result.get("dnssec"))
    ns = result.get("name_servers")
    if ns: feed_list("name servers", ns if isinstance(ns,list) else [ns])
    emails = result.get("emails")
    if emails: feed_list("registrar emails", emails if isinstance(emails,list) else [emails])
    status = result.get("status")
    if status: feed_list("status", status if isinstance(status,list) else [status])

def display_ports(result: Dict[str,Any]) -> None:
    feed_section(f"PORT EXPOSURE SCAN  ·  {result.get('host','')}")
    open_ports = result.get("open_ports",[])
    all_ports  = result.get("ports_scanned",[])
    if not open_ports:
        feed_miss("open ports", f"0 / {len(all_ports)} scanned")
        return
    feed_hit("open ports", f"{len(open_ports)} / {len(all_ports)} scanned")
    feed_blank()
    for p in open_ports:
        banner = p.get("banner_preview") or ""
        banner_short = banner[:60].replace("\n"," ") if banner else ""
        svc = p.get("service","")
        # flag risky services
        risky = p["port"] in (21,23,25,3389,6379,9200,27017,1521,1433)
        if risky:
            feed_warn(f":{p['port']}", f"{svc}  {banner_short}")
        else:
            feed_hit(f":{p['port']}", f"{svc}  {banner_short}")
    feed_blank()
    # summarise closed
    open_set = {p["port"] for p in open_ports}
    closed = [p for p in all_ports if p not in open_set]
    feed_miss("closed / filtered", ", ".join(str(p) for p in closed[:40]))

def display_web(result: Dict[str,Any]) -> None:
    feed_section("WEBSITE FINGERPRINT")
    if result.get("error"):
        feed_err("fetch failed", result["error"]); return
    sc = result.get("status_code")
    if isinstance(sc,int) and sc < 400:
        feed_hit("status", str(sc))
    else:
        feed_warn("status", str(sc))
    feed_kv("title",        result.get("title"))
    feed_kv("final url",    result.get("final_url"))
    feed_kv("server",       result.get("server"))
    feed_kv("content-type", result.get("content_type"))
    techs = result.get("technologies",[])
    if techs:
        feed_hit("technologies", "")
        for t in techs:
            feed_info(t, indent=1)
    feed_blank()
    # security headers
    feed_section("SECURITY HEADERS")
    sh = result.get("security_headers") or {}
    for h, v in sh.items():
        if v:
            feed_hit(h.lower(), v[:80] if len(v)>80 else v)
        else:
            feed_warn(h.lower(), "MISSING")
    # cookies
    cookies = result.get("cookie_analysis",[])
    if cookies:
        feed_blank(); feed_section(f"COOKIES  ({len(cookies)} found)")
        for c in cookies:
            flags = []
            if not c.get("secure_hint"):   flags.append("no-Secure")
            if not c.get("httponly_hint"): flags.append("no-HttpOnly")
            if not c.get("samesite_hint"): flags.append("no-SameSite")
            if flags:
                feed_warn(c["name"], "  ".join(flags))
            else:
                feed_hit(c["name"], "secure flags ok")

def display_secrets(result: Dict[str,Any]) -> None:
    feed_section("JS SECRETS SCANNER")
    if result.get("error"):
        feed_err("scan failed", result["error"]); return
    feed_info("url",           result.get("url",""))
    feed_info("js files found",str(result.get("total_js_files",0)))
    feed_info("js files scanned",str(len(result.get("js_files_scanned",[]))))
    feed_blank()
    secrets = result.get("secrets_found",[])
    if not secrets:
        feed_miss("secrets", "none detected")
        feed_info("note","patterns may miss obfuscated secrets", indent=1)
        return
    feed_warn("secrets found", str(len(secrets)))
    feed_blank()
    for s in secrets:
        src = s.get("source","?")
        src_short = src.split("/")[-1][:40] if "/" in src else src[:40]
        feed_err(s["type"], f"in {src_short}")
        feed_info("preview", s["match_preview"][:80], indent=1)
    feed_blank()
    feed_warn("note","verify all matches manually — false positives possible")

def display_crawl(result: Dict[str,Any]) -> None:
    feed_section("CRAWL ENGINE RESULTS")
    feed_info("start url",     result.get("start_url",""))
    feed_info("pages visited", str(result.get("pages_visited",0)))
    feed_blank()
    feed_list("emails found",          result.get("emails",[]))
    feed_blank()
    feed_list("phone numbers found",   result.get("phones",[]))
    feed_blank()
    feed_list("social links",          result.get("social_links",[]))
    feed_blank()
    feed_list("public documents",      result.get("public_documents",[]))
    feed_blank()
    feed_list("js api endpoints",      result.get("js_endpoints",[]))
    feed_blank()
    feed_list("js files",              result.get("js_files",[]), max_show=10)

def display_subdomains(result: Dict[str,Any]) -> None:
    feed_section(f"SUBDOMAIN DISCOVERY  ·  {result.get('domain','')}")
    found = result.get("found_subdomains",[])
    if not found:
        feed_miss("subdomains","none discovered"); return
    feed_hit("subdomains found", str(result.get("count",0)))
    feed_blank()
    for sub in found:
        ip = sub.get("ip") or "unresolved"
        src = sub.get("source","?")
        src_tag = "[crt.sh]" if "crt" in src else "[wordlist]"
        if sub.get("ip"):
            feed_hit(sub["subdomain"], f"{ip}  {src_tag}")
        else:
            feed_miss(sub["subdomain"], f"unresolved  {src_tag}")

def display_robots(result: Dict[str,Any]) -> None:
    feed_section("ROBOTS · SITEMAP ANALYSIS")
    rb = result.get("robots",{})
    sc = rb.get("status_code")
    if sc == 200:
        feed_hit("robots.txt", f"HTTP {sc}")
        dis = rb.get("disallow",[])
        allow = rb.get("allow",[])
        sitemaps = rb.get("declared_sitemaps",[])
        uas = rb.get("user_agents",[])
        feed_list("disallow rules", dis, max_show=20)
        feed_blank()
        feed_list("allow rules",    allow, max_show=10)
        feed_blank()
        feed_list("declared sitemaps", sitemaps)
        feed_blank()
        feed_list("user-agents listed", uas)
    elif sc:
        feed_miss("robots.txt", f"HTTP {sc}")
    else:
        feed_err("robots.txt", rb.get("error","fetch failed"))

    feed_blank(); feed_section("SITEMAP URLS")
    urls = result.get("urls",[])
    feed_list("urls found in sitemaps", urls, max_show=25)

def display_paths(result: Dict[str,Any]) -> None:
    feed_section(f"SAFE PATH DISCOVERY  ·  {result.get('base_url','')}")
    for r in result.get("results",[]):
        path = r.get("path","")
        if r.get("error"):
            feed_err(path, r["error"]); continue
        sc = r.get("status_code",0)
        ct = (r.get("content_type") or "").split(";")[0].strip()
        cl = r.get("content_length","")
        detail = f"HTTP {sc}  {ct}  {cl}".strip()
        if sc == 200:
            feed_hit(path, detail)
        elif sc in (301,302,307,308):
            feed_info(path, f"→ redirect  {detail}")
        elif sc == 403:
            feed_warn(path, f"forbidden  {detail}")
        elif sc == 401:
            feed_warn(path, f"auth required  {detail}")
        elif sc == 404:
            feed_miss(path)
        else:
            feed_info(path, detail)

def display_username_results(result: Dict[str,Any]) -> None:
    feed_section(f"USERNAME INTELLIGENCE  ·  {result.get('username','').upper()}")
    feed_info("platforms checked", str(result.get("platforms_checked",0)))
    feed_blank()
    found = result.get("accounts_found",[])
    if found:
        feed_hit("accounts found", str(len(found)))
        feed_blank()
        for acc in found:
            feed_hit(acc["platform"], acc["url"])
    else:
        feed_miss("accounts found","none")
    feed_blank()
    not_found = result.get("not_found",[])
    if not_found:
        feed_miss("not found", "")
        for p in not_found:
            feed_miss(p, indent=1)
    errors = result.get("errors",[])
    if errors:
        feed_blank()
        for e in errors[:10]:
            feed_warn("error", e)
    feed_blank()
    feed_warn("note", result.get("note","heuristic — verify manually"))

def display_security_rating(rating: Dict[str,Any]) -> None:
    feed_blank(); feed_section("SECURITY RATING")
    score = rating.get("score", 0)
    grade = rating.get("grade","?")
    grade_label = {"A":"excellent","B":"good","C":"fair","D":"poor","F":"critical"}.get(grade,"?")
    if grade in ("A","B"):
        feed_hit("grade", f"{grade}  ·  {score}/100  ·  {grade_label}")
    elif grade == "C":
        feed_warn("grade", f"{grade}  ·  {score}/100  ·  {grade_label}")
    else:
        feed_err("grade", f"{grade}  ·  {score}/100  ·  {grade_label}")
    feed_blank()
    for f in rating.get("findings",[]):
        sev = f["severity"]
        if sev == "high":    feed_err(sev.upper(),    f["issue"])
        elif sev == "medium":feed_warn(sev.upper(),   f["issue"])
        else:                feed_info(sev.upper(),   f["issue"])

def display_summary(title: str, data: Dict[str,Any]) -> None:
    """
    Generic fallback — routes to the right specialised display function
    or falls back to a live-feed key/value dump.
    """
    # Route to specialised displays where possible
    router = {
        "Geolocation":         lambda: display_geo(data),
        "DNS Recon":           lambda: display_dns(data),
        "RDAP":                lambda: display_rdap(data),
        "TLS Certificate":     lambda: display_tls(data),
        "WHOIS":               lambda: display_whois(data),
        "Port Scan":           lambda: display_ports(data),
        "Website Fingerprint": lambda: display_web(data),
        "Crawl Results":       lambda: display_crawl(data),
        "Subdomain Discovery": lambda: display_subdomains(data),
        "Robots + Sitemap":    lambda: display_robots(data),
        "Path Discovery":      lambda: display_paths(data),
        "Security Header Audit": lambda: display_web(data),
    }
    fn = router.get(title)
    if fn:
        fn(); return

    # Generic live-feed dump
    feed_section(title.upper())
    for k, v in list(data.items())[:40]:
        if isinstance(v, (dict, list)):
            flat = json.dumps(v, ensure_ascii=False, default=str)
            feed_kv(k, flat[:120])
        else:
            feed_kv(k, v)

def save_json_report(name: str, data: Dict[str,Any]) -> str:
    ensure_reports_dir()
    ts   = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"{slugify(name)}_{ts}.json")
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return path

def save_findings_csv(name: str, data: Dict[str,Any]) -> str:
    ensure_reports_dir()
    ts   = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"{slugify(name)}_{ts}.csv")
    rows = []
    def add(cat,k,v): rows.append({"category":cat,"key":k,"value":json.dumps(v,default=str) if isinstance(v,(dict,list)) else str(v)})
    if "security_rating" in data:
        add("security_rating","score",data["security_rating"].get("score"))
        add("security_rating","grade",data["security_rating"].get("grade"))
    for e in ((data.get("crawl") or {}).get("emails") or []): add("email","email",e)
    for p in ((data.get("crawl") or {}).get("phones") or []): add("phone","phone",p)
    for s in ((data.get("subdomains") or {}).get("found_subdomains") or []): add("subdomain",s.get("subdomain",""),s.get("ip"))
    for p in ((data.get("ports") or {}).get("open_ports") or []): add("open_port",str(p.get("port")),p.get("service"))
    for s in (data.get("js_secrets") or {}).get("secrets_found",[]): add("js_secret",s["type"],s["match_preview"])
    if "accounts_found" in data: # username report
        for a in data["accounts_found"]: add("username_hit",a["platform"],a["url"])
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["category","key","value"])
        w.writeheader(); w.writerows(rows)
    return path

def save_html_report(name: str, data: Dict[str,Any]) -> str:
    ensure_reports_dir()
    ts   = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"{slugify(name)}_{ts}.html")
    def render(obj): return html.escape(json.dumps(obj,indent=2,ensure_ascii=False,default=str))
    rating = data.get("security_rating",{})
    score  = rating.get("score","N/A")
    grade  = rating.get("grade","N/A")
    sections = "".join(
        f'<section><h2>{html.escape(str(k))}</h2><pre>{render(v)}</pre></section>'
        for k,v in data.items()
    )
    html_doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{html.escape(name)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
  :root{{--crimson:#c0152c;--bone:#f5f0e8;--shadow:#1a0a0d;--mid:#2a0d14;--dim:#8a6060}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--shadow);color:var(--bone);font-family:'Share Tech Mono',monospace;padding:2rem}}
  h1{{color:var(--crimson);font-size:2rem;letter-spacing:.2em;border-bottom:2px solid var(--crimson);padding-bottom:.5rem;margin-bottom:1rem}}
  h2{{color:var(--crimson);font-size:1rem;letter-spacing:.1em;margin-bottom:.5rem}}
  section{{background:var(--mid);border:1px solid var(--crimson);border-radius:4px;padding:1rem;margin-bottom:1rem}}
  pre{{white-space:pre-wrap;word-wrap:break-word;background:#100508;color:var(--bone);border:1px solid #3a1020;border-radius:4px;padding:.75rem;font-size:.8rem}}
  .badge{{display:inline-block;background:#3a0010;border:1px solid var(--crimson);border-radius:2px;padding:.4rem .8rem;margin:.25rem;font-size:.85rem}}
  .badge span{{color:var(--crimson)}}
  small{{color:var(--dim)}}
</style></head><body>
<h1>◈ {html.escape(name)}</h1>
<small>Generated {html.escape(now_iso())} · SOCIAL HOUND NOIR</small>
<div style="margin:1rem 0">
  <span class="badge">Score: <span>{html.escape(str(score))}</span></span>
  <span class="badge">Grade: <span>{html.escape(str(grade))}</span></span>
</div>
{sections}
</body></html>"""
    with open(path,"w",encoding="utf-8") as f: f.write(html_doc)
    return path

def batch_audit(file_path: str, max_pages: int = 5) -> Dict[str,Any]:
    if not os.path.isfile(file_path):
        return {"error":f"File not found: {file_path}"}
    with open(file_path,"r",encoding="utf-8",errors="replace") as f:
        targets = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    results = []
    for target in progress_iter(targets, "Batch auditing"):
        info(f"Auditing {target}")
        results.append({"target":target,"result":combined_audit(target,max_pages=max_pages)})
    return {"generated_at":now_iso(),"file":file_path,"target_count":len(targets),"results":results}

def ask(text: str, default: Optional[str] = None) -> str:
    if RICH_OK:
        prompt_text = f"[bold red]▸[/bold red] [bold white]{text}[/bold white]"
        return Prompt.ask(prompt_text, default=default) if default is not None else Prompt.ask(prompt_text)
    if default is not None:
        v = input(f"▸ {text} [{default}]: ").strip()
        return v or default
    return input(f"▸ {text}: ").strip()

def main() -> int:
    print_banner()
    last_result: Optional[Dict[str,Any]] = None
    last_name = "audit"

    while True:
        print_menu()
        choice = ask("Select option", "0").strip()

        if choice == "1":
            target = ask("Target (IP / host / URL)")
            with console.status("[bold red]Geolocating…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = geolocate_ip_or_host(target)
            last_result = result; last_name = f"geo_{host_from_input(target)}"
            display_summary("Geolocation", result); pretty_json(result)

        elif choice == "2":
            target = ask("Domain or URL")
            with console.status("[bold red]Resolving DNS…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = dns_lookup(target)
            last_result = result; last_name = f"dns_{host_from_input(target)}"
            display_summary("DNS Recon", result); pretty_json(result)

        elif choice == "3":
            target = ask("IP / host / URL")
            with console.status("[bold red]RDAP lookup…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = rdap_lookup(target)
            last_result = result; last_name = f"rdap_{host_from_input(target)}"
            display_summary("RDAP", result); pretty_json(result)

        elif choice == "4":
            target = ask("IP / host / URL")
            info("Querying BGPView API (may take a moment)…")
            result = asn_bgp_lookup(target)
            last_result = result; last_name = f"asn_{host_from_input(target)}"
            display_asn(result); pretty_json(result)

        elif choice == "5":
            target   = ask("Domain or URL")
            port_raw = ask("Port", "443")
            try: port = int(port_raw)
            except Exception: port = 443
            with console.status("[bold red]Handshaking TLS…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = tls_inspect(target, port)
            last_result = result; last_name = f"tls_{host_from_input(target)}"
            display_summary("TLS Certificate", result); pretty_json(result)

        elif choice == "6":
            target = ask("Domain or URL")
            with console.status("[bold red]WHOIS…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = whois_lookup(target)
            last_result = result; last_name = f"whois_{host_from_input(target)}"
            display_summary("WHOIS", result); pretty_json(result)

        elif choice == "7":
            target = ask("Host or URL")
            info(f"Scanning {len(COMMON_PORTS)} ports on {host_from_input(target)}…")
            result = port_scan(target)
            last_result = result; last_name = f"ports_{host_from_input(target)}"
            display_summary("Port Scan", result); pretty_json(result)

        elif choice == "8":
            target = ask("URL")
            with console.status("[bold red]Fingerprinting…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = fetch_page(target)
            last_result = result; last_name = f"page_{host_from_input(target)}"
            display_summary("Website Fingerprint", result); pretty_json(result)

        elif choice == "9":
            target = ask("URL")
            with console.status("[bold red]Fetching headers…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = fetch_page(target)
            last_result = result; last_name = f"headers_{host_from_input(target)}"
            divider("Security Header Audit")
            if RICH_OK:
                ht = Table(box=box.SIMPLE_HEAVY, header_style="bold red")
                ht.add_column("Header", style="bold white", width=38)
                ht.add_column("Value",  style="white",      width=70, overflow="fold")
                for h in SECURITY_HEADERS:
                    val = (result.get("security_headers") or {}).get(h)
                    style = "green" if val else "bold red"
                    ht.add_row(h, f"[{style}]{val or 'MISSING'}[/{style}]")
                console.print(ht)
            else:
                pretty_json(result.get("security_headers",{}))

        elif choice == "10":
            target = ask("URL to scan for secrets")
            info("Fetching page + JS files and scanning for secrets…")
            result = scan_js_secrets(target)
            last_result = result; last_name = f"secrets_{host_from_input(target)}"
            display_secrets(result); pretty_json(result)

        elif choice == "11":
            target    = ask("URL")
            pages_raw = ask("Max pages", "8")
            try: max_pages = max(1,min(50,int(pages_raw)))
            except Exception: max_pages = 8
            info(f"Crawling up to {max_pages} pages…")
            result = crawl_site(target, CrawlSettings(max_pages=max_pages))
            last_result = result; last_name = f"crawl_{host_from_input(target)}"
            display_summary("Crawl Results", result); pretty_json(result)

        elif choice == "12":
            target = ask("Domain or URL")
            info("Probing subdomains (wordlist + crt.sh passive)…")
            result = subdomain_discovery(target)
            last_result = result; last_name = f"subdomains_{host_from_input(target)}"
            display_summary("Subdomain Discovery", result); pretty_json(result)

        elif choice == "13":
            target = ask("URL")
            with console.status("[bold red]Fetching robots / sitemap…[/bold red]") if RICH_OK else open(os.devnull) as _:
                result = inspect_robots_and_sitemap(target)
            last_result = result; last_name = f"robots_{host_from_input(target)}"
            display_summary("Robots + Sitemap", result); pretty_json(result)

        elif choice == "14":
            target = ask("URL")
            info(f"Probing {len(SAFE_DISCOVERY_PATHS)} paths…")
            result = discover_paths(target)
            last_result = result; last_name = f"paths_{host_from_input(target)}"
            display_summary("Path Discovery", result); pretty_json(result)

        elif choice == "15":
            username = ask("Username to investigate")
            info(f"Hunting [{username}] across {len(USERNAME_PLATFORMS)} platforms…")
            result = username_intelligence(username)
            last_result = result; last_name = f"username_{username}"
            display_username_results(result); pretty_json(result)

        elif choice == "16":
            target    = ask("IP / host / domain / URL")
            pages_raw = ask("Max crawl pages", "8")
            try: max_pages = max(1,min(50,int(pages_raw)))
            except Exception: max_pages = 8
            info("Running full OSINT audit — this may take several minutes…")
            result = combined_audit(target, max_pages=max_pages)
            last_result = result; last_name = f"full_{host_from_input(target)}"
            display_summary("Full Audit", result)
            rating = result.get("security_rating",{})
            if RICH_OK:
                grade = rating.get("grade","?")
                score = rating.get("score","?")
                grade_color = {"A":"green","B":"yellow","C":"yellow","D":"red","F":"bold red"}.get(grade,"white")
                console.print(f"\n  Security Grade: [{grade_color}]{grade}[/{grade_color}]  Score: [bold white]{score}[/bold white]/100")
                for f in rating.get("findings",[]):
                    sev = f["severity"]
                    col = "bold red" if sev=="high" else "yellow" if sev=="medium" else "dim white"
                    console.print(f"  [{col}][{sev.upper()}][/{col}] {f['issue']}")
            pretty_json(result)

        elif choice == "17":
            file_path = ask("Path to targets file", "targets.txt")
            pages_raw = ask("Max crawl pages per target", "5")
            try: max_pages = max(1,min(20,int(pages_raw)))
            except Exception: max_pages = 5
            result = batch_audit(file_path, max_pages=max_pages)
            last_result = result; last_name = "batch_audit"
            display_summary("Batch Audit", result); pretty_json(result)

        elif choice == "18":
            if not last_result: warn("No result yet."); continue
            pretty_json(last_result)

        elif choice == "19":
            if not last_result: warn("No result yet."); continue
            path = save_json_report(last_name, last_result)
            good(f"JSON saved → {path}")

        elif choice == "20":
            if not last_result: warn("No result yet."); continue
            path = save_html_report(last_name, last_result)
            good(f"HTML saved → {path}")

        elif choice == "21":
            if not last_result: warn("No result yet."); continue
            path = save_findings_csv(last_name, last_result)
            good(f"CSV saved → {path}")

        elif choice == "0":
            divider()
            if RICH_OK: console.print("[bold red]◈[/bold red] [white]Exiting SOCIAL HOUND. Stay sharp.[/white]")
            else: print("Exiting.")
            return 0
        else:
            bad(f"Unknown option: {choice}")

if __name__ == "__main__":
    raise SystemExit(main())