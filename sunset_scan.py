#!/usr/bin/env python3
"""sunset_scan: find code that calls third-party APIs with a shutdown date.

Covers:
  apple-ads    Apple Ads Campaign Management API v5/v4   sunset 2027-01-26
  google-cse   Google Custom Search JSON API              discontinued 2027-01-01
  ews          Exchange Online EWS                        fully disabled 2027-04-01
  hubspot      HubSpot v1-v4 numbered APIs                unsupported 2027-03 / 2027-09
  keap         Keap (Infusionsoft) XML-RPC                deprecated 2027-03

Usage:
  python3 sunset_scan.py PATH [PATH ...]          scan files/dirs (also log or HAR files)
  python3 sunset_scan.py PATH --md report.md      also write a Markdown report
  python3 sunset_scan.py PATH --json              machine-readable output
  python3 sunset_scan.py PATH --only apple-ads    restrict to one or more packs (comma list)

Standard library only, Python 3.8+. Reads files locally; sends nothing anywhere.
Exit status: 0 nothing found, 1 findings, 2 usage error.
"""
import argparse, datetime as dt, json, os, re, sys

VERSION = "1.0.0"

PACKS = {
    "apple-ads": {
        "name": "Apple Ads Campaign Management API",
        "cutoff": "2027-01-26",
        "hard": True,
        "source": "https://developer.apple.com/documentation/apple_ads/apple-search-ads-campaign-management-api-5",
        "replacement": "Apple Ads Platform API (https://api.ads.apple.com/v1/)",
        "replacement_url": "https://developer.apple.com/documentation/apple-ads-platform-api",
    },
    "google-cse": {
        "name": "Google Custom Search JSON API",
        "cutoff": "2027-01-01",
        "hard": True,
        "source": "https://developers.google.com/custom-search/v1/overview",
        "replacement": "Vertex AI Search (site search) or another search API",
        "replacement_url": "https://cloud.google.com/use-cases/site-search",
    },
    "ews": {
        "name": "Exchange Web Services (Exchange Online)",
        "cutoff": "2027-04-01",
        "hard": True,
        "source": "https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/deprecation-of-ews-exchange-online",
        "replacement": "Microsoft Graph (mail, calendar, contacts)",
        "replacement_url": "https://aka.ms/ews2graphMap",
    },
    "hubspot": {
        "name": "HubSpot numbered-version APIs (v1-v4)",
        "cutoff": "2027-03-30 (v4) / 2027-09 (v1-v3)",
        "hard": False,
        "source": "https://developers.hubspot.com/changelog/legacy-apis-and-legacy-apps-whats-going-unsupported-and-when",
        "replacement": "HubSpot date-based API versions (e.g. 2026-09)",
        "replacement_url": "https://developers.hubspot.com/docs/api-reference/legacy/migration-guide",
    },
    "keap": {
        "name": "Keap (Infusionsoft) XML-RPC API",
        "cutoff": "2027-03-15 (deprecation, no support)",
        "hard": False,
        "source": "https://learn.thryv.com/hc/en-us/articles/41277574163469-Keap-s-XMLRPC-API-Sunset",
        "replacement": "Keap REST v2 (https://api.infusionsoft.com/crm/rest/v2/)",
        "replacement_url": "https://developer.infusionsoft.com/docs/restv2/",
    },
}

# (pack, rule id, regex, message). Order matters only for display.
RULES = [
    # ---------------- Apple Ads ----------------
    ("apple-ads", "host", r"api\.searchads\.apple\.com",
     "Old Apple Ads host. Replace with https://api.ads.apple.com/v1/ (paths change too, see mapping)."),
    ("apple-ads", "path", r"/api/v[2-5]/[A-Za-z{$<:%][^\s\"'`)]*",
     "Campaign Management API path; see suggested Platform API equivalent."),
    ("apple-ads", "context-org", r"X-AP-Context[^\n]{0,80}orgId|orgId=\{?|[\"']orgId=",
     "X-AP-Context now takes adAccountId=<id> (from GET /v1/acls), not orgId."),
    ("apple-ads", "reports", r"reports/campaigns",
     "v5 reports become POST /v1/reports/apps/{campaigns|adgroups|ads|keywords|searchterms}/query with a new request body and response envelope (result.rows[].totalMetrics)."),
    ("apple-ads", "nested", r"targetingkeywords|negativekeywords|creativesets|creative-sets|adgroups/find|campaigns/find|custom-reports",
     "Nested/find-style v5 resource; Platform API uses top-level resources with POST /v1/<resource>/query filters."),
    ("apple-ads", "resource", r"[\"'`]/?(?:campaigns|adgroups|acls|me|budgetorders|creatives|search/apps|search/geo|countries-or-regions|product-page-reasons)(?:[/?{][^\"'`\s]*)?[\"'`]",
     "v5 resource path string; see suggested Platform API equivalent."),
    ("apple-ads", "selector", r"[\"']selector[\"']\s*:|\"conditions\"\s*:",
     "v5 Selector bodies (conditions/orderBy/pagination) become QueryRequest {filters, sorting, pagination}."),
    ("apple-ads", "sdk", r"\bsearchads_api\b|apple-search-ads-go|tap-apple-search-ads|source-apple-search-ads|apple_search_ads|AppleSearchAds|asa-api|searchads-api",
     "Library or connector built on the old API; check its version supports the Platform API before Jan 26, 2027."),
    ("apple-ads", "budget", r"\bbudgetAmount\b|\blifetimeBudget\b",
     "Lifetime budgetAmount was removed (June 2026); use dailyBudgetAmount."),

    # ---------------- Google CSE ----------------
    ("google-cse", "endpoint", r"googleapis\.com/customsearch/v1",
     "Custom Search JSON API endpoint; discontinued for existing customers on Jan 1, 2027."),
    ("google-cse", "client", r"build\(\s*[\"']customsearch[\"']|\.cse\(\)|customsearch_v1|google\.customsearch|CustomsearchService|customsearch\.cse",
     "Custom Search client library call."),
    ("google-cse", "cx", r"[?&]cx=|[\"']cx[\"']\s*:",
     "Programmable Search Engine id (cx) passed to the JSON API."),

    # ---------------- EWS ----------------
    ("ews", "endpoint", r"outlook\.office365\.com/EWS|/EWS/Exchange\.asmx|outlook\.office\.com/EWS",
     "EWS endpoint on Exchange Online; disabled by default since Oct 2026, fully off Apr 1, 2027."),
    ("ews", "sdk", r"Microsoft\.Exchange\.WebServices|\bexchangelib\b|ews-javascript-api|ews-java-api|\bExchangeService\s*\(|microsoft\.exchange\.webservices|php-ews|jamesiarmes|garethp/php-ews|node-ews|\bviewpoint\b.*ews",
     "EWS client library; replace with Microsoft Graph SDK calls."),
    ("ews", "soap", r"schemas\.microsoft\.com/exchange/services/2006",
     "Raw EWS SOAP payload."),
    ("ews", "scope", r"EWS\.AccessAsUser\.All|full_access_as_app|outlook\.office365\.com/\.default",
     "EWS OAuth scope; Graph needs Mail.*/Calendars.* scopes instead."),

    # ---------------- HubSpot ----------------
    ("hubspot", "host", r"api\.hubapi\.com|api\.hubspot\.com",
     "HubSpot API host (anchor; see the version-specific findings)."),
    ("hubspot", "v1-v3-legacy", r"api\.hubapi\.com/(?:contacts|deals|companies|engagements|owners|properties|crm-associations|email|forms|form-integrations|automation|content|blogs|calendar|reports|events|analytics|marketing-emails|cms|broadcast|social|files|crm-pipelines|integrations|webhooks|marketing|conversations|crm-objects|extensions)/v[1-3]\b",
     "Legacy numbered HubSpot endpoint; unsupported after Sept 2027 (marketplace apps lose certification)."),
    ("hubspot", "crm-v3", r"/crm/v3/",
     "HubSpot CRM v3 endpoint; unsupported after Sept 2027. Migrate straight to date-based versions."),
    ("hubspot", "crm-v4", r"/crm/v4/",
     "HubSpot CRM v4 endpoint; unsupported from March 2027."),
    ("hubspot", "hapikey", r"hapikey=|\bhapikey\b",
     "Legacy HubSpot API key (removed 2022); use a private app token or Service Key."),
    ("hubspot", "sdk", r"@hubspot/api-client|hubspot-api-client|\bhubspot3\b|hubspot/api-client|HubSpot\\Factory|hubspot-php",
     "HubSpot SDK; check the version targets date-based APIs."),

    # ---------------- Keap ----------------
    ("keap", "endpoint", r"infusionsoft\.com/(?:crm/)?(?:api/)?xmlrpc|/crm/xmlrpc|api/xmlrpc",
     "Keap XML-RPC endpoint; deprecated, no support from March 2027. Move to REST v2."),
    ("keap", "method", r"\b(?:ContactService|DataService|InvoiceService|OrderService|ProductService|FunnelService|APIEmailService|APIAffiliateService|AffiliateService|AffiliateProgramService|ShippingService|WebFormService|SearchService|FileService|DiscountService|CreditCardSubmissionService|WebTrackingService)\.[a-zA-Z]+",
     "Keap XML-RPC service method; see Keap's XML-RPC to REST v2 mapping guide."),
    ("keap", "sdk", r"\biSDK\b|novaksolutions/infusionsoft|infusionsoft-php-sdk|\binfusionsoft-python\b|\bInfusionsoft\\Infusionsoft\b|isdk\.php|xmlrpc\.client\.ServerProxy\([^)]*infusionsoft",
     "Keap XML-RPC SDK or client."),
    ("keap", "rest-v1", r"crm/rest/v1/",
     "Keap REST v1 (not part of this sunset, but Keap points new work at REST v2)."),
]
COMPILED = [(p, rid, re.compile(rx), msg) for p, rid, rx, msg in RULES]

# Rules that are specific enough on their own. Every other rule only counts when at least one
# anchor of the same pack was found somewhere in the scanned paths (cuts false positives such as
# a generic /api/v5/ path or a "conditions" key in unrelated code).
ANCHORS = {
    "apple-ads": {"host", "sdk"},
    "google-cse": {"endpoint", "client"},
    "ews": {"endpoint", "sdk", "soap", "scope"},
    "hubspot": {"v1-v3-legacy", "hapikey", "sdk", "host"},
    "keap": {"endpoint", "sdk"},
}

# Apple Ads v5 -> Platform API v1 path mapping (first match wins). {m} = HTTP method if known.
APPLE_MAP = [
    (r"reports/campaigns/[^/]+/adgroups/[^/]+/keywords", "POST /v1/reports/apps/keywords/query (filter campaignId, adGroupId)"),
    (r"reports/campaigns/[^/]+/adgroups/[^/]+/searchterms", "POST /v1/reports/apps/searchterms/query (filter campaignId, adGroupId)"),
    (r"reports/campaigns/[^/]+/adgroups", "POST /v1/reports/apps/adgroups/query (filter campaignId)"),
    (r"reports/campaigns/[^/]+/ads", "POST /v1/reports/apps/ads/query (filter campaignId)"),
    (r"reports/campaigns/[^/]+/keywords", "POST /v1/reports/apps/keywords/query (filter campaignId)"),
    (r"reports/campaigns/[^/]+/searchterms", "POST /v1/reports/apps/searchterms/query (filter campaignId)"),
    (r"reports/campaigns", "POST /v1/reports/apps/campaigns/query"),
    (r"custom-reports", "POST /v1/insights/apps/impression-share/query"),
    (r"targetingkeywords/delete/bulk", "POST /v1/keywords/bulk-delete"),
    (r"negativekeywords/delete/bulk", "POST /v1/negative-keywords/bulk-delete"),
    (r"targetingkeywords/bulk", "POST /v1/keywords/bulk-create (POST) or /v1/keywords/bulk-update (PUT)"),
    (r"negativekeywords/bulk", "POST /v1/negative-keywords/bulk-create (POST) or /bulk-update (PUT)"),
    (r"targetingkeywords/find", "POST /v1/keywords/query"),
    (r"negativekeywords/find", "POST /v1/negative-keywords/query"),
    (r"targetingkeywords/[^/\s\"']+", "GET|PUT|DELETE /v1/keywords/{id}"),
    (r"targetingkeywords", "POST /v1/keywords/query (filter adGroupId)"),
    (r"negativekeywords/[^/\s\"']+", "GET|PUT|DELETE /v1/negative-keywords/{id}"),
    (r"negativekeywords", "POST /v1/negative-keywords/query (filter campaignId or adGroupId)"),
    (r"(?:campaigns/[^/]+/)?ads/find", "POST /v1/ads/query"),
    (r"adgroups/[^/]+/ads/[^/\s\"']+", "GET|PUT|DELETE /v1/ads/{id}"),
    (r"adgroups/[^/]+/ads", "POST /v1/ads (create) or POST /v1/ads/query (filter adGroupId)"),
    (r"adgroups/find", "POST /v1/adgroups/query"),
    (r"campaigns/[^/]+/adgroups/[^/\s\"']+", "GET|PUT|DELETE /v1/adgroups/{id}"),
    (r"campaigns/[^/]+/adgroups", "POST /v1/adgroups (create) or POST /v1/adgroups/query (filter campaignId)"),
    (r"campaigns/find", "POST /v1/campaigns/query"),
    (r"campaigns/[^/\s\"']+", "GET|PUT|DELETE /v1/campaigns/{id}"),
    (r"campaigns", "POST /v1/campaigns (create) or POST /v1/campaigns/query (list)"),
    (r"creativesets|creative-sets", "Removed (creative sets were deprecated); use creatives + ads"),
    (r"creatives/find", "POST /v1/creatives/query"),
    (r"creatives", "/v1/creatives, /v1/creatives/{id}, POST /v1/creatives/query"),
    (r"apps/[^/]+/eligibilities/find", "POST /v1/eligibilities/apps/query"),
    (r"apps/[^/]+/product-pages", "POST /v1/product-pages/query, GET /v1/product-pages/{id}"),
    (r"apps/[^/]+/locale-details", "POST /v1/apps/{adamId}/locale-details/query"),
    (r"apps/[^/]+/assets/find", "No direct equivalent; ads use product pages (check docs)"),
    (r"product-page-reasons", "POST /v1/rejection-reasons/apps/query"),
    (r"budgetorders", "Budget orders are org-scoped in the Platform API (see budget-orders-endpoints)"),
    (r"search/apps", "GET /v1/search/apps"),
    (r"search/geo", "GET|POST /v1/search/geo"),
    (r"countries-or-regions", "Check Platform API CampaignTargeting values"),
    (r"acls", "GET /v1/acls (now also returns ad accounts)"),
    (r"\bme\b", "GET /v1/me"),
]
APPLE_MAP = [(re.compile(rx), out) for rx, out in APPLE_MAP]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", ".idea", ".gradle",
             "target", "Pods", "bower_components", ".terraform"}
DOC_EXT = {".md", ".rst", ".txt", ".adoc", ".html"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".jar",
           ".class", ".so", ".dylib", ".dll", ".exe", ".woff", ".woff2", ".ttf", ".mp4", ".mp3",
           ".pyc", ".o", ".a", ".lock", ".min.js", ".map", ".sqlite", ".db", ".bin"}
MAX_BYTES = 2_000_000
MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "package.json",
             "go.mod", "composer.json", "gemfile", "pom.xml", "build.gradle", "build.gradle.kts",
             "meltano.yml", "packages.config", "cargo.toml", "podfile", "package.swift"}
IMPORT_LINE = re.compile(r"^\s*(?:import\b|from\s+\S+\s+import\b|using\s|use\s|require[\s(]|.*\brequire\(|.*\bimport\(|#include|<PackageReference)")


APPLE_REL = re.compile(r"(?:reports/campaigns|custom-reports|campaigns|adgroups|creativesets|creatives|apps/|budgetorders|product-page-reasons|search/(?:apps|geo)|countries-or-regions|acls\b|ads/find)[^\s\"'`)?]*")


def apple_suggest(text):
    m = re.search(r"/api/v[2-5]/([^\s\"'`)?]+)", text)
    if m:
        path = m.group(1)
    else:
        m = APPLE_REL.search(text)
        if not m:
            return None
        path = m.group(0)
    for rx, out in APPLE_MAP:
        if rx.search(path):
            return out
    return None


def iter_files(paths):
    for root in paths:
        if os.path.isfile(root):
            yield root
            continue
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") or x in (".github",)]
            for f in files:
                yield os.path.join(d, f)


def scan_file(path, packs):
    low = path.lower()
    if any(low.endswith(e) for e in BIN_EXT):
        return []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    if b"\0" in raw[:4096]:
        return []
    text = raw.decode("utf-8", "replace")
    doc = os.path.splitext(low)[1] in DOC_EXT
    base = os.path.basename(low)
    manifest = base in MANIFESTS or base.startswith("requirements") or base.endswith(".csproj")
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for pack, rid, rx, msg in COMPILED:
            if pack not in packs:
                continue
            m = rx.search(line)
            if not m:
                continue
            if rid == "sdk" and not (manifest or IMPORT_LINE.match(line)):
                continue
            h = {"pack": pack, "rule": rid, "file": path, "line": n, "match": m.group(0)[:160],
                 "code": line.strip()[:240], "message": msg, "docs_only": doc}
            if pack == "apple-ads" and rid in ("path", "host", "reports", "nested", "resource"):
                s = apple_suggest(line)
                if s:
                    h["suggest"] = s
            hits.append(h)
    return dedupe(hits)


def dedupe(hits):
    """One finding per (file, line, pack); keep the most specific rule, list the others in 'also'."""
    pri = {"path": 0, "endpoint": 0, "reports": 1, "method": 1, "nested": 2, "resource": 3, "sdk": 8, "host": 9}
    groups = {}
    for h in hits:
        groups.setdefault((h["file"], h["line"], h["pack"]), []).append(h)
    out = []
    for hs in groups.values():
        hs.sort(key=lambda h: pri.get(h["rule"], 5))
        best = dict(hs[0])
        if not best.get("suggest"):
            best["suggest"] = next((h["suggest"] for h in hs if h.get("suggest")), None)
        if best.get("suggest") is None:
            best.pop("suggest", None)
        others = [h for h in hs[1:] if h["rule"] != best["rule"]]
        if others:
            best["also"] = [{"rule": h["rule"], "message": h["message"]} for h in others]
        out.append(best)
    return out


def is_anchor(f):
    a = ANCHORS[f["pack"]]
    return f["rule"] in a or any(x["rule"] in a for x in f.get("also", []))


PATH_HINTS = {
    "apple-ads": re.compile(r"apple|searchads|search_ads|search-ads|(^|[/_.-])asa([/_.-]|$)", re.I),
    "google-cse": re.compile(r"customsearch|custom_search|(^|[/_.-])cse([/_.-]|$)", re.I),
    "ews": re.compile(r"(^|[/_.-])ews([/_.-]|$)|exchange", re.I),
    "hubspot": re.compile(r"hubspot", re.I),
    "keap": re.compile(r"keap|infusion", re.I),
}


def apply_anchors(findings):
    """Keep anchor findings. Keep generic findings only in a file that has an anchor for the same
    pack, or whose path names the vendor (e.g. tap_apple_search_ads/streams.py), and only if the
    pack is anchored somewhere in the scan. Stops multi-connector repos from flooding."""
    files, packs = set(), set()
    for f in findings:
        if is_anchor(f):
            files.add((f["pack"], f["file"])); packs.add(f["pack"])
    return [f for f in findings if is_anchor(f) or (f["file"] and (f["pack"], f["file"]) in files)
            or (f["pack"] in packs and PATH_HINTS[f["pack"]].search(f["file"]))]


def size_tier(n_code, n_files):
    if n_code == 0:
        return "none"
    if n_code <= 15 and n_files <= 4:
        return "small"
    if n_code <= 60 and n_files <= 15:
        return "medium"
    return "large"


def summarise(findings, packs):
    today = dt.date.today()
    out = []
    for p in packs:
        fs = [f for f in findings if f["pack"] == p]
        if not fs:
            continue
        code = [f for f in fs if not f["docs_only"] and f["rule"] != "sdk"]
        files = sorted({f["file"] for f in code})
        info = PACKS[p]
        try:
            days = (dt.date.fromisoformat(info["cutoff"][:10]) - today).days
        except ValueError:
            days = None
        out.append({"pack": p, **info, "days_left": days, "findings": len(fs), "code_findings": len(code),
                    "files": len(files), "size": size_tier(len(code), len(files))})
    return out


def render_text(summary, findings, root):
    lines = [f"sunset_scan {VERSION}: {root}", ""]
    if not findings:
        lines.append("No calls to the covered sunsetting APIs found.")
        return "\n".join(lines)
    for s in summary:
        when = f"{s['days_left']} days left" if s["days_left"] is not None else ""
        hard = "HARD CUTOFF" if s["hard"] else "soft (unsupported)"
        lines.append(f"== {s['name']}: {s['cutoff']} [{hard}] {when}")
        lines.append(f"   {s['code_findings']} code findings in {s['files']} files (+{s['findings']-s['code_findings']} in docs/dependency lines); size: {s['size']}")
        lines.append(f"   Replacement: {s['replacement']}")
        for f in sorted((f for f in findings if f["pack"] == s["pack"]), key=lambda f: (f["docs_only"], f["file"], f["line"])):
            tag = " (docs)" if f["docs_only"] else ""
            lines.append(f"   {f['file']}:{f['line']}{tag}  [{f['rule']}]  {f['code'][:120]}")
            if f.get("suggest"):
                lines.append(f"      -> {f['suggest']}")
        lines.append("")
    return "\n".join(lines)


def render_md(summary, findings, root):
    md = [f"# API sunset scan: `{root}`", "", f"Generated {dt.date.today().isoformat()} by sunset_scan {VERSION}.", ""]
    if not findings:
        md.append("No calls to the covered sunsetting APIs were found.")
        return "\n".join(md) + "\n"
    md += ["| API | Cutoff | Hard? | Days left | Code findings | Files | Size |", "|---|---|---|---|---|---|---|"]
    for s in summary:
        md.append(f"| {s['name']} | {s['cutoff']} | {'yes' if s['hard'] else 'no'} | {s['days_left']} | {s['code_findings']} | {s['files']} | {s['size']} |")
    for s in summary:
        md += ["", f"## {s['name']}", "", f"Source: {s['source']}  ", f"Replacement: [{s['replacement']}]({s['replacement_url']})", "",
               "| Location | Rule | Code | Suggested change |", "|---|---|---|---|"]
        for f in sorted((f for f in findings if f["pack"] == s["pack"]), key=lambda f: (f["docs_only"], f["file"], f["line"])):
            code = f["code"][:100].replace("|", "\\|").replace("`", "'")
            sug = " ".join([f.get("suggest") or f["message"]] + [a["message"] for a in f.get("also", []) if a["rule"] in ("context-org", "hapikey", "budget")]).replace("|", "\\|")
            md.append(f"| `{f['file']}:{f['line']}`{' (docs)' if f['docs_only'] else ''} | {f['rule']} | `{code}` | {sug} |")
    return "\n".join(md) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find calls to third-party APIs that are being shut down.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--only", help="comma list of packs: " + ",".join(PACKS))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--md", metavar="FILE", help="write a Markdown report")
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("--export-rules", action="store_true", help=argparse.SUPPRESS)
    if argv is None:
        argv = sys.argv[1:]
    if "--export-rules" in argv:  # for the browser checker: same rules, same mapping
        print(json.dumps({"version": VERSION, "packs": PACKS,
                          "rules": [{"pack": p, "id": r, "re": rx, "msg": m} for p, r, rx, m in RULES],
                          "anchors": {k: sorted(v) for k, v in ANCHORS.items()},
                          "apple_map": [[rx.pattern, out] for rx, out in APPLE_MAP],
                          "apple_rel": APPLE_REL.pattern,
                          "path_hints": {k: v.pattern for k, v in PATH_HINTS.items()}}, indent=1))
        return 0
    a = ap.parse_args(argv)
    packs = list(PACKS) if not a.only else [p.strip() for p in a.only.split(",")]
    bad = [p for p in packs if p not in PACKS]
    if bad:
        print(f"unknown pack(s): {', '.join(bad)}", file=sys.stderr)
        return 2
    for p in a.paths:
        if not os.path.exists(p):
            print(f"no such path: {p}", file=sys.stderr)
            return 2
    findings = []
    for f in iter_files(a.paths):
        findings += scan_file(f, set(packs))
    findings = apply_anchors(findings)
    summary = summarise(findings, packs)
    root = " ".join(a.paths)
    if a.json:
        print(json.dumps({"version": VERSION, "summary": summary, "findings": findings}, indent=2))
    else:
        print(render_text(summary, findings, root))
    if a.md:
        with open(a.md, "w") as fh:
            fh.write(render_md(summary, findings, root))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
