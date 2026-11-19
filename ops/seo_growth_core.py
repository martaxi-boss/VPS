#!/usr/bin/env python3
"""Small, bounded, read-only SEO growth core for owned websites.

No synthetic traffic, search-engine scraping, or site mutations.
Only public same-host pages listed in each site's public sitemap are fetched.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser
import xml.etree.ElementTree as ET

AGENT = "SEO-Growth-Core/1.0 (read-only sitemap audit; repository martaxi-boss/VPS)"
MAX_BYTES = 2_000_000
TIMEOUT = 12
SEVERITY = {"critical": 0, "important": 1, "opportunity": 2}


def origin_host(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Only HTTPS public site addresses are permitted")
    return parts.hostname.lower()


def safe_url(raw: str, host: str, base: str = "") -> str | None:
    url = urljoin(base, raw)
    parsed = urlsplit(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != host:
        return None
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        return None
    if not parsed.path.startswith("/"):
        return None
    return urlunsplit(("https", parsed.netloc.lower(), parsed.path or "/", "", ""))


def comparable(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.scheme.lower() + "://" + parsed.netloc.lower()
            + (parsed.path.rstrip("/") or "/"))


def get(url: str) -> tuple[int, str, bytes, str]:
    req = Request(url, headers={"User-Agent": AGENT, "Accept": "text/html,application/xml,text/xml,text/plain"})
    with urlopen(req, timeout=TIMEOUT) as response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("Response exceeds safe size cap")
        return response.status, response.geturl(), body, response.headers.get("Content-Type", "")


def xml_locs(data: bytes) -> tuple[str, list[str]]:
    root = ET.fromstring(data)
    tag = root.tag.rsplit("}", 1)[-1]
    if tag not in ("urlset", "sitemapindex"):
        raise ValueError("Unsupported sitemap XML root")
    urls = []
    for entry in root:
        for child in entry:
            if child.tag.rsplit("}", 1)[-1] == "loc" and child.text:
                urls.append(child.text.strip())
                break
    return tag, urls


def list_sitemap(sitemap: str, host: str) -> list[str]:
    pending = [sitemap]
    seen_sitemaps = set()
    pages = []
    seen_pages = set()
    while pending and len(seen_sitemaps) < 8:
        candidate = pending.pop(0)
        if candidate in seen_sitemaps:
            continue
        seen_sitemaps.add(candidate)
        _, target, body, _ = get(candidate)
        if safe_url(target, host) is None:
            raise ValueError("Cross-host sitemap redirect rejected")
        kind, found = xml_locs(body)
        for raw in found:
            url = safe_url(raw, host)
            if url is None:
                continue
            if kind == "sitemapindex":
                if url not in seen_sitemaps and url not in pending:
                    pending.append(url)
            elif url not in seen_pages:
                pages.append(url)
                seen_pages.add(url)
    if not pages:
        raise ValueError("No same-host URLs found in the sitemap")
    return pages


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_fragments: list[str] = []
        self.h1: list[str] = []
        self._h1_fragments: list[str] | None = None
        self.description = ""
        self.robots = ""
        self.canonical = ""
        self.links: list[str] = []
        self.text: list[str] = []
        self._title = False
        self._hidden = 0
        self.image_count = 0
        self.missing_image_alt = 0
        self.structured_data = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {key.lower(): (value or "") for key, value in attrs}
        if tag in ("script", "style", "noscript"):
            self._hidden += 1
            if tag == "script" and a.get("type", "").lower() == "application/ld+json":
                self.structured_data = True
        if tag == "title":
            self._title = True
        if tag == "h1":
            self._h1_fragments = []
        if tag == "meta":
            if a.get("name", "").lower() == "description":
                self.description = a.get("content", "")
            if a.get("name", "").lower() in ("robots", "googlebot"):
                self.robots += " " + a.get("content", "")
        if tag == "link" and "canonical" in a.get("rel", "").lower().split():
            self.canonical = a.get("href", "")
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "img":
            self.image_count += 1
            if not a.get("alt", "").strip():
                self.missing_image_alt += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._title = False
        if tag == "h1" and self._h1_fragments is not None:
            self.h1.append(" ".join("".join(self._h1_fragments).split()))
            self._h1_fragments = None
        if tag in ("script", "style", "noscript"):
            self._hidden = max(0, self._hidden - 1)

    def handle_data(self, data: str) -> None:
        if self._title:
            self.title_fragments.append(data)
        if self._h1_fragments is not None:
            self._h1_fragments.append(data)
        if not self._hidden:
            self.text.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_fragments).split())

    @property
    def word_count(self) -> int:
        return len(re.findall(r"\w+", " ".join(self.text), re.UNICODE))


def robot_policy(home: str, host: str) -> tuple[RobotFileParser | None, str | None]:
    try:
        code, final, raw, _ = get(home.rstrip("/") + "/robots.txt")
        if code != 200 or safe_url(final, host) is None:
            return None, "robots.txt unavailable"
        parser = RobotFileParser()
        parser.parse(raw.decode("utf-8", errors="replace").splitlines())
        return parser, None
    except (HTTPError, URLError, TimeoutError, ValueError):
        return None, "robots.txt unavailable; crawl safety cannot be confirmed"


def add(items: list[dict], level: str, url: str, problem: str, recommendation: str) -> None:
    items.append({"level": level, "url": url, "problem": problem, "recommendation": recommendation})


def audit(site: dict, page_cap_override: int | None = None, pause: float = 0.15) -> dict:
    name = site["id"]
    home = site["home"].rstrip("/")
    host = origin_host(home)
    sitemap = site["sitemap"]
    if safe_url(sitemap, host) != sitemap:
        raise ValueError("Sitemap must use the site HTTPS host")
    max_pages = min(200, page_cap_override or int(site.get("max_pages", 180)))
    pages = list_sitemap(sitemap, host)
    robots, robots_warning = robot_policy(home, host)
    records = []
    findings: list[dict] = []
    if robots_warning:
        add(findings, "important", home, robots_warning, "Inspect public robots.txt before relying on this scan")
    for url in pages[:max_pages]:
        if robots is None:
            # No unrestricted crawler behavior if robots policy cannot be checked.
            continue
        if not robots.can_fetch(AGENT, url):
            add(findings, "important", url, "robots.txt disallows this audit user-agent", "Verify intentional crawler exclusions")
            continue
        try:
            status, final_url, html, content_type = get(url)
            if safe_url(final_url, host) is None:
                add(findings, "critical", url, "Page redirects outside the canonical host", "Review the redirect and its canonical")
                continue
            if status != 200:
                add(findings, "critical", url, f"HTTP {status}", "Restore or remove the broken URL from the sitemap")
                continue
            if "html" not in content_type.lower():
                add(findings, "important", url, "Sitemap URL is not HTML", "Check page content type")
                continue
            parser = PageParser()
            parser.feed(html.decode("utf-8", errors="replace"))
            rec = {
                "url": url, "title": parser.title, "description": parser.description,
                "canonical": parser.canonical, "h1": parser.h1,
                "robots": parser.robots, "words": parser.word_count,
                "missing_image_alt": parser.missing_image_alt,
                "structured_data": parser.structured_data,
                "outbound_internal": sorted({s for href in parser.links if
                    (s := safe_url(href, host, url)) is not None}),
            }
            records.append(rec)
            if not rec["title"]:
                add(findings, "critical", url, "Missing HTML title", "Write a unique, descriptive title")
            if "noindex" in rec["robots"].lower():
                add(findings, "critical", url, "Noindex present on a sitemap page", "Confirm indexing is intended; remove contradictory metadata if accidental")
            canonical = safe_url(rec["canonical"], host, url) if rec["canonical"] else None
            if not canonical or comparable(canonical) != comparable(url):
                add(findings, "important", url, "Canonical missing or not self-referencing", "Review canonical versus the declared sitemap URL")
            if not rec["description"]:
                add(findings, "important", url, "Missing meta description", "Write a useful, non-duplicated description")
            if len(rec["h1"]) != 1:
                add(findings, "important", url, f"{len(rec['h1'])} H1 headings", "Review the primary page heading")
            if rec["missing_image_alt"] > 0:
                add(findings, "opportunity", url, "Some images lack alt text", "Add factual alternative text to meaningful images")
            if rec["words"] < 100:
                add(findings, "opportunity", url, "Low visible text volume (heuristic, not a ranking score)", "Check whether the page offers distinctive guidance for shoppers")
        except (HTTPError, URLError, TimeoutError, ValueError) as ex:
            add(findings, "critical", url, f"Fetch failed ({type(ex).__name__})", "Verify live availability and server logs")
        if pause > 0:
            time.sleep(pause)

    counts = Counter(record["title"].strip().casefold() for record in records if record["title"])
    by_url = {record["url"]: record for record in records}
    inbound = Counter()
    for record in records:
        for dest in record["outbound_internal"]:
            if dest in by_url and comparable(dest) != comparable(record["url"]):
                inbound[dest] += 1
    for record in records:
        if record["title"] and counts[record["title"].strip().casefold()] > 1:
            add(findings, "important", record["url"], "Duplicate title among scanned pages", "Differentiate page title and search intent")
        if inbound[record["url"]] == 0 and len(records) > 2 and comparable(record["url"]) != comparable(home):
            add(findings, "opportunity", record["url"], "No incoming links from scanned sitemap pages", "Add a relevant contextual internal link; validate against complete crawl")

    # Suggestions are based on observed public pages, not invented search volume.
    candidate_paths = site.get("focus_path_contains", [])
    commercial = [r for r in records if any(p in urlsplit(r["url"]).path for p in candidate_paths)]
    commercial.sort(key=lambda r: (inbound[r["url"]], r["words"]))
    ideas = [
        {"url": r["url"], "title": r["title"], "incoming_links": inbound[r["url"]],
         "suggestion": "Review buyer-intent coverage and add original comparison/selection advice plus contextual internal links"}
        for r in commercial[:5]
    ]
    findings.sort(key=lambda x: (SEVERITY[x["level"]], x["url"], x["problem"]))
    return {
        "site": name, "home": home, "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "sitemap_urls": len(pages), "pages_scanned": len(records),
        "pages_skipped": min(len(pages), max_pages) - len(records),
        "partial_scan": len(pages) > max_pages or robots is None,
        "findings": findings, "growth_opportunities": ideas,
        "limits": "Public on-page audit only: not Search Console index coverage, rankings, sales, or unique visitors.",
    }


def markdown(report: dict) -> str:
    f = report["findings"]
    tally = Counter(x["level"] for x in f)
    out = [
        f"# SEO Growth Core - {report['site']}",
        "", f"Checked (UTC): {report['checked_at_utc']}",
        f"Sitemap: {report['sitemap_urls']} URLs | audited: {report['pages_scanned']} | skipped: {report['pages_skipped']}",
        f"Findings: critical {tally['critical']} | important {tally['important']} | opportunities {tally['opportunity']}",
        "", "**Important:** This does not measure Google rank, organic clicks or purchases.",
        "It does not generate fake users, scrape SERPs, or modify a live site.", "",
        "## Highest-priority corrections", "",
    ]
    if not f:
        out.append("No issues detected in this bounded audit.")
    for item in f[:20]:
        out.append(f"- **{item['level'].upper()}** [{item['url']}]({item['url']}): {item['problem']}. "
                   f"Next: {item['recommendation']}.")
    out.extend(["", "## Buyer-intent improvement queue", ""])
    for idea in report["growth_opportunities"]:
        out.append(f"- [{idea['title'] or idea['url']}]({idea['url']}): {idea['suggestion']} "
                   f"(sampled inbound links: {idea['incoming_links']}).")
    if not report["growth_opportunities"]:
        out.append("No matching commercial pages in the sampled sitemap pages.")
    out.extend(["", "## Next autonomous phase", "",
        "1. Read real Google Search Console query/page data when a permitted read-only connector exists.",
        "2. Prepare targeted content/internal-link PRs for explicit review; never mass-publish unverified claims.",
        "3. Track impact using impressions, qualified clicks and outbound affiliate clicks, not bot visits.",
        "", f"Coverage caveat: {report['limits']}", ""])
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-pages", type=int, default=None)
    parser.add_argument("--pause", type=float, default=0.15)
    args = parser.parse_args()
    if args.max_pages is not None and not 1 <= args.max_pages <= 200:
        parser.error("--max-pages must be in 1..200")
    if not 0 <= args.pause <= 5:
        parser.error("--pause must be in 0..5")
    sites = json.loads(Path(args.config).read_text(encoding="utf-8"))
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    for site in sites["sites"]:
        name = site["id"]
        try:
            result = audit(site, args.max_pages, args.pause)
        except (ValueError, HTTPError, URLError, TimeoutError, ET.ParseError) as ex:
            failures += 1
            result = {"site": name, "home": site["home"],
                      "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                      "sitemap_urls": 0, "pages_scanned": 0, "pages_skipped": 0,
                      "partial_scan": True, "findings": [{"level": "critical",
                      "url": site["home"], "problem": f"Site audit failed ({type(ex).__name__})",
                      "recommendation": "Check sitemap and hosting"}],
                      "growth_opportunities": [],
                      "limits": "Audit failed. This result says nothing about ranking or indexation."}
        (output_dir / f"{name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (output_dir / f"{name}.md").write_text(markdown(result), encoding="utf-8")
        print(f"{name}: pages={result['pages_scanned']} findings={len(result['findings'])}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
