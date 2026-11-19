# SEO Growth Core (v1, experimental, no deployment)

Purpose: a shared, low-maintenance SEO growth backlog for existing and future affiliate websites.
This core runs in isolated GitHub Actions runners. It never runs a resident daemon on the VPS.

## Registered sites

- Low Cost Europa: https://www.lowcost-europa.eu (Django, manual catalogue; DO NOT edit links or products)
- Sevelora: https://sevelora.eu (Next.js, Awin feed; DO NOT edit feed or secrets)

The site roster is in ops/seo_growth_sites.json. Each entry must be the canonical HTTPS host
and public XML sitemap, with bounded page count and shopping-related URL patterns.

## What happens when the scheduled job runs

1. Read each public sitemap, and only visit same-origin HTTPS URLs if robots.txt allows it.
2. Audit title, meta description, H1, canonical, noindex, duplicate titles, images and basic link graph.
3. Prioritize site-specific technical corrections and buyer-intent page opportunities.
4. Export JSON/Markdown reports to short-lived GitHub Actions artifacts.
5. Keep **one** GitHub issue per website updated with the current prioritized tasks.

This is proactive monitoring and an actionable backlog, **not an autonomous publisher or a ranking generator**.
There is no claim of increased clicks, impressions or sales. The finding "low text volume" is
a review heuristic, not a Google ranking factor. No invented keyword volume or fabricated analytics.

## Security and operational limits

- No traffic bot, proxies, CTR manipulation, Google SERP scraping or fabricated clicks.
- No external packages, credentials, global installs, paid APIs, GitHub SSH or VPS access.
- HTTP requests only to canonical HTTPS hosts explicitly configured above; no affiliate redirects are followed.
- No changes to live websites, DNS, Search Console, affiliate links, catalogues, robots, sitemap or GitHub main.
- One request at a time, short delay, at most 200 sitemap pages per site and 2 MB per response.
- Reports contain PUBLIC page titles and URLs only; no private catalogue/feed data.
- A missing/invalid robots.txt prevents page crawling, producing a visible warning instead.
- Change this core through an approved PR. Disable workflow schedule to stop all jobs.

## Local test and one-time audit (no extra packages)

    python3 -m unittest discover -s ops/tests -p test_seo_growth_core.py
    python3 ops/seo_growth_core.py --config ops/seo_growth_sites.json --out reports --max-pages 20

The GitHub Actions job schedules a daily run at 07:21 UTC only after the PR is merged.
A manual workflow_dispatch can re-run it once it exists on main.

## Phase 2: actual growth actions (separate approval)

Use read-only Google Search Console data for impressions, queries, click-through rate
and actual country-level demand, where permitted credentials already exist; otherwise
state explicitly that these metrics are unavailable. Choose buyer-intent queries.
Prepare targeted site-specific PRs for original guides, improved internal linking,
commercial CTA clarity and technical fixes. Human review precedes publication.

Measure after release against real GSC, server outbound-affiliate events and actual orders
where accessible. Do not substitute synthetic activity for real buyers. If a new URL is
published, use the site's existing, authorized indexing pipeline; never resend unchanged
URLs or misuse Google's restricted Indexing API.

Future optional acquisition: distribute factual, editorial pages through owned,
consenting channels where an official posting API and permission exist. No unsolicited
group posting or spam automation.

## Existing checks that must NOT be duplicated

Low Cost Europa already has weekly production mobile Lighthouse and a working
sitemap/IndexNow arrangement. Sevelora already has QA for sitemap, robots, canonical
and live layout. This core complements them by analyzing site-wide opportunity
coverage, rather than replacing or restarting their established workflows.
