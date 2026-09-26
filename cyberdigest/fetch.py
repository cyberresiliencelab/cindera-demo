"""Fetch and normalise items from all configured RSS/Atom feeds."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import json as _json
from urllib.request import Request, urlopen

import feedparser

# A real browser UA — many feeds (Cloudflare/Feedburner-fronted) 403 a bot UA.
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_HDRS = {
    "User-Agent": _UA,
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, text/html, */*",
    "Accept-Language": "en-US,en;q=0.9",
}


def _http_get(url: str, timeout: int = 25, tries: int = 3) -> bytes:
    """Fetch bytes with a browser UA and simple backoff retries."""
    last: Exception | None = None
    for i in range(tries):
        try:
            with urlopen(Request(url, headers=_HDRS), timeout=timeout) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.2 * (i + 1))
    raise last if last else RuntimeError("unreachable")


# ---- Malicious-link screening (runs on every build) --------------------------
# Drops the common signals of an injected / malicious / spam link before the item
# is ever shown. This is heuristic, not a reputation service — real domain
# reputation needs an API (e.g. Google Safe Browsing); see _reputation_ok hook.
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
               "cutt.ly", "is.gd", "rb.gy", "rebrand.ly", "shorturl.at", "adf.ly"}
_BAD_EXT = re.compile(r"\.(exe|apk|scr|msi|bat|cmd|dll|jar|vbs|ps1|hta|iso)(\?|#|$)", re.I)
_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _safe_link(link: str) -> bool:
    """True if the link is safe to surface. Conservative: only rejects on strong
    malicious signals so legitimate off-domain links are not dropped."""
    if not link:
        return False
    try:
        p = urlparse(link)
    except Exception:  # noqa: BLE001
        return False
    if p.scheme not in ("http", "https"):
        return False
    netloc = p.netloc.lower()
    if "@" in netloc:                      # credentials embedded in URL
        return False
    host = netloc.split(":")[0]
    if not host or "." not in host:
        return False
    if _IP_HOST.match(host):               # raw IP address host
        return False
    if host.startswith("xn--") or ".xn--" in host:  # punycode / lookalike
        return False
    reg = ".".join(host.split(".")[-2:])
    if reg in _SHORTENERS:                  # masked destination
        return False
    if _BAD_EXT.search(p.path or ""):       # direct executable download
        return False
    return True


@dataclass
class Item:
    title: str
    link: str
    summary: str
    source: str
    tier: str
    weight: float
    published: datetime
    score: float = 0.0
    severity: str = "info"
    category: str = "news"  # display bucket: advisories | intel | health | news
    tags: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return urlparse(self.link).netloc.replace("www.", "")

    def key(self) -> str:
        """Dedup key: normalised title is the strongest signal across sources."""
        norm = re.sub(r"[^a-z0-9 ]", "", self.title.lower()).strip()
        norm = re.sub(r"\s+", " ", norm)
        return hashlib.sha1(norm.encode()).hexdigest()


_HTML = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _clean(text: str, limit: int = 600) -> str:
    text = _HTML.sub(" ", text or "")
    text = _WS.sub(" ", text).strip()
    return text[:limit].rsplit(" ", 1)[0] + "…" if len(text) > limit else text


def _parse_date(entry) -> datetime:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            return datetime.fromtimestamp(time.mktime(val), tz=timezone.utc)
    return datetime.now(timezone.utc)  # undated → treat as now, ranking handles it


def fetch_source(src: dict, since: datetime) -> list[Item]:
    """Fetch one source. Never raises — a dead feed must not kill the run.
    Tries the primary URL then an optional fallback_url, with retries."""
    items: list[Item] = []
    raw_bytes: bytes | None = None
    for url in (src["url"], src.get("fallback_url")):
        if not url:
            continue
        try:
            raw_bytes = _http_get(url)
            break
        except Exception as exc:  # noqa: BLE001 - resilience over precision
            print(f"  ! {src['name']}: fetch failed on {url} ({exc})")
    if raw_bytes is None:
        return items

    parsed = feedparser.parse(raw_bytes)
    if getattr(parsed, "bozo", 0) and not parsed.entries:
        print(f"  ! {src['name']}: unreadable feed, skipping")
        return items

    dropped = 0
    for e in parsed.entries:
        pub = _parse_date(e)
        if pub < since:
            continue
        title = _WS.sub(" ", (e.get("title") or "").strip())
        link = e.get("link") or ""
        if not title or not link:
            continue
        if not _safe_link(link):            # daily malicious-link screen
            dropped += 1
            continue
        items.append(
            Item(
                title=title,
                link=link,
                summary=_clean(e.get("summary", "") or e.get("description", "")),
                source=src["name"],
                tier=src.get("tier", "news"),
                weight=float(src.get("weight", 1.0)),
                published=pub,
                category=src.get("category", src.get("tier", "news")),
            )
        )
    tail = f" ({dropped} unsafe dropped)" if dropped else ""
    print(f"  · {src['name']}: {len(items)} in window{tail}")
    return items


def fetch_cisa_kev(src: dict, since: datetime) -> list[Item]:
    """CISA Known Exploited Vulnerabilities — JSON only since RSS was retired.
    Every entry is, by definition, actively exploited → forced high priority."""
    items: list[Item] = []
    try:
        req = Request(src["url"], headers={"User-Agent": _UA})
        with urlopen(req, timeout=30) as r:
            data = _json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        print(f"  ! {src['name']}: fetch failed ({exc})")
        return items

    for v in data.get("vulnerabilities", []):
        try:
            pub = datetime.fromisoformat(v["dateAdded"]).replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001
            pub = datetime.now(timezone.utc)
        if pub < since:
            continue
        cve = v.get("cveID", "")
        name = v.get("vulnerabilityName", "").strip()
        vendor = " ".join(x for x in (v.get("vendorProject", ""), v.get("product", "")) if x)
        title = f"{cve}: {name}" if name else f"{cve}: {vendor}".strip(": ")
        summary = _clean(f"{v.get('shortDescription', '')} "
                         f"Required action: {v.get('requiredAction', '')}")
        it = Item(
            title=title or cve,
            link=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else src["url"],
            summary=summary,
            source=src["name"],
            tier="advisory",
            weight=float(src.get("weight", 2.0)),
            published=pub,
            category=src.get("category", "advisories"),
        )
        it.tags = [cve] if cve else []
        if v.get("knownRansomwareCampaignUse", "").lower() == "known":
            it.tags.append("ransomware")
        it.tags.append("actively exploited")  # rank.py escalates this to critical
        items.append(it)
    print(f"  · {src['name']}: {len(items)} in window")
    return items


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _parse_threatfox(text: str, limit: int) -> list[dict]:
    """Parse abuse.ch ThreatFox 'recent' CSV into hash IOCs: value, type,
    malware family (threat), any CVE, and a link to the IOC page."""
    import csv
    import io
    rows = [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]
    out: list[dict] = []
    for rec in csv.reader(io.StringIO("\n".join(rows))):
        # first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware,
        # malware_alias, malware_printable, confidence, reference, tags, ...
        if len(rec) < 8:
            continue
        ioc_type = rec[3].strip().lower()
        if not ioc_type.endswith("_hash"):
            continue
        ioc_id = rec[1].strip()
        value = rec[2].strip()
        malware = (rec[7] or rec[5] or "Unknown").strip()
        tags = rec[10] if len(rec) > 10 else ""
        m = _CVE_RE.search(f"{tags} {malware}")
        out.append({
            "hash": value,
            "htype": ioc_type.replace("_hash", "").upper(),
            "malware": malware,
            "cve": m.group(0).upper() if m else "",
            "link": f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else "https://threatfox.abuse.ch/",
        })
        if len(out) >= limit:
            break
    return out


def fetch_iocs(limit: int = 40) -> list[dict]:
    """Recent malware hash IOCs from abuse.ch ThreatFox (free, no key).
    Never raises — an unreachable IOC feed just yields an empty hash panel."""
    url = "https://threatfox.abuse.ch/export/csv/recent/"
    try:
        text = _http_get(url, timeout=30).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! ThreatFox IOCs: fetch failed ({exc})")
        return []
    iocs = _parse_threatfox(text, limit)
    print(f"  · ThreatFox IOCs: {len(iocs)} hashes")
    return iocs


_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")


def rescan_hashes(items: list[Item], limit: int = 12) -> list[dict]:
    """For feeds that don't publish hashes in their RSS, fetch the article page
    (bounded) and extract file hashes. Prioritises intel/advisory items whose
    summary has no hash. Never raises; each fetch is best-effort."""
    out: list[dict] = []
    tried = 0
    for it in items:
        if tried >= limit:
            break
        if it.tier not in ("intel", "advisory"):
            continue
        if _HASH_RE.search(it.summary or ""):
            continue  # RSS already had a hash
        tried += 1
        try:
            html = _http_get(it.link, timeout=20).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        text = _HTML.sub(" ", html)
        cve = _CVE_RE.search(it.title + " " + text)
        for h in dict.fromkeys(_HASH_RE.findall(text)):   # unique, ordered
            kind = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "")
            out.append({"hash": h, "htype": kind, "malware": it.source,
                        "cve": cve.group(0).upper() if cve else "", "link": it.link})
    if out:
        print(f"  · Article rescan: {len(out)} hashes from {tried} pages")
    return out


def dedupe(items: list[Item]) -> list[Item]:
    """Collapse the same story reported by multiple outlets, keeping the
    highest-weight source and remembering the others for cross-referencing."""
    best: dict[str, Item] = {}
    for it in items:
        k = it.key()
        if k not in best or it.weight > best[k].weight:
            # preserve any already-collected corroborating sources
            if k in best:
                it.tags = list(set(it.tags) | set(best[k].tags))
            best[k] = it
    return list(best.values())


def window_start(period: str, now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return {
        "daily": now - timedelta(days=1),
        "weekly": now - timedelta(days=7),
        "monthly": now - timedelta(days=31),
        "interim": now - timedelta(hours=6),  # rapid check for breaking items
    }.get(period, now - timedelta(days=1))


def collect(sources: list[dict], period: str) -> list[Item]:
    since = window_start(period)
    print(f"Fetching {len(sources)} sources since {since:%Y-%m-%d %H:%M UTC} ({period})")
    raw: list[Item] = []
    for src in sources:
        if src.get("format") in ("json_kev", "cisa_kev"):
            raw.extend(fetch_cisa_kev(src, since))
        else:
            raw.extend(fetch_source(src, since))
    deduped = dedupe(raw)
    print(f"Collected {len(raw)} items → {len(deduped)} after dedupe")
    return deduped
