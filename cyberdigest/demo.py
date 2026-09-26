"""Demo mode: build the page from seeded SAMPLE items instead of live feeds.
Activated by `demo: true` in the config. No network, no real intel."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from pathlib import Path
import yaml
from .fetch import Item, dedupe
from .rank import rank


def _load(sample_path: Path):
    data = yaml.safe_load(open(sample_path, encoding="utf-8")) or {}
    now = datetime.now(timezone.utc)
    items = []
    for it in data.get("items", []):
        obj = Item(
            title=it["title"],
            link=it.get("link", "https://example.com/sample"),
            summary=it.get("summary", ""),
            source=it["source"],
            tier=it.get("tier", "news"),
            weight=float(it.get("weight", 1.2)),
            published=now - timedelta(hours=float(it.get("age_hours", 5))),
            category=it.get("category", it.get("tier", "news")),
        )
        if it.get("cve"):
            obj.tags = [it["cve"]]
        items.append(obj)
    iocs = data.get("iocs", [])
    return items, iocs


def demo_build(cfg: dict, sample_path: Path):
    items, iocs = _load(sample_path)
    ranked = rank(dedupe(items), cfg)
    return {"daily": ranked, "weekly": ranked, "monthly": ranked}, iocs
