# Cindera — Demo (public sample instance)

A **public, safe-to-share** instance of Cindera that renders the exact same UI as
the live app, but from **seeded sample data** (`sample.yaml`) — no live feeds, no
real intel, no passphrase. Use it to give new folks a glance at the look and feel
without exposing your real brief.

## What makes it a demo
- `feeds.yaml` has **`demo: true`** and points at **`sample.yaml`**.
- In demo mode the build **skips all network fetching** and renders the sample items.
- No `PAGE_PASSPHRASE` secret → the page publishes **unencrypted (public)**.

## Deploy in ~3 minutes
1. Create a **new GitHub repo** (e.g. `cindera-demo`) and push these files to `main`.
2. **Settings → Pages → Source = GitHub Actions.**
3. **Do NOT** add a `PAGE_PASSPHRASE` secret (that keeps the demo public).
4. **Actions → run the "Build & Publish Cindera DEMO" workflow** (or just push).
5. Your demo is live at `https://<your-username>.github.io/cindera-demo/` — share freely.

_Optional:_ to put the demo itself behind a throwaway passphrase, add a
`PAGE_PASSPHRASE` secret with any value; it will then show the lock screen.

## Customize the sample
Edit **`sample.yaml`** — each item takes:
```yaml
- {title: "...", source: "...", tier: news|advisory|intel,
   category: advisories|intel|health|news, cve: "CVE-YYYY-NNNN", age_hours: 6, summary: "keywords"}
```
Add or change items and IOCs to shape the demo. Re-run the workflow to rebuild.

## Keep it separate from your real instance
This repo shares **no** real feeds or passphrase with your production Cindera.
Your live brief stays private; this is a throwaway showcase.

— Cyber Resilience Lab
