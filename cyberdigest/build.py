"""Build the shareable page.  python -m cyberdigest.build

If PAGE_PASSPHRASE is set, the digest is AES-256-GCM encrypted at build time and
the published index.html contains only ciphertext — readers must enter the
passphrase to decrypt in-browser. If unset, a plain (public) page is written."""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .fetch import collect, fetch_iocs, rescan_hashes
from .rank import rank
from .site import build_encrypted, build_plain, render_inner

ROOT = Path(__file__).resolve().parent.parent
PBKDF2_ITERS = 250_000


def _encrypt(plaintext: str, passphrase: str):
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(passphrase.encode())
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)  # ct includes 16-byte tag
    b = lambda x: base64.b64encode(x).decode()
    return b(salt), b(iv), b(ct)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the Cyber Digest page")
    ap.add_argument("--config", default=str(ROOT / "feeds.yaml"))
    ap.add_argument("--out", default=os.environ.get("OUT_DIR", "public"))
    ap.add_argument("--share-url", default=os.environ.get("SHARE_URL", "your-page-url"))
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    brand = cfg.get("brand", {"name": "Cyber Digest", "tagline": ""})

    if cfg.get("demo"):
        # DEMO MODE — seed from sample data; no network, no real intel.
        from .demo import demo_build
        sample_path = Path(args.config).resolve().parent / cfg.get("sample_file", "sample.yaml")
        digests, iocs = demo_build(cfg, sample_path)
    else:
        digests = {}
        for period in ("daily", "weekly", "monthly"):
            digests[period] = rank(collect(cfg["sources"], period), cfg)

        iocs = []
        if cfg.get("iocs", True):
            iocs = fetch_iocs()
            # rescan a bounded set of feeds that didn't publish hashes in their RSS
            rescan_n = int(cfg.get("hash_rescan", 12))
            if rescan_n:
                iocs = iocs + rescan_hashes(digests.get("weekly", []), limit=rescan_n)

    passphrase = os.environ.get("PAGE_PASSPHRASE", "").strip()
    if passphrase:
        inner = render_inner(digests, cfg.get("display"), cfg.get("sources"), iocs)
        salt_b64, iv_b64, ct_b64 = _encrypt(inner, passphrase)
        page = build_encrypted(salt_b64, iv_b64, ct_b64, PBKDF2_ITERS, args.share_url, brand)
        mode = f"ENCRYPTED (AES-256-GCM, PBKDF2 {PBKDF2_ITERS} iters)"
    else:
        page = build_plain(digests, args.share_url, brand, cfg.get("display"), cfg.get("sources"), iocs)
        mode = "PLAIN (public) — set PAGE_PASSPHRASE to lock it"

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page, encoding="utf-8")
    print(f"Wrote {out/'index.html'} [{mode}] "
          f"(daily {len(digests['daily'])}, weekly {len(digests['weekly'])}, "
          f"monthly {len(digests['monthly'])})")
    if passphrase and args.share_url and args.share_url != "your-page-url":
        from urllib.parse import quote
        link = f"{args.share_url.rstrip('/')}/#k={quote(passphrase)}"
        print("\nReady-to-share link (tap opens + unlocks — this link IS the key):")
        print(f"  {link}")
        print("Roll it over anytime: change PAGE_PASSPHRASE and re-run; old links stop working.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
