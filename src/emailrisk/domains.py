"""Domain, URL and look-alike helpers. Pure functions, no network access."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urlsplit

from .models import UrlRef

# Heuristic registrable-domain handling. A full Public Suffix List would be more
# precise but would add a dependency; this covers the common ccTLD patterns.
_SLD_LABELS = frozenset({"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"})

RESERVED_TLDS = frozenset({"invalid", "test", "localhost", "local", "internal", "lan", "onion"})
SUSPICIOUS_TLDS = frozenset(
    {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga",
     "work", "support", "rest", "monster", "icu", "cam", "loan", "men", "party"}
)
URL_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
     "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id"}
)
FREEMAIL = frozenset(
    {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "proton.me",
     "protonmail.com", "icloud.com", "gmx.com", "mail.com", "yandex.com"}
)
# Brand -> legitimate registrable domains. Deliberately small and easy to extend.
BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "office.com", "outlook.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset({"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"}),
    "google": frozenset({"google.com", "gmail.com"}),
    "netflix": frozenset({"netflix.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "linkedin": frozenset({"linkedin.com"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "hdfcbank": frozenset({"hdfcbank.com"}),
    "sbi": frozenset({"sbi.co.in"}),
}

_COMMON_TLDS = frozenset({"com", "net", "org", "io", "co", "info", "edu", "gov"})
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
_ADDR_RE = re.compile(r"[^\s<>\"',;]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+")


def domain_of(address: str) -> str:
    """Lower-cased domain part of an address, or ``""``."""
    address = address.strip().strip("<>").lower()
    return address.rsplit("@", 1)[1].rstrip(".") if "@" in address else ""


def extract_addresses(value: str) -> list[str]:
    return [m.group(0).lower() for m in _ADDR_RE.finditer(value)]


@lru_cache(maxsize=4096)
def registrable(host: str) -> str:
    """Approximate eTLD+1 for ``host`` (IP literals are returned unchanged)."""
    host = host.lower().rstrip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SLD_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def tld(host: str) -> str:
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def same_org(a: str, b: str) -> bool:
    """True when two hosts share a registrable domain (relaxed alignment)."""
    return bool(a) and bool(b) and registrable(a) == registrable(b)


def defang(text: str) -> str:
    """Make a URL or host non-clickable for safe inclusion in reports."""
    return text.replace("http", "hxxp").replace(".", "[.]")


def _normalise_label(label: str) -> str:
    return label.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


@lru_cache(maxsize=4096)
def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Levenshtein distance, early-exiting once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def lookalike_of(host: str, reference: str) -> bool:
    """Is ``host`` a near-miss (typo or homoglyph) of ``reference`` without being it?"""
    h, r = registrable(host), registrable(reference)
    if not h or not r or h == r:
        return False
    hl, rl = h.split(".")[0], r.split(".")[0]
    if len(rl) < 4:  # too short to compare reliably
        return False
    if _normalise_label(hl) == _normalise_label(rl):
        # Same name on a different TLD (e.g. example.top vs example.com). Swaps between
        # ubiquitous TLDs are common for companies that own both, so they are not flagged.
        return hl != rl or tld(h) != tld(r) and not {tld(h), tld(r)} <= _COMMON_TLDS
    return edit_distance(hl, rl, 1) <= 1 and tld(h) == tld(r)


def brand_impersonated(host: str) -> str | None:
    """Return the brand a host appears to imitate, if it is not that brand's domain."""
    reg = registrable(host)
    labels = [_normalise_label(x) for x in re.split(r"[.\-_]", host.lower()) if x]
    for brand, legit in BRANDS.items():
        if reg in legit:
            continue
        if brand in labels or lookalike_of(reg, next(iter(legit))):
            return brand
    return None


def make_url_ref(raw: str, text: str = "") -> UrlRef | None:
    """Parse ``raw`` into a :class:`UrlRef`; ``None`` if it is not a usable URL/host."""
    raw = raw.strip()
    if not raw or raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
        return None
    candidate = raw if "://" in raw else "//" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host:
        return None
    scheme = parts.scheme.lower() if "://" in raw else None
    return UrlRef(
        url=raw[:2048],
        host=host,
        scheme=scheme,
        text=text.strip()[:512],
        has_userinfo="@" in parts.netloc,
    )
