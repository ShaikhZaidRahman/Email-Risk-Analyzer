"""Detection rules. Each rule is a pure function ``(Evidence, Config) -> list[Finding]``.

A rule fires at most once per message so that a long list of similar links cannot
inflate the score; the evidence string lists a few examples instead.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from itertools import islice, pairwise
from pathlib import PurePosixPath

from .config import Config
from .domains import (
    BRANDS,
    FREEMAIL,
    RESERVED_TLDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    brand_impersonated,
    defang,
    domain_of,
    is_ip,
    lookalike_of,
    registrable,
    same_org,
    tld,
)
from .models import Evidence, Finding

Rule = Callable[[Evidence, Config], list[Finding]]

_RISKY_EXT = frozenset(
    {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "ps1", "jar",
     "lnk", "iso", "img", "msi", "hta", "reg", "dll", "html", "htm", "xhtml", "svg",
     "docm", "xlsm", "pptm", "dotm", "xlam", "one", "chm", "apk"}
)
_ARCHIVE_EXT = frozenset({"zip", "rar", "7z", "gz", "tar", "cab", "ace"})
_DOC_EXT = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf",
                      "jpg", "jpeg", "png", "gif", "csv"})
_WEAK_ALGOS = ("rsa-sha1",)


def _f(cfg: Config, rule: str, category: str, title: str, evidence: str) -> Finding:
    return Finding(rule, category, title, cfg.w(rule), evidence)


def _examples(items: list[str], n: int = 3) -> str:
    shown = ", ".join(islice(items, n))
    return shown + (f" (+{len(items) - n} more)" if len(items) > n else "")


def _trusted(host: str, cfg: Config) -> bool:
    return registrable(host) in cfg.trusted_domains


# --------------------------------------------------------------------------- auth
def rule_spf(ev: Evidence, cfg: Config) -> list[Finding]:
    verdict = ev.spf
    key = {
        "fail": "AUTH-SPF-FAIL",
        "softfail": "AUTH-SPF-SOFTFAIL",
        "none": "AUTH-SPF-NONE",
        "neutral": "AUTH-SPF-NONE",
        "temperror": "AUTH-SPF-NONE",
        "permerror": "AUTH-SPF-NONE",
    }.get(verdict or "")
    if not key:
        return []
    labels = {"fail": "SPF check failed: sending host is not authorised for the envelope domain",
              "softfail": "SPF soft-fail: sending host is discouraged for the envelope domain"}
    title = labels.get(verdict or "", "No usable SPF result")
    return [_f(cfg, key, "Authentication", title, f"spf={verdict}")]


def rule_dkim(ev: Evidence, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    if ev.dkim in ("fail", "none", "permerror", "temperror", "policy"):
        key = "AUTH-DKIM-FAIL" if ev.dkim in ("fail", "permerror") else "AUTH-DKIM-NONE"
        title = ("DKIM signature failed verification" if key == "AUTH-DKIM-FAIL"
                 else "No valid DKIM signature present")
        out.append(_f(cfg, key, "Authentication", title, f"dkim={ev.dkim}"))
    sender = domain_of(ev.from_addr)
    if ev.dkim_signatures and sender:
        if not any(same_org(sig.domain, sender) for sig in ev.dkim_signatures):
            doms = _examples([s.domain for s in ev.dkim_signatures])
            out.append(_f(cfg, "AUTH-DKIM-ALIGN", "Authentication",
                          "DKIM signing domain does not align with the From domain",
                          f"d={doms}; From domain={sender}"))
        weak = [s for s in ev.dkim_signatures if s.algorithm in _WEAK_ALGOS]
        if weak:
            out.append(_f(cfg, "AUTH-DKIM-WEAK", "Authentication",
                          "DKIM signature uses a deprecated hash algorithm", f"a={weak[0].algorithm}"))
    return out


def rule_dmarc(ev: Evidence, cfg: Config) -> list[Finding]:
    if ev.dmarc in ("fail", "permerror"):
        return [_f(cfg, "AUTH-DMARC-FAIL", "Authentication",
                   "DMARC evaluation failed for the From domain", f"dmarc={ev.dmarc}")]
    return []


# ------------------------------------------------------------------------ headers
def rule_reply_to(ev: Evidence, cfg: Config) -> list[Finding]:
    sender = domain_of(ev.from_addr)
    if not sender or not ev.reply_to:
        return []
    other = [a for a in ev.reply_to if not same_org(domain_of(a), sender)]
    if not other:
        return []
    note = " (free-mail address)" if any(domain_of(a) in FREEMAIL for a in other) else ""
    return [_f(cfg, "HDR-REPLYTO", "Header spoofing",
               "Reply-To points to a different domain than From",
               f"From={ev.from_addr}; Reply-To={_examples(other)}{note}")]


def rule_return_path(ev: Evidence, cfg: Config) -> list[Finding]:
    sender, rp = domain_of(ev.from_addr), domain_of(ev.return_path or "")
    if sender and rp and not same_org(rp, sender):
        return [_f(cfg, "HDR-RETURNPATH", "Header spoofing",
                   "Return-Path (envelope sender) domain differs from From domain",
                   f"Return-Path={ev.return_path}; From={ev.from_addr}")]
    return []


def rule_display_name(ev: Evidence, cfg: Config) -> list[Finding]:
    name, sender = ev.from_name.lower(), domain_of(ev.from_addr)
    if not name or not sender:
        return []
    for addr in re.findall(r"[\w.+-]+@[\w.-]+", name):
        if not same_org(domain_of(addr), sender):
            return [_f(cfg, "HDR-DISPLAYNAME", "Header spoofing",
                       "Display name embeds an address from a different domain",
                       f"name={ev.from_name!r}; actual={ev.from_addr}")]
    squashed = re.sub(r"[^a-z0-9]", "", name)
    for brand, legit in BRANDS.items():
        if (re.search(rf"\b{brand}\b", name) or brand in squashed) and registrable(sender) not in legit:
            return [_f(cfg, "HDR-DISPLAYNAME", "Header spoofing",
                       f"Display name impersonates '{brand}' but the address is on another domain",
                       f"name={ev.from_name!r}; actual={ev.from_addr}")]
    return []


def rule_message_id(ev: Evidence, cfg: Config) -> list[Finding]:
    sender = domain_of(ev.from_addr)
    if sender and ev.msgid_domain and not same_org(ev.msgid_domain, sender):
        return [_f(cfg, "HDR-MSGID", "Header spoofing",
                   "Message-ID generated by a different domain than From",
                   f"Message-ID domain={ev.msgid_domain}; From={sender}")]
    return []


def rule_received(ev: Evidence, cfg: Config) -> list[Finding]:
    if ev.hops is None:
        return []
    if not ev.hops:
        return [_f(cfg, "HDR-NORECEIVED", "Header spoofing",
                   "No Received headers: message path cannot be verified", "0 hops")]
    chrono = [h.timestamp for h in reversed(ev.hops) if h.timestamp is not None]
    for earlier, later in pairwise(chrono):
        if later < earlier - 300:
            return [_f(cfg, "HDR-TIMESKEW", "Header spoofing",
                       "Received timestamps run backwards (forged or relayed header)",
                       f"{int(earlier - later)} s skew between hops")]
    return []


# --------------------------------------------------------------------------- links
def _link_groups(ev: Evidence, cfg: Config) -> dict[str, list[str]]:
    sender = domain_of(ev.from_addr)
    groups: dict[str, list[str]] = {k: [] for k in (
        "unrelated", "reserved", "suspicious", "ip", "userinfo", "puny", "short", "mismatch",
        "lookalike", "brand", "http", "deep")}
    for u in ev.urls:
        host, shown = u.host, defang(u.url if u.scheme else u.host)
        if _trusted(host, cfg):
            continue
        t = tld(host)
        if is_ip(host):
            groups["ip"].append(shown)
        if u.has_userinfo:
            groups["userinfo"].append(shown)
        if any(label.startswith("xn--") for label in host.split(".")) or not host.isascii():
            groups["puny"].append(shown)
        if registrable(host) in URL_SHORTENERS:
            groups["short"].append(shown)
        if t in RESERVED_TLDS:
            groups["reserved"].append(shown)
        elif t in SUSPICIOUS_TLDS:
            groups["suspicious"].append(shown)
        if u.scheme == "http":
            groups["http"].append(shown)
        if not is_ip(host) and host.count(".") >= 4:
            groups["deep"].append(shown)
        if sender and lookalike_of(host, sender):
            groups["lookalike"].append(f"{defang(registrable(host))} ~ {registrable(sender)}")
        brand = brand_impersonated(host) if not is_ip(host) else None
        if brand:
            groups["brand"].append(f"{defang(host)} ~ {brand}")
        if sender and not same_org(host, sender) and not is_ip(host):
            groups["unrelated"].append(defang(host))
        label_hosts = re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", u.text.lower())
        if label_hosts and not any(same_org(lh, host) for lh in label_hosts):
            groups["mismatch"].append(f"text '{u.text[:60]}' -> {defang(host)}")
    return groups


def rule_links(ev: Evidence, cfg: Config) -> list[Finding]:
    if not ev.urls and not ev.has_password_form:
        return []
    g = _link_groups(ev, cfg)
    spec = [
        ("mismatch", "LNK-MISMATCH", "Link text shows one domain but points to another"),
        ("userinfo", "LNK-USERINFO", "URL contains credentials/userinfo ('@') to disguise the real host"),
        ("ip", "LNK-IP", "Link points to a raw IP address"),
        ("puny", "LNK-PUNYCODE", "Link uses punycode / non-ASCII host (possible homograph attack)"),
        ("lookalike", "LNK-LOOKALIKE", "Link domain is a look-alike of the sender's domain"),
        ("brand", "LNK-BRAND", "Link domain imitates a well-known brand"),
        ("short", "LNK-SHORTENER", "Link hides its destination behind a URL shortener"),
        ("reserved", "LNK-RESERVED-TLD", "Link uses a reserved/non-routable TLD that cannot be legitimate"),
        ("suspicious", "LNK-SUSPICIOUS-TLD", "Link uses a TLD with a high abuse rate"),
        ("unrelated", "LNK-UNRELATED", "Link domain is unrelated to the sender's domain"),
        ("http", "LNK-HTTP", "Link uses unencrypted HTTP"),
        ("deep", "LNK-DEEPSUB", "Link has an unusually deep subdomain chain"),
    ]
    out = [_f(cfg, rid, "Links", title, _examples(g[key])) for key, rid, title in spec if g[key]]
    if ev.has_password_form:
        out.append(_f(cfg, "BODY-FORM", "Links", "Message embeds a password-entry form", "<input type=password>"))
    return out


# ------------------------------------------------------------------------ language
def _compile(phrases: list[str]) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(phrases) + r")\b", re.IGNORECASE)

_URGENCY = _compile([
    r"urgent(?:ly)?", r"immediate(?:ly)?", r"act now", r"right away", r"asap",
    r"within \d+ (?:hours?|days?|minutes?)", r"final (?:notice|warning|reminder)", r"last (?:chance|warning)",
    r"expires? (?:today|soon|in)", r"time[- ]sensitive", r"action required", r"response required",
    r"as soon as possible", r"don'?t (?:delay|ignore)", r"failure to (?:respond|comply|act)",
])
_THREAT = _compile([
    r"account (?:has been |will be |is )?(?:suspended|locked|closed|disabled|terminated|restricted|limited)",
    r"unauthori[sz]ed (?:access|activity|login|transaction)", r"suspicious (?:activity|sign[- ]?in|login)",
    r"legal action", r"security (?:alert|breach|incident)", r"will be (?:deleted|deactivated|terminated)",
    r"compromised",
])
_CREDENTIAL = _compile([
    r"verify your (?:account|identity|email|password|information|details)",
    r"confirm your (?:account|identity|password|details|information|payment)",
    r"update your (?:account|password|payment|billing|credentials|information)",
    r"(?:re-?)?enter your (?:password|credentials|pin|otp)", r"log ?in to (?:your account|continue|verify)",
    r"click (?:the )?(?:link|button) below", r"gift cards?", r"wire transfer", r"one[- ]time (?:password|code)",
    r"social security", r"bank (?:details|account number)", r"review (?:your )?account",
])


def _lang_hit(pattern: re.Pattern[str], subject: str, body: str) -> tuple[list[str], bool]:
    in_subject = {m.group(0).lower() for m in pattern.finditer(subject)}
    in_body = {m.group(0).lower() for m in pattern.finditer(body[:200_000])}
    return sorted(in_subject | in_body), bool(in_subject)


def rule_language(ev: Evidence, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    for pattern, rid, title in (
        (_URGENCY, "BODY-URGENCY", "Urgent / time-pressure language"),
        (_THREAT, "BODY-THREAT", "Threat or account-suspension language"),
        (_CREDENTIAL, "BODY-CREDENTIAL", "Request to verify, update or submit sensitive information"),
    ):
        hits, in_subject = _lang_hit(pattern, ev.subject, ev.body_text)
        if not hits:
            continue
        # Base weight, +4 for every extra distinct phrase (cap +8) and +4 when it is in the subject.
        points = cfg.w(rid) + min(4 * (len(hits) - 1), 8) + (4 if in_subject else 0)
        where = "subject" if in_subject else "body"
        out.append(Finding(rid, "Language", title, points, f"{where}: {_examples([repr(h) for h in hits])}"))
    return out


# ------------------------------------------------------------------- attachments
def rule_attachments(ev: Evidence, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    risky: list[str] = []
    double: list[str] = []
    archive: list[str] = []
    for att in ev.attachments:
        parts = PurePosixPath(att.filename.lower()).name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and parts[-2] in _DOC_EXT and (ext in _RISKY_EXT or ext in _ARCHIVE_EXT):
            double.append(att.filename)
        elif ext in _RISKY_EXT:
            risky.append(att.filename)
        elif ext in _ARCHIVE_EXT:
            archive.append(att.filename)
    if double:
        out.append(_f(cfg, "ATT-DOUBLEEXT", "Attachments", "Attachment hides an executable behind a document extension", _examples(double)))
    if risky:
        out.append(_f(cfg, "ATT-RISKY", "Attachments", "Attachment has an executable, script or macro-enabled type", _examples(risky)))
    if archive:
        out.append(_f(cfg, "ATT-ARCHIVE", "Attachments", "Compressed archive can conceal malicious payloads", _examples(archive)))
    if ev.unknown_attachment and not ev.attachments:
        out.append(_f(cfg, "ATT-GENERIC", "Attachments", "Attachment present (type unknown, contents not inspected)", "HasAttachment=Yes"))
    return out


RULES: tuple[Rule, ...] = (
    rule_spf, rule_dkim, rule_dmarc, rule_reply_to, rule_return_path, rule_display_name,
    rule_message_id, rule_received, rule_links, rule_language, rule_attachments,
)
