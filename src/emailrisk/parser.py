"""Turn a raw RFC 5322 message into :class:`Evidence`. Never touches the network."""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

from .config import Config
from .domains import domain_of, extract_addresses, make_url_ref
from .models import AttachmentRef, DkimSignature, Evidence, Hop, UrlRef

MAX_BODY_CHARS = 1_000_000
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\\]{3,2000}", re.IGNORECASE)
_TRAIL = ".,;:!?)]}>'\""
_AR_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_RECV_FROM = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_RECV_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_RECV_IP4 = re.compile(r"\[?\b((?:\d{1,3}\.){3}\d{1,3})\b\]?")
_RECV_IP6 = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]{3,39})\]")
_SKEW_SECONDS = 300


class _HtmlExtractor(HTMLParser):
    """Collect visible text, anchors and form signals without executing anything."""

    _SKIP = frozenset({"script", "style", "head", "title"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.password_form = False
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag == "a" and a.get("href"):
            self._href, self._anchor_text = a["href"], []
        elif tag == "form" and a.get("action"):
            self.links.append((a["action"], ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_form = True

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._anchor_text)))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor_text.append(data.strip())


def _text_of(part: EmailMessage) -> str:
    try:
        return str(part.get_content())
    except (LookupError, UnicodeError, ValueError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _parse_hop(value: str) -> Hop:
    value = " ".join(value.split())
    body, _, date = value.rpartition(";")
    ts: float | None = None
    try:
        ts = parsedate_to_datetime(date.strip()).timestamp()
    except (TypeError, ValueError, IndexError):
        pass
    m_from, m_by = _RECV_FROM.search(body), _RECV_BY.search(body)
    ip = ""
    paren = re.findall(r"\(([^)]*)\)", body)
    for chunk in paren or [body]:
        m = _RECV_IP6.search(chunk) or _RECV_IP4.search(chunk)
        if m:
            try:
                ip = str(ipaddress.ip_address(m.group(1)))
                break
            except ValueError:
                continue
    return Hop(
        from_host=m_from.group(1).strip("[]();") if m_from else "",
        by_host=m_by.group(1).strip("[]();") if m_by else "",
        ip=ip,
        timestamp=ts,
    )


def _parse_authentication(msg: EmailMessage, cfg: Config) -> tuple[dict[str, str], bool]:
    """Pick one Authentication-Results header and return its SPF/DKIM/DMARC verdicts.

    The topmost header is the one added by the receiving edge. When ``cfg.authserv_ids``
    is set only headers issued by those hosts are trusted, which defeats forged headers
    injected by the sender.
    """
    for raw in msg.get_all("Authentication-Results", []):
        value = " ".join(str(raw).split())
        authserv = value.split(";", 1)[0].split()[0].lower() if value else ""
        if cfg.authserv_ids and authserv not in cfg.authserv_ids:
            continue
        results: dict[str, str] = {}
        for method, verdict in _AR_RE.findall(value):
            method, verdict = method.lower(), verdict.lower()
            # Any DKIM "pass" wins (messages may carry several signatures).
            if method not in results or (method == "dkim" and verdict == "pass"):
                results[method] = verdict
        return results, True
    return {}, False


def _parse_dkim_signatures(msg: EmailMessage) -> tuple[DkimSignature, ...]:
    out: list[DkimSignature] = []
    for raw in msg.get_all("DKIM-Signature", [])[:10]:
        tags = {}
        for item in " ".join(str(raw).split()).split(";"):
            k, sep, v = item.strip().partition("=")
            if sep:
                tags[k.strip().lower()] = v.strip().replace(" ", "")
        if "d" in tags:
            out.append(
                DkimSignature(
                    domain=tags["d"].lower(),
                    selector=tags.get("s", ""),
                    algorithm=tags.get("a", "").lower(),
                    signed_headers=tuple(h.lower() for h in tags.get("h", "").split(":") if h),
                )
            )
    return tuple(out)


def _return_path(msg: EmailMessage) -> str | None:
    raw = msg.get("Return-Path")
    if raw is None:
        return None
    return parseaddr(str(raw))[1].lower()


def _collect_urls(
    text: str, anchors: list[tuple[str, str]], limit: int
) -> tuple[UrlRef, ...]:
    seen: set[tuple[str, str]] = set()
    out: list[UrlRef] = []

    def add(raw: str, anchor_text: str) -> None:
        if len(out) >= limit:
            return
        ref = make_url_ref(raw, anchor_text)
        if ref and (ref.url, ref.text) not in seen:
            seen.add((ref.url, ref.text))
            out.append(ref)

    for href, label in anchors:
        add(href, label)
    for m in _URL_RE.finditer(text):
        add(m.group(0).rstrip(_TRAIL), "")
    return tuple(out)


def parse_message(data: bytes, cfg: Config, source: str = "") -> Evidence:
    """Parse raw message bytes into :class:`Evidence`."""
    msg = BytesParser(policy=policy.default).parsebytes(data)
    assert isinstance(msg, EmailMessage)

    name, addr = parseaddr(str(msg.get("From", "")))
    reply_to = tuple(extract_addresses(" ".join(str(h) for h in msg.get_all("Reply-To", []))))
    msgid = str(msg.get("Message-ID", "")).strip()

    plain: list[str] = []
    html_text: list[str] = []
    anchors: list[tuple[str, str]] = []
    attachments: list[AttachmentRef] = []
    password_form = False
    budget = MAX_BODY_CHARS
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                AttachmentRef(str(filename or "(unnamed)")[:255], part.get_content_type(), len(payload))
            )
            continue
        ctype = part.get_content_type()
        if budget <= 0 or ctype not in ("text/plain", "text/html"):
            continue
        content = _text_of(part)[:budget]
        budget -= len(content)
        if ctype == "text/plain":
            plain.append(content)
        else:
            extractor = _HtmlExtractor()
            extractor.feed(content)
            extractor.close()
            html_text.append(" ".join(" ".join(extractor.text).split()))
            anchors.extend(extractor.links)
            password_form = password_form or extractor.password_form

    body = "\n".join(plain) if plain else "\n".join(html_text)
    url_text = "\n".join(plain + html_text)
    verdicts, from_header = _parse_authentication(msg, cfg)
    signatures = _parse_dkim_signatures(msg)

    spf = verdicts.get("spf")
    if spf is None:
        received_spf = str(msg.get("Received-SPF", "")).split()
        spf = received_spf[0].lower() if received_spf else "none"
    dkim = verdicts.get("dkim") or ("none" if not signatures else "unverified")

    hops = tuple(_parse_hop(str(h)) for h in msg.get_all("Received", [])[:50])
    return Evidence(
        message_id=msgid.strip("<>") or source,
        source=source,
        from_name=name.strip(),
        from_addr=addr.lower(),
        reply_to=reply_to,
        return_path=_return_path(msg),
        msgid_domain=domain_of(msgid.strip("<>")),
        subject=" ".join(str(msg.get("Subject", "")).split()),
        body_text=body,
        spf=spf,
        dkim=dkim,
        dmarc=verdicts.get("dmarc"),
        auth_from_header=from_header,
        dkim_signatures=signatures,
        urls=_collect_urls(url_text, anchors, cfg.max_urls),
        attachments=tuple(attachments),
        has_password_form=password_form,
        hops=hops,
    )
