"""Plain data structures shared by the parsing, rule and reporting layers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

LOW, MEDIUM, HIGH = "Low", "Medium", "High"
LEVELS: tuple[str, ...] = (LOW, MEDIUM, HIGH)


@dataclass(frozen=True, slots=True)
class UrlRef:
    """A link found in a message. ``text`` is the visible anchor text, if any."""

    url: str
    host: str
    scheme: str | None = None
    text: str = ""
    has_userinfo: bool = False


@dataclass(frozen=True, slots=True)
class AttachmentRef:
    filename: str
    content_type: str = ""
    size: int = 0


@dataclass(frozen=True, slots=True)
class Hop:
    """One ``Received`` header, newest first in :attr:`Evidence.hops`."""

    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    timestamp: float | None = None


@dataclass(frozen=True, slots=True)
class DkimSignature:
    domain: str
    selector: str = ""
    algorithm: str = ""
    signed_headers: tuple[str, ...] = ()


@dataclass(slots=True)
class Evidence:
    """Everything the rule engine may look at, independent of input format.

    ``None`` means "not observable for this input" (rules stay silent), which is
    different from an explicit ``"none"`` authentication result.
    """

    message_id: str = ""
    source: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: tuple[str, ...] = ()
    return_path: str | None = None
    msgid_domain: str = ""
    subject: str = ""
    body_text: str = ""
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    auth_from_header: bool = False
    dkim_signatures: tuple[DkimSignature, ...] = ()
    urls: tuple[UrlRef, ...] = ()
    attachments: tuple[AttachmentRef, ...] = ()
    unknown_attachment: bool = False
    has_password_form: bool = False
    hops: tuple[Hop, ...] | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    category: str
    title: str
    points: int
    evidence: str


@dataclass(slots=True)
class Analysis:
    message_id: str
    source: str
    sender: str
    subject: str
    score: int
    level: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    auth: dict[str, str | None] = field(default_factory=dict)
    hops: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)
    expected: str | None = None
    primary_indicator: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
