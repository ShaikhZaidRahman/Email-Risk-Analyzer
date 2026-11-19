"""Orchestration: Evidence -> Analysis."""

from __future__ import annotations

from .config import Config
from .models import Analysis, Evidence
from .parser import parse_message
from .rules import RULES


def analyze_evidence(ev: Evidence, cfg: Config | None = None) -> Analysis:
    cfg = cfg or Config()
    findings = [f for rule in RULES for f in rule(ev, cfg)]
    findings.sort(key=lambda f: (-f.points, f.rule_id))
    score = min(100, sum(f.points for f in findings))

    notes: list[str] = []
    if ev.dkim == "unverified":
        notes.append("DKIM-Signature present but no verification result in headers; signature not verified offline.")
    if ev.hops is not None and ev.spf and not ev.auth_from_header:
        notes.append("No Authentication-Results header; SPF taken from Received-SPF or assumed 'none'.")
    if ev.urls:
        notes.append("Links were analysed statically; no URL was fetched or resolved.")

    return Analysis(
        message_id=ev.message_id,
        source=ev.source,
        sender=ev.from_addr,
        subject=ev.subject,
        score=score,
        level=cfg.level_for(score),
        findings=findings,
        notes=notes,
        auth={"spf": ev.spf, "dkim": ev.dkim, "dmarc": ev.dmarc},
        details={
            "display_name": ev.from_name,
            "reply_to": ", ".join(ev.reply_to),
            "return_path": ev.return_path or "",
            "message_id_domain": ev.msgid_domain,
            "links": str(len(ev.urls)),
            "attachments": ", ".join(a.filename for a in ev.attachments),
        },
        hops=[
            {"from": h.from_host, "by": h.by_host, "ip": h.ip, "timestamp": h.timestamp}
            for h in (ev.hops or ())
        ],
    )


def analyze_message_bytes(data: bytes, cfg: Config | None = None, source: str = "") -> Analysis:
    cfg = cfg or Config()
    if len(data) > cfg.max_message_bytes:
        raise ValueError(f"message exceeds {cfg.max_message_bytes} bytes")
    return analyze_evidence(parse_message(data, cfg, source), cfg)
