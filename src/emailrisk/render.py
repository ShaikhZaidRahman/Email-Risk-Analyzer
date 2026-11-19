"""Text, JSON and CSV renderers."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from . import __version__
from .models import LEVELS, Analysis


def summarize(results: list[Analysis]) -> dict[str, Any]:
    counts = {lvl: sum(1 for r in results if r.level == lvl) for lvl in LEVELS}
    rules: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            rules[f.rule_id] = rules.get(f.rule_id, 0) + 1
    return {
        "messages": len(results),
        "by_level": counts,
        "mean_score": round(sum(r.score for r in results) / len(results), 1) if results else 0.0,
        "rule_frequency": dict(sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def to_json(results: list[Analysis], validation: dict[str, Any] | None) -> str:
    doc = {
        "tool": "emailrisk",
        "version": __version__,
        "summary": summarize(results),
        "validation": validation,
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in attacker-controlled text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_csv(results: list[Analysis]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["message_id", "sender", "subject", "spf", "dkim", "dmarc", "score", "level",
                "expected", "top_findings"])
    for r in results:
        w.writerow([_safe_cell(x) for x in (
            r.message_id, r.sender, r.subject, r.auth.get("spf") or "", r.auth.get("dkim") or "",
            r.auth.get("dmarc") or "", r.score, r.level, r.expected or "",
            "; ".join(f"{f.rule_id}(+{f.points})" for f in r.findings[:5]),
        )])
    return buf.getvalue()


def to_text(results: list[Analysis], verbose: bool = True) -> str:
    out: list[str] = []
    for r in results:
        out.append("=" * 78)
        out.append(f"{r.message_id or r.source}  |  RISK {r.score:3d}/100  [{r.level.upper()}]")
        out.append(f"From: {r.sender or '(unknown)'}   Subject: {r.subject[:70]}")
        a = r.auth
        out.append(f"Auth: SPF={a.get('spf')}  DKIM={a.get('dkim')}  DMARC={a.get('dmarc') or 'n/a'}")
        if verbose:
            for f in r.findings:
                out.append(f"  +{f.points:<3d} {f.rule_id:<18} {f.title}")
                out.append(f"       evidence: {f.evidence}")
            if not r.findings:
                out.append("  No phishing indicators detected.")
            for n in r.notes:
                out.append(f"  note: {n}")
    s = summarize(results)
    out.append("=" * 78)
    lv = s["by_level"]
    out.append(f"{s['messages']} message(s): High={lv['High']} Medium={lv['Medium']} "
               f"Low={lv['Low']}  mean score={s['mean_score']}")
    return "\n".join(out)
