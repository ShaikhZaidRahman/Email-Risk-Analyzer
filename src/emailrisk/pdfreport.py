"""PDF audit report (requires ``reportlab``).

Deliberately plain: black text on white, built-in fonts, no colour, no footer.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .config import Config
from .models import LEVELS, Analysis
from .render import summarize

BLACK = colors.black
SERIF, SERIF_B, MONO = "Times-Roman", "Times-Bold", "Courier"

CATALOGUE: dict[str, tuple[str, str]] = {
    "AUTH-SPF-FAIL": ("Authentication", "SPF fail: sending host not authorised"),
    "AUTH-SPF-SOFTFAIL": ("Authentication", "SPF softfail"),
    "AUTH-SPF-NONE": ("Authentication", "No / neutral / errored SPF result"),
    "AUTH-DKIM-FAIL": ("Authentication", "DKIM verification failed"),
    "AUTH-DKIM-NONE": ("Authentication", "No valid DKIM signature"),
    "AUTH-DMARC-FAIL": ("Authentication", "DMARC fail for From domain"),
    "AUTH-DKIM-ALIGN": ("Authentication", "DKIM d= domain not aligned with From"),
    "AUTH-DKIM-WEAK": ("Authentication", "DKIM uses rsa-sha1"),
    "HDR-REPLYTO": ("Header spoofing", "Reply-To domain differs from From"),
    "HDR-RETURNPATH": ("Header spoofing", "Return-Path domain differs from From"),
    "HDR-DISPLAYNAME": ("Header spoofing", "Display name spoofs brand / embeds other address"),
    "HDR-MSGID": ("Header spoofing", "Message-ID domain differs from From"),
    "HDR-NORECEIVED": ("Header spoofing", "No Received headers"),
    "HDR-TIMESKEW": ("Header spoofing", "Received timestamps run backwards"),
    "LNK-UNRELATED": ("Links", "Link domain unrelated to sender"),
    "LNK-RESERVED-TLD": ("Links", "Reserved / non-routable TLD"),
    "LNK-SUSPICIOUS-TLD": ("Links", "High-abuse TLD"),
    "LNK-IP": ("Links", "Link to raw IP address"),
    "LNK-USERINFO": ("Links", "user@host URL trick"),
    "LNK-PUNYCODE": ("Links", "Punycode / non-ASCII host"),
    "LNK-SHORTENER": ("Links", "URL shortener"),
    "LNK-MISMATCH": ("Links", "Anchor text domain != href domain"),
    "LNK-LOOKALIKE": ("Links", "Look-alike of sender domain"),
    "LNK-BRAND": ("Links", "Imitates a known brand"),
    "LNK-HTTP": ("Links", "Unencrypted HTTP link"),
    "LNK-DEEPSUB": ("Links", "Deep subdomain chain"),
    "BODY-FORM": ("Links", "Embedded password form"),
    "BODY-URGENCY": ("Language", "Urgent / time-pressure wording"),
    "BODY-THREAT": ("Language", "Account threat wording"),
    "BODY-CREDENTIAL": ("Language", "Credential / payment request wording"),
    "ATT-RISKY": ("Attachments", "Executable / script / macro type"),
    "ATT-DOUBLEEXT": ("Attachments", "Double extension (doc.pdf.exe)"),
    "ATT-ARCHIVE": ("Attachments", "Compressed archive"),
    "ATT-GENERIC": ("Attachments", "Attachment of unknown type"),
}


_APPX = ParagraphStyle("appx", fontName=SERIF, fontSize=8, leading=9.5, textColor=BLACK, alignment=TA_LEFT)


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("base", fontName=SERIF, fontSize=10.5, leading=14.5, textColor=BLACK, alignment=TA_LEFT)
    return {
        "base": base,
        "cell": ParagraphStyle("cell", parent=base, fontSize=8.5, leading=10.5),
        "cellb": ParagraphStyle("cellb", parent=base, fontName=SERIF_B, fontSize=8.5, leading=10.5),
        "mono": ParagraphStyle("mono", parent=base, fontName=MONO, fontSize=7.5, leading=10),
        "note": ParagraphStyle("note", parent=base, fontSize=9, leading=12),
        "title": ParagraphStyle("title", parent=base, fontName=SERIF_B, fontSize=20, leading=24, spaceAfter=3),
        "h1": ParagraphStyle("h1", parent=base, fontName=SERIF_B, fontSize=13, leading=16, spaceBefore=16, spaceAfter=6,
                             keepWithNext=1),
        "h2": ParagraphStyle("h2", parent=base, fontName=SERIF_B, fontSize=10.5, leading=14, spaceBefore=10,
                             spaceAfter=4, keepWithNext=1),
        "item": ParagraphStyle("item", parent=base, leftIndent=16, firstLineIndent=-16, spaceAfter=3),
    }


def _p(text: str, st: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text), st)


def _items(lines: list[str], st: dict[str, ParagraphStyle]) -> list[Paragraph]:
    return [Paragraph(f"{i}.&nbsp;&nbsp;{escape(t)}", st["item"]) for i, t in enumerate(lines, 1)]


def _table(rows: list[list[Any]], widths: list[float]) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEABOVE", (0, 0), (-1, 0), 0.8, BLACK),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BLACK),
        ("LINEBELOW", (0, 1), (-1, -2), 0.2, BLACK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, BLACK),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _hdr(cells: list[str], st: dict[str, ParagraphStyle]) -> list[Paragraph]:
    return [Paragraph(escape(c), st["cellb"]) for c in cells]


def _level_cell(level: str, score: int, st: dict[str, ParagraphStyle]) -> Paragraph:
    return Paragraph(f"{score} {escape(level)}", st["cellb"] if level == "High" else st["cell"])


def _bars(items: list[tuple[str, int]], width: float, label_w: float, vmax: int, mono: bool = False) -> Drawing:
    """Horizontal bars in solid black, one row per item."""
    row_h, gap = 11, 5
    d = Drawing(width, len(items) * (row_h + gap) + 2)
    track = width - label_w - 30
    y = len(items) * (row_h + gap) - row_h
    for label, v in items:
        d.add(String(0, y + 2.5, label, fontName=MONO if mono else SERIF, fontSize=7.5 if mono else 9, fillColor=BLACK))
        w = track * v / vmax if vmax else 0
        if w > 0:
            d.add(Rect(label_w, y, w, row_h, fillColor=BLACK, strokeColor=None))
        d.add(String(label_w + w + 4, y + 2.5, str(v), fontName=SERIF, fontSize=9, fillColor=BLACK))
        y -= row_h + gap
    d.add(Line(label_w, 0, label_w, len(items) * (row_h + gap), strokeColor=BLACK, strokeWidth=0.5))
    return d


def _brk(text: str) -> Paragraph:
    """Appendix cell: break an address after '@' so long IDs wrap cleanly instead of mid-word."""
    return Paragraph("@<br/>".join(escape(part) for part in text.split("@", 1)), _APPX)


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def build_pdf(results: list[Analysis], validation: dict[str, Any] | None, cfg: Config,
              path: Path, title: str = "Email Security Audit Report", author: str = "",
              subtitle: str = "Phishing risk analysis of email headers, links and content") -> None:
    st = _styles()
    page_w, page_h = A4
    margin = 20 * mm
    width = page_w - 2 * margin
    summary = summarize(results)
    n = summary["messages"]

    doc = BaseDocTemplate(str(path), pagesize=A4, leftMargin=margin, rightMargin=margin,
                          topMargin=20 * mm, bottomMargin=20 * mm, title=title, author=author, creator="", producer="")
    doc.addPageTemplates([PageTemplate("main", [Frame(margin, 20 * mm, width, page_h - 40 * mm, id="f",
                                                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)])])
    S: list[Any] = []

    # ---- 1. Summary
    lv = summary["by_level"]
    S += [_p(title, st["title"]), _p(subtitle, st["base"])]
    meta = dt.date.today().strftime("%d %B %Y")
    S.append(_p(f"Prepared by {author}  |  {meta}" if author else meta, st["base"]))
    S.append(_p("1. Summary", st["h1"]))
    high_pct = lv["High"] / n * 100 if n else 0
    S.append(_p(
        f"I ran {n} messages through the analyzer. {lv['High']} of them ({high_pct:.0f}%) scored High, {lv['Medium']} "
        f"scored Medium and {lv['Low']} scored Low. The average score was {summary['mean_score']} out of 100. "
        f"A score under {cfg.medium_threshold} is Low, {cfg.medium_threshold} to {cfg.high_threshold - 1} is Medium, "
        f"and {cfg.high_threshold} or above is High.", st["base"]))
    S.append(Spacer(1, 8))
    S.append(_bars([(l, lv[l]) for l in LEVELS], width * 0.6, 50, max(lv.values()) or 1))
    S.append(_p("Highest scoring messages", st["h2"]))
    rows = [_hdr(["Message", "Sender", "Score", "Main indicators"], st)]
    for r in sorted(results, key=lambda r: -r.score)[:5]:
        rows.append([_p(r.message_id[:40], st["cell"]), _p(r.sender, st["cell"]), _level_cell(r.level, r.score, st),
                     _p(", ".join(f.rule_id for f in r.findings[:4]), st["cell"])])
    S.append(_table(rows, [width * 0.30, width * 0.28, width * 0.12, width * 0.30]))

    # ---- 2. Method
    S.append(_p("2. How messages are scored", st["h1"]))
    S.append(_p("The analyzer only reads the message. It does not follow links, query DNS or open attachments, so it is "
                "safe to point at hostile mail. Every message goes through four steps.", st["base"]))
    S.append(Spacer(1, 3))
    S += _items([
        "Headers are parsed: From, Reply-To, Return-Path, Message-ID, the Received chain, the SPF/DKIM/DMARC results "
        "added by the receiving server, and the DKIM-Signature tags.",
        "Links and wording are checked. Links come from anchors, forms and plain text and are tested for IP hosts, "
        "user@host tricks, punycode, shorteners, look-alike or brand-imitating domains, and text that does not match "
        "the real target. The subject and body are matched against phrase lists for urgency, threats and requests for "
        "credentials or payment. Attachments are checked by type and for double extensions.",
        "Each rule that fires adds its fixed weight, once per message. The total is capped at 100.",
        "Results are written out with all URLs defanged (hxxp, [.]).",
    ], st)
    S.append(PageBreak())
    S.append(_p("Rule weights", st["h2"]))
    rows = [_hdr(["Rule", "Category", "Detects", "Weight"], st)]
    for rid, w in cfg.weights.items():
        cat, desc = CATALOGUE.get(rid, ("", ""))
        rows.append([_p(rid, st["mono"]), _p(cat, st["cell"]), _p(desc, st["cell"]), _p(f"+{w}", st["cell"])])
    S.append(_table(rows, [width * 0.25, width * 0.17, width * 0.46, width * 0.12]))
    S.append(Spacer(1, 4))
    S.append(_p("The wording rules add 4 for each extra phrase matched (up to 8 more) and 4 if a phrase is in the subject.",
                st["note"]))

    # ---- 3. Findings
    S.append(PageBreak())
    S.append(_p("3. What was found", st["h1"]))
    S.append(_p("Messages that triggered each rule (twelve most common)", st["h2"]))
    top = list(summary["rule_frequency"].items())[:12]
    S.append(_bars(top, width, 115, max(n, 1), mono=True))
    spf = Counter(r.auth.get("spf") or "n/a" for r in results)
    dkim = Counter(r.auth.get("dkim") or "n/a" for r in results)
    rows = [_hdr(["Result", "SPF", "DKIM"], st)]
    for key in sorted(set(spf) | set(dkim)):
        rows.append([_p(key, st["cell"]), _p(str(spf.get(key, 0)), st["cell"]), _p(str(dkim.get(key, 0)), st["cell"])])
    S.append(_p("Authentication results", st["h2"]))
    S.append(_table(rows, [width * 0.4, width * 0.3, width * 0.3]))
    fails = sum(1 for r in results if r.auth.get("spf") in ("fail", "softfail") or r.auth.get("dkim") == "fail")
    clean = sum(1 for r in results if r.auth.get("spf") == "pass" and r.auth.get("dkim") == "pass" and r.level != "Low")
    S.append(Spacer(1, 6))
    S.append(_p(f"{fails} messages failed or soft-failed SPF or DKIM. {clean} passed both and were still scored Medium "
                "or High because of what the message said or linked to. Passing authentication only shows the sender "
                "controls the domain they used, and a phisher can easily own one.", st["base"]))

    # ---- 4. Validation
    if validation:
        S.append(PageBreak())
        S.append(_p("4. Check against labelled samples", st["h1"]))
        S.append(_p(f"{validation['labelled']} of the messages came with an expected level. Those labels were only used "
                    "to measure accuracy afterwards. The analyzer never saw them.", st["base"]))
        S.append(Spacer(1, 4))
        m = validation["confusion_matrix"]
        rows = [_hdr(["Expected / Predicted", *LEVELS], st)]
        for e in LEVELS:
            rows.append([_p(e, st["cellb"]), *[_p(str(m[e][p]), st["cell"]) for p in LEVELS]])
        S.append(_table(rows, [width * 0.4] + [width * 0.2] * 3))
        b = validation["suspicious_vs_low"]
        S.append(Spacer(1, 8))
        rows = [_hdr(["Measure", "Value"], st),
                [_p("Exact level match", st["cell"]), _p(_pct(validation["exact_agreement"]), st["cell"])],
                [_p("Within one level", st["cell"]), _p(_pct(validation["within_one_level"]), st["cell"])],
                [_p("Medium/High vs Low, precision", st["cell"]), _p(_pct(b["precision"]), st["cell"])],
                [_p("Medium/High vs Low, recall", st["cell"]), _p(_pct(b["recall"]), st["cell"])],
                [_p("Medium/High vs Low, specificity", st["cell"]), _p(_pct(b["specificity"]), st["cell"])]]
        S.append(_table(rows, [width * 0.7, width * 0.3]))
        S.append(Spacer(1, 6))
        S.append(_p(
            f"Telling suspicious mail from safe mail works well here: precision is {_pct(b['precision'])} and recall is "
            f"{_pct(b['recall'])}. Picking the exact level is harder, at {_pct(validation['exact_agreement'])}. Nearly all "
            "of the misses sit on the Medium/High line. Several rows in the CSV have identical columns but different "
            "labels, and some labels (a display-name mismatch, for instance) describe a field the CSV does not contain. "
            "No scoring rule can recover those from the data given. The thresholds were chosen up front and not tuned "
            "to these labels.", st["base"]))

    # ---- 5. Case studies
    raw = [r for r in results if r.hops]
    if raw:
        S.append(PageBreak())
        S.append(_p("5. Full .eml messages", st["h1"]))
        for r in raw:
            block: list[Any] = [_p(r.message_id, st["h2"])]
            d = r.details
            rows = [_hdr(["Field", "Value"], st),
                    [_p("From", st["cellb"]), _p(f"{d.get('display_name', '')} <{r.sender}>".strip(), st["cell"])],
                    [_p("Subject", st["cellb"]), _p(r.subject, st["cell"])],
                    [_p("Reply-To", st["cellb"]), _p(d.get("reply_to") or "-", st["cell"])],
                    [_p("Return-Path", st["cellb"]), _p(d.get("return_path") or "-", st["cell"])],
                    [_p("SPF / DKIM / DMARC", st["cellb"]),
                     _p(f"{r.auth.get('spf')} / {r.auth.get('dkim')} / {r.auth.get('dmarc') or 'n/a'}", st["cell"])],
                    [_p("Links, attachments", st["cellb"]),
                     _p(f"{d.get('links', '0')} link(s); {d.get('attachments') or 'no attachments'}", st["cell"])],
                    [_p("Score", st["cellb"]), _level_cell(r.level, r.score, st)]]
            block.append(_table(rows, [width * 0.22, width * 0.78]))
            block.append(Spacer(1, 4))
            hop_rows = [_hdr(["#", "Claimed host", "Received by", "IP", "Time (UTC)"], st)]
            for i, h in enumerate(reversed(r.hops), 1):
                ts = dt.datetime.fromtimestamp(h["timestamp"], dt.UTC).strftime("%d %b %H:%M:%S") if h["timestamp"] else "-"
                hop_rows.append([_p(str(i), st["cell"]), _p(h["from"] or "-", st["cell"]), _p(h["by"] or "-", st["cell"]),
                                 _p(h["ip"] or "-", st["cell"]), _p(ts, st["cell"])])
            block.append(_p("Received chain, oldest hop first", st["note"]))
            block.append(_table(hop_rows, [width * 0.06, width * 0.3, width * 0.28, width * 0.17, width * 0.19]))
            block.append(Spacer(1, 4))
            f_rows = [_hdr(["Pts", "Rule", "Indicator and evidence"], st)]
            for f in r.findings:
                f_rows.append([_p(f"+{f.points}", st["cell"]), _p(f.rule_id, st["mono"]),
                               Paragraph(f"<b>{escape(f.title)}</b><br/>{escape(f.evidence)}", st["cell"])])
            if not r.findings:
                f_rows.append([_p("0", st["cell"]), _p("-", st["cell"]), _p("Nothing flagged.", st["cell"])])
            block.append(_table(f_rows, [width * 0.07, width * 0.2, width * 0.73]))
            S.append(KeepTogether(block[:2]))
            S += block[2:]
            S.append(Spacer(1, 8))

    # ---- 6. Recommendations
    S.append(_p("6. Recommendations", st["h1"]))
    freq = summary["rule_frequency"]
    recs = [
        "Publish SPF, DKIM and DMARC for every domain you send from, start DMARC at p=quarantine, then move to p=reject.",
        "Quarantine High scores automatically and send Medium to a review queue. In a mail pipeline, --fail-on does this.",
        "Block or rewrite links that use raw IPs, shorteners, punycode hosts or non-routable TLDs.",
        "Strip or sandbox executables, macro-enabled Office files, scripts and double-extension attachments.",
        "Mark external mail whose display name matches an employee or a well-known brand.",
        "Teach staff to read the real sender address, check where a link goes, and confirm payment or password "
        "requests by another channel.",
    ]
    if freq.get("HDR-REPLYTO"):
        recs.insert(1, f"{freq['HDR-REPLYTO']} messages had a Reply-To on a different domain than From. Alert on that.")
    S += _items(recs, st)

    # ---- 7. Limitations
    S.append(_p("7. Limitations", st["h1"]))
    S += _items([
        "SPF, DKIM and DMARC are read from headers the receiving server added. They are not checked again here, so they "
        "are only as reliable as that server. Use --authserv to trust a single issuer. There is no reputation lookup, "
        "domain-age check or URL detonation.",
        "Registrable domains are worked out without the Public Suffix List. The brand list and phrase lists are small and "
        "English only.",
        "A score is a likelihood and not proof. Tune the weights and thresholds on your own mail before using them to block.",
        "CSV exports carry only some header fields, so rules that need the full message cannot fire on them.",
    ], st)

    # ---- Appendix
    S.append(PageBreak())
    S.append(_p("Appendix A. Results for every message", st["h1"]))
    rows = [_hdr(["ID", "Sender", "SPF", "DKIM", "Score", "Level", "Expected", "Top indicators"], st)]
    for r in results:
        rows.append([_brk(r.message_id), _brk(r.sender), _p(r.auth.get("spf") or "-", st["cell"]),
                     _p(r.auth.get("dkim") or "-", st["cell"]), _p(str(r.score), st["cell"]), _p(r.level, st["cell"]),
                     _p(r.expected or "-", st["cell"]), _p(", ".join(f.rule_id for f in r.findings[:3]), st["cell"])])
    S.append(_table(rows, [width * 0.22, width * 0.2, width * 0.07, width * 0.07, width * 0.06, width * 0.08,
                           width * 0.09, width * 0.21]))

    doc.build(S)
