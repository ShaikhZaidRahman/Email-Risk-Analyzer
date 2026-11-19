"""Input adapters: .eml files, directories, stdin and CSV exports."""

from __future__ import annotations

import csv
import logging
import sys
from collections.abc import Iterator
from pathlib import Path

from .config import Config
from .domains import make_url_ref
from .engine import analyze_evidence, analyze_message_bytes
from .models import Analysis, Evidence

log = logging.getLogger(__name__)

_VALID_AUTH = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
_REQUIRED_CSV = {"MessageID", "From"}


class InputError(Exception):
    """Unreadable or malformed input."""


def _norm_auth(value: str) -> str | None:
    value = (value or "").strip().lower()
    return value if value in _VALID_AUTH else None


def _addr(value: str) -> str:
    return (value or "").strip().lower()


def _iter_csv(path: Path, cfg: Config) -> Iterator[Analysis]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            missing = _REQUIRED_CSV - set(reader.fieldnames or [])
            if missing:
                raise InputError(f"{path}: CSV missing required column(s): {sorted(missing)}")
            for line, row in enumerate(reader, start=2):
                try:
                    yield _analyze_row(row, path, cfg)
                except (KeyError, ValueError) as exc:
                    log.warning("%s line %d skipped: %s", path, line, exc)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc


def _analyze_row(row: dict[str, str], path: Path, cfg: Config) -> Analysis:
    sender = _addr(row.get("From", ""))
    if "@" not in sender:
        raise ValueError(f"invalid From address {sender!r}")
    reply = _addr(row.get("ReplyTo", ""))
    link = make_url_ref(row.get("BodyLinkDomain", ""))
    attach = (row.get("HasAttachment") or "").strip().lower() in {"yes", "y", "true", "1"}
    ev = Evidence(
        message_id=(row.get("MessageID") or "").strip(),
        source=str(path),
        from_addr=sender,
        reply_to=(reply,) if reply else (),
        subject=(row.get("Subject") or "").strip(),
        spf=_norm_auth(row.get("SPF", "")),
        dkim=_norm_auth(row.get("DKIM", "")),
        urls=(link,) if link else (),
        unknown_attachment=attach,
    )
    result = analyze_evidence(ev, cfg)
    result.expected = (row.get("ExpectedLabel") or "").strip().title() or None
    result.primary_indicator = (row.get("PrimaryIndicator") or "").strip() or None
    return result


def _iter_files(paths: list[str]) -> Iterator[Path | None]:
    for raw in paths:
        if raw == "-":
            yield None
            continue
        p = Path(raw)
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in {".eml", ".csv"})
        elif p.is_file():
            yield p
        else:
            raise InputError(f"no such file or directory: {raw}")


def iter_analyses(paths: list[str], cfg: Config) -> Iterator[Analysis]:
    """Yield an :class:`Analysis` for every message found under ``paths``."""
    found = False
    for p in _iter_files(paths):
        if p is None:
            found = True
            yield analyze_message_bytes(sys.stdin.buffer.read(cfg.max_message_bytes + 1), cfg, "<stdin>")
        elif p.suffix.lower() == ".csv":
            for result in _iter_csv(p, cfg):
                found = True
                yield result
        else:
            try:
                if p.stat().st_size > cfg.max_message_bytes:
                    raise ValueError("file too large")
                found = True
                yield analyze_message_bytes(p.read_bytes(), cfg, str(p))
            except (OSError, ValueError) as exc:
                log.warning("skipping %s: %s", p, exc)
    if not found:
        raise InputError("no messages found in the given inputs")
