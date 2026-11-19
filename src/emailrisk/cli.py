"""Command-line interface.

Exit codes: 0 success, 1 a message met ``--fail-on``, 2 usage error, 3 input error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError
from .evaluate import evaluate
from .loader import InputError, iter_analyses
from .models import LEVELS
from .render import to_csv, to_json, to_text

EXIT_OK, EXIT_THRESHOLD, EXIT_INPUT = 0, 1, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="email_risk_analyzer",
        description="Scan emails for phishing and spoofing indicators and score their risk.",
    )
    p.add_argument("inputs", nargs="+", metavar="PATH",
                   help=".eml file, directory (recursive), CSV export, or '-' for stdin")
    p.add_argument("-f", "--format", choices=("text", "json", "csv"), default="text")
    p.add_argument("-o", "--output", type=Path, help="write the main output here instead of stdout")
    p.add_argument("--pdf", type=Path, metavar="FILE", help="also write the PDF audit report")
    p.add_argument("--title", default="Email Security Audit Report", help="title for the PDF report")
    p.add_argument("--author", default="", help="name to print in the PDF report ('Prepared by ...')")
    p.add_argument("--subtitle", default="Phishing risk analysis of email headers, links and content",
                   help="subtitle line for the PDF report")
    p.add_argument("-c", "--config", type=Path, help="JSON file with weights/thresholds/trusted_domains")
    p.add_argument("--trusted-domain", action="append", default=[], metavar="DOMAIN",
                   help="registrable domain whose links are never flagged (repeatable)")
    p.add_argument("--authserv", action="append", default=[], metavar="HOST",
                   help="only trust Authentication-Results issued by this host (repeatable)")
    p.add_argument("--fail-on", choices=("medium", "high"),
                   help="exit with status 1 if any message reaches this level")
    p.add_argument("--summary", action="store_true", help="text format: omit per-finding detail")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose > 1 else logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    overrides = {
        "trusted_domains": frozenset(d.lower() for d in args.trusted_domain),
        "authserv_ids": frozenset(h.lower() for h in args.authserv),
    }
    try:
        cfg = (Config.from_file(args.config, **overrides) if args.config
               else Config(trusted_domains=overrides["trusted_domains"], authserv_ids=overrides["authserv_ids"]))
        results = list(iter_analyses(args.inputs, cfg))
    except (ConfigError, InputError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT

    validation = evaluate(results)
    rendered = {"json": lambda: to_json(results, validation), "csv": lambda: to_csv(results),
                "text": lambda: to_text(results, verbose=not args.summary)}[args.format]()
    try:
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            sys.stdout.write(rendered + "\n")
        if args.pdf:
            from .pdfreport import build_pdf  # optional dependency: reportlab

            build_pdf(results, validation, cfg, args.pdf, title=args.title, author=args.author, subtitle=args.subtitle)
    except ImportError:
        print("error: PDF output needs reportlab (py -m pip install reportlab)", file=sys.stderr)
        return EXIT_INPUT
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return EXIT_INPUT

    if args.fail_on:
        floor = LEVELS.index(args.fail_on.title())
        if any(LEVELS.index(r.level) >= floor for r in results):
            return EXIT_THRESHOLD
    return EXIT_OK
