"""Launcher so the tool runs straight from a checkout: ``py email_risk_analyzer.py --help``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from emailrisk.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
