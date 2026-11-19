"""Email Risk Analyzer: phishing and spoofing triage for raw email and tabular exports."""

from __future__ import annotations

__version__ = "1.0.0"

from .config import Config
from .engine import analyze_evidence, analyze_message_bytes
from .models import Analysis, Finding

__all__ = [
    "Analysis",
    "Config",
    "Finding",
    "__version__",
    "analyze_evidence",
    "analyze_message_bytes",
]
