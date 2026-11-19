# Changelog

## 1.0.1
- PDF report: appendix IDs and senders wrap at "@" instead of being cut off; added subtitle line and optional `--author` / `--subtitle`.

## 1.0.0
- Header parsing: Received chain, Return-Path, Reply-To, Message-ID, Authentication-Results, Received-SPF, DKIM-Signature.
- Link, language and attachment analysis with defanged evidence.
- Additive 0-100 risk score with configurable weights and thresholds.
- Inputs: `.eml`, directories, stdin, CSV exports. Outputs: text, JSON, CSV, PDF audit report.
