# Email Risk Analyzer

Static phishing and spoofing triage for email. It parses raw headers, scans links, wording and attachments, assigns a
0-100 risk score with a Low / Medium / High level, and produces an audit report (text, JSON, CSV or PDF).

It is **offline and safe by design**: it never fetches URLs, resolves DNS or opens attachments, and every URL in its
output is defanged (`hxxp://evil[.]example`).

## Quick start

```powershell
py email_risk_analyzer.py samples/02_credential_phish.eml          # one message
py email_risk_analyzer.py samples/ --pdf reports/audit.pdf --summary   # .eml + CSV, with PDF report
py email_risk_analyzer.py mail/ -f json -o results.json --fail-on high # CI / mail-flow gate
Get-Content message.eml -Raw | py email_risk_analyzer.py -        # stdin (PowerShell)
```

Core analysis needs only Python 3.11+ (standard library). The PDF report needs `py -m pip install reportlab`.
Add `--author "Your Name"` to print a "Prepared by" line on the PDF.
Optional install: `py -m pip install .[pdf]` gives an `emailrisk` command.

## What it checks

| Stage | Indicators |
|---|---|
| Headers | SPF / DKIM / DMARC verdicts, DKIM `d=` alignment and weak `rsa-sha1`, Reply-To and Return-Path vs From, display-name spoofing (brand or embedded address), Message-ID domain, missing or time-skewed `Received` chain |
| Links | Anchor text vs href mismatch, raw IP hosts, `user@host` tricks, punycode / non-ASCII hosts, URL shorteners, look-alike and brand-imitating domains, reserved or high-abuse TLDs, unrelated domains, HTTP, password forms |
| Language | Urgency, threat / suspension, credential and payment requests (subject weighted higher) |
| Attachments | Executable / script / macro types, double extensions (`invoice.pdf.exe`), archives |

Each rule fires once per message and adds its weight; the total is capped at 100. Default levels:
Low < 25, Medium 25-59, High >= 60. All weights are in `src/emailrisk/config.py` and can be overridden:

```json
{"weights": {"HDR-REPLYTO": 25}, "thresholds": {"medium": 20, "high": 55}, "trusted_domains": ["partner.example.net"]}
```
Use with `-c config.json`. `--trusted-domain` suppresses link rules for known partners; `--authserv mx.example.org`
trusts only Authentication-Results added by your own gateway (a sender can forge the header otherwise).

## Input formats

* `.eml` files, directories (recursive), or `-` for stdin.
* CSV exports with columns `MessageID, From` and optionally `ReplyTo, Subject, SPF, DKIM, HasAttachment, BodyLinkDomain`.
  If `ExpectedLabel` is present the tool reports accuracy against it (labels are never used as input).

Exit codes: `0` ok, `1` a message reached `--fail-on`, `2` usage error, `3` input/config error.

## Results on the bundled data

`samples/email_samples.csv` (80 synthetic messages) plus five crafted `.eml` files: all 72 suspicious CSV rows and all 8
safe rows are separated correctly (precision / recall 100%), every prediction is within one level of the label, and exact
three-level agreement is 51%. The remainder is not recoverable from the CSV: rows with identical columns carry different
labels, and labels such as "display-name mismatch" refer to fields the export does not contain. Details and the full
confusion matrix are in `reports/Phishing_Analysis_Report.pdf`.

## Layout

```
email_risk_analyzer.py   launcher (run from a checkout)
src/emailrisk/           parser, rules, engine, loader, renderers, PDF report, CLI
tests/                   py -m unittest discover -s tests
samples/                 synthetic training emails (example.* / .invalid domains only)
reports/                 generated audit report and result files
```

## Limitations

SPF/DKIM/DMARC are read from receiver headers, not re-verified. Registrable-domain detection is heuristic (no Public
Suffix List), and brand and phrase lists are English-centric and small. Scores indicate likelihood, not proof: tune on your
own mail before using `--fail-on` to block. Test only mail you are authorised to analyse.
