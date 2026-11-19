from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from emailrisk import Config, analyze_message_bytes
from emailrisk.cli import main
from emailrisk.config import ConfigError
from emailrisk.domains import defang, lookalike_of, registrable
from emailrisk.evaluate import evaluate
from emailrisk.loader import iter_analyses
from emailrisk.render import to_csv

SAMPLES = ROOT / "samples"


def analyze(name: str, cfg: Config | None = None):
    return analyze_message_bytes((SAMPLES / name).read_bytes(), cfg, name)


def rules(result) -> set[str]:
    return {f.rule_id for f in result.findings}


class DomainTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable("a.b.example.com"), "example.com")
        self.assertEqual(registrable("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable("203.0.113.5"), "203.0.113.5")

    def test_lookalike(self):
        self.assertTrue(lookalike_of("paypa1.com", "paypal.com"))
        self.assertTrue(lookalike_of("examp1e.com", "example.com"))
        self.assertFalse(lookalike_of("example.com", "example.com"))
        self.assertFalse(lookalike_of("example.org", "example.com"))  # common-TLD swap tolerated
        self.assertFalse(lookalike_of("abc.com", "abd.com"))  # too short to judge

    def test_defang(self):
        self.assertEqual(defang("http://a.b/x"), "hxxp://a[.]b/x")


class SampleMessageTests(unittest.TestCase):
    def test_legitimate_is_low(self):
        r = analyze("01_legitimate_notification.eml")
        self.assertEqual((r.score, r.level), (0, "Low"))

    def test_credential_phish(self):
        r = analyze("02_credential_phish.eml")
        self.assertEqual(r.level, "High")
        for rid in ("AUTH-SPF-FAIL", "AUTH-DMARC-FAIL", "HDR-REPLYTO", "HDR-DISPLAYNAME",
                    "LNK-MISMATCH", "LNK-IP", "BODY-FORM", "BODY-URGENCY", "LNK-BRAND"):
            self.assertIn(rid, rules(r))

    def test_double_extension_attachment(self):
        r = analyze("03_malware_attachment.eml")
        self.assertIn("ATT-DOUBLEEXT", rules(r))
        self.assertIn("AUTH-DKIM-WEAK", rules(r))

    def test_bec(self):
        r = analyze("04_ceo_fraud_bec.eml")
        self.assertTrue({"HDR-DISPLAYNAME", "HDR-REPLYTO", "HDR-TIMESKEW"} <= rules(r))

    def test_obfuscated_links(self):
        r = analyze("05_obfuscated_links.eml")
        self.assertTrue({"LNK-USERINFO", "LNK-PUNYCODE", "LNK-SHORTENER", "LNK-IP"} <= rules(r))

    def test_urls_defanged_in_evidence(self):
        for f in analyze("02_credential_phish.eml").findings:
            self.assertNotIn("http://", f.evidence)

    def test_score_capped(self):
        self.assertLessEqual(analyze("05_obfuscated_links.eml").score, 100)


class RobustnessTests(unittest.TestCase):
    def test_garbage_input_does_not_crash(self):
        for blob in (b"", b"\xff\xfe\x00garbage", b"From: \nSubject:\n\n" + b"A" * 100_000):
            r = analyze_message_bytes(blob)
            self.assertIn(r.level, ("Low", "Medium", "High"))

    def test_forged_auth_results_ignored_with_authserv(self):
        raw = (b"Authentication-Results: evil.example.invalid; spf=pass; dkim=pass\r\n"
               b"Authentication-Results: mx.example.org; spf=fail; dkim=fail\r\n"
               b"From: a@example.com\r\n\r\nhi")
        trusted = Config(authserv_ids=frozenset({"mx.example.org"}))
        self.assertEqual(analyze_message_bytes(raw, trusted).auth["spf"], "fail")

    def test_oversize_rejected(self):
        with self.assertRaises(ValueError):
            analyze_message_bytes(b"x" * 20, Config(max_message_bytes=10))

    def test_trusted_domain_suppresses_link_rules(self):
        raw = b"From: a@example.com\r\nContent-Type: text/plain\r\n\r\nsee https://cdn.partner.example.net/x"
        self.assertIn("LNK-UNRELATED", rules(analyze_message_bytes(raw)))
        cfg = Config(trusted_domains=frozenset({"example.net"}))
        self.assertNotIn("LNK-UNRELATED", rules(analyze_message_bytes(raw, cfg)))


class ConfigTests(unittest.TestCase):
    def _write(self, obj) -> Path:
        d = tempfile.mkdtemp()
        p = Path(d) / "c.json"
        p.write_text(json.dumps(obj))
        return p

    def test_override(self):
        cfg = Config.from_file(self._write({"weights": {"HDR-REPLYTO": 30}, "thresholds": {"medium": 10, "high": 40}}))
        self.assertEqual((cfg.w("HDR-REPLYTO"), cfg.medium_threshold, cfg.high_threshold), (30, 10, 40))

    def test_rejects_bad_values(self):
        for bad in ({"weights": {"NOPE": 1}}, {"weights": {"HDR-REPLYTO": 500}},
                    {"thresholds": {"medium": 50, "high": 10}}, {"extra": 1}):
            with self.assertRaises(ConfigError):
                Config.from_file(self._write(bad))


class CsvAndEvaluationTests(unittest.TestCase):
    def test_csv_end_to_end(self):
        results = list(iter_analyses([str(SAMPLES / "email_samples.csv")], Config()))
        self.assertEqual(len(results), 80)
        ev = evaluate(results)
        self.assertEqual(ev["suspicious_vs_low"]["recall"], 1.0)
        self.assertEqual(ev["suspicious_vs_low"]["precision"], 1.0)
        self.assertEqual(ev["within_one_level"], 1.0)

    def test_csv_formula_injection_neutralised(self):
        d = Path(tempfile.mkdtemp()) / "x.csv"
        d.write_text("MessageID,From,Subject\nM1,a@example.com,=HYPERLINK(1)\n")
        out = to_csv(list(iter_analyses([str(d)], Config())))
        self.assertIn("'=HYPERLINK", out)

    def test_missing_columns(self):
        d = Path(tempfile.mkdtemp()) / "x.csv"
        d.write_text("foo,bar\n1,2\n")
        from emailrisk.loader import InputError
        with self.assertRaises(InputError):
            list(iter_analyses([str(d)], Config()))


class CliTests(unittest.TestCase):
    def run_cli(self, *argv) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_json_output(self):
        code, out = self.run_cli(str(SAMPLES / "02_credential_phish.eml"), "-f", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["results"][0]["level"], "High")

    def test_fail_on(self):
        self.assertEqual(self.run_cli(str(SAMPLES / "02_credential_phish.eml"), "--fail-on", "high")[0], 1)
        self.assertEqual(self.run_cli(str(SAMPLES / "01_legitimate_notification.eml"), "--fail-on", "medium")[0], 0)

    def test_missing_input(self):
        self.assertEqual(self.run_cli("/nonexistent/file.eml")[0], 3)

    def test_launcher_script(self):
        p = subprocess.run([sys.executable, str(ROOT / "email_risk_analyzer.py"), "--version"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("1.0.0", p.stdout)

    def test_pdf_generation(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab not installed")
        out = Path(tempfile.mkdtemp()) / "r.pdf"
        self.run_cli(str(SAMPLES), "--summary", "--pdf", str(out))
        self.assertTrue(out.read_bytes().startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
