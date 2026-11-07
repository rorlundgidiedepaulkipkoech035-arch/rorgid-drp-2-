"""Tests for the scraper helpers and the KE-CIRT reporter (no browser or real email needed)."""
import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["DRP_DB"] = os.path.join(tempfile.mkdtemp(), "w.db")

import smtplib  # noqa: E402
from src import db  # noqa: E402
from src.remediation import reporting_bot  # noqa: E402
from src.workers import tasks  # noqa: E402


class ScraperHelperTests(unittest.TestCase):
    def test_public_vs_private_addresses(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.20", "172.16.3.4", "169.254.169.254", "::1", "0.0.0.0"):
            self.assertFalse(tasks.is_public_ip(ip), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(tasks.is_public_ip(ip), ip)

    def test_resolve_refuses_internal_hosts(self):
        fake = lambda ip: (lambda *a, **k: [(2, 1, 6, "", (ip, 443))])
        self.assertEqual(tasks.resolve_public("ok.example", resolver=fake("93.184.216.34")), "93.184.216.34")
        for bad in ("127.0.0.1", "10.1.2.3", "169.254.169.254"):
            with self.assertRaises(ValueError):
                tasks.resolve_public("evil.example", resolver=fake(bad))
        mixed = lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("10.0.0.9", 443))]
        with self.assertRaises(ValueError):                       # one internal address is enough to refuse
            tasks.resolve_public("sneaky.example", resolver=mixed)

    def test_find_serials(self):
        html = "<p>RGD-2026-9F3A1C7E and rgd-2026-9f3a1c7e and RGD-26-1 and RGD-2026-ABCDEF12</p>"
        self.assertEqual(tasks.find_serials(html), ["RGD-2026-9F3A1C7E", "RGD-2026-ABCDEF12"])

    def test_process_rejects_bad_and_internal_domains(self):
        self.assertEqual(asyncio.run(tasks.process_suspicious_domain("not a domain"))["error"], "invalid domain")
        real = tasks.resolve_public
        tasks.resolve_public = lambda d: (_ for _ in ()).throw(ValueError("refused: resolves to a non-public address (10.0.0.1)"))
        try:
            self.assertIn("non-public", asyncio.run(tasks.process_suspicious_domain("internal.example.com"))["error"])
        finally:
            tasks.resolve_public = real

    def test_registered_photo_hash_lookup(self):
        db.init_db()
        cid = db.create_company({"legal_name": "W", "registration_number": "W-1", "official_email": "a@w.com"},
                                ["wbrand"], ["w.com"], "a@w.com", "x")
        db.save_document(cid, "trademark_photo", "logo.png", f"{cid}/h.png", "image/png", 1, "ab" * 32, "RGD-2026-11112222")
        db.save_document(cid, "kra_pin_cert", "kra.pdf", f"{cid}/k.pdf", "application/pdf", 1, "cd" * 32, "RGD-2026-33334444")
        self.assertEqual(db.serial_by_hash("ab" * 32), "RGD-2026-11112222")
        self.assertIsNone(db.serial_by_hash("cd" * 32))               # only trademark photos count as logo copies
        self.assertIsNone(db.serial_by_hash("ef" * 32))


class ReporterTests(unittest.TestCase):
    def test_report_email_contents_and_attachment(self):
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=0): sent["conn"] = (host, port)
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, context=None): sent["tls"] = True
            def login(self, u, p): sent["login"] = u
            def send_message(self, m): sent["msg"] = m
        real = smtplib.SMTP
        smtplib.SMTP = FakeSMTP
        shot = os.path.join(tempfile.mkdtemp(), "evil_com.png")
        open(shot, "wb").write(b"\x89PNG\r\n\x1a\nfake")
        try:
            r = reporting_bot.ThreatReporter("smtp.example", 587, "sec@brand.co.ke", "pw", recipient="cert@example.go.ke")
            r.dispatch_kecirt_report("evil.com", "ab" * 32, "RGD-2026-11112222", shot)
        finally:
            smtplib.SMTP = real
        m = sent["msg"]
        self.assertEqual((m["To"], m["From"]), ("cert@example.go.ke", "sec@brand.co.ke"))
        self.assertIn("evil.com", m["Subject"])
        body = m.get_body().get_content()
        self.assertIn("ab" * 32, body)
        self.assertIn("RGD-2026-11112222", body)
        self.assertEqual([p.get_filename() for p in m.iter_attachments()], ["evil_com.png"])
        self.assertTrue(sent["tls"] and sent["login"] == "sec@brand.co.ke")

    def test_refuses_without_recipient(self):
        os.environ.pop("KECIRT_REPORT_TO", None)
        with self.assertRaises(RuntimeError):
            reporting_bot.ThreatReporter("s", 587, "a@b.c", "p").dispatch_kecirt_report("x.com", "h", None, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
