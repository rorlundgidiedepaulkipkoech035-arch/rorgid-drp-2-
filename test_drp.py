"""Offline tests: detection + engine pipeline (stubs replace certstream, Playwright worker and SMTP)."""
import asyncio
import os
import sys
import tempfile
import time
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(tempfile.mkdtemp(), "engine.db")
os.environ["DRP_DB"] = DB_FILE
os.environ.update(SMTP_SERVER="x", SMTP_SENDER="a@b.c", SMTP_PASSWORD="p", REGISTRY_REFRESH_SECONDS="0")

sent_reports = []


class FakeReporter:
    def __init__(self, **kw):
        pass

    def dispatch_kecirt_report(self, **kw):
        sent_reports.append(kw)


async def fake_process(domain):
    if "boom" in domain:
        raise RuntimeError("playwright died")
    if "fail" in domain:
        return {"error": "timeout"}
    if "owned" in domain:
        return {"sha256": "cd" * 32, "serial_detected": os.environ["TEST_OWNED_SERIAL"]}
    return {"sha256": "ab" * 32, "serial_detected": "SN-12345" if "login" in domain else None}


def stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m


stub("certstream", listen_for_events=lambda *a, **k: None)
stub("src.config", settings=types.SimpleNamespace(PROJECT_NAME="DRP-Test"))
stub("src.workers.tasks", process_suspicious_domain=fake_process)
stub("src.remediation.reporting_bot", ThreatReporter=FakeReporter)

from src import db  # noqa: E402
from src.detection import assess_domain, split_domain  # noqa: E402
import main  # noqa: E402

BRANDS, LEGIT = ["yourbrand"], ["yourbrand.com", "yourbrand.co.ke"]


class DetectionTests(unittest.TestCase):
    def flagged(self, d):
        return assess_domain(d, BRANDS, LEGIT) is not None

    def test_legit_not_flagged(self):
        for d in ["yourbrand.com", "www.yourbrand.com", "mail.yourbrand.co.ke", "*.yourbrand.com",
                  "google.com", "example.org", "brandnew.com"]:
            self.assertFalse(self.flagged(d), d)

    def test_typosquats_flagged(self):
        for d in ["yourbrnad.com", "yourbrand.xyz", "yourbrand-login.com", "secure-yourbrand.net",
                  "y0urbrand.com", "yourbrannd.com", "yourbrand.com.evil.xyz", "login.yourbrand.evil.top"]:
            self.assertTrue(self.flagged(d), d)

    def test_cyrillic_homoglyph(self):
        self.assertTrue(self.flagged("yоurbrand.com"))

    def test_split_domain(self):
        self.assertEqual(split_domain("a.b.brand.co.ke")[1:], ("brand", "co.ke"))


def make_company(reg, brand, domain, approve=True):
    cid = db.create_company({"legal_name": f"Co {reg}", "registration_number": reg, "official_email": f"info@{domain}"},
                            [brand], [domain], f"admin@{domain}", "x")
    if approve:
        db.set_company_status(cid, "approved")
    return cid


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["DRP_DB"] = DB_FILE
        db.init_db()
        cls.a = make_company("A-1", "yourbrand", "yourbrand.com")
        cls.b = make_company("B-1", "otherbrand", "otherbrand.com")
        cls.c = make_company("C-1", "pendingbrand", "pendingbrand.com", approve=False)
        if not any(t.name == "drp-async-loop" for t in __import__("threading").enumerate()):
            __import__("threading").Thread(target=main._run_loop, name="drp-async-loop", daemon=True).start()

    def feed(self, *domains):
        main.registry.invalidate()
        main.certstream_callback(
            {"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": list(domains)}}}, None)
        time.sleep(0.6)

    def test_1_findings_are_tenant_scoped(self):
        self.feed("yourbrand-login.com", "www.yourbrand.com", "yourbrnad.net", "otherbrand-shop.com",
                  "pendingbrand-login.com", "yourbrand-login.com")
        a = sorted(f["domain"] for f in db.list_findings(self.a))
        b = [f["domain"] for f in db.list_findings(self.b)]
        self.assertEqual(a, ["yourbrand-login.com", "yourbrnad.net"])   # no legit, no dupes
        self.assertEqual(b, ["otherbrand-shop.com"])
        self.assertEqual(db.list_findings(self.c), [])                  # unapproved company not monitored
        self.assertEqual(sent_reports, [])                              # nothing sent without approval

    def test_2_scrape_errors_dont_kill_pipeline(self):
        self.feed("yourbrand-fail.com", "yourbrand-boom.com", "yourbrand-ok.com")
        doms = [f["domain"] for f in db.list_findings(self.a)]
        self.assertIn("yourbrand-ok.com", doms)
        self.assertNotIn("yourbrand-fail.com", doms)

    def test_3_report_only_after_admin_approval(self):
        f = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-login.com"][0]
        self.assertFalse(db.set_finding_status(self.a, f["id"], "approved_for_report"))  # must be confirmed first
        self.assertTrue(db.set_finding_status(self.a, f["id"], "confirmed"))
        self.assertTrue(db.set_finding_status(self.a, f["id"], "approved_for_report"))
        asyncio.run_coroutine_threadsafe(main.report_pending_once(), main._loop).result(5)
        self.assertEqual(len(sent_reports), 1)
        self.assertEqual(sent_reports[0]["serial_number"], "SN-12345")
        self.assertEqual(db.get_finding(self.a, f["id"])["status"], "reported")

    def test_5_registered_key_serial_is_recognised(self):
        db.save_document(self.a, "trademark_photo", "logo.png", f"{self.a}/x.png", "image/png", 1, "ef" * 32, "RGD-2026-0000AAAA")
        os.environ["TEST_OWNED_SERIAL"] = "RGD-2026-0000AAAA"
        self.feed("yourbrand-owned.com")
        f = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-owned.com"][0]
        self.assertIn("key serial matches this company's registered asset", f["reason"])

    def test_6_other_companys_serial_is_not_evidence(self):
        db.save_document(self.b, "trademark_photo", "logo.png", f"{self.b}/y.png", "image/png", 1, "12" * 32, "RGD-2026-0000BBBB")
        os.environ["TEST_OWNED_SERIAL"] = "RGD-2026-0000BBBB"          # belongs to company B, found on a site flagged for A
        self.feed("yourbrand-owned2.com")
        f = [x for x in db.list_findings(self.a) if x["domain"] == "yourbrand-owned2.com"][0]
        self.assertIsNone(f["serial"])

    def test_4_other_company_cannot_touch_finding(self):
        f = db.list_findings(self.a)[0]
        self.assertIsNone(db.get_finding(self.b, f["id"]))
        self.assertFalse(db.set_finding_status(self.b, f["id"], "dismissed"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
