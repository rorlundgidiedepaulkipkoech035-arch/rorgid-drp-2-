"""Backend demo: walks the whole platform through its real code (no browser) and prints what happened.
Run:  python demo_backend.py        (uses a temporary database, stub scraper and a captured email)"""
import hashlib
import io
import os
import re
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
tmp = tempfile.mkdtemp()
os.environ.update(DRP_DB=f"{tmp}/demo.db", UPLOAD_DIR=f"{tmp}/uploads", ARTIFACT_DIR=f"{tmp}/art",
                  SECRET_KEY="demo-backend", REGISTRY_REFRESH_SECONDS="0", SMTP_SERVER="x", SMTP_SENDER="a@b.c", SMTP_PASSWORD="p")
reports = []


class FakeReporter:                       # stands in for your SMTP reporter
    def __init__(self, **kw): pass
    def dispatch_kecirt_report(self, **kw): reports.append(kw)


async def fake_scrape(domain):            # stands in for Playwright + steganography check
    return {"sha256": hashlib.sha256(domain.encode()).hexdigest(), "serial_detected": "SN-777" if "login" in domain else None}


def stub(name, **attrs):
    m = types.ModuleType(name); m.__dict__.update(attrs); sys.modules[name] = m


stub("certstream", listen_for_events=lambda *a, **k: None)
stub("src.config", settings=types.SimpleNamespace(PROJECT_NAME="DRP"))
stub("src.workers.tasks", process_suspicious_domain=fake_scrape)
stub("src.remediation.reporting_bot", ThreatReporter=FakeReporter)

import threading  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
from dashboard.app import create_app  # noqa: E402
from src import db, mailer, security  # noqa: E402
import main  # noqa: E402

PW = "Savannah-Admin-2026!"
ok_count = fail_count = 0


def step(title):
    print(f"\n=== {title}")


def check(label, cond, detail=""):
    global ok_count, fail_count
    ok_count += cond; fail_count += (not cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  -> {detail}" if detail else ""))


def token(c, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


app = create_app()
db.create_user(None, "root@platform.io", generate_password_hash("Platform-Root-1!"), "platform_admin")
client = app.test_client()
inbox = []
mailer.send_mail = lambda to, subject, body: inbox.append((to, subject, body)) or True
threading.Thread(target=main._run_loop, daemon=True).start()

step("1. Password rules (8+ chars, upper, lower, special)")
for pw in ("short", "alllowercase1!", "NoSpecial123", PW):
    p = security.password_problem(pw)
    check(f"{pw!r}", (p is None) == (pw == PW), p or "accepted")

step("2. Company registration")
form = dict(legal_name="Savannah Tech Ltd", registration_number="PVT-2024-05512", official_email="info@savannahtech.co.ke",
            phone="0700", website="https://savannahtech.co.ke", address="Thika Road, Nairobi", country="Kenya",
            brands="savannahtech, savannahpay", domains="savannahtech.co.ke, savannahpay.com",
            admin_email="wanjiku@savannahtech.co.ke", password=PW, password2=PW)
bad = client.post("/register", data={**form, "admin_email": "wanjiku@gmail.com", "csrf_token": token(client, "/register")})
check("admin email outside company domains is rejected", bad.status_code == 400)
r = client.post("/register", data={**form, "csrf_token": token(client, "/register")})
cid = db.get_user_by_email("wanjiku@savannahtech.co.ke")["company_id"]
check("registration accepted", r.status_code == 302)
check("company starts as pending (not monitored)", db.get_company(cid)["status"] == "pending" and db.registry_snapshot() == [])

step("3. Login -> verification page (front end)")
r = client.post("/login", data={"email": "wanjiku@savannahtech.co.ke", "password": PW, "csrf_token": token(client)})
r = client.get("/dashboard")
check("pending company admin is sent to the verification page", r.status_code == 302 and r.headers["Location"].endswith("/verification"))

step("4. Upload KRA PIN, IP certificate and trademark photo (back end hashes + issues key serials)")
files = {"kra_pin_cert": (b"%PDF-1.4 KRA certificate of Savannah", "kra.pdf"),
         "registration_cert": (b"%PDF-1.4 Certificate of incorporation", "cr12.pdf"),
         "trademark_cert": (b"%PDF-1.4 Trademark registration certificate", "tm.pdf"),
         "trademark_photo": (b"\x89PNG\r\n\x1a\n savannah-logo-pixels", "logo.png")}
r = client.post("/verification/details", data={"kra_pin": "P051234567A", "trademark_number": "TM-2024-0042", "csrf_token": token(client, "/verification")})
check("KRA PIN P051234567A saved", db.get_company(cid)["kra_pin"] == "P051234567A")
for i, (t, (data, name)) in enumerate(files.items()):
    client.post(f"/verification/upload/{t}", content_type="multipart/form-data",
                data={"csrf_token": token(client, "/verification"), "file": (io.BytesIO(data), name)})
    d = [x for x in db.documents(cid) if x["doc_type"] == t][0]
    check(f"{t}: serial {d['serial']}", d["sha256"] == hashlib.sha256(data).hexdigest(), f"sha256 {d['sha256'][:20]}...")
    stored = open(os.path.join(os.environ["UPLOAD_DIR"], d["stored_name"]), "rb").read()
    check(f"{t}: stored file re-hashes to the recorded hash", hashlib.sha256(stored).hexdigest() == d["sha256"])
check("company verified automatically after the last upload", db.get_company(cid)["status"] == "approved")
check("monitoring started for its brands", db.registry_snapshot()[0]["brands"] == ["savannahpay", "savannahtech"])

step("5. Fraud checks")
other = app.test_client()
other.post("/register", data={**form, "legal_name": "Copycat Ltd", "registration_number": "PVT-1", "official_email": "x@copy.co.ke",
                              "brands": "copycat", "domains": "copy.co.ke", "admin_email": "b@copy.co.ke", "csrf_token": token(other, "/register")})
other.post("/login", data={"email": "b@copy.co.ke", "password": PW, "csrf_token": token(other)})
r = other.post("/verification/upload/trademark_photo", content_type="multipart/form-data", follow_redirects=True,
               data={"csrf_token": token(other, "/verification"), "file": (io.BytesIO(files["trademark_photo"][0]), "stolen.png")})
check("the same trademark photo cannot be registered by another company", "already registered" in r.get_data(as_text=True))
r = other.post("/verification/details", data={"kra_pin": "P051234567A", "csrf_token": token(other, "/verification")}, follow_redirects=True)
check("the same KRA PIN cannot be registered twice", "already registered to another company" in r.get_data(as_text=True))
r = other.post("/verification/upload/kra_pin_cert", content_type="multipart/form-data", follow_redirects=True,
               data={"csrf_token": token(other, "/verification"), "file": (io.BytesIO(b"MZ evil.exe"), "kra.pdf")})
check("an .exe renamed .pdf is rejected (real file type is checked)", "Unsupported file" in r.get_data(as_text=True))
doc = db.documents(cid)[0]
check("another company cannot download Savannah's documents", other.get(f"/documents/{doc['id']}").status_code == 404)

step("6. Engine: certificate stream -> detection -> findings in the dashboard")
main.registry.invalidate()
main.certstream_callback({"message_type": "certificate_update", "data": {"leaf_cert": {"all_domains": [
    "savannahtech-login.com", "savannahtec.co.ke", "www.savannahtech.co.ke", "unrelated.org"]}}}, None)
time.sleep(0.8)
found = sorted(f["domain"] for f in db.list_findings(cid))
check("typosquats flagged, own subdomain and unrelated domains ignored", found == ["savannahtec.co.ke", "savannahtech-login.com"], str(found))
page = client.get("/dashboard").get_data(as_text=True)
check("overview shows KPI cards, donut and 14-day chart", "kpi" in page and "stroke-dasharray" in page and page.count('class="bar"') == 14)

step("7. Takedown only after a company admin approves")
f = [x for x in db.list_findings(cid) if x["domain"] == "savannahtech-login.com"][0]
check("nothing sent automatically", reports == [])
client.post(f"/findings/{f['id']}/confirm", data={"csrf_token": token(client, "/dashboard")})
client.post(f"/findings/{f['id']}/report", data={"csrf_token": token(client, "/dashboard")})
import asyncio  # noqa: E402
asyncio.run_coroutine_threadsafe(main.report_pending_once(), main._loop).result(5)
check("report sent to KE-CIRT/CC after approval", len(reports) == 1 and reports[0]["target_domain"] == "savannahtech-login.com")
check("finding marked reported", db.get_finding(cid, f["id"])["status"] == "reported")

step("8. Forgot password (code sent to the registered email)")
client2 = app.test_client()
client2.post("/forgot-password", data={"email": "wanjiku@savannahtech.co.ke", "csrf_token": token(client2, "/forgot-password")})
to, subject, body = inbox[-1]
code = re.search(r"code is (\d{6})", body).group(1)
check(f"6-digit code emailed to {to}", to == "wanjiku@savannahtech.co.ke" and len(code) == 6, f"subject: {subject}")
r = client2.post("/reset-password", data={"email": to, "code": code, "new": "weakpass", "new2": "weakpass", "csrf_token": token(client2, "/reset-password")})
check("right code but weak new password is refused", r.status_code == 400)
r = client2.post("/reset-password", data={"email": to, "code": code, "new": "Brand-New-Pass9!", "new2": "Brand-New-Pass9!", "csrf_token": token(client2, "/reset-password")})
check("password reset with the code", r.status_code == 302)
r = client2.post("/login", data={"email": to, "password": "Brand-New-Pass9!", "csrf_token": token(client2)})
check("login works with the new password", r.status_code == 302 and r.headers["Location"].endswith("/dashboard"))

print(f"\nResult: {ok_count} passed, {fail_count} failed")
sys.exit(1 if fail_count else 0)
