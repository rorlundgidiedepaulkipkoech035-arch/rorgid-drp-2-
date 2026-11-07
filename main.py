import asyncio
import logging
import os
import threading
import time
from collections import OrderedDict

import certstream

from src import db
from src.config import settings
from src.tenants import TenantRegistry
from src.workers.tasks import process_suspicious_domain
from src.remediation.reporting_bot import ThreatReporter

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("DRP-Orchestrator")

ARTIFACT_DIR = "./artifacts"
CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
MAX_CONCURRENT_SCRAPES = int(os.getenv("MAX_CONCURRENT_SCRAPES", "3"))
MAX_PENDING = int(os.getenv("MAX_PENDING", "200"))
SEEN_CACHE_SIZE = int(os.getenv("SEEN_CACHE_SIZE", "50000"))
REPORT_POLL_SECONDS = int(os.getenv("REPORT_POLL_SECONDS", "30"))

# Platform-wide switch. Even when true, a company must also enable auto_report in its own settings.
# Default: nothing is sent to KE-CIRT until a company admin approves the finding in the dashboard.
AUTO_REPORT = os.getenv("DRP_AUTO_REPORT", "false").lower() == "true"


def build_reporter():
    server, sender, password = (os.getenv(k) for k in ("SMTP_SERVER", "SMTP_SENDER", "SMTP_PASSWORD"))
    if not (server and sender and password):
        logger.warning("SMTP_SERVER / SMTP_SENDER / SMTP_PASSWORD not set; email reporting disabled.")
        return None
    return ThreatReporter(smtp_server=server, smtp_port=int(os.getenv("SMTP_PORT", "587")),
                          sender_email=sender, sender_password=password)


reporter = build_reporter()
registry = TenantRegistry()

# Callback is synchronous (certstream), so async work runs on a dedicated loop in its own thread.
_loop = asyncio.new_event_loop()
_scrape_slots = asyncio.Semaphore(MAX_CONCURRENT_SCRAPES)
_pending = 0
_pending_lock = threading.Lock()
_seen = OrderedDict()
_seen_lock = threading.Lock()


def _run_loop():
    asyncio.set_event_loop(_loop)
    _loop.run_forever()


def _already_seen(key) -> bool:
    with _seen_lock:
        if key in _seen:
            _seen.move_to_end(key)
            return True
        _seen[key] = time.time()
        if len(_seen) > SEEN_CACHE_SIZE:
            _seen.popitem(last=False)
        return False


def _done(future):
    global _pending
    with _pending_lock:
        _pending -= 1
    if future.exception():
        logger.error(f"[-] Pipeline task crashed: {future.exception()!r}")


def submit_threat(domain, reason, company_id, company_auto_report):
    global _pending
    with _pending_lock:
        if _pending >= MAX_PENDING:
            logger.warning(f"[!] Backlog full ({MAX_PENDING}); dropping {domain}")
            return
        _pending += 1
    fut = asyncio.run_coroutine_threadsafe(
        handle_threat_lifecycle(domain, reason, company_id, company_auto_report), _loop)
    fut.add_done_callback(_done)


def certstream_callback(message, context):
    """Runs for every certificate issued worldwide: keep it fast, never scrape here."""
    if message.get("message_type") != "certificate_update":
        return
    try:
        for domain in message.get("data", {}).get("leaf_cert", {}).get("all_domains", []):
            domain = domain.lower().lstrip("*.")
            for hit in registry.evaluate(domain):
                if _already_seen((hit.company_id, domain)):
                    continue
                logger.warning(f"[!] POTENTIAL INFRINGEMENT: {domain} -> company {hit.company_id} ({hit.reason})")
                submit_threat(domain, hit.reason, hit.company_id, hit.auto_report)
    except Exception as e:
        logger.error(f"[-] Error processing Certstream message: {e!r}")


async def send_report(finding) -> bool:
    if reporter is None:
        logger.error("[-] Cannot report: SMTP not configured")
        return False
    try:
        await asyncio.get_running_loop().run_in_executor(
            None, lambda: reporter.dispatch_kecirt_report(
                target_domain=finding["domain"], sha256_hash=finding["sha256"],
                serial_number=finding["serial"], screenshot_path=finding["screenshot"]))
        logger.info(f"[*] Takedown notice sent to KE-CIRT/CC for {finding['domain']}")
        return True
    except Exception as e:
        logger.error(f"[-] Failed to send KE-CIRT report for {finding['domain']}: {e!r}")
        return False


async def report_pending_once():
    """Sends findings a company admin approved in the dashboard."""
    for f in await asyncio.to_thread(db.fetch_approved_findings):
        ok = await send_report(f)
        await asyncio.to_thread(db.mark_reported, f["id"], ok)


async def report_loop():
    while True:
        try:
            await report_pending_once()
        except Exception as e:
            logger.error(f"[-] Report loop error: {e!r}")
        await asyncio.sleep(REPORT_POLL_SECONDS)


async def handle_threat_lifecycle(domain, reason="", company_id=None, company_auto_report=False):
    """Scrape evidence + hash + serial check, then store the finding for the company's dashboard."""
    async with _scrape_slots:
        logger.info(f"[*] Initiating triage and evidence collection for: {domain}")
        try:
            result = await process_suspicious_domain(domain)
        except Exception as e:
            logger.error(f"[-] Scrape crashed for {domain}: {e!r}")
            return
    if "error" in result:
        logger.error(f"[-] Scrape failed for {domain}: {result['error']}")
        return

    serial = result.get("serial_detected")
    if serial:
        owner = await asyncio.to_thread(db.serial_owner, serial)
        if owner is None:
            pass                                    # serial from the scraper's own watermark check: keep as before
        elif owner == company_id:
            reason += " | key serial matches this company's registered asset"
        else:
            serial = None                           # another company's asset: not evidence for this company
    screenshot = os.path.join(ARTIFACT_DIR, f"{domain.replace('.', '_')}.png")
    fid = await asyncio.to_thread(db.add_finding, company_id, domain, reason, result.get("sha256"), serial, screenshot)
    if fid is None:
        return  # already stored for this company
    if serial:
        logger.critical(f"[!] CONFIRMED WATERMARK MATCH! Serial: {serial} on {domain} (company {company_id})")
    else:
        logger.info(f"[+] {domain} stored for company {company_id}; awaiting review.")

    if serial and AUTO_REPORT and company_auto_report:
        finding = {"domain": domain, "sha256": result.get("sha256"), "serial": serial, "screenshot": screenshot}
        ok = await send_report(finding)
        await asyncio.to_thread(db.mark_reported, fid, ok)


def start_engine():
    db.init_db()
    threading.Thread(target=_run_loop, name="drp-async-loop", daemon=True).start()
    asyncio.run_coroutine_threadsafe(report_loop(), _loop)
    logger.info(f"[*] Starting {settings.PROJECT_NAME} (platform auto-report: {AUTO_REPORT})")
    backoff = 1
    try:
        while True:
            try:
                certstream.listen_for_events(certstream_callback, url=CERTSTREAM_URL)
                backoff = 1
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"[-] Certstream connection lost: {e!r}; retrying in {backoff}s")
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)
    except KeyboardInterrupt:
        logger.info("[*] Shutting down DRP Engine gracefully.")
        _loop.call_soon_threadsafe(_loop.stop)


if __name__ == "__main__":
    start_engine()
