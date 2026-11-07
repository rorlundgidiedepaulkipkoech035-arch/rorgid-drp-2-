# RORGID Cyber Security: brand-protection platform

Front end: Flask pages (login, registration, verification uploads, forgot password, dashboard).
Back end: validation, hashing, key serial numbers, storage, auto-verification, email codes, detection engine.

## Run for real
See RUN_REAL.md (GitHub Codespaces for testing, Docker for a 24/7 server).

## Quick demo (no certstream / Playwright / SMTP needed)
    pip install flask
    python demo.py              # real app with sample data on http://127.0.0.1:5000
    python demo_backend.py      # back-end walk-through printed in the terminal (32 checks)
    python detection_check.py   # detection test with a FAKE company (22 test domains)

## Real install
    pip install -r requirements.txt
    playwright install chromium
    set SECRET_KEY / SMTP_SERVER / SMTP_SENDER / SMTP_PASSWORD   (PowerShell: $env:NAME="value")
    python -m dashboard.manage create-admin you@yourdomain.com     # or set ADMIN_EMAIL / ADMIN_PASSWORD and run python bootstrap.py
    python serve.py             # dashboard  http://127.0.0.1:8000
    python main.py              # detection engine (second terminal, same folder and variables)

Optional: DRP_DB, UPLOAD_DIR (verification documents, keep private and backed up), ARTIFACT_DIR (screenshots),
SESSION_IDLE_MINUTES (default 30), DRP_AUTO_REPORT, CERTSTREAM_URL.
Never set DRP_SHOW_RESET_CODE in production: it shows the reset code on screen (demo only).

## Flow
1. Company registers (details, brands, domains, admin email on its own domain). Password: 8+ characters with upper, lower and a special character.
2. Company admin logs in and lands on Verification: KRA PIN, certificate of incorporation, IP/trademark certificate, trademark photo.
3. Each file is type-checked by content, hashed (SHA-256) and given a key serial number (RGD-YYYY-XXXXXXXX). The same file or KRA PIN cannot be registered twice.
4. When everything is received the company is verified automatically and monitoring starts. Documents are then locked.
5. Findings appear in the dashboard; analysts review; a company admin approves a takedown report to KE-CIRT/CC.
6. Forgot password: a 6-digit code (15 minutes, 5 tries, 3 requests per hour) is emailed to the registered address.

## Tests (run separately)
    python test_drp.py && python test_dashboard.py
