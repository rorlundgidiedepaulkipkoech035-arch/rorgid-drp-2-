# Run the real system from GitHub (not the demo)

This starts the real website and the real detection engine with an empty database. Nothing here is sample data.

## Step 1. Upload the project to GitHub
1. github.com > **+** > **New repository** > name `rorgid-drp` > **Private** > leave "Add a README" unticked > **Create repository**.
2. Click **uploading an existing file**. Open the extracted `drp` folder, press Ctrl+A, and drag everything into the page. Click **Commit changes**.
3. Refresh. Check that the folders `.devcontainer`, `.github`, `dashboard`, `src` and `scripts` are all there. If `.devcontainer` is missing, click Add file > Upload files and drag that folder in again.
(If you already uploaded an older version: delete the old files or the old repository first, so no old files are left behind.)

## Step 2. Save your private settings as Codespaces secrets
GitHub: click your profile picture > **Settings** > **Codespaces** > **Secrets** > **New secret**. Add each name below, paste the value, and under "Repository access" choose `rorgid-drp`.

| Secret name | What to put |
|---|---|
| SECRET_KEY | any long random text, 40 characters or more |
| ADMIN_EMAIL | your own email, this becomes your platform-admin login |
| ADMIN_PASSWORD | a strong password: 8+ characters, upper and lower case, a special character |
| SMTP_SERVER | your email provider's server, e.g. smtp.gmail.com |
| SMTP_SENDER | the email address that sends codes and reports |
| SMTP_PASSWORD | that account's app password (not your normal password) |
| KECIRT_REPORT_TO | the official KE-CIRT/CC address that receives takedown reports |

## Step 3. Start it
1. Open your repository > green **Code** button > **Codespaces** tab > **Create codespace on main**.
2. Wait about 5 to 10 minutes the first time (it installs a browser for evidence screenshots).
3. When a browser tab opens with the login page, you are live. If it does not open, click the **Ports** tab at the bottom and click the link next to port 8000.
4. Log in with ADMIN_EMAIL and ADMIN_PASSWORD. Companies register at the same address followed by `/register`.

## What happens next
Company registers > uploads KRA PIN and documents on the Verification page > is verified > the engine starts watching its brands. Findings appear in that company's dashboard. A company admin must approve each takedown report before it is emailed.

## Good to know
- **A codespace is not a 24/7 server.** It stops after about 30 minutes without use (you can raise this up to 4 hours in Settings > Codespaces), and your free monthly hours are limited. Reopening it starts everything again and keeps your data for about 30 days of inactivity. Use it to run and test the real system.
- **For 24/7**, rent a small server (VPS), install Docker, copy the project, copy `.env.example` to `.env`, fill it in, and run `docker compose up -d`. Put HTTPS in front (Caddy is the simplest) and set `COOKIE_SECURE=true`. The Docker files are included but have not been tested yet.
- To see what the engine is doing, open the terminal in the codespace and type `tail -f engine.log`.
- The free public certstream server is often down. If the engine log keeps showing reconnects, run your own certstream server and set `CERTSTREAM_URL`.
- The screenshot-and-hash scraper (`src/workers/tasks.py`) is a starter version. It catches exact copies of a company's registered trademark photo and registered key serials printed on a page. It does not catch resized or re-saved copies. If your original `tasks.py` has a steganographic watermark check, replace this file with yours.
