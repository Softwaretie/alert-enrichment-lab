# Alert Enrichment Lab

**Forward a suspicious email, get a verdict.** This tool reads reported phishing emails, looks *inside* their attachments, checks every link and file against threat-intelligence services, and asks Claude to explain whether each one is malicious, suspicious or likely harmless - and what to do about it.

```
suspicious email --> links + attachments pulled apart --> VirusTotal / AbuseIPDB / urlscan.io
                 --> Claude writes the verdict        --> dashboard on your own computer
```

Built for learning and lab use, It is **not** a production security product. Windows 10/11 for the one-click setup; the Python code itself should run elsewhere (the tests pass on Linux), but it has only been used live on Windows.

## See it work in 2 minutes (no accounts, no API keys)

1. **Install Python 3.10 or newer.** Open the Start menu, type `cmd`, press Enter, and run:
   ```
   winget install Python.Python.3.12
   ```
   Then close that window. (No winget? Use the installer from [python.org](https://www.python.org/downloads/) and tick **Add python.exe to PATH**.)
2. **Download this project:** green **Code** button -> **Download ZIP** -> right-click the ZIP -> **Extract All**.
3. **Double-click `demo.bat`.**

The demo builds harmless fake attachments in memory and shows how the analyzer judges each one. Nothing is saved, uploaded or run. Example of what you'll see:

```
[3/7] A program pretending to be a PDF
      File: invoice.pdf.exe   (Windows executable (PE), 2048 bytes)
      Verdict: HIGH RISK - treat as malicious until proven otherwise
        [HIGH  ] Looks like a .pdf but actually ends in .exe.
        [HIGH  ] Windows executable (program) attached to an email.
      Links found inside: http://payload.example.invalid/dropper.bin

[7/7] A ZIP hiding a program, with the password in the email
      Verdict: HIGH RISK - treat as malicious until proven otherwise
        [HIGH  ] An attachment is password-protected and the email body mentions a password
                 -- a common way to hide malware from antivirus scanning.
        [HIGH  ] scan.pdf.exe: Looks like a .pdf but actually ends in .exe.
```

## Set it up for real

Double-click **`setup.bat`**. It creates a private Python environment inside the folder, installs the packages, and asks for your API keys one at a time (stored in Windows Credential Manager, not in a file).

**What you need:**

| | Why | Cost |
|---|---|---|
| [Anthropic API key](https://console.anthropic.com/settings/keys) | Claude writes the verdicts | Pay-as-you-go - set a spending limit in the console |
| [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) | Reputation of links, domains, IPs, file hashes | Free tier |
| [AbuseIPDB API key](https://www.abuseipdb.com/account/api) | Reputation of IP addresses | Free tier |
| Gmail account + a free Google Cloud "OAuth" file | Lets the tool read your reporting mailbox | Free |
| *Optional:* Yahoo, Slack, urlscan.io | More mailboxes, chat alerts, link sandboxing | Free tiers |

The Gmail part is the only fiddly step. **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)** walks through everything with the exact buttons to click, plus a "Something went wrong" table for common errors.

## Using it

| Double-click | What it does |
|---|---|
| `run_alerts.bat` | Checks your mailbox for new reported emails and analyzes them |
| `run_dashboard.bat` | Opens the results in your browser at <http://localhost:5000> |
| `run_scheduler.bat` | *Optional:* checks the mailbox every night (PC must be on) |
| `check_setup.bat` | Health check - tells you exactly what's missing or broken |
| `check_model.bat` | Sends one fake phishing email to Claude to confirm your API key and model work (one small API request) |
| `demo.bat` | The keyless demo |

**To report a phish:** put the email in your Gmail label `phishing-reports` (or your Yahoo report folder), leave it unread, and run `run_alerts.bat`. Open the dashboard to read the verdict, Claude's reasoning, every indicator found, and the recommended action.

## Which Claude model

Verdicts come from the Anthropic API (Messages API) using **`claude-sonnet-5-5`** by default. To use a different model, set `CLAUDE_MODEL` in `.env`; no code changes are needed. Run `check_model.bat` after changing it.

## How attachments are analyzed

Every attachment is downloaded **into memory only** - never saved to disk, opened or run - and then:

- **Hashed** (SHA-256); the hash is looked up on VirusTotal. Only the hash is sent, the file is never uploaded.
- **Identified by its contents**, not its name (a `.pdf` that is really an `.exe`).
- **Checked for red flags:** Office macros (including auto-run and hidden Excel macro sheets), remote templates, PDF scripts, HTML phishing forms and "HTML smuggling", shortcut/script/OneNote launchers, double extensions, and more.
- **Unpacked** if it's a ZIP or an attached email, and every file inside is checked too.
- **Mined for links**, which get the same checks as links in the email body.

**"Nothing found" never means "safe".** Password-protected files and RAR/7z/ISO archives can't be looked inside (they're flagged instead), and nothing is run in a sandbox yet.

## Privacy and safety

- **Use a dedicated reporting mailbox**, not your personal inbox. For each email, the text and indicators (links, domains, IPs, file hashes) are sent to Anthropic and to VirusTotal / AbuseIPDB / urlscan.io. Only forward emails you're comfortable sharing with them.
- **Keep secrets private.** `.env`, `credentials.json` and `token.json` are already listed in `.gitignore`. Never post them or paste them into an issue.
- The dashboard listens only on your own computer and has **no login** - don't expose it to a network.
- Never open a suspicious attachment yourself "just to check".

## Project layout

```
setup.bat, run_*.bat, demo.bat, check_setup.bat   double-click helpers
main.py                  the analysis run (what run_alerts.bat starts)
src/                     the pipeline: mail clients, IOC extraction, enrichment, Claude
src/attachments/         attachment analyzer (Python standard library only)
dashboard/               the local results website
scripts/                 setup wizard, nightly scheduler, health check, demo
tests/                   automated tests (harmless synthetic samples only)
docs/SETUP_GUIDE.md      step-by-step setup for beginners
docs/README.md           technical reference: options, architecture, limits
```

## Development

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest discover -s tests -t .
```

The tests build fake files in memory and never use real malware. Command-line options and architecture are in [docs/README.md](docs/README.md).

## Roadmap

The analyzer is deliberately **hash + static** so it's safe to run anywhere. Possible next steps: opt-in upload of unknown files to an online sandbox, and detonation in an isolated malware-analysis VM for samples static checks can't settle.
