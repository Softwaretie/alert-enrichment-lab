# Alert Enrichment System

Pulls phishing reports forwarded to a Gmail (and optionally Yahoo) mailbox, extracts
IOCs (URLs, domains, IPs, file hashes), reads what's inside the attachments, enriches
everything via VirusTotal + AbuseIPDB (+ urlscan.io), and asks Claude to triage each
alert (verdict, confidence, summary, recommended action). Results are written as JSON
to `logs/` and to `findings.db` for the dashboard.

## Setup

**Easiest (Windows):** double-click `setup.bat` and follow the prompts -- or read the
beginner walkthrough in [SETUP_GUIDE.md](SETUP_GUIDE.md). Run `check_setup.bat` any time to
see what's missing, and `demo.bat` to try the attachment analyzer without any keys.

**Manual quick start** (what `setup.bat` does for you):

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/setup_secrets.py
```

That last command is a guided wizard: it walks you through the 3 required
API keys and any optional integrations (Slack, Yahoo, URL sandboxing) one at
a time, printing what each one is for and exactly where to get it before
asking you to paste it in — no need to know in advance which env vars exist
or where secrets are supposed to go. It creates `.env` for you if it doesn't
exist yet, and is safe to re-run any time (existing values show as defaults;
press Enter to keep them, or type a new value to replace one).

The one thing it can't do for you is Gmail's OAuth file (Google requires a
manual download, not an API key) and creating the Gmail label — the wizard
prints those steps and pauses for you to do them, but here's the detail:

- Go to the [Google Cloud Console](https://console.cloud.google.com/), create
  (or reuse) a project, enable the **Gmail API**.
- Under *APIs & Services > Credentials*, create an **OAuth client ID** of type
  *Desktop app*, and download the JSON as `credentials.json` in the project root.
- Create a `phishing-reports` label in Gmail (and a filter to auto-apply it to
  forwards sent to your security mailbox) — that's what `main.py` polls by
  default (`label:phishing-reports is:unread`; edit `GMAIL_QUERY` in `.env`
  if you use a different label/rule).
- The first run opens a browser to authorize read/modify access to your mailbox
  (`gmail.modify` scope — used only to clear the UNREAD label on processed
  messages; the app never sends, deletes, or edits mail content). A `token.json`
  cache is written afterward so you won't need to re-auth every run.

The rest of this section is reference detail for each integration, in case
you want to understand what the wizard is doing or set something up by hand.

### Yahoo Mail (optional)

Yahoo has no self-serve OAuth path to Mail data for third-party apps —
confirmed live: their current developer platform
(https://developer.yahoo.com/api/) only lists two APIs, Fantasy Sports and
Sign In With Yahoo (identity/login only), and requesting Mail scope
(`mail-r`) is rejected outright regardless of app configuration. So this
integration authenticates the plain IMAP way instead, using an
app-specific password:

- Enable 2-step verification on the Yahoo account (required first), then
  go to *Account Info → Account Security → Generate app password* and
  create one for this app.
- Set `YAHOO_EMAIL` (the mailbox address) and `YAHOO_APP_PASSWORD` (the
  generated password — a secret; the setup wizard handles both).
- Yahoo has no Gmail-style label search — point `YAHOO_FOLDER` at a folder
  you file forwarded phishing reports into (default `INBOX`), and adjust
  `YAHOO_SEARCH_CRITERIA` (default `UNSEEN`) if needed. A dedicated folder
  matters: an `UNSEEN` search against a large `INBOX` (tens of thousands of
  emails) can take a very long time, since IMAP has to scan the whole
  mailbox server-side before returning results.
- Leaving `YAHOO_EMAIL`/`YAHOO_APP_PASSWORD` unset skips Yahoo entirely —
  Gmail-only setups need no changes.

An app password is a broader, static-but-revocable credential rather than
a scoped, expiring OAuth token — if it leaks, whatever IMAP allows is
exposed until you revoke it, not just what this code's read-only usage
needs. Consider pointing this at a dedicated/secondary Yahoo mailbox for
phishing reports rather than your primary inbox, to limit that blast
radius, and revoke/regenerate the password if you ever suspect a leak.

### Keeping secrets out of plaintext

`.env` is convenient but plaintext on disk. `python scripts/setup_secrets.py`
(the same guided wizard from Quick start above) stores each secret in your
OS credential store instead — Windows Credential Manager, macOS Keychain, or
Linux Secret Service, via the `keyring` package — encrypted at rest and tied
to your OS login rather than readable in a file. `src/config.py` checks the
credential store first and only falls back to `.env` for anything not
configured that way, so pasting a value into `.env` directly still works if
you'd rather do that for one you're not worried about; non-secret config
(paths, queries, channel/folder names) always stays in plain `.env`, since
there's nothing sensitive about those.

## Running

```
python main.py
```

Options:
- `--max-results N` — cap how many matching emails to process **per source** per run (default 25)
- `--batch` — process ALL matching unread emails in one run instead of capping at
  `--max-results`, paging through results if there are more than 500. Meant
  for lab scale (100-500 emails/day): one sequential pass, no workers or queues.
- `--no-mark-read` — leave messages marked unread; only use this while testing, since
  the default query is `is:unread` and an email left unread gets reprocessed (and
  re-billed against VirusTotal/Claude) on every subsequent run
- `--slack` — post each verdict to Slack (see below); errors immediately if
  `SLACK_BOT_TOKEN`/`SLACK_CHANNEL_ID` aren't set in `.env`
- `--yahoo` / `--no-yahoo` — force Yahoo Mail processing on/off. Without either
  flag, Yahoo runs automatically if `YAHOO_EMAIL`/`YAHOO_APP_PASSWORD` are both
  set, and is skipped otherwise. `--yahoo` errors
  immediately if those aren't set, rather than silently doing nothing.
- `--no-attachments` — skip attachment analysis for this run (see below)
- `-v` — verbose/debug logging

Gmail and Yahoo are processed independently through the exact same pipeline
(IOC extraction → VirusTotal/AbuseIPDB → Claude → `findings.db` → Slack), so a
finding looks identical regardless of which mailbox it came from — only its
`source` field differs. One failing (a bad enrichment call, a source being
unreachable) doesn't affect the other.

By default (no `--no-mark-read`), each email only has its `UNREAD` label cleared
*after* it's been fully enriched and analyzed — so a crash mid-run never marks an
email read before it's actually been checked, and a successfully processed email
won't be re-analyzed (and re-billed) on the next run.

Emails are processed one at a time; if one fails (a bad enrichment call, a
malformed message, etc.) it's logged and skipped — left unread so it's retried
next run — rather than aborting the whole batch. `main.py` prints a summary at
the end (`Processed X/Y alert(s); Z failed.`) listing any failed message IDs.

### Running it overnight

`scripts/scheduler.py` runs `--batch` automatically once a day (APScheduler,
default 2 AM — override with `BATCH_SCHEDULE_HOUR`/`BATCH_SCHEDULE_MINUTE` in
`.env`). Start it and leave it running:

```
python scripts/scheduler.py
```

This is a single cron-style job, not a task queue — appropriate for lab scale.
If you outgrow a nightly batch (or 100-500 emails/day), that's the point to
look at PostgreSQL + a worker pool instead of scaling this further.

### Slack notifications

Pass `--slack` to post each triage verdict to a Slack channel: an emoji by
verdict (🚨 malicious, ⚠️ suspicious, ✅ likely_benign, ❓ unknown), sender,
subject, confidence, Claude's summary, and the recommended action.

1. Create a Slack app at https://api.slack.com/apps (or reuse one), add the
   `chat:write` OAuth scope under *OAuth & Permissions*, install it to your
   workspace, and copy the **Bot User OAuth Token** (`xoxb-...`).
2. Invite the bot to the target channel: `/invite @YourBotName` in that
   channel (a bot posting will fail with `not_in_channel` until it's a member).
3. Get the channel ID (right-click the channel → *View channel details* →
   copy the ID at the bottom, starts with `C`).
4. Run `python scripts/setup_secrets.py` and answer "y" at the Slack prompt —
   it asks for the bot token and channel ID together.

A Slack API error or outage is logged and skipped rather than failing the
enrichment run — notifications are best-effort, not load-bearing.

### Sender authentication and URL sandboxing

Two extra signals feed into Claude's judgment beyond VirusTotal/AbuseIPDB:

- **Sender authentication** (always on, no setup needed): Gmail and Yahoo's
  own receiving servers already run SPF/DKIM/DMARC checks and stamp the
  result in an `Authentication-Results` header — this just parses that
  (`src/auth_headers.py`) rather than re-deriving it. A `fail` is a real
  spoofing signal, but not decisive on its own (legitimate mail can fail
  alignment for benign reasons like forwarding).
- **URL sandboxing** (optional): set `URLSCAN_API_KEY` (free key from
  https://urlscan.io/user/signup; a secret — prefer `setup_secrets.py`) to
  have up to 2 URLs per email actually visited in an isolated browser via
  urlscan.io, reporting what a link really does rather than just its
  reputation history. This catches freshly-registered or never-indexed
  malicious pages that VirusTotal has no history for yet. Each scan takes
  roughly 5-30 seconds (submit + poll), so this noticeably slows down
  processing of emails that contain links — capped at 2 per email to bound
  that cost. Leaving `URLSCAN_API_KEY` unset skips it entirely; VirusTotal/
  AbuseIPDB still run as before.

### Attachment analysis (hash + static)

Reported emails often carry the real payload in an attachment, so each attachment is
now downloaded **into memory** and examined. This is *hash + static* analysis: files
are never written to disk, never opened by another program, never executed, and never
uploaded anywhere.

For every attachment the report records:

- **Hashes** (SHA-256/SHA-1/MD5). The SHA-256 is looked up in VirusTotal (a lookup,
  not an upload) for the riskiest files, up to 5 per email to respect the free-tier
  rate limit. "Not found" means *unknown*, not safe -- fresh malware has no history.
- **What the file really is**, from its bytes rather than its name, and whether that
  disagrees with the extension (a `.pdf` that is really an `.exe`, a `.docx` that is
  really RTF).
- **Filename tricks**: double extensions (`invoice.pdf.exe`), padding spaces, and the
  Unicode right-to-left override (shown as `<U+202E>`).
- **Format-specific red flags**:
  - *Office (docx/xlsx/pptx and legacy doc/xls/ppt):* VBA macros, including auto-run
    entry points (`AutoOpen`, `Document_Open`, ...) and suspicious calls (download,
    shell, PowerShell) and URLs inside the macro source; Excel 4.0 (XLM) macro sheets,
    hidden ones especially; macros hiding behind a macro-free extension; remote
    templates and network-path (UNC) links; DDE fields; embedded executables;
    password-protected documents.
  - *PDF:* JavaScript (auto-run especially), Launch actions, embedded files, rich
    media, remote form submission; keywords are also searched inside compressed
    streams and `#xx`-obfuscated names are decoded.
  - *RTF:* embedded objects, Equation Editor, remote templates.
  - *HTML/SVG:* password forms, "HTML smuggling" (a file built in the browser),
    obfuscated scripts, script inside SVG.
  - *Executables, shortcuts, scripts, OneNote, disk images:* flagged, with command-line
    indicators and embedded URLs pulled from their strings.
  - *ZIP archives and attached `.eml` emails:* unpacked in memory (with size, ratio and
    nesting limits) and every member analysed the same way; encrypted archives and
    decompression bombs are flagged, and an encrypted attachment plus a "password" in
    the email body is called out as a classic antivirus-evasion pattern.
- **Links inside the files.** URLs found in attachments are merged into the email's own
  IOCs, so the existing VirusTotal and urlscan.io checks cover them too.

Everything is summarised as a `static_risk` (none/low/medium/high) with plain-English
`signals`, added to the enrichment Claude sees, stored with the finding, and shown in
the dashboard's detail panel. Claude is told that absence of signals is not proof of
safety.

Limits worth knowing: RAR/7z/CAB archives, disk images (ISO/VHD) and password-protected
files can't be looked inside (they're flagged, not opened); macro source is decoded on
a best-effort basis, so heavily obfuscated macros may be reported as "macros present"
only; there is no dynamic (run-it-and-watch) analysis. Settings: `ATTACHMENT_ANALYSIS`
(on/off) and `ATTACHMENT_MAX_MB` in `.env`.

Each processed email produces `logs/<timestamp>_<message_id>.json` containing the
original alert metadata, extracted IOCs, raw enrichment data, and Claude's triage
verdict. The same result is also written to `findings.db` (SQLite) for the dashboard.

## Dashboard

A Flask app reads `findings.db` and shows stats, a searchable/filterable table of
recent findings, and Claude's full reasoning per finding. The page polls for new
findings every 10s and either refreshes automatically or, if you have a finding
expanded, shows a "new findings are in" banner instead of yanking the page out
from under you.

**To open it yourself, without needing a terminal command each time:** double-click
[`run_dashboard.bat`](../run_dashboard.bat) in the project root. It starts the
server in its own window (leave that window open; close it to stop the server) and
opens http://localhost:5000 in your default browser automatically.

To run it manually instead:

```
python dashboard/app.py
```

Then open http://localhost:5000. Filter by verdict via the dropdown, search by
subject/sender, and click a row to expand Claude's summary, key indicators, and
recommended action.

If you already have JSON logs from before `findings.db` existed, backfill them once:

```
python scripts/import_logs.py
```

### Deleting findings

Check the box on one or more rows and click "Delete N selected" to remove them
from the dashboard. This is a soft delete — the finding moves to the **Deleted**
page (linked from the header) where it can be restored, or left alone until it's
permanently purged (DB row + its `logs/*.json` file) after `DELETED_RETENTION_DAYS`
days (default 7, set in `.env`). Purging happens automatically and opportunistically
— on every dashboard page load and at the start of every pipeline run — so deleted
data doesn't pile up whether or not the dashboard is open.

## Architecture

```
main.py
  -> src/config.py         load + validate secrets (Credential Manager, then .env) + config
  -> src/pipeline.py       orchestrates the run below, one mail source at a time
       -> src/gmail_client.py     Gmail OAuth + fetch/parse messages
       -> src/yahoo_client.py     YahooListener: IMAP (app password) fetch/parse
       -> src/email_message.py    shared EmailMessage shape both sources produce
       -> src/auth_headers.py     parses SPF/DKIM/DMARC from Authentication-Results
       -> src/html_text.py        HTML-body-to-text, preserving links before tag-stripping
       -> src/attachments/        attachment analysis: hash, true file type, static red flags,
                                  archive/eml unpacking in memory, links inside files
       -> src/ioc_extractor.py    regex-based IOC extraction (with defang handling)
       -> src/enrichment/         VirusTotal + AbuseIPDB + urlscan.io (optional) lookups
       -> src/claude_analyzer.py  Claude triage call, JSON-structured verdict
       -> src/database.py         persists each finding to findings.db (SQLite)
       -> src/slack_notifier.py   optional: posts each verdict to Slack (--slack)

dashboard/app.py   Flask app reading findings.db, serves index.html + deleted.html
scripts/import_logs.py    one-time backfill of legacy logs/*.json into findings.db
scripts/scheduler.py      APScheduler daily job running the batch pipeline overnight
scripts/setup_secrets.py  guided setup wizard: required keys + optional integrations
scripts/check_setup.py    read-only health check (never prints secrets)
scripts/demo.py           keyless demo of the attachment analyzer on harmless fake samples
setup.bat, run_*.bat, check_setup.bat, demo.bat   double-click helpers for Windows
tests/                    unit tests (synthetic samples only -- no real malware)
```

## Tests

```
python -m unittest discover -s tests -t .
```

The suite builds harmless fake files in memory (a macro-bearing Word file, a fake program
with a double extension, a PDF with hidden JavaScript, an encrypted-flag ZIP, ...) and
checks each is flagged -- and that clean files are not. It also fuzzes the parsers with
corrupted files to make sure none can crash a run. It deliberately does not use the EICAR
test string, which antivirus software would flag in the repository itself.

## Known limitations (Week 1 scope)

- VirusTotal free tier is rate-limited to 4 req/min; the client throttles itself,
  so a large batch of alerts with many IOCs will take a while. Per-email IOC
  checks are capped at 5 per category to keep a single noisy alert from eating
  the whole rate budget.
- IOC extraction is regex-based (with defang/refang handling for `hxxp://`,
  `[.]`, etc.) rather than a full email/URL parser — expect occasional false
  positives on unusual formatting.
- No dedup/caching of previously-seen IOCs across runs yet — repeated reports of
  the same phishing link will re-query VirusTotal/AbuseIPDB each time.
- No retry/backoff beyond a single request per lookup; transient API failures
  are logged and recorded as `{"error": ...}` in the output rather than retried.
- Yahoo Mail has no OAuth path for third-party apps (confirmed live), so it uses IMAP with an
  app-specific password instead -- a broader, static credential than a scoped OAuth token.
  See the Yahoo setup section above.
- Attachment analysis is static only (see "Attachment analysis"): it can't look inside
  password-protected files, RAR/7z archives or disk images, and has no sandbox detonation.
