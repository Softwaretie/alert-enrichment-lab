# Setup guide (for beginners)

No programming knowledge needed. Plan on **30-45 minutes the first time**, most of it spent creating accounts. If you only want to see the tool work, skip all of this and double-click `demo.bat` - it needs nothing.

**Contents:** [1. Install Python](#1-install-python) - [2. Get the project](#2-get-the-project) - [3. Get your API keys](#3-get-your-api-keys) - [4. Gmail](#4-gmail) - [5. Run setup.bat](#5-run-setupbat) - [6. First run](#6-first-run) - [Optional extras](#optional-extras) - [Everyday use](#everyday-use) - [Something went wrong](#something-went-wrong) - [Removing everything](#removing-everything)

---

## 1. Install Python

The project needs **Python 3.10 or newer**.

1. Click the Start menu, type `cmd`, press Enter. A black window opens.
2. Paste this and press Enter:

   ```
   winget install Python.Python.3.12
   ```

3. When it finishes, **close the black window** (this matters - it picks up the change only in a new window).

**No `winget`?** Download the installer from <https://www.python.org/downloads/>. On the **first installer screen, tick "Add python.exe to PATH"**, then click Install Now.

**Check it worked:** open a new black window and run `py -3 --version`. You should see something like `Python 3.12.x`.

> If typing `python` opens the Microsoft Store, Python simply isn't installed yet (Windows is offering to install it). Use one of the methods above instead.

## 2. Get the project

1. On the project's GitHub page click the green **Code** button, then **Download ZIP**.
2. Find the ZIP in your Downloads, right-click it, choose **Extract All...**, and extract to somewhere simple like `C:\Projects\alert-enrichment`. (Don't run files from inside the ZIP window - it won't work.)
3. Open the extracted folder. You should see `setup.bat`, `demo.bat`, `README.md` and others.

**Windows warns "Windows protected your PC"** when you double-click a `.bat` file? That's SmartScreen being cautious about downloaded files. Click **More info -> Run anyway**. You can open any `.bat` file in Notepad first (right-click -> Edit) - they are short and readable.

**Try the demo now:** double-click `demo.bat`.

## 3. Get your API keys

An API key is a password that lets this tool use a service. Make an account at each, create a key, and keep the page open (or paste into a temporary note) - `setup.bat` will ask for them later. They're stored in Windows Credential Manager, never in a file.

| Service | Where | Notes |
|---|---|---|
| **Anthropic (Claude)** - required | <https://console.anthropic.com/settings/keys> | Needs a payment method / credit. It is pay-as-you-go; **set a monthly spending limit** in the console. |
| **VirusTotal** - required | <https://www.virustotal.com/gui/my-apikey> | Free account. The free tier allows about 4 lookups per minute; the tool waits automatically, so big batches are slow, not broken. |
| **AbuseIPDB** - required | <https://www.abuseipdb.com/account/api> | Free account. |

Keys look like long random strings. **Never post them anywhere or send them to anyone.**

## 4. Gmail

This is the longest part. It lets the tool read one mailbox (the one that receives reported emails). Google asks you to create a small private "app" for this. It's free and only you will ever use it.

> **Use a dedicated Gmail account for reports** if you can, not your personal inbox. The tool can read and mark emails as read in whatever account you connect.

### 4a. Create the Google Cloud project

1. Go to <https://console.cloud.google.com/> and sign in with the Gmail account you will use. Accept the terms if asked.
2. At the top of the page click the project picker -> **New Project**. Name it `alert-enrichment`, click **Create**, and make sure it's selected.
3. Open <https://console.cloud.google.com/apis/enableflow;apiid=gmail.googleapis.com>, check the project name at the top is yours, and click **Enable**.

### 4b. Set up the consent screen

1. In the left menu (the three-line button, top left) go to **Google Auth platform**. If you see "not configured yet", click **Get Started**.
2. **App information:** name it `Alert Enrichment`, pick your email as support email. Click Next.
3. **Audience:** choose **External** (for a normal @gmail.com account). Click Next.
4. **Contact information:** your email. Click Next, tick the agreement box, **Create**.
5. Go to **Google Auth platform -> Audience**. Under **Test users** click **Add users** and add **your own Gmail address**. Save.

   (This step is the one people miss. Without it, sign-in later fails with "access blocked".)

### 4c. Create the key file

1. Go to **Google Auth platform -> Clients -> Create client**.
2. **Application type: Desktop app.** Name it anything. Click **Create**.
3. Click **Download JSON** in the box that appears.
4. Rename the downloaded file to exactly **`credentials.json`** and move it into the project folder (next to `setup.bat`).

> Google renames menus now and then. If a name above doesn't match, look for the closest one ("Branding", "Audience", "Clients" / "Credentials").

### 4d. Make the reporting label

The tool reads emails that carry the Gmail label **`phishing-reports`**.

1. In Gmail, click the gear -> **See all settings -> Labels -> Create new label** -> `phishing-reports`.
2. To label forwarded reports automatically: **Settings -> Filters and Blocked Addresses -> Create a new filter**. Put a word or address in *Has the words* / *To* that your reports use (or the address you forward from), click **Create filter**, tick **Apply the label: phishing-reports**, click **Create filter**.
3. You can also just drag a suspicious email into that label by hand.

Only **unread** emails with that label are processed, and they're marked read once done.

## 5. Run setup.bat

Double-click **`setup.bat`** and follow the prompts. It will:

1. find Python (and tell you what to do if it can't),
2. create a private environment in a folder called `.venv`,
3. install the needed packages (a minute or two),
4. ask for each API key - paste with right-click or Ctrl+V; the characters are hidden as you type, which is normal. Press Enter to skip optional ones,
5. run a health check.

It is safe to run again whenever you like; it keeps what already works.

## 6. First run

1. Put a test email in the `phishing-reports` label and make sure it is unread (a harmless email works fine - the verdict should come back "likely benign").
2. Double-click **`run_alerts.bat`**.
3. **The first time, your browser opens a Google sign-in.** Choose the Gmail account. You'll see **"Google hasn't verified this app"** - that's expected, because you made the app yourself. Click **Advanced -> Go to Alert Enrichment (unsafe)**, tick the permission, and continue. (The permission is Google's "read and modify mail" scope. The tool only uses it to read emails and clear their unread flag; it never sends or deletes mail.)
4. Wait for `Processed 1/1 alert(s)`.
5. Double-click **`run_dashboard.bat`** to see the result in your browser.

**Good to know:** while your Google app is in "Testing" mode, Google signs you out roughly **every 7 days**. The tool notices this and simply opens your browser to sign in again, so keep an eye out for that browser tab.

---

## Optional extras

Run `setup.bat` again (or `.venv\Scripts\python.exe scripts\setup_secrets.py`) and answer **y** to the extras you want. It explains each one.

- **Slack notifications** - posts each verdict to a channel. Run the tool with `run_alerts.bat --slack`.
- **Yahoo Mail** - also checks a Yahoo mailbox. Needs 2-step verification and an *app password* (the wizard tells you where). Use a dedicated folder rather than a huge inbox.
- **urlscan.io** - opens up to 2 links per email in a throw-away online browser and reports what they do.

Settings like the mailbox label, how big an attachment may be, or the nightly run time are in `.env` (created by the wizard); every setting has a comment explaining it.

## Everyday use

| Double-click | When |
|---|---|
| `run_alerts.bat` | Whenever you want new reports processed |
| `run_dashboard.bat` | To read the results |
| `run_scheduler.bat` | To process automatically every night (leave the window open and the PC awake) |
| `check_setup.bat` | Any time something seems off |
| `check_model.bat` | To test your Anthropic key and the Claude model with one fake email |

You can add options after the name when running from a black window, for example `run_alerts.bat --no-attachments` (skip attachment analysis) or `run_alerts.bat --no-gmail` (Yahoo only). Full list: [docs/README.md](README.md#running).

---

## Something went wrong

First step, always: **double-click `check_setup.bat`**. It names the problem and the fix. Common ones:

| What you see | What it means / what to do |
|---|---|
| `Python 3.10 or newer was not found` / `python is not recognized` / the Microsoft Store opens | Python isn't installed (or isn't on PATH). Do [step 1](#1-install-python), close all black windows, run `setup.bat` again. |
| Installing packages fails in `setup.bat` | No internet, or a work network blocking `pip`. Try another network. Run `py -3 --version` to confirm the Python version. |
| `Missing required secret: ...` | A key was skipped. Run `setup.bat` again and paste it (or double-click `check_setup.bat` to see which). |
| `credentials.json not found` | Finish [step 4c](#4c-create-the-key-file); the file must be named exactly `credentials.json` and sit next to `setup.bat`. Windows may hide `.json` - check it isn't `credentials.json.json` (File Explorer -> View -> Show -> File name extensions). |
| Google says **"Access blocked"** / `access_denied` / error 403 | Add your Gmail address under **Google Auth platform -> Audience -> Test users** ([step 4b](#4b-set-up-the-consent-screen)), then run again. |
| `invalid_grant` / "Token has been expired or revoked" | The 7-day sign-in expired. The tool opens your browser to sign in again automatically; if no browser appears, delete `token.json` and run `run_alerts.bat` again. |
| `Processed 0/0 alert(s)` | Nothing to do: no **unread** email carries the `phishing-reports` label. Add one and retry. |
| Many emails take ages | VirusTotal's free tier allows ~4 lookups/min; the tool waits automatically. urlscan.io adds 5-30 s per email with links. |
| Yahoo login fails | You need an *app password* (not your Yahoo password) and 2-step verification turned on. |
| Dashboard page won't load | Make sure the "Alert Enrichment Dashboard" window is still open, then visit <http://localhost:5000>. |
| `.bat` file flashes and closes | Run it from a black window (Start -> `cmd` -> `cd` into the folder -> type its name) to see the message, or use `check_setup.bat`. |
| Antivirus flags the project's test files | The tests contain harmless *fake* "malicious" samples built in memory; nothing is written to disk. If your antivirus complains anyway, tell it to ignore the project folder. |

Still stuck? Open an issue on the GitHub page and paste the output of `check_setup.bat` (it never shows your keys). **Do not paste `.env`, `credentials.json`, or `token.json`.**

## Removing everything

1. Delete the project folder.
2. Open **Credential Manager** (Start menu -> type it) -> **Windows Credentials** and remove any entries containing `alert-enrichment`.
3. To revoke Gmail access: <https://myaccount.google.com/permissions> -> remove *Alert Enrichment*. You can also delete the Google Cloud project.
4. Delete the API keys on the Anthropic / VirusTotal / AbuseIPDB pages if you won't use them again.
