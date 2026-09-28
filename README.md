# Million Euro Wallet

An **intentionally vulnerable local coursework demo** for the University of Helsinki Cyber Security Base course. All application logic and HTML are in the single-file Flask app `wallet.py`, using SQLite.

**Do not deploy this application or expose it to a network.** Run it only on your own computer at `127.0.0.1`. Use only fictional data and the public demo credentials; never enter real passwords or personal information.

## Security topics

The application demonstrates these five OWASP Top 10:2021 categories:

- **A01 Broken Access Control**
- **A02 Cryptographic Failures**
- **A03 Injection**
- **A07 Identification and Authentication Failures**
- **A09 Security Logging and Monitoring Failures**

Each flaw is active, with a commented-out fix next to it in `wallet.py`. The fixes are teaching examples and are not enabled.

## Setup and run (Windows PowerShell)

Install Python 3.10 or newer, then open PowerShell in the project folder:

```powershell
cd "C:\path\to\project"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe wallet.py
```

These commands use the virtual environment directly; activation is unnecessary. Replace `C:\path\to\project` with the folder where you saved or cloned this project.

Open <http://127.0.0.1:5000>. Stop the app with **Ctrl+C**. The app binds to the local loopback address with debug mode disabled; keep those settings.

## Demo accounts

| Username | Password | Fictional starting balance |
| --- | --- | --- |
| bob | bob-demo-password | EUR 1,000,000.00 |
| alice | alice-demo-password | EUR 250,000.00 |

All balances are fictional; there are no real payments or funds.

The app automatically creates `wallet.sqlite3` beside `wallet.py` and preserves data between runs. To reset the demo accounts and balances, stop the app, delete that generated database, and restart. Restarting also signs users out.

## Repository contents

Include only `wallet.py`, `README.md`, `requirements.txt`, and `.gitignore`. The generated database, virtual environment, environment files, Python caches, and editor/temp files are excluded by `.gitignore`. Do not force-add ignored files.
