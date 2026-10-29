# honeyfile

[![CI](https://github.com/winxtxrgit/honeyfile/actions/workflows/ci.yml/badge.svg)](https://github.com/winxtxrgit/honeyfile/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-0e75b6)
![No dependencies](https://img.shields.io/badge/dependencies-none-2ea44f)
[![MIT License](https://img.shields.io/badge/license-MIT-0e75b6)](https://github.com/winxtxrgit/honeyfile/blob/main/LICENSE)

**Plant decoy files and get alerted the moment ransomware or an intruder touches them.**

honeyfile drops tempting-looking bait — `Payroll_2026_Q4.csv`, `passwords.txt`, `.env`, `backup.sql` — into a directory and records exactly what each one looks like. Then it watches. The instant something encrypts, modifies or deletes a decoy, you get an alert with the file and what happened. It's a tripwire: a normal user never touches these files, so any change is a signal.

<p align="center">
  <img src="https://raw.githubusercontent.com/winxtxrgit/honeyfile/main/docs/terminal.png" alt="honeyfile planting three office decoys, reporting them intact, then detecting two encrypted files, one deleted file and a dropped ransom note" width="820">
</p>

## Why

Ransomware encrypts files fast, and by the time you notice, it's done. But it has to touch files to encrypt them, and a decoy that no human ever opens is the perfect early warning: one honeyfile changing means something is walking through your directory encrypting everything. The same tripwire catches an intruder browsing a file share for `passwords.txt`.

This is a detection tool, the opposite of malware. It never encrypts anything; it watches for something else that does.

## Try it in 30 seconds

```bash
pipx install git+https://github.com/winxtxrgit/honeyfile

mkdir demo
honeyfile plant demo --profile office
honeyfile status demo                 # OK: all 3 decoys are intact

echo "encrypted" > demo/passwords.txt # pretend to be ransomware
honeyfile watch demo --once           # [modified] passwords.txt — contents changed
```

## Usage

```bash
honeyfile plant /srv/share --profile office   # plant decoys and record a baseline
honeyfile plant ./repo --profile dev          # .env, id_rsa, deploy_keys.json
honeyfile status /srv/share                   # one-shot check, exits 1 if anything changed

honeyfile watch /srv/share                    # keep watching, alert on every change
honeyfile watch /srv/share --json alerts.jsonl
honeyfile watch /srv/share --webhook https://hooks.example.com/honeyfile
honeyfile watch /srv/share --exec "/usr/local/bin/isolate-host.sh"
honeyfile watch /srv/share --once             # for cron; exits 1 if anything changed

# Keep the baseline out of the watched directory (recommended for shares an
# intruder can browse). Use the same --manifest path for plant, status and watch:
honeyfile plant  /srv/share --manifest /var/lib/honeyfile/share.json
honeyfile status /srv/share --manifest /var/lib/honeyfile/share.json
```

**Profiles** decide which decoys get planted: `office` (payroll, passwords, a confidential doc), `dev` (`.env`, `id_rsa`, deploy keys), `db` (SQL dumps, a customer export). Every decoy contains only inert placeholder data — the one AWS-shaped key is AWS's own documented example — plus a unique `HONEYFILE-CANARY-…` token you can also search for in logs, email or outbound traffic.

## What it detects

| Event | Severity | Means |
| :--- | :---: | :--- |
| `modified` | high | A decoy's contents changed — ransomware encrypting, or someone editing it |
| `deleted` | high | A decoy is gone — wiped or moved |
| `manifest-error` | high | The baseline itself was altered or deleted — someone covering their tracks |
| `new-file` | medium | A file that wasn't planted appeared next to the decoys — a ransom note, a dropped tool |
| `touched` | low | A decoy's timestamp changed but its contents are intact — re-saved or restored |

Each decoy is fingerprinted by **sha256 + size**, so a change that keeps the same byte count is still caught. The baseline lives in `.honeyfile.json`, which carries a checksum of its own contents: editing it to hide a change fails the check, and deleting it is reported too. Pass `--manifest PATH` to keep that baseline **outside** the watched directory, so an intruder among the decoys can't read it to learn which files are bait. Planted decoys also get **varied, backdated timestamps** so a directory of them doesn't betray itself by sharing one creation time.

## Alerting

`watch` prints every alert to stderr (coloured by severity on a terminal) and fans each one out to whatever you configure:

- **`--json FILE`** — one JSON object per line: `{"time", "event", "severity", "path", "directory", "detail"}`. Feed it to your log pipeline.
- **`--webhook URL`** — POST that JSON to Slack, Discord, or your SOAR. A dead endpoint is logged and never stops the watch.
- **`--exec CMD`** — run a command on each alert, with the event passed as `HONEYFILE_EVENT`, `HONEYFILE_PATH`, `HONEYFILE_SEVERITY` and so on. Use it to isolate a host, kill a session, or page someone. No shell is involved, so a filename from disk is never interpreted.

## Good places to plant decoys

- **File shares** people rarely open — the first thing ransomware and intruders sweep.
- **A user's Documents or Desktop** — many ransomware strains start there.
- **Backup and database directories** — high-value targets.
- **Web roots and repos** — where a `.env` or `id_rsa` is what an attacker is hunting for.

Put decoys where a legitimate user has no reason to go, so every alert is real. honeyfile tells you *something touched the bait*; pair it with `--exec` or your EDR to respond.

## Limits, honestly

- It detects **tampering**, not reads. A plain open that changes nothing surfaces only as `touched`, and only if the filesystem updates access times (many don't, with `relatime`/`noatime`). For true read-auditing use the OS (Linux `auditd`, Windows file-access auditing); honeyfile is the lightweight, portable layer.
- `watch` polls every few seconds, so detection is near-real-time, not instant. Fast ransomware may encrypt several files between scans — you'll still catch it, within one interval.
- Decoys protect themselves and signal an attack; they don't stop it. The response is yours, via `--exec` or your tooling.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

No dependencies outside the Python standard library. Tested on Python 3.10–3.13, Linux/macOS/Windows.

## License

[MIT](https://github.com/winxtxrgit/honeyfile/blob/main/LICENSE) © Thanut Jongteerathanachote
