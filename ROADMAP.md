# Roadmap

honeyfile 0.3 plants decoys and reports when something touches them: instantly, reads included,
on Linux; by polling every few seconds on macOS and Windows. The next releases close that gap,
then connect honeyfile to the rest of a defender's tools. The rule in every release: **a normal
user never touches a decoy, so every alert must be worth reading.**

## 0.4.0: real time on every OS

- [x] Release with twine 7 and current hatchling (Metadata-Version 2.5), and run the same
      build and `twine check` in CI, so a packaging break shows up in a pull request.
- [x] kqueue backend for macOS and the BSDs: modify, delete, rename, replace and new files are
      reported the instant they happen, using `select.kqueue` from the standard library.
- [ ] Windows backend with `ReadDirectoryChangesW` through `ctypes`, still no dependencies.
- [ ] Catch up on start: a real-time backend only sees changes after it starts, so `watch`
      first compares against the baseline, as polling does, and reports what happened while
      nothing was watching.

## 0.5.0: work with loghunt

Every decoy carries a `HONEYFILE-CANARY-…` token, and a decoy in a web root is a path no
legitimate visitor requests.

- [ ] `honeyfile list --json`: the planted paths and tokens, for other tools to read.
- [ ] In [loghunt](https://github.com/winxtxrgit/loghunt), a `decoy-path` rule (a request for
      a planted file) and a `canary-token` rule (a token in a URL), each enough to report an IP
      alone.

## 0.6.0: run as a service

- [ ] `honeyfile install DIR` writes a systemd unit (Linux) or launchd agent (macOS) that runs
      `watch` at boot, and `honeyfile uninstall` removes it.
- [ ] A heartbeat option, so silence from a stopped watcher is distinguishable from "nothing
      happened".

## Not planned

- Reads on macOS and Windows. kqueue has no open event on macOS, and the APIs that do
  (Endpoint Security, Windows file-access auditing) need entitlements or system auditing
  settings. The README points to them; honeyfile stays the portable layer.
- Stopping an attack by itself. `--exec` hands the alert to whatever response you trust.
- Dependencies outside the Python standard library.
