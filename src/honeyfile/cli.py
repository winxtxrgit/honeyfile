"""Command line: ``honeyfile plant``, ``honeyfile watch``, ``honeyfile status``."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

from . import __version__
from .alerts import Sinks, format_terminal
from .decoys import PROFILES
from .manifest import ManifestError, read
from .plant import PlantError, plant
from .watch import monitor, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeyfile",
        description="Plant decoy files and get alerted the moment something modifies, "
        "encrypts or deletes them — an early warning for ransomware and intruders.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plant", help="write decoy files and record their baseline")
    p.add_argument("directory", type=Path, help="directory to plant decoys in")
    p.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="office",
        help="which set of decoys to plant (default: %(default)s)",
    )
    p.add_argument("--force", action="store_true", help="overwrite existing files of the same name")

    w = sub.add_parser("watch", help="monitor planted decoys and alert on any change")
    w.add_argument("directory", type=Path)
    w.add_argument(
        "--interval",
        type=_positive,
        default=5.0,
        metavar="SECONDS",
        help="seconds between scans (default: %(default)s)",
    )
    w.add_argument("--once", action="store_true", help="scan once and exit instead of looping")
    w.add_argument(
        "--no-new-files",
        action="store_true",
        help="do not alert on unplanted files appearing in the directory",
    )
    w.add_argument("--json", metavar="FILE", help="append each alert to FILE as JSON lines")
    w.add_argument("--webhook", metavar="URL", help="POST each alert as JSON to URL")
    w.add_argument(
        "--exec",
        dest="exec_cmd",
        metavar="CMD",
        help="run CMD on each alert (shell-style quoting; event passed as HONEYFILE_* env)",
    )

    s = sub.add_parser("status", help="show the current state of the decoys and exit")
    s.add_argument("directory", type=Path)
    s.add_argument("--no-new-files", action="store_true")

    return parser


def _positive(text: str) -> float:
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return value


def _cmd_plant(args) -> int:
    try:
        manifest = plant(args.directory, args.profile, args.force)
    except (PlantError, ValueError, OSError) as error:
        print(f"honeyfile: {error}", file=sys.stderr)
        return 2
    print(f"Planted {len(manifest.entries)} {args.profile} decoys in {args.directory}:")
    for entry in manifest.entries:
        print(f"  {entry.name}")
    print(f"\nNow watch them:\n  honeyfile watch {args.directory}")
    return 0


def _cmd_status(args) -> int:
    try:
        manifest = read(args.directory)
    except ManifestError as error:
        print(f"honeyfile: {error}", file=sys.stderr)
        return 2
    alerts = scan(args.directory, manifest, detect_new=not args.no_new_files)
    color = sys.stdout.isatty()
    if not alerts:
        print(f"OK: all {len(manifest.entries)} decoys in {args.directory} are intact.")
        return 0
    print(f"{len(alerts)} alert(s) in {args.directory}:")
    for alert in alerts:
        print("  " + format_terminal(alert, color))
    return 1


def _cmd_watch(args) -> int:
    sinks = Sinks(
        directory=str(args.directory),
        json_path=args.json,
        webhook=args.webhook,
        exec_cmd=shlex.split(args.exec_cmd) if args.exec_cmd else None,
        color=sys.stderr.isatty(),
    )
    if args.once:
        try:
            manifest = read(args.directory)
        except ManifestError as error:
            print(f"honeyfile: {error}", file=sys.stderr)
            return 2
        alerts = scan(args.directory, manifest, detect_new=not args.no_new_files)
        for alert in alerts:
            sinks.emit(alert)
        return 1 if alerts else 0

    print(f"Watching {args.directory} every {args.interval:g}s. Ctrl+C to stop.", file=sys.stderr)
    try:
        for event in monitor(args.directory, args.interval, detect_new=not args.no_new_files):
            if isinstance(event, ManifestError):
                print(f"honeyfile: baseline problem: {event}", file=sys.stderr, flush=True)
            else:
                sinks.emit(event)
    except KeyboardInterrupt:
        return 130
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"plant": _cmd_plant, "watch": _cmd_watch, "status": _cmd_status}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
