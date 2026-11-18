from __future__ import annotations

import argparse
from pathlib import Path

from .loader import load_project
from .scanner import scan, to_json, to_markdown
from .web import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="reposleuth", description="Local-first, architecture-agnostic codebase auditor")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("web", help="Start the local web interface")
    web.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    web.add_argument("--port", type=int, default=8765)
    cli = commands.add_parser("scan", help="Scan a project and write a report")
    cli.add_argument("path", nargs="?", default=".", help="Project folder, .zip archive, or public HTTPS GitHub URL")
    cli.add_argument("--format", choices=("markdown", "json"), default="markdown")
    cli.add_argument("--output", "-o", help="Output file; defaults to audit-report.md or .json")
    args = parser.parse_args()
    if args.command == "scan":
        with load_project(args.path) as (root, label):
            report = scan(root)
            report["root"] = label
            content = to_json(report) if args.format == "json" else to_markdown(report)
            destination = Path(args.output or ("audit-report.json" if args.format == "json" else "audit-report.md"))
            destination.write_text(content, encoding="utf-8")
            print(f"Scanned {report['files_scanned']} files; found {report['summary']['total']} findings.")
            print(f"Report: {destination.resolve()}")
    else:
        serve(getattr(args, "host", "127.0.0.1"), getattr(args, "port", 8765))


if __name__ == "__main__":
    main()
