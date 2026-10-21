"""Command-line entry point for REQUIEM SecretGuard."""
import argparse
import json
import sys
from pathlib import Path

from .report import html_report
from .scanner import SEVERITY_ORDER, scan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="REQUIEM SecretGuard: local-only credential pattern scanner")
    parser.add_argument("path", nargs="?", default=".", help="Local path to scan (default: current directory)")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", help="Report format")
    parser.add_argument("--output", "-o", help="Save report to file instead of stdout")
    parser.add_argument("--fail-on", choices=["off", "low", "medium", "high", "critical"], default="high", help="Exit with code 2 at/above severity level")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    args = parser.parse_args(argv)
    try:
        data = scan(args.path, max_files=args.max_files, max_bytes=args.max_bytes)
        if args.format == "json":
            rendered = json.dumps(data, ensure_ascii=False, indent=2)
        elif args.format == "html":
            rendered = html_report(data)
        else:
            lines = [f'REQUIEM SECRETGUARD · {data["verdict"]}', f'{data["files_scanned"]} files scanned · {data["findings_count"]} finding(s)']
            for f in data["findings"]:
                lines.append(f'[{f["severity"].upper()}] {f["file"]}:{f["line"]} {f["description"]} (fp:{f["fingerprint"]})')
            for warning in data["warnings"]:
                lines.append(f'WARNING: {warning}')
            rendered = "\n".join(lines)
        if args.output:
            output = Path(args.output).expanduser()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered + "\n", encoding="utf-8")
            print(f'Report saved to {output}', file=sys.stderr)
        else:
            print(rendered)
        if data["incomplete"]:
            return 2
        if args.fail_on != "off" and any(SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER[args.fail_on] for f in data["findings"]):
            return 2
        return 0
    except (OSError, ValueError) as exc:
        print(f'Scan error: {exc}', file=sys.stderr)
        return 1
