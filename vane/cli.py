"""Small local CLI for environment and configuration diagnostics."""
import argparse
import json
import sys
from pathlib import Path

def main() -> int:
    parser = argparse.ArgumentParser(prog="vane", description="VANE engine diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="show package version")
    check = sub.add_parser("check", help="check repository configuration presence")
    check.add_argument("--config", default="config.yaml")
    args = parser.parse_args()
    if args.command == "version":
        from vane import __version__
        print(__version__)
        return 0
    if args.command == "check":
        path = Path(args.config)
        if not path.is_file():
            print(json.dumps({"ok": False, "error": "config_not_found", "path": str(path)}))
            return 2
        print(json.dumps({"ok": True, "config": str(path),
                          "note": "Presence checked only; no runtime or target action performed."}))
        return 0
    return 2

if __name__ == "__main__":
    sys.exit(main())
