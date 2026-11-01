"""Local CLI for package and configuration diagnostics."""
import argparse
import json
import sys
from pathlib import Path
from vane.config import ConfigurationError, load_config

def main() -> int:
    parser = argparse.ArgumentParser(prog="vane", description="VANE engine diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="show package version")
    check = sub.add_parser("check", help="validate engine configuration")
    check.add_argument("--config", default="config/vane.example.json")
    args = parser.parse_args()
    if args.command == "version":
        from vane import __version__
        print(__version__)
        return 0
    if args.command == "check":
        path = Path(args.config)
        try:
            data = load_config(path)
        except ConfigurationError as exc:
            print(json.dumps({"ok": False, "error": str(exc), "path": str(path)}))
            return 2
        print(json.dumps({"ok": True, "config": str(path),
            "profile": data.get("profile"), "runtime_integration": data.get("runtime_integration"),
            "note": "Configuration validated; no runtime or target action performed."}))
        return 0
    return 2

if __name__ == "__main__":
    sys.exit(main())
