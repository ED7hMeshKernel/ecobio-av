#!/usr/bin/env python3
"""ECOBIO Antivirus — Real-time YARA Scanner
Watches directories for new/modified files and scans with YARA rules."""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

try:
    import yara
except ImportError:
    print("[!] yara-python not installed. Install with: pip install yara-python")
    sys.exit(1)


RULES_DIR = Path(__file__).parent.parent / "rules"
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".wsf", ".scr", ".pif", ".msi", ".msp", ".cpl",
    ".html", ".htm", ".svg", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".lnk", ".iso", ".img", ".vhd", ".vhdx",
}
QUARANTINE_DIR = Path.home() / ".ecobio-av" / "quarantine"
LOG_FILE = Path.home() / ".ecobio-av" / "scan.log"


def load_rules():
    """Compile all YARA rules from the rules directory."""
    rule_files = {}
    for yar_file in RULES_DIR.glob("*.yar"):
        rule_files[yar_file.stem] = str(yar_file)

    if not rule_files:
        print(f"[!] No .yar files found in {RULES_DIR}")
        return None

    try:
        rules = yara.compile(filepaths=rule_files)
        print(f"[+] Loaded {len(rule_files)} rule files from {RULES_DIR}")
        for name in sorted(rule_files):
            print(f"    - {name}.yar")
        return rules
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
        return None


def scan_file(rules, filepath):
    """Scan a single file against YARA rules."""
    try:
        matches = rules.match(filepath, timeout=15)
        return matches
    except yara.Error:
        return []


def file_hash(filepath):
    """SHA-256 hash of file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return "error"


def quarantine(filepath):
    """Move file to quarantine directory (cross-device safe)."""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = QUARANTINE_DIR / f"{filepath.name}.{int(time.time())}.quarantined"
    try:
        # Use copy+delete instead of rename for cross-device support (WSL→Windows)
        shutil.copy2(str(filepath), str(dest))
        filepath.unlink()
        print(f"  [Q] Quarantined: {filepath.name} -> {dest}")
        return True
    except (OSError, PermissionError) as e:
        # If delete fails (permissions), at least log it
        if dest.exists():
            print(f"  [Q] Copied to quarantine (original kept — no delete permission)")
            return True
        print(f"  [!] Cannot quarantine {filepath.name}: {e}")
        return False


def log_detection(filepath, matches):
    """Log detection to file."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "file": str(filepath),
        "hash": file_hash(str(filepath)),
        "size": filepath.stat().st_size if filepath.exists() else 0,
        "matches": [
            {
                "rule": m.rule,
                "tags": m.tags,
                "meta": m.meta,
            }
            for m in matches
        ],
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def scan_directory(rules, directory, recursive=True, do_quarantine=True):
    """Scan all files in a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        print(f"[!] Not a directory: {directory}")
        return 0

    total = 0
    detections = 0
    clean = 0
    pattern = "**/*" if recursive else "*"

    for filepath in sorted(directory.glob(pattern)):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() not in SCAN_EXTENSIONS:
            continue

        total += 1
        matches = scan_file(rules, str(filepath))
        if matches:
            detections += 1
            threat_level = max(
                (m.meta.get("threat_level", "unknown") for m in matches),
                key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0),
            )
            print(f"\n  [{'!!' if threat_level == 'critical' else '!'}] {filepath.name}")
            print(f"      Path: {filepath}")
            print(f"      Threat: {threat_level.upper()}")
            print(f"      SHA256: {file_hash(str(filepath))[:32]}...")
            for m in matches:
                print(f"      Rule: {m.rule}")
                print(f"        MITRE: {m.meta.get('mitre', 'N/A')}")
                print(f"        Action: {m.meta.get('action', 'ALERT')}")
            log_detection(filepath, matches)

            # Auto-quarantine critical threats
            if threat_level == "critical" and do_quarantine:
                quarantine(filepath)
        else:
            clean += 1
            sys.stdout.write(".")
            sys.stdout.flush()

    print(f"\n\n{'=' * 50}")
    print(f"  Scan complete")
    print(f"  Files scanned: {total}")
    print(f"  Clean: {clean}")
    print(f"  Detections: {detections}")
    if detections:
        print(f"  Log: {LOG_FILE}")
    print(f"{'=' * 50}")
    return detections


def watch_directory(rules, directory, interval=2):
    """Watch directory for new/modified files and scan them."""
    directory = Path(directory)
    print(f"[*] Watching {directory} (interval: {interval}s)")
    print("[*] Press Ctrl+C to stop\n")

    seen = {}  # filepath -> mtime

    while True:
        try:
            for filepath in directory.iterdir():
                if not filepath.is_file():
                    continue
                if filepath.suffix.lower() not in SCAN_EXTENSIONS:
                    continue

                try:
                    mtime = filepath.stat().st_mtime
                except OSError:
                    continue

                if filepath not in seen or seen[filepath] != mtime:
                    seen[filepath] = mtime
                    matches = scan_file(rules, str(filepath))
                    if matches:
                        threat_level = max(
                            (m.meta.get("threat_level", "unknown") for m in matches),
                            key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0),
                        )
                        ts = time.strftime("%H:%M:%S")
                        print(f"\n  [{ts}] [ALERT] {filepath.name} — {threat_level.upper()}")
                        for m in matches:
                            print(f"    {m.rule} | {m.meta.get('mitre', '')}")
                        log_detection(filepath, matches)

            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped watching.")
            break


def main():
    parser = argparse.ArgumentParser(
        description="ECOBIO Antivirus — YARA-based threat scanner"
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--watch", "-w", metavar="DIR", help="Watch directory for new files")
    parser.add_argument("--recursive", "-r", action="store_true", default=True)
    parser.add_argument("--rules", metavar="DIR", help="Custom rules directory")
    parser.add_argument("--no-quarantine", action="store_true", help="Disable auto-quarantine")
    args = parser.parse_args()

    global RULES_DIR
    if args.rules:
        RULES_DIR = Path(args.rules)

    print("=" * 50)
    print("  ECOBIO Antivirus Scanner v0.1")
    print("=" * 50)
    print()

    rules = load_rules()
    if not rules:
        sys.exit(1)

    print()

    if args.watch:
        watch_directory(rules, args.watch)
    else:
        target = Path(args.path)
        if target.is_file():
            matches = scan_file(rules, str(target))
            if matches:
                print(f"\n  [DETECTION] {target}")
                for m in matches:
                    print(f"    Rule: {m.rule} | {m.meta.get('threat_level', '?')}")
                log_detection(target, matches)
            else:
                print(f"  [CLEAN] {target}")
        elif target.is_dir():
            scan_directory(rules, target, args.recursive, not args.no_quarantine)
        else:
            print(f"[!] Path not found: {target}")
            sys.exit(1)


if __name__ == "__main__":
    main()
