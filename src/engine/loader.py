#!/usr/bin/env python3
"""ECOBIO Antivirus — Rule Loader Engine
Loads YARA rules from local directory and optional remote feed.
Production rules are distributed separately from the open-source engine."""

import hashlib
import json
import os
import tempfile
from pathlib import Path

try:
    import yara
except ImportError:
    raise ImportError("yara-python required: pip install yara-python")


class RuleLoader:
    """Manages YARA rule compilation from multiple sources."""

    def __init__(self, rules_dirs=None, feed_url=None):
        self.rules_dirs = rules_dirs or []
        self.feed_url = feed_url
        self._compiled = None
        self._rule_count = 0
        self._rule_hashes = {}

    def add_rules_dir(self, path):
        """Add a directory containing .yar files."""
        p = Path(path)
        if p.is_dir():
            self.rules_dirs.append(p)
        else:
            raise FileNotFoundError(f"Rules directory not found: {path}")

    def compile(self):
        """Compile all rules from all sources."""
        filepaths = {}
        for rules_dir in self.rules_dirs:
            for yar_file in rules_dir.glob("*.yar"):
                name = yar_file.stem
                # Avoid name collisions across directories
                if name in filepaths:
                    name = f"{rules_dir.name}_{name}"
                filepaths[name] = str(yar_file)
                self._rule_hashes[name] = self._file_hash(yar_file)

        if not filepaths:
            raise RuntimeError("No .yar rule files found in any configured directory")

        self._compiled = yara.compile(filepaths=filepaths)
        self._rule_count = len(filepaths)
        return self._compiled

    def scan(self, filepath, timeout=15):
        """Scan a file against compiled rules."""
        if not self._compiled:
            self.compile()
        try:
            return self._compiled.match(filepath, timeout=timeout)
        except yara.Error:
            return []

    def scan_data(self, data, timeout=15):
        """Scan raw bytes against compiled rules."""
        if not self._compiled:
            self.compile()
        try:
            return self._compiled.match(data=data, timeout=timeout)
        except yara.Error:
            return []

    @property
    def rule_count(self):
        return self._rule_count

    @property
    def rule_checksums(self):
        return dict(self._rule_hashes)

    @staticmethod
    def _file_hash(filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()[:16]

    def info(self):
        """Return engine info for diagnostics."""
        return {
            "engine": "ecobio-av",
            "version": "0.1.0",
            "rules_dirs": [str(d) for d in self.rules_dirs],
            "rules_loaded": self._rule_count,
            "feed": self.feed_url or "none",
        }
