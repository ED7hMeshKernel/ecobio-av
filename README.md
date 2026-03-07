# ECOBIO Antivirus

**Free, open-source detection engine** — lightweight YARA-based threat scanner built from real-world offensive research.

> Built by [ECOBIO Security](https://github.com/ED7hMeshKernel) — we attack systems to build better defenses.

## What is ECOBIO-AV

ECOBIO-AV is a **detection engine** that scans files using YARA rules. The engine is open-source and free. Detection rules are developed separately through offensive security research.

**Engine** (this repo) = open-source, MIT license
**Detection rules** = maintained by ECOBIO Security ([details](RULES.md))

This is the same model used by ClamAV, Suricata, and other professional security tools — the engine is open, the intelligence is curated.

## Features

- **YARA-powered** — industry-standard pattern matching
- **Real-time monitoring** — watches directories for new threats
- **Auto-quarantine** — critical detections are isolated immediately
- **Multi-source rules** — load rules from local dirs, custom paths, or feed
- **MITRE ATT&CK mapped** — every rule references its technique ID
- **Lightweight** — pure Python, no bloatware, no telemetry, no cloud dependency

## Quick Start

```bash
pip install yara-python
git clone https://github.com/ED7hMeshKernel/ecobio-av.git
cd ecobio-av

# Scan with included example rules
python3 src/scanner/scan.py /path/to/scan

# Scan with custom rules directory
python3 src/scanner/scan.py --rules /path/to/my-rules/ /path/to/scan

# Watch a directory in real-time
python3 src/scanner/scan.py --watch ~/Downloads
```

## Architecture

```
src/
  engine/       — Rule loader, compiler, multi-source support
  scanner/      — File watcher, real-time scanning, quarantine
  rules/        — Example rules (production rules distributed separately)
```

## Rule Format

ECOBIO uses standard YARA with required metadata:

```yara
rule ECOBIO_Example {
    meta:
        author = "ECOBIO Security"
        description = "What this detects"
        threat_level = "low|medium|high|critical"
        mitre = "T1059 - Technique Name"
        action = "ALERT|BLOCK|KILL|QUARANTINE"
    strings:
        $pattern = "suspicious_string"
    condition:
        $pattern
}
```

See [RULES.md](RULES.md) for details on production rules.

## Contributing

Engine contributions welcome (scanner improvements, new features, bug fixes).

## License

MIT — Engine is free for personal and commercial use.

## Roadmap

- [ ] Behavioral engine (process tree analysis)
- [ ] Windows service mode
- [ ] Linux daemon mode
- [ ] Rule update feed
- [ ] Memory scanning
- [ ] Network traffic analysis

---

**ECOBIO Security** — *Attack to defend.*
