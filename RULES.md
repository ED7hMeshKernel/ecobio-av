# ECOBIO Detection Rules

## Open-source rules

The `src/rules/` directory contains **example rules** for testing and development.
These demonstrate the format and metadata schema used by the ECOBIO engine.

## Production rules

Production detection rules are developed and maintained by ECOBIO Security
based on real-world offensive research and lab-validated attack chains.

Production rules cover:
- HTML smuggling & LOLBIN abuse
- AMSI and security tool bypass techniques
- PowerShell-based threats and encoded payloads
- Credential theft (browsers, Windows Credential Manager)
- Process injection and shellcode execution
- Keyloggers and input capture
- Data exfiltration channels

### Using production rules

```bash
# Point the scanner to your rules directory
python3 src/scanner/scan.py --rules /path/to/ecobio-rules-pro/ /target/

# Or configure in environment
export ECOBIO_RULES_DIR=/path/to/ecobio-rules-pro/
python3 src/scanner/scan.py /target/
```

### Obtaining production rules

Contact: ECOBIO Security — https://github.com/ED7hMeshKernel

Production rules are available for:
- Security researchers and blue teams
- Managed security providers
- Organizations under partnership agreement
