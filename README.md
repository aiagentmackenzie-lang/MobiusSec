# MobiusSec

**Unified Mobile Security Platform — One tool. Both platforms. No escape.**

MobiusSec is a developer-first mobile security scanner that tests both Android (APK) and iOS (IPA) apps in one tool. Static analysis, OWASP MASVS 2.0 compliance, secrets detection, privacy auditing, and SBOM generation — all from the CLI.

## Features

- **Android + iOS** — Unified scanning for both platforms
- **OWASP MASVS 2.0** — Direct compliance mapping with pass/fail status and L1/L2 gates
- **Privacy Engine** — Automated data-flow mapping, SDK tracking detection, LGPD/GDPR/CCPA gap analysis
- **CI/CD-Native** — GitHub Actions, GitLab CI, Jenkins. Quality gates, non-blocking by default
- **AI Remediation** — Local Ollama-powered fix suggestions with static fallback
- **SBOM Generation** — Dynamic SBOM from mobile binaries (CycloneDX 1.6)
- **STIX 2.1 Export** — Structured threat intelligence output
- **Secrets Scanner** — AWS keys, private keys, hardcoded passwords, generic API keys
- **YARA Engine** — Packer/malware detection with regex fallback when yara-python is unavailable
- **Cross-Platform Analysis** — Flutter and React Native framework detection

## Quick Start

```bash
# Install
pip install mobiussec

# Scan an APK
mobius scan app.apk

# Scan an IPA
mobius scan app.ipa

# Quick scan (critical/high only)
mobius scan app.apk --quick

# CI/CD gate — fail build if MASVS L1 not met
mobius scan app.apk --gate L1 --fail-on high

# MASVS compliance report
mobius masvs app.ipa

# MASVS with gate check
mobius masvs app.ipa --gate L1

# Quick MASVS scan
mobius masvs app.apk --quick
```

## Architecture

```
mobius scan app.apk
    |
    +-- Extract (apktool / zipfile)
    +-- Analyze (Android + iOS static analysis)
    +-- Secrets (AWS keys, private keys, hardcoded passwords)
    +-- YARA (packer/malware detection)
    +-- Cross-Platform (Flutter / React Native)
    +-- Privacy (SDK tracking, data collection, compliance gaps)
    +-- SBOM (CycloneDX from binaries)
    +-- Map (OWASP MASVS 2.0 compliance)
    +-- Report (Rich / JSON / HTML / SARIF / Markdown)
```

## All Commands

| Command | Description |
|---------|-------------|
| `mobius scan` | Scan APK/IPA for security vulnerabilities |
| `mobius masvs` | OWASP MASVS 2.0 compliance report |
| `mobius diff` | Compare two app versions for security differences |
| `mobius fix` | AI-powered remediation suggestions (Ollama) |
| `mobius report` | Generate HTML/SARIF/Markdown/JSON report |
| `mobius privacy` | Privacy analysis — SDK tracking, data collection, compliance |
| `mobius sbom` | Generate Software Bill of Materials (CycloneDX) |
| `mobius stix` | Export findings as STIX 2.1 bundle |
| `mobius cicd` | Generate CI/CD configs (GitHub/GitLab/Jenkins) |
| `mobius deploy` | Generate deploy configs (local/Docker/K8s/Cloud Run/Fargate) |
| `mobius bridge` | Portfolio tool recommendations based on findings |
| `mobius version` | Show version |

## MASVS Categories

| Category | Focus |
|----------|-------|
| STORAGE | Secure data storage at rest |
| CRYPTO | Cryptographic functionality |
| AUTH | Authentication and authorization |
| NETWORK | Secure network communication |
| PLATFORM | Platform and IPC interaction |
| CODE | Code-level security |
| RESILIENCE | Anti-RE and anti-tampering |
| PRIVACY | Privacy controls |

## Known Limitations

- **Binary Android XML**: Manifest analysis requires `apktool` decompilation or `lxml`. Fallback ZIP extraction may not parse binary XML.
- **iOS analysis**: Depends on Info.plist structure. Binary plists use `biplist` when available.
- **Static only**: No dynamic analysis, no runtime testing, no device interaction.
- **File caps**: Source file analysis is capped at 200 files per category to manage memory.
- **AI remediation**: Requires Ollama running locally. Falls back to static remediation guidance.

## Requirements

- Python 3.12+
- `lxml` (recommended — graceful fallback if missing)
- `apktool` (optional — for better APK decompilation)
- `yara-python` (optional — regex fallback built in)
- `ollama` (optional — for AI remediation)

## License

Apache-2.0