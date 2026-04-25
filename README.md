# MobiusSec

**Unified Mobile Security Platform — One tool. Both platforms. No escape.**

MobiusSec is a developer-first mobile security platform that tests both Android (APK) and iOS (IPA) apps in one tool. It bridges the gap between fragmented open-source tools and expensive enterprise platforms.

## Features

- 🔍 **Android + iOS** — Unified scanning for both platforms
- 📋 **OWASP MASVS 2.0** — Direct compliance mapping with pass/fail status
- 🔒 **Privacy Engine** — Automated data-flow and SDK tracking analysis
- 🚀 **CI/CD-Native** — GitHub Action, quality gates, non-blocking by default
- 🧠 **AI Remediation** — Local Ollama-powered fix suggestions
- 📦 **SBOM Generation** — Dynamic SBOM from mobile binaries (CycloneDX)
- 🇧🇷 **Brazil-Ready** — LGPD compliance mapping, Pix fraud detection patterns planned

## Quick Start

```bash
# Install
pip install mobiussec

# Scan an APK
mobius scan app.apk

# Scan an IPA
mobius scan app.ipa

# Quick check (critical/high only)
mobius scan app.apk --quick

# CI/CD gate mode
mobius scan app.apk --gate L1 --fail-on high

# MASVS compliance report
mobius masvs app.ipa

# MASVS with gate check
mobius masvs app.ipa --gate L1

# Quick MASVS scan (critical/high only)
mobius masvs app.apk --quick
```

## Architecture

```
mobius scan app.apk
    │
    ├── Extract (apktool / zipfile)
    ├── Analyze (Android + iOS static analysis)
    ├── Map (OWASP MASVS 2.0 compliance)
    └── Report (Rich / JSON / SARIF)
```

## MASVS Categories

| Category | Focus |
|----------|-------|
| STORAGE | Secure data storage at rest |
| CRYPTO | Cryptographic functionality |
| AUTH | Authentication & authorization |
| NETWORK | Secure network communication |
| PLATFORM | Platform & IPC interaction |
| CODE | Code-level security |
| RESILIENCE | Anti-RE & anti-tampering |
| PRIVACY | Privacy controls |

## All Commands

| Command | Description |
|---------|-------------|
| `mobius scan` | Scan APK/IPA for vulnerabilities |
| `mobius masvs` | MASVS 2.0 compliance report |
| `mobius diff` | Compare two app versions |
| `mobius fix` | AI-powered remediation suggestions |
| `mobius report` | Generate HTML/SARIF/Markdown/JSON report |
| `mobius privacy` | Privacy analysis (SDK tracking, LGPD/GDPR/CCPA) |
| `mobius sbom` | Generate CycloneDX SBOM |
| `mobius stix` | Export findings as STIX 2.1 bundle |
| `mobius cicd` | Generate CI/CD configs (GitHub/GitLab/Jenkins) |
| `mobius deploy` | Generate deploy configs (local/Docker/K8s/cloud) |
| `mobius bridge` | Portfolio tool recommendations |
| `mobius version` | Show version |

## License

Apache-2.0