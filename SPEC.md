# MobiusSec — Unified Mobile Security Platform

**Version:** 0.1.0-spec  
**Date:** April 18, 2026  
**Author:** Raphael + Agent Mackenzie

---

## 1. Vision

MobiusSec is a **developer-first, unified mobile security platform** that tests both Android and iOS apps in one tool. It bridges the gap between fragmented open-source tools (MobSF, Frida, Objection) and expensive enterprise platforms ($20K–$200K+/year).

**One tool. Both platforms. Developer-friendly.**

---

## 2. Problem Statement

| Problem | Detail |
|---------|--------|
| **Fragmented tooling** | Android testing = MobSF + Drozer + APKTool + Frida. iOS testing = MobSF + Objection + class-dump + Frida. No single tool covers both well. |
| **No privacy/compliance** | Zero OSS tools map findings to OWASP MASVS, GDPR, LGPD, CCPA, PCI DSS. This is manual, painful, and error-prone. |
| **No CI/CD integration** | MobSF in Docker ≠ CI/CD-native. No mobile security GitHub Actions exist. |
| **Enterprise pricing** | NowSecure: $21K median. Checkmarx: $50K–200K. Veracode: $80K–300K. Mid-market ($5K–15K) is wide open. |
| **No cross-platform support** | Flutter, React Native, Kotlin Multiplatform — no tool handles these. |
| **Brazil/LATAM gap** | Top banking Trojan target. LGPD compliance required. Zero locally-focused tools. |
| **Developer-hostile UX** | Mobile security tools are built for auditors, not developers. Slow, noisy, blocking. |

---

## 3. Core Differentiators

1. **Unified Android + iOS** — One CLI, one API, one dashboard for both platforms
2. **Direct OWASP MASVS 2.0 compliance mapping** — Every finding maps to a MASVS control with pass/fail status
3. **Privacy engine** — Automated data-flow analysis: what data is collected, where it goes, which SDKs touch it, LGPD/GDPR/CCPA alignment
4. **CI/CD-native** — GitHub Action, GitLab CI, Bitrise, Fastlane. Quality gates. Non-blocking by default.
5. **Developer-first UX** — Fast feedback, IDE integration, AI-powered remediation with code samples, clean reports
6. **Cross-platform framework support** — Flutter/Dart, React Native, Kotlin Multiplatform analysis
7. **Mobile SBOM** — Dynamic SBOM generation from binaries: all SDKs, libraries, known CVEs
8. **Brazil-first** — Portuguese language, LGPD compliance, local threat intelligence, Pix fraud detection

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        MobiusSec                             │
├──────────────┬──────────────┬───────────────┬───────────────┤
│   CLI        │   Web API    │  Dashboard    │  CI/CD        │
│  (Typer)     │  (Fastify)  │  (React/Vite) │  (Actions)   │
├──────────────┴──────────────┴───────────────┴───────────────┤
│                     Core Engine (Python)                      │
├──────────┬──────────┬──────────┬──────────┬──────────────────┤
│ Android  │   iOS    │ Privacy  │  MASVS   │   SBOM           │
│ Analyzer │ Analyzer │ Engine   │ Mapper   │   Generator      │
├──────────┴──────────┴──────────┴──────────┴──────────────────┤
│                    Shared Analysis Layer                       │
├──────────┬──────────┬──────────┬──────────┬──────────────────┤
│ Semgrep  │   YARA   │ Binary  │ Secrets  │  Framework       │
│ Rules    │  Engine  │ Analysis │ Scanner  │  CVE Checker     │
└──────────┴──────────┴──────────┴──────────┴──────────────────┘
```

---

## 5. Modules

### 5.1 Android Analyzer

**Input:** APK file or source code directory  
**Capabilities:**

| Category | Checks | Method |
|----------|--------|--------|
| **Manifest** | Exported components, permissions, backup flag, debuggable, network security config | APKTool + manifest parser |
| **Storage** | SharedPreferences insecurity, external storage writes, hardcoded secrets in XML | Semgrep + pattern matching |
| **Crypto** | Weak algorithms (MD5, SHA1, DES, ECB), hardcoded keys, insecure random | Semgrep + mobsfscan rules |
| **Network** | Certificate pinning detection, cleartext traffic, TLS misconfiguration | Manifest + source analysis |
| **IPC** | Intent injection, content provider leakage, PendingIntent misuse, deep link risks | Semgrep + Drozer-inspired rules |
| **WebView** | JavaScript interfaces, file:// access, deep link→WebView, addJavascriptInterface | Semgrep + pattern matching |
| **Resilience** | Root detection, anti-debug, obfuscation assessment (APKiD), emulator detection | YARA + binary analysis |
| **Code** | SQL injection, logging sensitive data, implicit intents, hardcoded credentials | Semgrep + pattern matching |

**Key tools leveraged:** APKTool (decompile), Jadx (decompile to Java), APKiD (packer detection), Semgrep (SAST), YARA (binary patterns), custom rules

### 5.2 iOS Analyzer

**Input:** IPA file or source code directory  
**Capabilities:**

| Category | Checks | Method |
|----------|--------|--------|
| **Info.plist** | ATS exceptions, URL schemes, background modes, privacy descriptions, minimum iOS version | Plist parser |
| **Keychain** | Insecure protection classes (kSecAttrAccessibleAlways), missing kSecAttrAccessibleWhenUnlockedThisDeviceOnly | Semgrep + binary strings |
| **Network** | SSL pinning detection, NSAllowsArbitraryLoads, custom trust evaluators | Plist + source analysis |
| **Storage** | UserDefaults for sensitive data, CoreData unencrypted, cookies insecure flags | Semgrep + binary analysis |
| **WebView** | WKWebView JS injection, file:// loading, evaluateJavaScript misuse, missing CSP | Semgrep (akabe1 + custom rules) |
| **Auth** | LAContext bypass, biometric fallback weakness, TouchID/FaceID implementation gaps | Semgrep + pattern matching |
| **Pasteboard** | UIPasteboard usage, sensitive data on clipboard | Semgrep |
| **Resilience** | Jailbreak detection, anti-debug (ptrace/sysctl), code signing validity | Binary analysis + YARA |
| **Entitlements** | Dangerous entitlements, shared keychain groups, app group containers | codesign + plist parsing |
| **Binary** | Hardcoded strings (URLs, keys, tokens), encryption status, framework versions | strings + class-dump + ktool |

**Key tools leveraged:** class-dump/ktool (Mach-O analysis), Semgrep (SAST), YARA (binary patterns), biplist (plist parsing), custom rules

**No-jailbreak required** for static analysis. Dynamic analysis hooks into Frida when available.

### 5.3 Privacy Engine

**What it does:** Automatically maps what user data an app collects, where it goes, and whether it complies with privacy regulations.

| Feature | Detail |
|---------|--------|
| **Data collection mapping** | Identify all data accessed: location, camera, microphone, contacts, clipboard, identifiers (IDFA, IDFV) |
| **SDK tracking** | Map which third-party SDKs collect/transmit data, and what they send |
| **Permission analysis** | Cross-reference declared permissions with actual usage (over-privileged detection) |
| **Consent gaps** | Missing NS*UsageDescription keys (iOS), missing permission rationale (Android) |
| **Data flow visualization** | Show where data enters → where it's stored → where it's transmitted |
| **Compliance scoring** | GDPR, LGPD, CCPA alignment score per app |

### 5.4 MASVS Mapper

**What it does:** Maps every finding to OWASP MASVS 2.0 controls with pass/fail status.

| Output | Detail |
|--------|--------|
| **Per-category score** | STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY |
| **Per-test status** | Each MASTG test: PASS / FAIL / WARN / SKIP / N/A |
| **Compliance report** | PDF/HTML with MASVS L1/L2 certification readiness |
| **Diff tracking** | Compare MASVS scores across app versions |

### 5.5 SBOM Generator

**What it does:** Generates a Software Bill of Materials from mobile binaries.

| Feature | Detail |
|---------|--------|
| **SDK inventory** | All embedded third-party SDKs and libraries |
| **Version detection** | Best-effort version identification from binary strings/symbols |
| **CVE cross-reference** | Check identified libraries against known CVEs |
| **Format** | CycloneDX JSON (industry standard SBOM format) |
| **Continuous monitoring** | Alert when new CVEs affect previously scanned libraries |

### 5.6 AI Remediation Engine

**What it does:** Provides context-specific fix suggestions for every finding.

| Feature | Detail |
|---------|--------|
| **Code fix suggestions** | AI-generated fix code in the app's language (Kotlin, Java, Swift, Dart) |
| **Severity explanation** | Plain-English explanation of why a finding matters |
| **Priority ranking** | Which findings to fix first (exploitability × impact) |
| **False positive reduction** | AI triage to suppress likely false positives |
| **Local AI** | Ollama-based (optional) — no data leaves the machine |

---

## 6. CLI Design

```bash
# Scan an APK
mobius scan app.apk

# Scan an IPA
mobius scan app.ipa

# Scan source code
mobius scan ./my-app-src --type android

# Quick check (fast, top findings only)
mobius scan app.apk --quick

# Full MASVS compliance report
mobius scan app.ipa --report masvs --output report.html

# Privacy analysis only
mobius privacy app.apk

# SBOM generation
mobius sbom app.apk --format cyclonedx

# Compare two versions
mobius diff app-v1.apk app-v2.apk

# CI/CD mode (exit code based on severity threshold)
mobius scan app.apk --gate L1 --fail-on high

# List MASVS categories and their status
mobius masvs app.apk

# AI-powered remediation
mobius fix app.apk --finding STORAGE-001
```

### CLI Principles
- **Non-blocking by default** — scans don't break builds unless you set `--fail-on`
- **Fast feedback** — `--quick` mode runs in <60 seconds
- **Machine-readable output** — JSON, SARIF, CycloneDX formats
- **Human-readable too** — Beautiful terminal output with Rich/textual

---

## 7. API Design

**Fastify (Node.js) REST API + WebSocket**

```
POST   /api/v1/scan              — Submit app for scanning
GET    /api/v1/scan/:id          — Get scan status
GET    /api/v1/scan/:id/results   — Get scan results
GET    /api/v1/scan/:id/masvs    — Get MASVS compliance mapping
GET    /api/v1/scan/:id/privacy  — Get privacy analysis
GET    /api/v1/scan/:id/sbom     — Get SBOM (CycloneDX)
GET    /api/v1/scan/:id/report   — Download report (HTML/PDF/SARIF)
POST   /api/v1/diff              — Compare two scans
WS     /ws/scan/:id              — Real-time scan progress
```

---

## 8. Dashboard

**React + Vite + Tailwind + D3**

### Pages
1. **Scan Dashboard** — Upload apps, view scan history, queue status
2. **Findings** — Filterable, sortable vulnerability list with severity, MASVS category, remediation
3. **MASVS Compliance** — Radar chart per category, L1/L2 readiness score, per-test pass/fail
4. **Privacy Map** — Data flow visualization, SDK tracking, compliance score
5. **SBOM** — Library inventory, CVE alerts, version tracking
6. **Diff View** — Side-by-side comparison between app versions
7. **Settings** — API keys, CI/CD config, notification preferences

### Design Principles
- Clean, modern UI (not MobSF's 2015 aesthetic)
- Mobile-responsive
- Dark mode default
- Real-time WebSocket updates during scans

---

## 9. CI/CD Integration

### GitHub Action (Priority 1)

```yaml
- name: MobiusSec Security Scan
  uses: mobiussec/action@v1
  with:
    app-path: ./app/build/outputs/apk/release/app.apk
    masvs-level: L1
    fail-on: high
    report-format: sarif
    report-path: mobiussec-results.sarif
```

### Other Integrations
- **GitLab CI** — Docker image + CI template
- **Bitrise** — Step for mobile CI/CD
- **Fastlane** — Plugin for iOS deployment pipelines
- **Jenkins** — Pipeline shared library

---

## 10. Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Core Engine** | Python 3.12+ | Rich ecosystem for binary analysis, semgrep integration, ML/AI |
| **CLI** | Typer + Rich | Beautiful terminal UX, type-safe |
| **API Server** | Fastify (Node.js) | Fast, WebSocket support, TypeScript ecosystem |
| **Dashboard** | React + Vite + Tailwind + D3 | Modern, fast, great charting |
| **SAST Engine** | Semgrep + custom rules | Industry standard, extensible |
| **Binary Analysis** | ktool, APKTool, class-dump | Proven tools |
| **Pattern Matching** | YARA (yara-python) | Standard for binary pattern detection |
| **SBOM Format** | CycloneDX | Industry standard, OWASP project |
| **AI/Remediation** | Ollama (local) + OpenAI API (optional) | Privacy-first, cloud optional |
| **Database** | SQLite (local) / PostgreSQL (server) | Simple for single-user, scalable for teams |
| **Container** | Docker | Easy deployment, CI/CD integration |
| **Reporting** | Jinja2 (HTML/PDF) + SARIF | Multi-format output |

---

## 11. Build Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Project scaffolding (monorepo: core/, cli/, api/, dashboard/)
- [ ] Core engine: APK/IPA extraction and parsing
- [ ] Android analyzer: Manifest + Semgrep rules (top 30 checks)
- [ ] iOS analyzer: Info.plist + entitlements + binary strings (top 30 checks)
- [ ] CLI: `mobius scan`, `mobius masvs`, basic output
- [ ] MASVS mapper: Map findings to MASVS 2.0 categories
- [ ] Docker setup

### Phase 2: Depth (Week 3-4)
- [ ] Android deep analysis: IPC, WebView, crypto, resilience
- [ ] iOS deep analysis: Keychain, WebView, ATS, pasteboard, biometrics
- [ ] Privacy engine: Data collection mapping, SDK tracking
- [ ] SBOM generator: Library inventory + CVE cross-reference
- [ ] YARA integration: APKiD rules + custom malware rules
- [ ] Secrets scanner: Hardcoded API keys, tokens, passwords
- [ ] CLI: `mobius privacy`, `mobius sbom`, `--quick`, `--gate`

### Phase 3: Interface (Week 5-6)
- [ ] Fastify API: All endpoints + WebSocket
- [ ] React dashboard: All 7 pages
- [ ] Reports: HTML + PDF + SARIF + CycloneDX
- [ ] AI remediation: Ollama-powered fix suggestions
- [ ] Diff analysis: Compare app versions
- [ ] Cross-platform support: Flutter/Dart, React Native analysis

### Phase 4: Ship (Week 7-8)
- [ ] GitHub Action: mobiussec/action
- [ ] CI/CD templates: GitLab, Bitrise, Fastlane
- [ ] Brazil/LATAM: Portuguese language, LGPD rules, Pix fraud detection
- [ ] Documentation: Getting started, API reference, MASVS mapping guide
- [ ] PyPI package: `pip install mobiussec`
- [ ] Docker Hub: `docker pull mobiussec/mobiussec`
- [ ] Landing page + GitHub README

---

## 12. Target Users

| Persona | Need | MobiusSec Value |
|---------|------|-----------------|
| **Mobile developer** | "Is my app secure before I ship?" | CLI in CI/CD, fast feedback, fix suggestions |
| **Security engineer** | "Audit this app against MASVS" | Full MASVS mapping, privacy engine, SBOM |
| **Startup CTO** | "We can't afford NowSecure" | Free OSS, mid-market SaaS later |
| **Brazilian fintech** | "LGPD compliance for our Pix app" | LGPD rules, Portuguese, local threat intel |
| **Pentester** | "Quick recon on this APK/IPA" | `--quick` mode, CLI-first, combines MobSF+Objection+Frida |

---

## 13. Pricing (Future SaaS — OSS Core Remains Free)

| Tier | Price | What's Included |
|------|-------|-----------------|
| **Community** | Free | CLI, core scanner, MASVS mapping, local AI |
| **Team** | $5K/year (per 5 devs) | Dashboard, API, CI/CD, team management |
| **Business** | $15K/year (per 20 devs) | Privacy engine, SBOM, compliance reports, priority support |
| **Enterprise** | Custom | On-prem, SSO, custom rules, SLA, training |

---

## 14. Competitive Positioning

| Feature | MobiusSec | MobSF | NowSecure | Data Theorem | Appdome |
|---------|-----------|-------|-----------|-------------|---------|
| **Android + iOS** | ✅ Both | ✅ Both | ✅ Both | ✅ Both | ✅ Both |
| **MASVS mapping** | ✅ Direct | ❌ | ⚠️ Partial | ⚠️ Partial | ❌ |
| **Privacy engine** | ✅ Built-in | ❌ | ✅ | ❌ | ❌ |
| **CI/CD-native** | ✅ First-class | ⚠️ Docker | ✅ | ✅ | ✅ |
| **SBOM** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Cross-platform** | ✅ Flutter/RN | ❌ | ❌ | ❌ | ❌ |
| **AI remediation** | ✅ Local | ❌ | ✅ Cloud | ⚠️ | ❌ |
| **Price (entry)** | Free | Free | $21K/yr | $30K/yr | Enterprise |
| **Brazil/LGPD** | ✅ First-class | ❌ | ❌ | ❌ | ❌ |
| **Developer UX** | ✅ First-class | ❌ Dated | ⚠️ | ⚠️ | ❌ No-code |

---

## 15. Portfolio Fit

MobiusSec fits Raphael's security portfolio as:
- **Mobile security** — New coverage area (current portfolio: network forensics, malware analysis, digital forensics, deception, web pentesting)
- **Commercial potential** — Clear monetization path (OSS → SaaS)
- **Learning vehicle** — Deep mobile security expertise, MASVS mastery, binary analysis
- **Service offering** — "Mobile App Security Audit using MobiusSec" as a service ($3K–7K)
- **Brazil angle** — Unique market positioning nobody else has

---

## 16. Name & Brand

**MobiusSec** — Named after the Möbius strip: continuous, unified, no inside/outside.  
The metaphor: Android and iOS are two sides of the same security problem. MobiusSec treats them as one continuous surface.

**Tagline:** *"One tool. Both platforms. No escape."*

---

_Draft spec v0.1.0 — April 18, 2026. Ready for review and iteration._