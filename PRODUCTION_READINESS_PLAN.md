# MobiusSec — Production Readiness Plan

**Created:** April 25, 2026
**Status:** Pre-production
**Goal:** Get MobiusSec to a state where it can reliably scan real APK/IPA files and produce trustworthy results.
**Current state:** 122/122 tests pass (all unit), but zero integration tests against real app binaries. Silent failure modes exist.

---

## Phase 1: Synthetic APK Integration Test (BLOCKING — nothing else matters until this is done)

### Why
The scanner has never been tested against a real APK. Every test uses mock/tempfile data. A security tool that silently returns "all clear" when it fails to parse is *dangerous*. We need proof the full pipeline works end-to-end.

### Tasks

#### 1.1 Build a synthetic vulnerable APK
- Create a Python script: `tests/fixtures/build_test_apk.py`
- This script programmatically builds a minimal but valid APK containing:
  - **AndroidManifest.xml** with:
    - `android:debuggable="true"` (should trigger AND-001)
    - `android:usesCleartextTraffic="true"` (should trigger AND-NET-001)
    - `android:allowBackup="true"` (should trigger AND-BACKUP-001)
    - Dangerous permissions: `READ_SMS`, `RECORD_AUDIO`, `CAMERA`, `READ_PHONE_STATE`
    - An exported activity without permission
  - **network_security_config.xml** with:
    - `cleartextTrafficPermitted="true"` (should trigger AND-NET-002)
  - **strings.xml** with `app_name`
  - **smali/** directory with minimal package structure:
    - A class containing `getLocation()`, `getDeviceId()`, `ClipboardManager` calls
    - A class with hardcoded AWS key pattern: `AKIA[0-9A-Z]{16}`
    - A class with `http://` URLs (no TLS)
    - A class with `SharedPreferences` for sensitive data
  - **assets/** with a JS file containing `http://` endpoints
- The script uses Python's `zipfile` module to create the APK (APK = ZIP with specific structure)
- Output: `tests/fixtures/vulnerable_test.apk`
- **Validation:** The APK must be a valid ZIP that the extractor can open

#### 1.2 Build a synthetic vulnerable IPA
- Create: `tests/fixtures/build_test_ipa.py`
- Builds a minimal IPA (ZIP) containing:
  - **Payload/TestApp.app/Info.plist** with:
    - `NSAppTransportSecurity > NSAllowsArbitraryLoads = true` (should trigger IOS-ATS-NSAllowsArbitraryLoads)
    - `NSAllowsArbitraryLoadsInWebContent = true`
    - `NSCameraUsageDescription`, `NSLocationWhenInUseUsageDescription` (privacy findings)
    - Missing `NSAllowsLocalNetworking = false`
  - **Payload/TestApp.app/main executable** (small Mach-O or placeholder)
  - **Payload/TestApp.app/Frameworks/** with a fake framework (for SBOM detection)
  - A Swift source file reference containing `kSecAttrAccessibleAlways`
- Output: `tests/fixtures/vulnerable_test.ipa`

#### 1.3 Write end-to-end integration test
- Create: `tests/test_integration.py`
- **Test: `test_full_apk_scan_pipeline`**
  1. Load synthetic APK
  2. Run `Scanner(config).scan()`
  3. Assert: `result.platform == Platform.ANDROID`
  4. Assert: at least 1 critical finding
  5. Assert: `AND-001` (debuggable) is in findings
  6. Assert: `AND-NET-001` (cleartext traffic) is in findings
  7. Assert: `AND-NET-002` (network security config) is in findings
  8. Assert: `AND-BACKUP-001` is in findings
  9. Assert: secrets scanner found hardcoded key
  10. Assert: privacy engine found tracking-related data collection
  11. Assert: MASVS result exists with FAIL status for STORAGE/NETWORK categories
  12. Assert: L1 readiness is False (because of fails)
  13. Assert: SBOM was generated with components
  14. Assert: total_findings > 0
  15. Assert: no errors in result.errors

- **Test: `test_full_ipa_scan_pipeline`**
  1. Load synthetic IPA
  2. Run full scan
  3. Assert: `result.platform == Platform.IOS`
  4. Assert: ATS findings present
  5. Assert: privacy findings present
  6. Assert: MASVS result exists
  7. Assert: total_findings > 0

- **Test: `test_quick_mode_filters_correctly`**
  1. Scan synthetic APK with `quick=True`
  2. Assert: only CRITICAL and HIGH severity findings
  3. Assert: no MEDIUM/LOW/INFO findings

- **Test: `test_gate_check_fails_on_vulnerable_app`**
  1. Scan synthetic APK with `gate_level="L1"`
  2. Assert: `scanner.check_gate(result) == 1` (fails)

- **Test: `test_report_generation_from_scan`**
  1. Scan synthetic APK
  2. Generate HTML report → assert non-empty, contains finding titles
  3. Generate SARIF report → assert valid JSON structure
  4. Generate Markdown report → assert contains finding IDs

- **Test: `test_diff_between_vulnerable_and_clean`**
  1. Create a "clean" synthetic APK (no vulns)
  2. Scan both
  3. DiffAnalyzer on both results
  4. Assert: vulnerable app has added findings
  5. Assert: verdict includes "REGRESSION" or "WARNING"

### Acceptance Criteria
- [ ] Synthetic APK builds and is valid ZIP
- [ ] Synthetic IPA builds and is valid ZIP
- [ ] Full APK scan produces expected findings (not zero)
- [ ] Full IPA scan produces expected findings (not zero)
- [ ] Quick mode filters correctly
- [ ] Gate check works on real scan output
- [ ] Reports generate from real scan results
- [ ] Diff analysis works between two scan results

---

## Phase 2: Silent Failure Elimination (CRITICAL — trustworthiness)

### Why
Currently, if the scanner fails to parse the manifest, it silently returns zero Android findings and the MASVS report shows "all PASS." This is the worst possible behavior for a security tool. Users must know when the tool *didn't* analyze something.

### Tasks

#### 2.1 Add scan coverage metrics to ScanResult
- Add fields to `ScanResult` in `models.py`:
  - `files_scanned: int` — number of files actually analyzed
  - `files_total: int` — total files in extracted app
  - `coverage_pct: float` — percentage of files scanned
  - `analysis_warnings: list[str]` — non-fatal issues (e.g., "lxml unavailable, manifest not parsed")
  - `components_run: list[str]` — which scanner components actually executed (e.g., ["android_analyzer", "secrets_scanner", "yara_engine"])
- Update `Scanner.scan()` to populate these fields
- Update `to_dict()` to include them

#### 2.2 Manifest parse failure is NOT silent
- In `android_analyzer.py`, if `_parse_manifest()` fails (lxml missing, binary XML, etc.):
  - Add an `analysis_warning`: "AndroidManifest.xml could not be parsed — manifest security checks skipped. Install lxml or use apktool for decompilation."
  - If `etree is None`, set `self._manifest_parse_failed = True`
  - Propagate this to the scan result

#### 2.3 Binary XML detection
- Real APKs contain binary Android XML (AXML), not plain XML
- `lxml` CANNOT parse binary XML — it will fail silently
- Add detection: if manifest file starts with binary magic bytes (`\x00\x00\x08\x00`), flag it
- Add warning: "Binary Android XML detected. Use apktool for decompilation or manifest analysis will be incomplete."
- Document this clearly in the CLI output

#### 2.4 CLI shows coverage/warnings
- In `_display_rich()`, after findings table, show:
  - "📊 Coverage: 847/1200 files scanned (70.5%)"
  - Any analysis warnings in yellow
- In JSON output, include coverage and warnings
- If coverage < 50%, show a RED warning: "⚠️ LOW COVERAGE — results may be incomplete"

#### 2.5 "All PASS" MASVS result requires proof of analysis
- In `MASVSResult`, add `analyzed: bool` field
- Only set to True if at least one finding or PASS status was explicitly set (not just default SKIP)
- In `l1_ready` and `l2_ready` properties: if `analyzed` is False, return False (can't be ready if not analyzed)
- In `masvs` CLI command: if `analyzed` is False, show "⚠️ MASVS compliance could not be determined — scan incomplete"

### Acceptance Criteria
- [ ] ScanResult includes coverage metrics
- [ ] Manifest parse failure produces visible warnings
- [ ] Binary XML detection works and warns user
- [ ] CLI output shows coverage percentage
- [ ] Low coverage triggers red warning
- [ ] MASVS "all PASS" requires actual analysis proof
- [ ] Tests for all of the above

---

## Phase 3: Robustness & Edge Cases (IMPORTANT — real-world readiness)

### Tasks

#### 3.1 Handle corrupted/invalid APK/IPA
- Test scanner with: empty file, random binary file, ZIP with no manifest, IPA with no Payload/
- All should return errors in `result.errors`, not crash
- Add tests for each

#### 3.2 Large APK handling
- Test with a synthetic APK containing 10,000+ smali files
- Verify: file iteration is bounded (the `[:200]` and `[:100]` caps are intentional but should be documented in warnings)
- Verify: memory usage stays reasonable (no loading entire APK into RAM)
- Add `analysis_warning` when file cap is hit: "Only first 200 source files analyzed per category"

#### 3.3 YARA engine without yara-python
- The regex fallback is implemented but not well-tested against real content
- Test regex fallback against synthetic APK with known packer strings
- Verify findings are produced

#### 3.4 Secrets scanner deduplication
- Currently deduplicates by file+pattern, but different patterns in the same file could produce near-duplicate findings
- Add test: file with both AWS key pattern AND generic secret pattern → should produce 2 findings, not 1

#### 3.5 Cross-platform analyzer with mixed frameworks
- Test: APK containing both Flutter and React Native markers (hybrid app)
- Verify: both frameworks detected, findings from both

### Acceptance Criteria
- [ ] Scanner handles all invalid inputs without crashing
- [ ] Large file caps produce warnings
- [ ] YARA regex fallback works on real content
- [ ] Secrets dedup is correct
- [ ] Mixed framework detection works

---

## Phase 4: Report & Output Quality (IMPORTANT — usability)

### Tasks

#### 4.1 SARIF report must be valid
- Current SARIF output structure needs validation against the SARIF schema
- Test: generate SARIF from a real scan, validate with `sarif-schema-validator` or manual schema check
- Fix any structural issues

#### 4.2 HTML report improvements
- Add scan metadata: coverage %, scan time, platform, version
- Add confidence indicators (when coverage is low)
- Make "no findings" page explicit: "Scan complete. No security issues detected." vs "Scan incomplete — could not verify security status."

#### 4.3 STIX export validation
- Validate STIX 2.1 bundle against the specification
- Ensure all required fields are present
- Test with empty findings (should still produce valid bundle with identity + software objects)

#### 4.4 CLI exit codes
- Document exit codes:
  - 0: scan complete, no issues (or only INFO)
  - 1: gate check failed OR critical/high findings found with `--fail-on`
  - 2: scan failed (extraction error, no findings at all)
- Currently: `scan` returns 0 even with critical findings unless `--gate` is used. Consider: should `--fail-on high` cause exit 1? Currently only gate does.

### Acceptance Criteria
- [ ] SARIF output validates against schema
- [ ] HTML report includes coverage metadata
- [ ] STIX export is structurally valid
- [ ] Exit codes are documented and tested

---

## Phase 5: Documentation & README Sync (NICE TO HAVE — polish)

### Tasks

#### 5.1 README accuracy pass
- Verify every feature claim maps to working code
- Document current limitations honestly
- Add "Known Limitations" section:
  - Binary Android XML requires apktool
  - iOS analysis depends on plist structure
  - File caps per category (200 source files)
  - No dynamic analysis (static only)
  - No jailbroken/rooted device testing

#### 5.2 CLI help text quality
- Every command should have a one-line description that's useful
- Every flag should have a help string

#### 5.3 CONTRIBUTING.md
- How to run tests
- How to add a new analyzer
- Code style expectations

### Acceptance Criteria
- [ ] README has no false claims
- [ ] Known limitations documented
- [ ] All CLI help texts are clear
- [ ] Contributing guide exists

---

## Execution Priority

| Order | Phase | Reason |
|-------|-------|--------|
| **1** | Phase 1 — Integration Tests | Without this, we don't know if the tool works AT ALL |
| **2** | Phase 2 — Silent Failures | Without this, results can't be trusted |
| **3** | Phase 3 — Robustness | Without this, it crashes on real input |
| **4** | Phase 4 — Reports | Without this, results aren't useful |
| **5** | Phase 5 — Docs | Polish, not blocking |

## Estimated Effort

| Phase | Time | Complexity |
|-------|------|-----------|
| Phase 1 | 2-3 hours | Medium — building synthetic APK/IPA is tricky |
| Phase 2 | 2-3 hours | Medium — model changes cascade through codebase |
| Phase 3 | 1-2 hours | Low — mostly edge case tests |
| Phase 4 | 1-2 hours | Low — output formatting |
| Phase 5 | 30 min | Low — documentation |

**Total: ~7-10 hours of focused work**

---

## Session Resume Checklist

When picking this up in the next session:

1. `cd "/Users/main/Security Apps/MobiusSec"`
2. `.venv/bin/python -m pytest tests/ -v` — confirm 122/122 still pass
3. Start with Phase 1, Task 1.1 — build the synthetic APK
4. The biggest unknown: whether `lxml` can parse a real AndroidManifest.xml inside a ZIP-extracted APK (it likely CAN'T for binary XML — this will surface immediately in Phase 1)
5. If binary XML is a blocker, the fix is: require apktool OR implement a minimal AXML parser

---

## Audit Trail

- **April 25, 2026:** Initial audit completed. Found 7 bugs. Fixed all 7. Tests 96→122. README corrected.
  - Bug #1: Duplicate finding IDs in cross_platform.py → fixed with hashlib.md5
  - Bug #2: lxml hard import in android_analyzer.py → try/except with None fallback
  - Bug #3: lxml unguarded in privacy_engine.py → try/except with early return
  - Bug #4: extractor.parse_xml no fallback → added stdlib xml.etree fallback
  - Bug #5: masvs command missing flags → added --quick, --gate, --fail-on
  - Bug #6: Duplicate step numbering in scanner.py → fixed to sequential 1-11
  - Bug #7: strings command no availability check → added shutil.which() guard