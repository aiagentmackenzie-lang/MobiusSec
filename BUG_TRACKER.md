# MobiusSec Bug Tracker — Lead Code Quality Audit

**Audit Date:** 2026-05-17
**Auditor:** Agent Mackenzie (Lead Code Quality)
**Branch:** main
**Tests Before:** 122/122 passing

---

## CRITICAL (Functionality or Spec Mismatch)

### C1: `--fail-on` CLI option is accepted but NEVER enforced
- **Location:** `core/mobiussec/cli.py` (scan, masvs), `core/mobiussec/scanner.py`
- **Impact:** Users running `mobius scan app.apk --fail-on high` expect exit code 1 on high findings. Tool silently returns 0.
- **Fix:** Implement severity-based exit logic in CLI after scan.

### C2: `ScanResult` not imported in `cli.py`
- **Location:** `core/mobiussec/cli.py:707,774`
- **Impact:** `_display_rich` and `_output_json` use string annotation `"ScanResult"`. If `from __future__ import annotations` is removed, NameError. Also breaks static analysis.
- **Fix:** Add `from mobiussec.models import ..., ScanResult`

### C3: `scanner.py` analyzer variable reuse + missing Android version
- **Location:** `core/mobiussec/scanner.py:52-70`
- **Impact:** `analyzer` typed as AndroidAnalyzer then rebound to iOSAnalyzer. Mypy fails. Android version always "unknown" because AndroidAnalyzer lacks `.version` but scanner doesn't extract it.
- **Fix:** Use separate variable names. Add version extraction for Android.

### C4: `secrets_scanner.py` ambiguous variable `l`
- **Location:** `core/mobiussec/secrets_scanner.py:242`
- **Impact:** E741 — `l` looks like `1` or `I`. Code quality / readability bug.
- **Fix:** Rename to `line`.

---

## HIGH (Type Safety / Silent Failures)

### H1: `remediation.py` — `CATEGORY_REMEDIATIONS` value type mismatch
- **Location:** `core/mobiussec/remediation.py:35-105`
- **Impact:** Typed `dict[str, dict[str, str]]` but "references" keys hold `list[str]`. Mypy error.
- **Fix:** Broaden type to `dict[str, dict[str, Any]]`.

### H2: `deploy.py` — `list_profiles()` return type mismatch
- **Location:** `core/mobiussec/deploy.py:106`
- **Impact:** Typed `list[dict[str, str]]` but profiles contain nested dicts. Mypy error.
- **Fix:** Change to `list[dict[str, Any]]`.

### H3: `android_analyzer.py` — `ns` variable unused + untyped
- **Location:** `core/mobiussec/android_analyzer.py:292`
- **Impact:** Mypy: Need type annotation for "ns". Dead code.
- **Fix:** Remove unused `ns = {}`.

### H4: `ios_analyzer.py` — unused `name` variable
- **Location:** `core/mobiussec/ios_analyzer.py:264`
- **Impact:** Dead assignment.
- **Fix:** Remove or use.

### H5: `yara_engine.py` — dead assignments `rule_text`, `rule_pattern`
- **Location:** `core/mobiussec/yara_engine.py:344,347`
- **Impact:** Dead code.
- **Fix:** Remove.

### H6: `privacy_engine.py` — unused `requested` variable
- **Location:** `core/mobiussec/privacy_engine.py:351`
- **Impact:** Dead code.
- **Fix:** Remove.

---

## MEDIUM (Lint / Cleanup)

### M1: 86 ruff errors (F401, F541, F841, E741, E402)
- **Files affected:** 15+ files
- **Fix:** Systematic pass with `--fix` where safe, manual where not.

### M2: 44 mypy errors (missing type args, incompatible assignments, stub issues)
- **Files affected:** 15 files
- **Fix:** Add type args to generics, fix incompatible dict/list types, suppress untyped third-party imports.

### M3: `extractor.py` — `parse_xml` returns `object`
- **Location:** `core/mobiussec/extractor.py`
- **Impact:** Imprecise type.
- **Fix:** Return `Any | None`.

### M4: `stix_export.py` — missing type args
- **Location:** `core/mobiussec/stix_export.py:33,91`
- **Fix:** Add `dict[str, Any]` annotations.

### M5: `reports.py` — missing type args + f-string without placeholders
- **Location:** `core/mobiussec/reports.py:150,151,199-214`
- **Fix:** Add `dict[str, Any]`, remove unnecessary f prefixes.

### M6: `scanner.py` — unused imports `PLATFORM_ANDROID`, `PLATFORM_IOS`, `Path`
- **Fix:** Remove.

---

## LOW (Spec / Polish)

### L1: README claims `mobius version` works but `version` command has no version string formatting
- **Fix:** Verify output format.

### L2: No integration tests against real APK/IPA binaries
- **Location:** `tests/` — all unit tests use mocks
- **Impact:** Cannot verify end-to-end pipeline.
- **Fix:** Build synthetic APK/IPA fixtures (Phase 1 of PRODUCTION_READINESS_PLAN.md).

### L3: `sbom_generator.py` — unused imports `json`, `MASVS_CODE`, `Severity`
- **Fix:** Remove.

---

## Resolution Log

| 1 | C1: `--fail-on` CLI option unimplemented | **FIXED** | `fix: implement --fail-on severity check in CLI` |
| 2 | C2: `ScanResult` not imported in `cli.py` | **FIXED** | `fix: add ScanResult import` |
| 3 | C3: `scanner.py` analyzer reuse + missing Android version | **FIXED** | `fix: separate analyzer variables, add version property to AndroidAnalyzer` |
| 4 | C4: `secrets_scanner.py` ambiguous variable `l` | **FIXED** | `fix: rename l -> line` |
| 5 | H1: `remediation.py` dict type mismatch | **FIXED** | `fix: CATEGORY_REMEDIATIONS -> dict[str, dict[str, Any]]` |
| 6 | H2: `deploy.py` list_profiles return type | **FIXED** | `fix: list[dict[str, Any]]` |
| 7 | H3: `android_analyzer.py` dead `ns` variable | **FIXED** | `fix: remove unused ns` |
| 8 | H4: `ios_analyzer.py` unused `name` variable | **FIXED** | `fix: remove unused name` |
| 9 | H5: `yara_engine.py` dead assignments | **FIXED** | `fix: remove rule_text/rule_pattern dead code` |
| 10 | H6: `privacy_engine.py` unused `requested` | **FIXED** | `fix: remove unused requested` |
| 11 | M1-M2: 86 ruff + 44 mypy errors | **FIXED** | `fix: systematic lint/type cleanup across 20 files` |
| 12 | YARA: unreferenced strings `$s3` in rules | **FIXED** | `fix: add $s3/$s4 to YARA conditions` |
| 13 | **C5: `android_analyzer.py` debuggable check on wrong XML element** | **FIXED** | `fix: check <application> for debuggable, not <manifest>` |
| 14 | **C6: `android_analyzer.py` networkSecurityConfig missing `.xml` extension** | **FIXED** | `fix: append .xml to resource reference` |
| 15 | L2: No integration tests | **FIXED** | `test: add test_integration.py with 7 E2E tests` |
