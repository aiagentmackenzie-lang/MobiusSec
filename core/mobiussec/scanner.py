"""Main scanner orchestrator."""

from __future__ import annotations

import time
from pathlib import Path

from mobiussec import PLATFORM_ANDROID, PLATFORM_IOS
from mobiussec.extractor import Extractor
from mobiussec.android_analyzer import AndroidAnalyzer
from mobiussec.ios_analyzer import iOSAnalyzer
from mobiussec.masvs_mapper import MASVSMapper
from mobiussec.models import (
    Finding,
    Platform,
    ScanConfig,
    ScanResult,
    Severity,
)


class Scanner:
    """Main scanner that orchestrates extraction, analysis, and MASVS mapping."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.extractor = Extractor(config.app_path)
        self.findings: list[Finding] = []
        self.errors: list[str] = []

    def scan(self) -> ScanResult:
        """Run a complete security scan."""
        start_time = time.time()

        # 1. Extract
        try:
            extracted_dir = self.extractor.extract()
        except Exception as e:
            return ScanResult(
                app_path=str(self.config.app_path),
                platform=Platform.UNKNOWN,
                errors=[f"Extraction failed: {e}"],
                scan_time_seconds=time.time() - start_time,
            )

        platform_str = self.extractor.platform
        platform = Platform(platform_str) if platform_str in ("android", "ios") else Platform.UNKNOWN

        # 2. Analyze
        package_name = "unknown"
        app_name = "unknown"
        version = "unknown"

        if platform == Platform.ANDROID:
            analyzer = AndroidAnalyzer(extracted_dir)
            self.findings = analyzer.analyze()
            package_name = analyzer.package_name
            app_name = analyzer.app_name
        elif platform == Platform.IOS:
            analyzer = iOSAnalyzer(extracted_dir)
            self.findings = analyzer.analyze()
            package_name = analyzer.bundle_id
            app_name = analyzer.app_name
            version = analyzer.version

        # 3. Filter for quick mode
        if self.config.quick:
            self.findings = [
                f for f in self.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]

        # 4. Map to MASVS
        mapper = MASVSMapper(platform)
        masvs_result = mapper.map_findings(self.findings)

        # 5. Build result
        scan_time = time.time() - start_time
        result = ScanResult(
            app_path=str(self.config.app_path),
            platform=platform,
            package_name=package_name,
            app_name=app_name,
            version=version,
            findings=self.findings,
            masvs_result=masvs_result,
            scan_time_seconds=scan_time,
            errors=self.errors,
        )

        # 6. Cleanup
        self.extractor.cleanup()

        return result

    def check_gate(self, result: ScanResult) -> int:
        """Check if scan result passes a MASVS gate level.

        Returns 0 if pass, 1 if fail.
        """
        if not self.config.gate_level:
            return 0

        if not result.masvs_result:
            return 1

        if self.config.gate_level.upper() == "L1":
            return 0 if result.masvs_result.l1_ready else 1
        elif self.config.gate_level.upper() == "L2":
            return 0 if result.masvs_result.l2_ready else 1

        return 0