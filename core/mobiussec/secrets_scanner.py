"""Secrets scanner — detect hardcoded API keys, tokens, and passwords."""

from __future__ import annotations

import re
from pathlib import Path

from mobiussec import MASVS_CRYPTO, MASVS_CODE
from mobiussec.models import Finding, Severity, Platform


# High-confidence secret patterns with validation
SECRET_VALIDATORS = {
    # AWS keys have specific formats
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID — 20-char string starting with AKIA",
        "severity": Severity.CRITICAL,
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        "description": "AWS Secret Access Key",
        "severity": Severity.CRITICAL,
    },
    # GitHub tokens
    "github_token": {
        "pattern": r"gh[ps]_[A-Za-z0-9_]{36,255}",
        "description": "GitHub Personal Access Token",
        "severity": Severity.CRITICAL,
    },
    # Slack tokens
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "description": "Slack Token",
        "severity": Severity.CRITICAL,
    },
    # Stripe keys
    "stripe_live_key": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Live Secret Key",
        "severity": Severity.CRITICAL,
    },
    "stripe_publishable_key": {
        "pattern": r"pk_live_[0-9a-zA-Z]{24,}",
        "description": "Stripe Publishable Key",
        "severity": Severity.HIGH,
    },
    # Google API keys
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Google API Key",
        "severity": Severity.HIGH,
    },
    # Firebase / Google Cloud
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "description": "Firebase Database URL — may expose data if rules are permissive",
        "severity": Severity.MEDIUM,
    },
    # Private keys
    "private_key": {
        "pattern": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "description": "Private key embedded in source code",
        "severity": Severity.CRITICAL,
    },
    # Telegram bot tokens
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
        "description": "Telegram Bot API Token",
        "severity": Severity.CRITICAL,
    },
    # OpenRouter / OpenAI keys
    "openai_key": {
        "pattern": r"sk-[a-zA-Z0-9]{32,}",
        "description": "OpenAI API Key",
        "severity": Severity.CRITICAL,
    },
    # Generic high-entropy strings (potential secrets)
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*[\"'][a-zA-Z0-9]{20,}[\"']",
        "description": "Generic API key/secret",
        "severity": Severity.HIGH,
    },
    "generic_password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']",
        "description": "Hardcoded password",
        "severity": Severity.HIGH,
    },
    "generic_token": {
        "pattern": r"(?i)(token|bearer|auth_token|access_token)\s*[=:]\s*[\"'][a-zA-Z0-9\-_.]{20,}[\"']",
        "description": "Hardcoded token/bearer string",
        "severity": Severity.HIGH,
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|encryption_key|signing_key)\s*[=:]\s*[\"'][a-zA-Z0-9]{16,}[\"']",
        "description": "Hardcoded secret/encryption key",
        "severity": Severity.HIGH,
    },
    # OAuth client secrets
    "oauth_secret": {
        "pattern": r"(?i)(client[_-]?secret|oauth[_-]?secret)\s*[=:]\s*[\"'][^\"']{10,}[\"']",
        "description": "OAuth Client Secret",
        "severity": Severity.HIGH,
    },
    # Webhook URLs
    "webhook_url": {
        "pattern": r"https://(hooks\.slack\.com|discord\.com/api/webhooks|hooks\.zapier\.com)/[^\s\"']+",
        "description": "Webhook URL — can be used to send unauthorized messages",
        "severity": Severity.HIGH,
    },
    # Base64-encoded potential secrets
    "base64_key": {
        "pattern": r"(?i)(key|secret|token|password)\s*[=:]\s*[\"'][A-Za-z0-9+/]{40,}={0,2}[\"']",
        "description": "Base64-encoded potential secret",
        "severity": Severity.MEDIUM,
    },
}

# File patterns to skip (reduce false positives)
SKIP_PATTERNS = {
    "*.png", "*.jpg", "*.gif", "*.webp", "*.ico",  # Images
    "*.mp3", "*.wav", "*.ogg", "*.mp4",  # Media
    "*.ttf", "*.otf", "*.woff", "*.woff2",  # Fonts
    "*.dex", "*.so", "*.o", "*.class",  # Compiled
    "*.apk", "*.ipa", "*.zip",  # Archives
    "*.db", "*.sqlite",  # Databases
}

# Known test/placeholder values (not real secrets)
KNOWN_PLACEHOLDERS = {
    "your_api_key_here", "insert_your_key", "xxx", "todo", "fixme",
    "changeme", "placeholder", "example", "test", "dummy",
    "your-api-key", "your_token_here", "replace_me",
    "sk_test_", "pk_test_",  # Stripe test keys (legitimate in dev)
    "AKIAIOSFODNN7EXAMPLE",  # AWS example key used in docs
}


class SecretsScanner:
    """Scans mobile app source code for hardcoded secrets."""

    def __init__(self, extracted_dir: Path, platform: Platform) -> None:
        self.extracted_dir = extracted_dir
        self.platform = platform
        self.findings: list[Finding] = []

    def scan(self) -> list[Finding]:
        """Run secrets scanning against all source files."""
        self.findings = []

        # Determine file patterns to scan based on platform
        if self.platform == Platform.ANDROID:
            patterns = ["*.java", "*.kt", "*.xml", "*.json", "*.properties", "*.smali", "*.swift", "*.m", "*.h"]
        elif self.platform == Platform.IOS:
            patterns = ["*.swift", "*.m", "*.h", "*.plist", "*.json", "*.entitlements", "*.java", "*.kt"]
        else:
            patterns = ["*.java", "*.kt", "*.swift", "*.m", "*.h", "*.xml", "*.json"]

        # Collect files to scan
        files_to_scan: list[Path] = []
        for pattern in patterns:
            files_to_scan.extend(self.extracted_dir.rglob(pattern))

        # Scan each file
        for file_path in files_to_scan[:500]:
            self._scan_file(file_path)

        # Deduplicate findings
        self._deduplicate()

        return self.findings

    def _scan_file(self, file_path: Path) -> None:
        """Scan a single file for secrets."""
        # Skip files matching skip patterns
        for skip in SKIP_PATTERNS:
            if file_path.match(skip):
                return

        try:
            content = file_path.read_text(errors="ignore")
        except Exception:
            return

        if len(content) > 1_000_000:  # Skip very large files
            return

        rel_path = str(file_path.relative_to(self.extracted_dir))

        for key, validator in SECRET_VALIDATORS.items():
            for m in re.finditer(validator["pattern"], content):
                match_str = m.group(0)  # Full match, not just captured group

                # Skip known placeholders (check both the match and surrounding context)
                match_lower = match_str.lower()
                line_context = ""
                for line in content.split("\n"):
                    if match_str in line:
                        line_context = line.lower()
                        break

                if any(ph in match_lower or ph in line_context for ph in KNOWN_PLACEHOLDERS):
                    continue

                # Skip very short matches (likely false positives)
                if len(match_str) < 8:
                    continue

                # Find line number
                line_num = 0
                for i, line in enumerate(content.split("\n"), 1):
                    if match_str in line:
                        line_num = i
                        break

                # Get code snippet (context around the match)
                snippet = self._get_snippet(content, match_str)

                self.findings.append(Finding(
                    id=f"SECRET-{key[:12]}-{rel_path[:10].replace('/', '-')}",
                    title=f"Hardcoded {validator['description']}",
                    description=f"Found in {rel_path}:{line_num}. Secrets embedded in source code can be extracted by anyone with access to the app binary.",
                    severity=validator["severity"],
                    masvs_category=MASVS_CRYPTO,
                    masvs_test_id="MASTG-CRYPTO-1",
                    platform=self.platform,
                    file=rel_path,
                    line=line_num,
                    code_snippet=snippet,
                    remediation="Move secrets to environment variables, secure keystore (Android Keystore / iOS Keychain), or a secrets management service. Never commit secrets to source control.",
                ))

    def _get_snippet(self, content: str, match: str, context_lines: int = 2) -> str:
        """Get a code snippet around a match for context."""
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if match in line:
                start = max(0, i - context_lines)
                end = min(len(lines), i + context_lines + 1)
                snippet_lines = lines[start:end]
                # Mask the actual secret
                masked = [re.sub(re.escape(match), "***REDACTED***", l) for l in snippet_lines]
                return "\n".join(masked)
        return ""

    def _deduplicate(self) -> None:
        """Remove duplicate findings (same type + same file)."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in self.findings:
            key = f"{f.id}:{f.file}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique