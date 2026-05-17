"""Build a synthetic vulnerable IPA for integration testing.

IPA = ZIP file with Payload/TestApp.app/ structure. This script creates
a minimal but valid IPA containing intentional vulnerabilities for iOS scanning.
"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

# Info.plist with ATS bypasses and privacy descriptions
INFO_PLIST: dict = {
    "CFBundleIdentifier": "com.test.vulnerableapp",
    "CFBundleName": "VulnerableTestApp",
    "CFBundleDisplayName": "VulnerableTestApp",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "1",
    "CFBundleExecutable": "TestApp",
    "CFBundlePackageType": "APPL",
    "MinimumOSVersion": "14.0",

    # ATS bypass — should trigger IOS-ATS-NSAllowsArbitraryLoads
    "NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True,
        "NSAllowsArbitraryLoadsInWebContent": True,
    },

    # Privacy descriptions (present but empty — should trigger findings)
    "NSCameraUsageDescription": "",  # Empty!
    "NSLocationWhenInUseUsageDescription": "We need your location for delivery",

    # URL schemes
    "CFBundleURLTypes": [
        {
            "CFBundleURLName": "com.test.vulnerableapp",
            "CFBundleURLSchemes": ["vulnerableapp", "vuln-oauth-callback"],
        }
    ],

    # Background modes
    "UIBackgroundModes": ["location", "audio", "fetch"],

    # IDFA tracking description
    "NSUserTrackingUsageDescription": "We track you for better ads",
}

# Swift source with insecure Keychain usage
KEYCHAIN_SWIFT = """\
import Foundation

class KeychainHelper {
    // Insecure: kSecAttrAccessibleAlways
    func saveToken(_ token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKeyGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueData as String: token.data(using: .utf8)!,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}
"""

# Swift source with WebView issues
WEBVIEW_SWIFT = """\
import UIKit
import WebKit

class WebViewController: UIViewController {
    var webView: WKWebView!

    func loadPage() {
        let config = WKWebViewConfiguration()
        // Insecure: JavaScript enabled
        config.preferences.javaScriptEnabled = true
        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.loadFileURL(URL(fileURLWithPath: "/local/file.html"), allowingReadAccessTo: URL(fileURLWithPath: "/"))
        view.addSubview(webView)
    }
}
"""

# Swift source with pasteboard usage
CLIPBOARD_SWIFT = """\
import UIKit

class ClipboardManager {
    func copySensitiveData(_ text: String) {
        UIPasteboard.general.string = text  // Leaks to system clipboard
    }

    func readClipboard() -> String? {
        return UIPasteboard.general.string
    }
}
"""


def build_vulnerable_ipa(output_path: str | Path | None = None) -> Path:
    """Build a synthetic vulnerable IPA for testing.

    Args:
        output_path: Path to write the IPA. Defaults to same dir as this script.

    Returns:
        Path to the created IPA file.
    """
    if output_path is None:
        output_path = Path(__file__).parent / "vulnerable_test.ipa"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Serialize Info.plist to binary plist format
    plist_bytes = plistlib.dumps(INFO_PLIST, fmt=plistlib.FMT_BINARY)

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Payload/TestApp.app/Info.plist
        zf.writestr("Payload/TestApp.app/Info.plist", plist_bytes)

        # Main binary placeholder (Mach-O magic bytes)
        # MH_MAGIC_64 = 0xFEEDFACF
        mach_o_header = b"\xcf\xfa\xed\xfe" + b"\x00" * 256
        zf.writestr("Payload/TestApp.app/TestApp", mach_o_header)

        # Swift source files
        zf.writestr("Payload/TestApp.app/KeychainHelper.swift", KEYCHAIN_SWIFT)
        zf.writestr("Payload/TestApp.app/WebViewController.swift", WEBVIEW_SWIFT)
        zf.writestr("Payload/TestApp.app/ClipboardManager.swift", CLIPBOARD_SWIFT)

        # Framework (for SBOM detection)
        zf.writestr("Payload/TestApp.app/Frameworks/Alamofire.framework/Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "org.alamofire.alamofire",
            "CFBundleName": "Alamofire",
            "CFBundleShortVersionString": "5.6.4",
            "CFBundlePackageType": "FMWK",
        }, fmt=plistlib.FMT_BINARY))

        # entitlements placeholder
        zf.writestr("Payload/TestApp.app/embedded.mobileprovision", b"")

    return output_path


if __name__ == "__main__":
    ipa = build_vulnerable_ipa()
    print(f"Built vulnerable IPA: {ipa} ({ipa.stat().st_size} bytes)")