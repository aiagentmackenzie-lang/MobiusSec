"""Build a synthetic vulnerable APK for integration testing.

APK = ZIP file with Android structure. This script creates a minimal but
valid APK containing intentional vulnerabilities that MobiusSec should detect.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

# XML content for AndroidManifest.xml with intentional vulnerabilities
MANIFEST_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.vulnerableapp"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />

    <!-- Dangerous permissions -->
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="@string/app_name">

        <!-- Exported activity without permission -->
        <activity
            android:name="com.test.vulnerableapp.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported service without permission -->
        <service
            android:name="com.test.vulnerableapp.DataService"
            android:exported="true" />

    </application>
</manifest>
"""

# Network security config allowing cleartext
NETWORK_SECURITY_CONFIG_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""

# Strings resource
STRINGS_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VulnerableTestApp</string>
</resources>
"""

# Smali class with hardcoded AWS key, tracking calls, and HTTP URLs
TRACKING_SMALI = """\
.class public Lcom/test/vulnerableapp/TrackingUtil;
.super Ljava/lang/Object;

.method public static getLocation()Ljava/lang/String;
    .locals 2
    const-string v0, "http://tracker.example.com/api/location"
    return-object v0
.end method

.method public static getDeviceId()Ljava/lang/String;
    .locals 2
    const-string v0, "android_id"
    return-object v0
.end method

.method public static sendClipboardData()V
    .locals 2
    const-class v0, Landroid/content/ClipboardManager;
    return-void
.end method
"""

# Smali class with hardcoded AWS key
SECRETS_SMALI = """\
.class public Lcom/test/vulnerableapp/SecretsManager;
.super Ljava/lang/Object;

# Hardcoded AWS Access Key
.field private static final AWS_KEY:Ljava/lang/String; = "AKIAIOSFODNN7EXAMPLE"

# Telegram Bot Token (fake — triggers MobiusSec secrets scanner, not GitHub)
.field private static final BOT_TOKEN:Ljava/lang/String; = "123456789:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"

.method public static getApiKey()Ljava/lang/String;
    .locals 1
    const-string v0, "AKIAIOSFODNN7EXAMPLE"
    return-object v0
.end method
"""

# Smali with SharedPreferences for sensitive data
PREFS_SMALI = """\
.class public Lcom/test/vulnerableapp/PrefsManager;
.super Ljava/lang/Object;

.method public static saveToken(Ljava/lang/String;)V
    .locals 3
    const-string v0, "auth_token"
    invoke-static {v0, p1}, Landroid/content/SharedPreferences;->edit()V
    return-void
.end method

.method public static getPassword()Ljava/lang/String;
    .locals 1
    const-string v0, "password123456"
    return-object v0
.end method
"""

# Java source with WebView and SQL injection issues
WEBVIEW_JAVA = """\
package com.test.vulnerableapp;

import android.webkit.WebView;
import android.database.sqlite.SQLiteDatabase;

public class VulnerableActivity extends android.app.Activity {
    private WebView webView;

    public void loadContent() {
        // Insecure WebView config
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
        webView.loadUrl("http://vulnerable.example.com");
    }

    public void queryDatabase(String userInput) {
        // SQL injection
        SQLiteDatabase db = openOrCreateDatabase("app.db", 0, null);
        db.rawQuery("SELECT * FROM users WHERE name = '" + userInput + "'", null);
    }
}
"""

# JavaScript file with HTTP endpoints
JS_ASSET = """\
// Analytics tracker
var API_ENDPOINT = "http://api.vulnerableapp.com/track";
var WEBSOCKET_URL = "ws://api.vulnerableapp.com/ws";

function trackEvent(event) {
    fetch(API_ENDPOINT, {
        method: 'POST',
        body: JSON.stringify({type: event.type, data: event.data})
    });
}
"""


def build_vulnerable_apk(output_path: str | Path | None = None) -> Path:
    """Build a synthetic vulnerable APK for testing.

    Args:
        output_path: Path to write the APK. Defaults to same dir as this script.

    Returns:
        Path to the created APK file.
    """
    if output_path is None:
        output_path = Path(__file__).parent / "vulnerable_test.apk"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # AndroidManifest.xml (plain text XML — lxml can parse this)
        zf.writestr("AndroidManifest.xml", MANIFEST_XML)

        # Network security config
        zf.writestr("res/xml/network_security_config.xml", NETWORK_SECURITY_CONFIG_XML)

        # Strings resource
        zf.writestr("res/values/strings.xml", STRINGS_XML)

        # Smali files
        zf.writestr("smali/com/test/vulnerableapp/TrackingUtil.smali", TRACKING_SMALI)
        zf.writestr("smali/com/test/vulnerableapp/SecretsManager.smali", SECRETS_SMALI)
        zf.writestr("smali/com/test/vulnerableapp/PrefsManager.smali", PREFS_SMALI)

        # Java source files
        zf.writestr("java/com/test/vulnerableapp/VulnerableActivity.java", WEBVIEW_JAVA)

        # Assets with JS
        zf.writestr("assets/tracker.js", JS_ASSET)

        # classes.dex placeholder (needed for APK validity)
        zf.writestr("classes.dex", b"dex\n035\x00")

    return output_path


def build_clean_apk(output_path: str | Path | None = None) -> Path:
    """Build a synthetic clean APK (minimal vulnerabilities) for diff testing.

    Args:
        output_path: Path to write the APK. Defaults to same dir as this script.

    Returns:
        Path to the created APK file.
    """
    if output_path is None:
        output_path = Path(__file__).parent / "clean_test.apk"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    clean_manifest = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.secureapp"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />

    <application
        android:allowBackup="false"
        android:debuggable="false"
        android:usesCleartextTraffic="false"
        android:label="@string/app_name">

        <activity
            android:name="com.test.secureapp.MainActivity"
            android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

    clean_strings = """\
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">SecureTestApp</string>
</resources>
"""

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", clean_manifest)
        zf.writestr("res/values/strings.xml", clean_strings)
        zf.writestr("classes.dex", b"dex\n035\x00")

    return output_path


if __name__ == "__main__":
    apk = build_vulnerable_apk()
    print(f"Built vulnerable APK: {apk} ({apk.stat().st_size} bytes)")

    clean = build_clean_apk()
    print(f"Built clean APK: {clean} ({clean.stat().st_size} bytes)")