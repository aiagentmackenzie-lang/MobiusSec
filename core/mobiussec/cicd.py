"""CI/CD integration — GitHub Actions, GitLab CI, Jenkinsfile."""

from __future__ import annotations

from pathlib import Path
from typing import Any


GITHUB_ACTIONS_WORKFLOW = """name: MobiusSec Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: mobiussec/scanner:latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Build Android APK
        if: hashFiles('**/build.gradle') != ''
        run: |
          ./gradlew assembleRelease
          echo "APK_PATH=app/build/outputs/apk/release/app-release.apk" >> $GITHUB_ENV

      - name: Run MobiusSec Scan
        run: |
          mobius scan ${{ env.APK_PATH }} --gate l1 --output sarif > mobiussec-results.sarif.json
        continue-on-error: true

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mobiussec-results.sarif.json
          category: mobiussec

      - name: Security Gate Check
        run: |
          mobius scan ${{ env.APK_PATH }} --gate l1
        # This will fail the build if MASVS L1 compliance is not met

      - name: Generate HTML Report
        if: always()
        run: |
          mobius report ${{ env.APK_PATH }} --format html --output security-report.html

      - name: Upload Report Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mobiussec-report
          path: security-report.html
"""

GITLAB_CI = """stages:
  - build
  - security

build:android:
  stage: build
  image: ghcr.io/nickysemenza/android-builder:latest
  script:
    - ./gradlew assembleRelease
  artifacts:
    paths:
      - app/build/outputs/apk/release/app-release.apk
    expire_in: 1 day

mobiussec:scan:
  stage: security
  image: mobiussec/scanner:latest
  needs: [build:android]
  script:
    - mobius scan app/build/outputs/apk/release/app-release.apk --gate l1
    - mobius report app/build/outputs/apk/release/app-release.apk --format sarif --output mobiussec.sarif.json
    - mobius report app/build/outputs/apk/release/app-release.apk --format html --output security-report.html
  artifacts:
    when: always
    paths:
      - mobiussec.sarif.json
      - security-report.html
    reports:
      sast: mobiussec.sarif.json
"""

JENKINSFILE = """pipeline {
    agent any

    environment {
        APK_PATH = 'app/build/outputs/apk/release/app-release.apk'
    }

    stages {
        stage('Build') {
            steps {
                sh './gradlew assembleRelease'
            }
        }

        stage('MobiusSec Scan') {
            steps {
                sh 'mobius scan ${APK_PATH} --gate l1 || true'
            }
            post {
                always {
                    sh 'mobius report ${APK_PATH} --format html --output security-report.html'
                    sh 'mobius report ${APK_PATH} --format sarif --output mobiussec.sarif.json'
                    archiveArtifacts artifacts: 'security-report.html, mobiussec.sarif.json', allowEmptyArchive: true
                    recordIssues(tools: [sarif(pattern: 'mobiussec.sarif.json')], qualityGates: [[threshold: 0, type: 'TOTAL', unstable: true]])
                }
            }
        }
    }

    post {
        failure {
            mail to: "${env.BUILD_NOTIFICATION_EMAIL}",
                 subject: "MobiusSec: Security issues found in ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                 body: "Security scan found issues. See ${env.BUILD_URL} for details."
        }
    }
}
"""


def generate_github_actions(output_dir: Path | None = None) -> str:
    """Generate GitHub Actions workflow file."""
    content = GITHUB_ACTIONS_WORKFLOW.strip() + "\n"
    if output_dir:
        path = output_dir / ".github" / "workflows" / "mobiussec.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return content


def generate_gitlab_ci(output_dir: Path | None = None) -> str:
    """Generate GitLab CI configuration."""
    content = GITLAB_CI.strip() + "\n"
    if output_dir:
        path = output_dir / ".gitlab-ci-mobiussec.yml"
        path.write_text(content)
    return content


def generate_jenkinsfile(output_dir: Path | None = None) -> str:
    """Generate Jenkinsfile."""
    content = JENKINSFILE.strip() + "\n"
    if output_dir:
        path = output_dir / "Jenkinsfile.mobiussec"
        path.write_text(content)
    return content


def generate_all_cicd(output_dir: Path) -> dict[str, str]:
    """Generate all CI/CD configurations."""
    return {
        "github_actions": generate_github_actions(output_dir),
        "gitlab_ci": generate_gitlab_ci(output_dir),
        "jenkins": generate_jenkinsfile(output_dir),
    }