"""Tests for CI/CD integration."""

import tempfile
from pathlib import Path

import pytest

from mobiussec.cicd import generate_github_actions, generate_gitlab_ci, generate_jenkinsfile, generate_all_cicd


class TestCICD:
    def test_github_actions_content(self):
        content = generate_github_actions()
        assert "MobiusSec Security Scan" in content
        assert "mobius scan" in content
        assert "sarif" in content.lower()

    def test_github_actions_file_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate_github_actions(Path(tmp))
            path = Path(tmp) / ".github" / "workflows" / "mobiussec.yml"
            assert path.exists()
            assert "MobiusSec" in path.read_text()

    def test_gitlab_ci_content(self):
        content = generate_gitlab_ci()
        assert "mobiussec:scan" in content
        assert "sast" in content

    def test_gitlab_ci_file_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            generate_gitlab_ci(Path(tmp))
            path = Path(tmp) / ".gitlab-ci-mobiussec.yml"
            assert path.exists()

    def test_jenkinsfile_content(self):
        content = generate_jenkinsfile()
        assert "pipeline" in content
        assert "MobiusSec" in content

    def test_generate_all(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = generate_all_cicd(Path(tmp))
            assert len(results) == 3
            assert "github_actions" in results
            assert "gitlab_ci" in results
            assert "jenkins" in results