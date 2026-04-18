"""Tests for deploy profiles."""

import pytest

from mobiussec.deploy import get_profile, list_profiles, generate_docker_compose, PROFILES


class TestDeployProfiles:
    def test_all_profiles_exist(self):
        assert len(PROFILES) == 5
        assert "local" in PROFILES
        assert "docker" in PROFILES
        assert "kubernetes" in PROFILES
        assert "cloud-run" in PROFILES
        assert "aws-fargate" in PROFILES

    def test_get_profile(self):
        profile = get_profile("local")
        assert profile["name"] == "Local Development"
        assert "api" in profile

    def test_get_unknown_profile(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile("nonexistent")

    def test_list_profiles(self):
        profiles = list_profiles()
        assert len(profiles) == 5
        assert all("name" in p and "description" in p for p in profiles)

    def test_docker_compose_generation(self):
        content = generate_docker_compose()
        assert "services" in content
        assert "api" in content

    def test_docker_compose_file_output(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            generate_docker_compose(Path(tmp))
            path = Path(tmp) / "docker-compose.mobiussec.yml"
            assert path.exists()