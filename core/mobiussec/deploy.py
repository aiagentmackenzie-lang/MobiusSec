"""Deploy profiles — local, Docker, cloud configurations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROFILES = {
    "local": {
        "name": "Local Development",
        "description": "Run MobiusSec locally for development and testing",
        "api": {
            "host": "127.0.0.1",
            "port": 3000,
            "workers": 1,
        },
        "database": {
            "url": "sqlite:///mobiussec.db",
        },
        "scanner": {
            "temp_dir": "/tmp/mobiussec",
            "timeout": 300,
            "max_file_size_mb": 500,
        },
    },
    "docker": {
        "name": "Docker Compose",
        "description": "Run MobiusSec in Docker containers with PostgreSQL",
        "api": {
            "host": "0.0.0.0",
            "port": 3000,
            "workers": 4,
        },
        "database": {
            "url": "postgresql://mobiussec:mobiussec@db:5432/mobiussec",
        },
        "scanner": {
            "temp_dir": "/tmp/mobiussec",
            "timeout": 600,
            "max_file_size_mb": 1000,
        },
        "containers": {
            "api": {"image": "mobiussec/api:latest", "ports": ["3000:3000"]},
            "dashboard": {"image": "mobiussec/dashboard:latest", "ports": ["8080:80"]},
            "db": {"image": "postgres:16-alpine", "volumes": ["pgdata:/var/lib/postgresql/data"]},
            "redis": {"image": "redis:7-alpine"},
        },
    },
    "kubernetes": {
        "name": "Kubernetes",
        "description": "Deploy MobiusSec to Kubernetes cluster",
        "api": {
            "replicas": 3,
            "resources": {"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {"cpu": "2", "memory": "2Gi"}},
        },
        "dashboard": {
            "replicas": 2,
            "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}},
        },
        "database": {
            "type": "managed",  # Use CloudSQL/RDS
            "url_env": "DATABASE_URL",
        },
    },
    "cloud-run": {
        "name": "Google Cloud Run",
        "description": "Serverless deployment on Google Cloud Run",
        "api": {
            "image": "gcr.io/PROJECT_ID/mobiussec-api",
            "region": "us-central1",
            "memory": "2Gi",
            "cpu": "2",
            "min_instances": 1,
            "max_instances": 10,
        },
    },
    "aws-fargate": {
        "name": "AWS Fargate",
        "description": "Serverless deployment on AWS ECS Fargate",
        "api": {
            "image": "ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/mobiussec-api",
            "cpu": "1024",
            "memory": "2048",
            "tasks": {"min": 1, "max": 5},
        },
        "database": {
            "type": "rds",
            "engine": "aurora-postgresql",
        },
    },
}


def get_profile(name: str) -> dict[str, Any]:
    """Get a deploy profile by name."""
    if name not in PROFILES:
        available = ", ".join(PROFILES.keys())
        raise ValueError(f"Unknown profile: {name}. Available: {available}")
    return PROFILES[name]


def list_profiles() -> list[dict[str, str]]:
    """List all available deploy profiles."""
    return [{"name": k, "description": v["description"]} for k, v in PROFILES.items()]


def generate_docker_compose(output_dir: Path | None = None) -> str:
    """Generate a docker-compose.yml for the Docker profile."""
    compose = {
        "version": "3.8",
        "services": {
            "api": {
                "build": {"context": ".", "dockerfile": "docker/Dockerfile"},
                "ports": ["3000:3000"],
                "environment": [
                    "DATABASE_URL=postgresql://mobiussec:mobiussec@db:5432/mobiussec",
                    "REDIS_URL=redis://redis:6379",
                    "NODE_ENV=production",
                ],
                "depends_on": {"db": {"condition": "service_healthy"}, "redis": {"condition": "service_started"}},
                "volumes": ["./core:/app/core", "scan-data:/tmp/mobiussec"],
            },
            "dashboard": {
                "build": {"context": "./dashboard", "dockerfile": "Dockerfile"},
                "ports": ["8080:80"],
                "depends_on": ["api"],
            },
            "db": {
                "image": "postgres:16-alpine",
                "environment": [
                    "POSTGRES_USER=mobiussec",
                    "POSTGRES_PASSWORD=mobiussec",
                    "POSTGRES_DB=mobiussec",
                ],
                "volumes": ["pgdata:/var/lib/postgresql/data"],
                "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U mobiussec"], "interval": "5s", "timeout": "5s", "retries": 5},
            },
            "redis": {
                "image": "redis:7-alpine",
                "ports": ["6379:6379"],
            },
        },
        "volumes": {
            "pgdata": {},
            "scan-data": {},
        },
    }

    content = json.dumps(compose, indent=2, default=str)
    if output_dir:
        path = output_dir / "docker-compose.mobiussec.yml"
        path.write_text(content)
    return content