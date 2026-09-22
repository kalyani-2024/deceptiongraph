from __future__ import annotations

from pathlib import Path

import pytest

from deceptiongraph.graph.loader import build_model, load_network
from deceptiongraph.graph.repository import InMemoryGraphRepository

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "networks"


@pytest.fixture
def enterprise_model():
    """The reference network from the project brief."""
    return load_network(DATA_DIR / "enterprise.yaml")


@pytest.fixture
def enterprise_repo(enterprise_model):
    return InMemoryGraphRepository(enterprise_model)


@pytest.fixture
def linear_model():
    """A deliberately simple chain: INTERNET -> web -> app -> db (crown jewel).

    Every probability here is chosen so expected scores can be worked out by
    hand, which keeps the analysis tests independent of the reference topology.
    """
    raw = {
        "name": "linear",
        "hosts": [
            {
                "id": "web",
                "name": "Web",
                "exposure": "INTERNET",
                "criticality": 0.2,
                "patch_level": 0.0,
                "services": [
                    {
                        "name": "http",
                        "port": 80,
                        "vulnerabilities": [
                            {"cve": "CVE-X-1", "cvss": 10.0, "exploitability": 1.0}
                        ],
                    }
                ],
                "credentials": [
                    {"username": "svc", "strength": 0.0, "grants_access": ["app"]}
                ],
            },
            {
                "id": "app",
                "name": "App",
                "criticality": 0.5,
                "patch_level": 0.0,
                "services": [
                    {
                        "name": "tomcat",
                        "port": 8080,
                        "vulnerabilities": [
                            {"cve": "CVE-X-2", "cvss": 10.0, "exploitability": 1.0}
                        ],
                    }
                ],
            },
            {
                "id": "db",
                "name": "DB",
                "criticality": 1.0,
                "crown_jewel": True,
                "patch_level": 0.0,
                "services": [
                    {
                        "name": "postgres",
                        "port": 5432,
                        "vulnerabilities": [
                            {"cve": "CVE-X-3", "cvss": 5.0, "exploitability": 1.0}
                        ],
                    }
                ],
            },
            {"id": "island", "name": "Island", "criticality": 0.9, "patch_level": 1.0},
        ],
        "connections": [
            {"from": "INTERNET", "to": "web"},
            {"from": "web", "to": "app"},
            {"from": "app", "to": "db"},
        ],
    }
    return build_model(raw)


@pytest.fixture
def linear_repo(linear_model):
    return InMemoryGraphRepository(linear_model)
