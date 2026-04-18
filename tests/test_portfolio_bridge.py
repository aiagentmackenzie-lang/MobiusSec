"""Tests for portfolio bridge."""

import pytest

from mobiussec.portfolio_bridge import PortfolioBridge, BridgeConfig, PORTFOLIO_TOOLS
from mobiussec.models import Finding, Severity, Platform


class TestPortfolioBridge:
    def test_all_tools_exist(self):
        assert len(PORTFOLIO_TOOLS) == 5
        assert "GHOSTWIRE" in PORTFOLIO_TOOLS
        assert "HATCHERY" in PORTFOLIO_TOOLS
        assert "DEADDROP" in PORTFOLIO_TOOLS
        assert "HONEYTRAP" in PORTFOLIO_TOOLS
        assert "WEBBREAKER" in PORTFOLIO_TOOLS

    def test_recommendations_by_category(self):
        bridge = PortfolioBridge()
        # Network findings should recommend GHOSTWIRE, HONEYTRAP, WEBBREAKER
        recs = bridge.get_recommended_tools(["NETWORK"])
        rec_names = [r["name"] for r in recs]
        assert "GHOSTWIRE" in rec_names
        assert "WEBBREAKER" in rec_names

    def test_recommendations_empty(self):
        bridge = PortfolioBridge()
        recs = bridge.get_recommended_tools([])
        assert recs == []

    def test_all_bridges(self):
        bridge = PortfolioBridge()
        bridges = bridge.get_all_bridges()
        assert len(bridges) == 5
        assert all("bridge_type" in b for b in bridges)

    def test_export_findings_for_tool(self):
        bridge = PortfolioBridge()
        findings = [
            Finding(id="1", title="a", description="a", severity=Severity.HIGH, masvs_category="NETWORK"),
            Finding(id="2", title="b", description="b", severity=Severity.LOW, masvs_category="CODE"),
        ]
        exported = bridge.export_findings_for_tool("GHOSTWIRE", findings)
        assert exported["source"] == "MobiusSec"
        assert exported["target"] == "GHOSTWIRE"
        assert exported["findings_count"] == 1  # Only NETWORK matches

    def test_export_unknown_tool(self):
        bridge = PortfolioBridge()
        result = bridge.export_findings_for_tool("NONEXISTENT", [])
        assert "error" in result