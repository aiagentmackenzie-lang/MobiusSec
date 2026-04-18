"""Portfolio bridge — link MobiusSec to other security tools in the portfolio."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BridgeConfig:
    """Configuration for portfolio bridge integration."""
    ghostwire_url: str = ""
    hatchery_url: str = ""
    deaddrop_url: str = ""
    honeytrap_url: str = ""
    webbreaker_url: str = ""


# Portfolio tool capabilities
PORTFOLIO_TOOLS = {
    "GHOSTWIRE": {
        "name": "GHOSTWIRE",
        "description": "Network forensics engine — C2 beacon detection, JA4+ fingerprinting",
        "url": "https://github.com/aiagentmackenzie-lang/GHOSTWIRE",
        "capabilities": ["network_analysis", "c2_detection", "ja4_fingerprinting", "pcap_analysis"],
        "relevant_findings": ["NETWORK", "RESILIENCE"],
    },
    "HATCHERY": {
        "name": "HATCHERY",
        "description": "Malware sandbox — dynamic analysis, IOC extraction",
        "url": "https://github.com/aiagentmackenzie-lang/HATCHERY",
        "capabilities": ["malware_analysis", "dynamic_analysis", "ioc_extraction", "yara_scanning"],
        "relevant_findings": ["RESILIENCE", "CODE"],
    },
    "DEADDROP": {
        "name": "DEADDROP",
        "description": "Digital forensics toolkit — disk/memory forensics, timeline analysis",
        "url": "https://github.com/aiagentmackenzie-lang/DEADDROP",
        "capabilities": ["disk_forensics", "memory_forensics", "timeline_analysis", "yara_hunting"],
        "relevant_findings": ["STORAGE", "CODE"],
    },
    "HONEYTRAP": {
        "name": "HONEYTRAP",
        "description": "Deception framework — honeypots, honeytokens, behavioral analysis",
        "url": "https://github.com/aiagentmackenzie-lang/HONEYTRAP",
        "capabilities": ["deception", "honeytokens", "honeypots", "behavioral_analysis"],
        "relevant_findings": ["NETWORK", "RESILIENCE"],
    },
    "WEBBREAKER": {
        "name": "WEBBREAKER",
        "description": "Web app pentest toolkit — SQLi, XSS, CSRF, fuzzing",
        "url": "https://github.com/aiagentmackenzie-lang/WebBreaker",
        "capabilities": ["web_pentesting", "sqli", "xss", "csrf", "fuzzing", "header_analysis"],
        "relevant_findings": ["NETWORK", "PLATFORM"],
    },
}


class PortfolioBridge:
    """Bridge MobiusSec findings to the broader security portfolio."""

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or BridgeConfig()

    def get_recommended_tools(self, masvs_categories: list[str]) -> list[dict[str, Any]]:
        """Recommend portfolio tools based on MASVS categories with findings."""
        recommended = []
        seen = set()

        for tool_name, tool in PORTFOLIO_TOOLS.items():
            # Check if any of the tool's relevant findings match the given categories
            overlap = set(tool["relevant_findings"]) & set(masvs_categories)
            if overlap and tool_name not in seen:
                seen.add(tool_name)
                recommended.append({
                    **tool,
                    "matching_categories": list(overlap),
                    "recommendation": self._make_recommendation(tool_name, list(overlap)),
                })

        return recommended

    def get_all_bridges(self) -> list[dict[str, Any]]:
        """Get all portfolio bridge connections."""
        return [
            {
                **tool,
                "bridge_type": self._get_bridge_type(name),
                "data_flow": self._get_data_flow(name),
            }
            for name, tool in PORTFOLIO_TOOLS.items()
        ]

    def export_findings_for_tool(self, tool_name: str, findings: list) -> dict[str, Any]:
        """Export findings in a format suitable for a specific portfolio tool."""
        tool = PORTFOLIO_TOOLS.get(tool_name)
        if not tool:
            return {"error": f"Unknown tool: {tool_name}"}

        relevant_categories = tool["relevant_findings"]
        relevant_findings = [f for f in findings if f.masvs_category in relevant_categories]

        return {
            "source": "MobiusSec",
            "target": tool_name,
            "findings_count": len(relevant_findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.masvs_category,
                    "description": f.description,
                    "file": f.file,
                }
                for f in relevant_findings
            ],
        }

    @staticmethod
    def _make_recommendation(tool_name: str, categories: list[str]) -> str:
        """Generate a recommendation reason."""
        reasons = {
            "GHOSTWIRE": f"Network findings detected ({', '.join(categories)}). Use GHOSTWIRE for deep network forensics — C2 beacon detection, JA4+ fingerprinting, and PCAP analysis to identify communication patterns.",
            "HATCHERY": f"Code/resilience issues found ({', '.join(categories)}). Submit suspicious APK/IPA samples to HATCHERY for dynamic malware analysis and IOC extraction.",
            "DEADDROP": f"Storage/code findings ({', '.join(categories)}). Use DEADDROP for disk and memory forensics to trace data leaks and timeline analysis.",
            "HONEYTRAP": f"Network/resilience issues ({', '.join(categories)}). Deploy HONEYTRAP honeypots and honeytokens to detect real-world attacks against your mobile infrastructure.",
            "WEBBREAKER": f"Network/platform findings ({', '.join(categories)}). Use WebBreaker to pentest any backend APIs or web services the mobile app communicates with.",
        }
        return reasons.get(tool_name, f"Use {tool_name} for deeper analysis of {', '.join(categories)} findings.")

    @staticmethod
    def _get_bridge_type(tool_name: str) -> str:
        """Get the bridge connection type."""
        types = {
            "GHOSTWIRE": "pcap_export",
            "HATCHERY": "sample_submission",
            "DEADDROP": "artifact_export",
            "HONEYTRAP": "alert_feed",
            "WEBBREAKER": "api_url_export",
        }
        return types.get(tool_name, "generic")

    @staticmethod
    def _get_data_flow(tool_name: str) -> str:
        """Get the data flow direction."""
        flows = {
            "GHOSTWIRE": "MobiusSec → GHOSTWIRE (export network artifacts for forensics)",
            "HATCHERY": "MobiusSec → HATCHERY (submit suspicious samples for sandboxing)",
            "DEADDROP": "MobiusSec → DEADDROP (export disk/memory artifacts for forensics)",
            "HONEYTRAP": "HONEYTRAP → MobiusSec (feed honeypot alerts into mobile threat model)",
            "WEBBREAKER": "MobiusSec → WEBBREAKER (export API URLs for web pentesting)",
        }
        return flows.get(tool_name, "bidirectional")