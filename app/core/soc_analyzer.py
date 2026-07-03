"""SOC analyst dashboard aggregation and incident scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SOCAlert:
    id: str
    title: str
    severity: str
    source: str
    description: str
    mitre_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "open"


@dataclass
class SOCDashboard:
    overall_risk: int
    alerts: list[SOCAlert]
    metrics: dict[str, Any]
    blue_team_actions: list[str]


def calculate_overall_risk(scores: list[int]) -> int:
    if not scores:
        return 0
    weighted = sum(s * (1 + i * 0.1) for i, s in enumerate(sorted(scores, reverse=True)))
    return min(int(weighted / len(scores)), 100)


def build_soc_dashboard(
    phishing_score: int = 0,
    malware_score: int = 0,
    recon_flags: int = 0,
    kill_chain_risk: int = 0,
    custom_alerts: list[SOCAlert] | None = None,
) -> SOCDashboard:
    alerts: list[SOCAlert] = list(custom_alerts or [])

    if phishing_score >= 60:
        alerts.append(SOCAlert(
            id="ALT-PHISH-001",
            title="High-Risk Phishing Indicator",
            severity="high",
            source="Anti-Phishing Engine",
            description=f"Phishing score {phishing_score}/100 exceeds threshold",
            mitre_ids=["T1566", "T1598"],
        ))

    if malware_score >= 60:
        alerts.append(SOCAlert(
            id="ALT-MAL-001",
            title="Malware Detection",
            severity="critical",
            source="Malware Scanner",
            description=f"Malware score {malware_score}/100",
            mitre_ids=["T1204", "T1105"],
        ))

    if recon_flags >= 3:
        alerts.append(SOCAlert(
            id="ALT-RECON-001",
            title="External Reconnaissance Exposure",
            severity="medium",
            source="Recon Platform",
            description=f"{recon_flags} recon risk flags identified",
            mitre_ids=["T1595", "T1590"],
        ))

    if kill_chain_risk >= 50:
        alerts.append(SOCAlert(
            id="ALT-KC-001",
            title="Kill Chain Progression Detected",
            severity="high",
            source="Cyber Kill Chain Analyzer",
            description=f"Kill chain risk score {kill_chain_risk}/100",
            mitre_ids=["T1071", "T1486"],
        ))

    overall = calculate_overall_risk([phishing_score, malware_score, kill_chain_risk])

    metrics = {
        "open_alerts": len([a for a in alerts if a.status == "open"]),
        "critical_count": len([a for a in alerts if a.severity == "critical"]),
        "high_count": len([a for a in alerts if a.severity == "high"]),
        "phishing_score": phishing_score,
        "malware_score": malware_score,
        "recon_flags": recon_flags,
        "kill_chain_risk": kill_chain_risk,
        "overall_risk": overall,
    }

    blue_team_actions = [
        "Review and triage open alerts in SIEM queue",
        "Validate IOCs against MITRE ATT&CK mapped techniques",
        "Update detection rules for newly identified TTPs",
        "Run purple team exercise on phishing delivery stage",
        "Ensure EDR policies block quarantined file hashes",
        "Document findings in incident ticket with kill chain stage",
    ]

    if overall >= 70:
        blue_team_actions.insert(0, "ESCALATE: Activate Tier-2 SOC / IR team immediately")

    return SOCDashboard(
        overall_risk=overall,
        alerts=alerts,
        metrics=metrics,
        blue_team_actions=blue_team_actions,
    )


def severity_color(severity: str) -> str:
    return {
        "critical": "#ff4757",
        "high": "#ff6b35",
        "medium": "#ffa502",
        "low": "#2ed573",
        "info": "#1e90ff",
    }.get(severity.lower(), "#747d8c")
