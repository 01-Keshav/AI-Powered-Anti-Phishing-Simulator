"""Cyber Kill Chain framework mapping and analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class KillChainStage(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command & Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


@dataclass
class KillChainIndicator:
    stage: KillChainStage
    indicator: str
    severity: str  # low, medium, high, critical
    source: str
    mitre_mapping: list[str] = field(default_factory=list)


@dataclass
class KillChainAssessment:
    stages_detected: list[KillChainStage]
    indicators: list[KillChainIndicator]
    current_stage: KillChainStage | None
    risk_score: int
    soc_playbook: list[str]
    narrative: str


STAGE_DESCRIPTIONS = {
    KillChainStage.RECONNAISSANCE: "Adversary gathers target intelligence (OSINT, scanning, social profiling).",
    KillChainStage.WEAPONIZATION: "Malware/payload paired with exploit; phishing kit or document weaponized.",
    KillChainStage.DELIVERY: "Payload delivered via email, web, USB, or social engineering.",
    KillChainStage.EXPLOITATION: "Vulnerability triggered; user executes malicious content.",
    KillChainStage.INSTALLATION: "Persistence established; backdoor or malware installed.",
    KillChainStage.COMMAND_AND_CONTROL: "Beaconing to C2 infrastructure; exfiltration channels opened.",
    KillChainStage.ACTIONS_ON_OBJECTIVES: "Data theft, ransomware, lateral movement, or sabotage.",
}

STAGE_MITRE_TACTICS = {
    KillChainStage.RECONNAISSANCE: ["TA0043", "Reconnaissance"],
    KillChainStage.WEAPONIZATION: ["TA0001", "Initial Access"],
    KillChainStage.DELIVERY: ["TA0001", "Initial Access"],
    KillChainStage.EXPLOITATION: ["TA0002", "Execution"],
    KillChainStage.INSTALLATION: ["TA0003", "Persistence"],
    KillChainStage.COMMAND_AND_CONTROL: ["TA0011", "Command and Control"],
    KillChainStage.ACTIONS_ON_OBJECTIVES: ["TA0010", "Exfiltration", "TA0040", "Impact"],
}

SOC_PLAYBOOKS = {
    KillChainStage.RECONNAISSANCE: [
        "Review firewall/WAF logs for scanning patterns",
        "Enable rate limiting on public-facing assets",
        "Hunt for credential dumps mentioning your domain",
        "Brief users on social engineering awareness",
    ],
    KillChainStage.WEAPONIZATION: [
        "Update email gateway rules for new attachment types",
        "Sandbox suspicious documents in isolated VM",
        "Review threat intel for active phishing kits",
    ],
    KillChainStage.DELIVERY: [
        "Quarantine suspicious emails; preserve headers",
        "Block sender domains/IPs at perimeter",
        "Notify affected users; run phishing simulation follow-up",
    ],
    KillChainStage.EXPLOITATION: [
        "Isolate affected endpoint from network",
        "Collect memory dump and process tree",
        "Reset credentials for impacted accounts",
    ],
    KillChainStage.INSTALLATION: [
        "Run EDR full scan; check autoruns and scheduled tasks",
        "Review registry and startup folders",
        "Deploy YARA/hash blocklists org-wide",
    ],
    KillChainStage.COMMAND_AND_CONTROL: [
        "Block C2 IPs/domains at firewall and DNS",
        "Analyze network PCAPs for beacon intervals",
        "Enable enhanced logging on proxy/DNS",
    ],
    KillChainStage.ACTIONS_ON_OBJECTIVES: [
        "Activate incident response plan; declare SEV-1 if data loss",
        "Preserve forensic evidence; engage legal/comms",
        "Implement containment: segment VLANs, revoke tokens",
    ],
}


def map_findings_to_kill_chain(findings: dict[str, Any]) -> KillChainAssessment:
    """Map scanner/recon findings onto Cyber Kill Chain stages."""
    indicators: list[KillChainIndicator] = []
    stages: set[KillChainStage] = set()

    if findings.get("suspicious_urls") or findings.get("phishing_score", 0) > 50:
        stages.add(KillChainStage.DELIVERY)
        indicators.append(
            KillChainIndicator(
                stage=KillChainStage.DELIVERY,
                indicator="Phishing URL or malicious link detected",
                severity="high",
                source="phishing_scanner",
                mitre_mapping=["T1566", "T1566.002"],
            )
        )

    if findings.get("open_ports") or findings.get("dns_records"):
        stages.add(KillChainStage.RECONNAISSANCE)
        indicators.append(
            KillChainIndicator(
                stage=KillChainStage.RECONNAISSANCE,
                indicator="External reconnaissance surface exposed",
                severity="medium",
                source="recon_module",
                mitre_mapping=["T1595", "T1590"],
            )
        )

    if findings.get("malware_detected") or findings.get("malware_score", 0) > 60:
        stages.add(KillChainStage.WEAPONIZATION)
        stages.add(KillChainStage.INSTALLATION)
        indicators.append(
            KillChainIndicator(
                stage=KillChainStage.WEAPONIZATION,
                indicator="Malicious file/hash signature match",
                severity="critical",
                source="malware_scanner",
                mitre_mapping=["T1204", "T1059"],
            )
        )

    if findings.get("c2_indicators"):
        stages.add(KillChainStage.COMMAND_AND_CONTROL)
        indicators.append(
            KillChainIndicator(
                stage=KillChainStage.COMMAND_AND_CONTROL,
                indicator="Potential C2 beacon or suspicious outbound connection",
                severity="critical",
                source="network_analysis",
                mitre_mapping=["T1071", "T1573"],
            )
        )

    if findings.get("credential_harvest"):
        stages.add(KillChainStage.EXPLOITATION)
        stages.add(KillChainStage.ACTIONS_ON_OBJECTIVES)
        indicators.append(
            KillChainIndicator(
                stage=KillChainStage.EXPLOITATION,
                indicator="Credential harvesting page or form detected",
                severity="high",
                source="phishing_scanner",
                mitre_mapping=["T1056", "T1555"],
            )
        )

    severity_weights = {"low": 10, "medium": 25, "high": 40, "critical": 60}
    risk_score = min(
        sum(severity_weights.get(i.severity, 10) for i in indicators),
        100,
    )

    ordered = list(KillChainStage)
    current = None
    if stages:
        current = max(stages, key=lambda s: ordered.index(s))

    playbook: list[str] = []
    if current:
        playbook = SOC_PLAYBOOKS.get(current, [])

    stage_names = ", ".join(s.value for s in sorted(stages, key=lambda x: ordered.index(x)))
    narrative = (
        f"Kill Chain analysis detected activity across: {stage_names or 'none'}. "
        f"Current estimated stage: {current.value if current else 'N/A'}. "
        f"Risk score: {risk_score}/100."
    )

    return KillChainAssessment(
        stages_detected=sorted(stages, key=lambda x: ordered.index(x)),
        indicators=indicators,
        current_stage=current,
        risk_score=risk_score,
        soc_playbook=playbook,
        narrative=narrative,
    )


def get_all_stages_info() -> list[dict[str, str]]:
    return [
        {
            "stage": stage.value,
            "description": STAGE_DESCRIPTIONS[stage],
            "mitre_tactics": ", ".join(STAGE_MITRE_TACTICS.get(stage, [])),
        }
        for stage in KillChainStage
    ]
