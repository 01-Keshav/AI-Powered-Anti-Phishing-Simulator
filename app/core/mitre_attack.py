"""MITRE ATT&CK framework integration — fetch, parse, analyze, compare."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import requests

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CACHE: dict[str, Any] = {}


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    description: str
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""


@dataclass
class AttackComparison:
    technique_a: AttackTechnique
    technique_b: AttackTechnique
    shared_tactics: list[str]
    shared_platforms: list[str]
    similarity_score: float
    recommendation: str


def fetch_mitre_data(force_refresh: bool = False) -> dict[str, Any]:
    """Download enterprise ATT&CK STIX bundle from MITRE CTI GitHub."""
    if not force_refresh and "stix" in CACHE:
        return CACHE["stix"]

    response = requests.get(MITRE_STIX_URL, timeout=60)
    response.raise_for_status()
    data = response.json()
    CACHE["stix"] = data
    return data


def parse_techniques(stix_data: dict[str, Any] | None = None) -> list[AttackTechnique]:
    """Extract attack-pattern techniques from STIX objects."""
    if stix_data is None:
        stix_data = fetch_mitre_data()

    tactic_map: dict[str, str] = {}
    for obj in stix_data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            ext = obj.get("external_references", [{}])[0]
            tactic_map[obj["id"]] = ext.get("external_id", obj.get("name", ""))

    techniques: list[AttackTechnique] = []
    for obj in stix_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        kill_chain_phases = obj.get("kill_chain_phases", [])
        tactics = [
            tactic_map.get(p.get("phase_id", ""), p.get("phase_name", ""))
            for p in kill_chain_phases
            if p.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            AttackTechnique(
                technique_id=technique_id,
                name=obj.get("name", "Unknown"),
                description=obj.get("description", "")[:500],
                tactics=tactics,
                platforms=obj.get("x_mitre_platforms", []),
                data_sources=obj.get("x_mitre_data_sources", []),
                detection=obj.get("x_mitre_detection", "")[:300],
                url=url,
            )
        )

    return sorted(techniques, key=lambda t: t.technique_id)


def search_techniques(query: str, techniques: list[AttackTechnique] | None = None) -> list[AttackTechnique]:
    """Search techniques by ID, name, tactic, or keyword."""
    if techniques is None:
        techniques = parse_techniques()

    query_lower = query.lower().strip()
    if not query_lower:
        return techniques[:50]

    results = []
    for t in techniques:
        haystack = " ".join(
            [t.technique_id, t.name, t.description, " ".join(t.tactics), " ".join(t.platforms)]
        ).lower()
        if query_lower in haystack or re.search(re.escape(query_lower), haystack):
            results.append(t)
    return results[:100]


def get_techniques_by_tactic(tactic: str, techniques: list[AttackTechnique] | None = None) -> list[AttackTechnique]:
    if techniques is None:
        techniques = parse_techniques()
    tactic_lower = tactic.lower()
    return [t for t in techniques if any(tactic_lower in tac.lower() for tac in t.tactics)]


def compare_techniques(
    id_a: str,
    id_b: str,
    techniques: list[AttackTechnique] | None = None,
) -> AttackComparison | None:
    """Compare two MITRE techniques and produce SOC-oriented recommendation."""
    if techniques is None:
        techniques = parse_techniques()

    tech_map = {t.technique_id.upper(): t for t in techniques}
    a = tech_map.get(id_a.upper())
    b = tech_map.get(id_b.upper())

    if not a or not b:
        return None

    shared_tactics = list(set(a.tactics) & set(b.tactics))
    shared_platforms = list(set(a.platforms) & set(b.platforms))

    score = 0.0
    if a.tactics and b.tactics:
        score += len(shared_tactics) / max(len(set(a.tactics) | set(b.tactics)), 1) * 40
    if a.platforms and b.platforms:
        score += len(shared_platforms) / max(len(set(a.platforms) | set(b.platforms)), 1) * 30

    desc_tokens_a = set(re.findall(r"\w+", a.description.lower()))
    desc_tokens_b = set(re.findall(r"\w+", b.description.lower()))
    if desc_tokens_a and desc_tokens_b:
        overlap = len(desc_tokens_a & desc_tokens_b)
        union = len(desc_tokens_a | desc_tokens_b)
        score += (overlap / union) * 30

    score = round(min(score, 100), 1)

    if score >= 70:
        recommendation = (
            f"HIGH OVERLAP ({score}%): {a.technique_id} and {b.technique_id} share significant "
            f"tactics/platforms. Consolidate detection rules and correlate alerts across both."
        )
    elif score >= 40:
        recommendation = (
            f"MODERATE OVERLAP ({score}%): Partial alignment. Map shared detections to "
            f"SIEM use cases; differentiate by data source coverage."
        )
    else:
        recommendation = (
            f"LOW OVERLAP ({score}%): Distinct techniques. Prioritize {a.technique_id} vs "
            f"{b.technique_id} based on your threat model and recent incident trends."
        )

    return AttackComparison(
        technique_a=a,
        technique_b=b,
        shared_tactics=shared_tactics,
        shared_platforms=shared_platforms,
        similarity_score=score,
        recommendation=recommendation,
    )


def get_phishing_related_techniques(techniques: list[AttackTechnique] | None = None) -> list[AttackTechnique]:
    """Return techniques commonly relevant to phishing / initial access."""
    keywords = [
        "phish", "spearphishing", "credential", "initial access",
        "social engineering", "link", "attachment", "email",
    ]
    if techniques is None:
        techniques = parse_techniques()

    results = []
    for t in techniques:
        text = f"{t.name} {t.description} {' '.join(t.tactics)}".lower()
        if any(kw in text for kw in keywords):
            results.append(t)
    return results


def get_tactic_summary(techniques: list[AttackTechnique] | None = None) -> dict[str, int]:
    if techniques is None:
        techniques = parse_techniques()
    summary: dict[str, int] = {}
    for t in techniques:
        for tac in t.tactics:
            summary[tac] = summary.get(tac, 0) + 1
    return dict(sorted(summary.items(), key=lambda x: -x[1]))


def export_techniques_json(techniques: list[AttackTechnique] | None = None) -> str:
    if techniques is None:
        techniques = parse_techniques()
    payload = [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "tactics": t.tactics,
            "platforms": t.platforms,
            "url": t.url,
        }
        for t in techniques
    ]
    return json.dumps(payload, indent=2)
