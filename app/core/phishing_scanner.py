"""Anti-phishing URL and email analysis engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import tldextract
import validators


@dataclass
class PhishingReport:
    target: str
    score: int  # 0-100, higher = more suspicious
    verdict: str  # clean, suspicious, malicious
    indicators: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click"}
BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "bank", "secure", "login", "verify", "account", "update", "support",
]
PHISHING_PATTERNS = [
    (r"@.*@", "Multiple @ symbols in URL"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address used instead of domain"),
    (r"login.*@|signin.*@", "Credential harvesting pattern"),
    (r"\.(php|asp|aspx)\?", "Dynamic script with query params"),
    (r"bit\.ly|tinyurl|t\.co|goo\.gl", "URL shortener — obscures destination"),
    (r"data:text/html", "Data URI HTML payload"),
    (r"-%[0-9a-f]{2}", "URL encoding obfuscation"),
    (r"(urgent|immediate|suspend|locked|verify.?now)", "Urgency language indicator"),
]


def analyze_url(url: str) -> PhishingReport:
    indicators: list[str] = []
    score = 0
    mitre: list[str] = ["T1566.002", "T1598"]

    if not validators.url(url):
        return PhishingReport(
            target=url,
            score=0,
            verdict="invalid",
            indicators=["Invalid URL format"],
            recommendations=["Provide a valid HTTP/HTTPS URL"],
        )

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain

    metadata = {
        "scheme": parsed.scheme,
        "domain": domain,
        "subdomain": subdomain,
        "path": parsed.path,
        "query_length": len(parsed.query or ""),
        "fragment": parsed.fragment,
    }

    if parsed.scheme == "http":
        score += 15
        indicators.append("Unencrypted HTTP connection")

    if f".{ext.suffix}" in SUSPICIOUS_TLDS:
        score += 25
        indicators.append(f"Suspicious TLD: .{ext.suffix}")

    if subdomain and subdomain.count(".") >= 2:
        score += 20
        indicators.append("Excessive subdomain nesting (possible homograph/subdomain trick)")

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        score += 15
        indicators.append("Multiple hyphens in domain name")

    for brand in BRAND_KEYWORDS:
        if brand in url.lower() and brand not in domain.lower():
            score += 20
            indicators.append(f"Brand impersonation keyword '{brand}' in non-brand domain")
            mitre.append("T1589.002")

    for pattern, desc in PHISHING_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            score += 10
            indicators.append(desc)

    if len(parsed.path or "") > 80:
        score += 10
        indicators.append("Unusually long URL path")

    if parsed.query and len(parsed.query) > 100:
        score += 10
        indicators.append("Long query string — possible tracking/payload")

    if "@" in parsed.netloc:
        score += 30
        indicators.append("Userinfo @ in URL — credential phishing technique")

    score = min(score, 100)

    if score >= 70:
        verdict = "malicious"
    elif score >= 35:
        verdict = "suspicious"
    else:
        verdict = "clean"

    recommendations = _build_recommendations(verdict, indicators)

    return PhishingReport(
        target=url,
        score=score,
        verdict=verdict,
        indicators=indicators,
        mitre_techniques=list(set(mitre)),
        recommendations=recommendations,
        metadata=metadata,
    )


def analyze_email_headers(raw_headers: str) -> PhishingReport:
    indicators: list[str] = []
    score = 0
    mitre = ["T1566.001", "T1598.003"]

    headers_lower = raw_headers.lower()

    checks = [
        ("spf=fail", 25, "SPF authentication failed"),
        ("dkim=fail", 25, "DKIM verification failed"),
        ("dmarc=fail", 30, "DMARC policy failure"),
        ("received: from unknown", 15, "Unknown mail relay"),
        ("x-mailer: phpmailer", 10, "Common spam/phishing mailer"),
        ("reply-to:", 5, "Reply-To header present — verify sender alignment"),
    ]

    for pattern, pts, desc in checks:
        if pattern in headers_lower:
            score += pts
            indicators.append(desc)

    if re.search(r"from:.*<[^>]+@[^>]+>", raw_headers, re.IGNORECASE):
        from_match = re.search(r"from:\s*(.+)", raw_headers, re.IGNORECASE)
        if from_match and "@" in from_match.group(1):
            pass
    else:
        score += 10
        indicators.append("Malformed or missing From header")

    if re.search(r"urgent|act now|verify|password|click here", headers_lower):
        score += 15
        indicators.append("Social engineering language in headers/body preview")

    score = min(score, 100)
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 30 else "clean"

    return PhishingReport(
        target="email_headers",
        score=score,
        verdict=verdict,
        indicators=indicators,
        mitre_techniques=mitre,
        recommendations=_build_recommendations(verdict, indicators),
        metadata={"header_lines": len(raw_headers.splitlines())},
    )


def _build_recommendations(verdict: str, indicators: list[str]) -> list[str]:
    recs = []
    if verdict == "malicious":
        recs.extend([
            "Block URL/domain at email gateway and web proxy immediately",
            "Create SIEM alert rule for similar IOC patterns",
            "Run targeted phishing awareness for affected user group",
            "Submit IOCs to threat intelligence platform",
        ])
    elif verdict == "suspicious":
        recs.extend([
            "Quarantine message; perform manual SOC review",
            "Check URL in sandbox before releasing",
            "Correlate with recent MITRE T1566 detections",
        ])
    else:
        recs.append("No immediate action required; continue monitoring")
    return recs
