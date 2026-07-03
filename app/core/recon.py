"""Multi-platform reconnaissance module for SOC blue team operations."""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import tldextract
import validators
import whois


@dataclass
class ReconResult:
    platform: str
    target: str
    status: str
    findings: dict[str, Any] = field(default_factory=dict)
    risk_flags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _safe_resolve(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []


class DNSRecon:
    """DNS enumeration — A, AAAA, MX, NS, TXT, SPF, DMARC."""

    PLATFORM = "DNS Recon"

    @classmethod
    def scan(cls, target: str) -> ReconResult:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        flags: list[str] = []
        findings: dict[str, Any] = {}

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            records = _safe_resolve(domain, rtype)
            if records:
                findings[rtype] = records

        dmarc = _safe_resolve(f"_dmarc.{domain}", "TXT")
        if dmarc:
            findings["DMARC"] = dmarc
        else:
            flags.append("No DMARC record — email spoofing risk")

        spf = [t for t in findings.get("TXT", []) if "v=spf1" in t.lower()]
        findings["SPF"] = spf if spf else ["Not configured"]
        if not spf:
            flags.append("Missing SPF — phishing delivery risk")

        if not findings.get("A") and not findings.get("AAAA"):
            flags.append("Domain does not resolve")

        return ReconResult(
            platform=cls.PLATFORM,
            target=domain,
            status="completed",
            findings=findings,
            risk_flags=flags,
        )


class WHOISRecon:
    """WHOIS domain intelligence."""

    PLATFORM = "WHOIS Lookup"

    @classmethod
    def scan(cls, target: str) -> ReconResult:
        ext = tldextract.extract(target)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else target
        flags: list[str] = []
        findings: dict[str, Any] = {}

        try:
            w = whois.whois(domain)
            findings = {
                "registrar": str(w.registrar or "Unknown"),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers if w.name_servers else [],
                "org": str(w.org or "Redacted"),
                "country": str(w.country or "Unknown"),
            }

            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                age_days = (datetime.now() - created).days if hasattr(created, "day") else None
                if age_days is not None and age_days < 30:
                    flags.append(f"Recently registered domain ({age_days} days) — phishing indicator")
                findings["domain_age_days"] = age_days
        except Exception as exc:
            findings["error"] = str(exc)
            flags.append("WHOIS lookup failed or domain privacy enabled")

        return ReconResult(
            platform=cls.PLATFORM,
            target=domain,
            status="completed",
            findings=findings,
            risk_flags=flags,
        )


class SSLRecon:
    """TLS/SSL certificate analysis."""

    PLATFORM = "SSL/TLS Analysis"

    @classmethod
    def scan(cls, target: str) -> ReconResult:
        if not target.startswith("http"):
            target = f"https://{target}"
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port or 443
        flags: list[str] = []
        findings: dict[str, Any] = {}

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    findings["subject"] = dict(x[0] for x in cert.get("subject", []))
                    findings["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    findings["not_before"] = cert.get("notBefore")
                    findings["not_after"] = cert.get("notAfter")
                    findings["san"] = [v for _, v in cert.get("subjectAltName", [])]
                    findings["protocol"] = ssock.version()
        except ssl.SSLCertVerificationError:
            flags.append("Invalid or self-signed certificate — MITM/phishing risk")
            findings["ssl_valid"] = False
        except Exception as exc:
            findings["error"] = str(exc)
            flags.append(f"SSL connection failed: {exc}")

        return ReconResult(
            platform=cls.PLATFORM,
            target=hostname,
            status="completed",
            findings=findings,
            risk_flags=flags,
        )


class PortRecon:
    """Lightweight port reconnaissance (common SOC ports)."""

    PLATFORM = "Port Scanner"
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }

    @classmethod
    def scan(cls, target: str, ports: list[int] | None = None) -> ReconResult:
        hostname = urlparse(target if "://" in target else f"http://{target}").hostname or target
        ports = ports or list(cls.COMMON_PORTS.keys())
        open_ports: dict[int, str] = {}
        flags: list[str] = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                if sock.connect_ex((hostname, port)) == 0:
                    open_ports[port] = cls.COMMON_PORTS.get(port, "Unknown")
                sock.close()
            except socket.gaierror:
                flags.append(f"Cannot resolve hostname: {hostname}")
                break

        risky = {445: "SMB exposed", 3389: "RDP exposed", 21: "FTP exposed"}
        for p, msg in risky.items():
            if p in open_ports:
                flags.append(msg)

        return ReconResult(
            platform=cls.PLATFORM,
            target=hostname,
            status="completed",
            findings={"open_ports": open_ports, "scanned_count": len(ports)},
            risk_flags=flags,
        )


class SubdomainRecon:
    """Subdomain enumeration via common wordlist."""

    PLATFORM = "Subdomain Enum"
    WORDLIST = [
        "www", "mail", "ftp", "admin", "portal", "vpn", "dev", "staging",
        "api", "secure", "login", "webmail", "mx", "smtp", "remote",
    ]

    @classmethod
    def scan(cls, target: str) -> ReconResult:
        ext = tldextract.extract(target)
        base = f"{ext.domain}.{ext.suffix}"
        found: list[str] = []
        flags: list[str] = []

        for sub in cls.WORDLIST:
            fqdn = f"{sub}.{base}"
            if _safe_resolve(fqdn, "A") or _safe_resolve(fqdn, "CNAME"):
                found.append(fqdn)

        if len(found) > 8:
            flags.append("Large attack surface — many subdomains discovered")

        return ReconResult(
            platform=cls.PLATFORM,
            target=base,
            status="completed",
            findings={"subdomains": found, "count": len(found)},
            risk_flags=flags,
        )


class OSINTRecon:
    """OSINT-style metadata and hash fingerprinting."""

    PLATFORM = "OSINT Metadata"

    @classmethod
    def scan(cls, target: str) -> ReconResult:
        flags: list[str] = []
        findings: dict[str, Any] = {
            "target_hash_md5": hashlib.md5(target.encode()).hexdigest(),
            "target_hash_sha256": hashlib.sha256(target.encode()).hexdigest(),
            "is_url": validators.url(target),
            "is_domain": validators.domain(target.split("/")[0] if "://" not in target else urlparse(target).hostname or ""),
        }

        if findings["is_url"]:
            parsed = urlparse(target)
            findings["scheme"] = parsed.scheme
            findings["path_depth"] = len([p for p in parsed.path.split("/") if p])
            if parsed.scheme == "http":
                flags.append("Plain HTTP — credentials may be transmitted insecurely")

        return ReconResult(
            platform=cls.PLATFORM,
            target=target,
            status="completed",
            findings=findings,
            risk_flags=flags,
        )


RECON_PLATFORMS = {
    "dns": DNSRecon,
    "whois": WHOISRecon,
    "ssl": SSLRecon,
    "ports": PortRecon,
    "subdomains": SubdomainRecon,
    "osint": OSINTRecon,
}


def run_full_recon(target: str, platforms: list[str] | None = None) -> list[ReconResult]:
    """Run selected or all recon platforms against a target."""
    selected = platforms or list(RECON_PLATFORMS.keys())
    results: list[ReconResult] = []
    for key in selected:
        scanner = RECON_PLATFORMS.get(key)
        if scanner:
            results.append(scanner.scan(target))
    return results


def aggregate_recon_findings(results: list[ReconResult]) -> dict[str, Any]:
    all_flags = []
    for r in results:
        all_flags.extend(r.risk_flags)
    return {
        "platforms_run": len(results),
        "total_risk_flags": len(all_flags),
        "risk_flags": all_flags,
        "dns_records": next((r.findings for r in results if r.platform == "DNS Recon"), {}),
        "open_ports": next(
            (r.findings.get("open_ports", {}) for r in results if r.platform == "Port Scanner"),
            {},
        ),
    }
