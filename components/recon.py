import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import streamlit as st
import time

# Socket-based WHOIS lookup - no binaries required, platform independent
def get_whois_info(domain: str) -> str:
    """Queries WHOIS databases using raw socket connections to port 43."""
    domain = domain.strip().lower()
    if not domain:
        return "Please enter a valid domain name."
    
    try:
        # Step 1: Query IANA to locate the authoritative WHOIS server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode("utf-8"))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        iana_text = response.decode("utf-8", errors="ignore")
        
        # Parse output for registrar server
        whois_server = None
        for line in iana_text.splitlines():
            if line.startswith("refer:") or line.startswith("whois:"):
                whois_server = line.split(":", 1)[1].strip()
                break
        
        # Fallbacks if IANA didn't refer us
        if not whois_server:
            if domain.endswith(".com") or domain.endswith(".net"):
                whois_server = "whois.verisign-grs.com"
            elif domain.endswith(".org"):
                whois_server = "whois.pir.org"
            elif domain.endswith(".edu"):
                whois_server = "whois.educause.edu"
            elif domain.endswith(".gov"):
                whois_server = "whois.dotgov.gov"
            else:
                # Default fallback
                whois_server = "whois.ripe.net"
        
        # Step 2: Query the authoritative server
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(5.0)
        s2.connect((whois_server, 43))
        # Some registrars require '=' prefix or specific formats; standard works for most
        s2.send((domain + "\r\n").encode("utf-8"))
        
        response2 = b""
        while True:
            data = s2.recv(4096)
            if not data:
                break
            response2 += data
        s2.close()
        
        return response2.decode("utf-8", errors="ignore")
        
    except Exception as e:
        return f"WHOIS query failed: {str(e)}"

# DNS Records Lookup
def get_dns_records(domain: str) -> dict:
    """Fetches basic DNS records using built-in socket mechanisms."""
    records = {"A": [], "TXT": [], "MX": []}
    domain = domain.strip()
    
    # Resolve A record (IP)
    try:
        ips = socket.getaddrinfo(domain, None)
        records["A"] = list(set([ip[4][0] for ip in ips]))
    except Exception:
        records["A"] = ["Could not resolve A record"]
        
    # Attempt TXT/MX records via dnspython if installed, otherwise show basic A record
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        
        try:
            mx_answers = resolver.resolve(domain, 'MX')
            records["MX"] = [f"{r.preference} {r.exchange.to_text()}" for r in mx_answers]
        except Exception:
            records["MX"] = ["None found or query timed out"]
            
        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            records["TXT"] = [r.to_text() for r in txt_answers]
        except Exception:
            records["TXT"] = ["None found or query timed out"]
            
    except ImportError:
        records["MX"] = ["Install dnspython for MX lookup"]
        records["TXT"] = ["Install dnspython for TXT lookup"]
        
    return records

# Port Scanner
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Checks if a single port is open on the target host."""
    res = {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "Closed"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        if result == 0:
            res["status"] = "Open"
        s.close()
    except Exception:
        pass
    return res

def run_port_scan(host: str, progress_bar=None, status_text=None) -> list:
    """Runs a multithreaded port scan on the target host."""
    open_ports = []
    ports_to_scan = list(COMMON_PORTS.keys())
    total_ports = len(ports_to_scan)
    
    # Try resolving host first
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        return [{"port": "-", "service": "N/A", "status": f"Error: Cannot resolve host {host}"}]

    # Multithreading scan using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in ports_to_scan}
        for i, future in enumerate(futures):
            res = future.result()
            if res["status"] == "Open":
                open_ports.append(res)
            
            # Update Streamlit progress UI if provided
            if progress_bar and status_text:
                progress = (i + 1) / total_ports
                progress_bar.progress(progress)
                status_text.text(f"Scanning port {res['port']} ({res['service']})...")
                time.sleep(0.02) # Subtle delay for UI smoothness
                
    if progress_bar and status_text:
        status_text.text("Scan complete.")
        
    return open_ports

# TypoSquatting Domain Generator
def generate_typosquatting_domains(domain: str) -> list:
    """Generates a list of potential typosquatting / homoglyph domains for security reviews."""
    if "." not in domain:
        return []
    
    parts = domain.split(".")
    name = parts[0]
    tld = ".".join(parts[1:])
    
    candidates = []
    
    # 1. Homoglyphs / Character Substitutions
    substitutions = {
        'o': ['0', 'o-'],
        'l': ['1', 'i'],
        'i': ['1', 'l'],
        'e': ['3'],
        's': ['5'],
        'a': ['4', '@'],
        'g': ['9']
    }
    
    for i, char in enumerate(name):
        if char in substitutions:
            for sub in substitutions[char]:
                alt_name = name[:i] + sub + name[i+1:]
                candidates.append({
                    "domain": f"{alt_name}.{tld}",
                    "type": "Homoglyph/Character Swap",
                    "reason": f"Swapped '{char}' with '{sub}'"
                })
                
    # 2. Omissions
    for i in range(len(name)):
        alt_name = name[:i] + name[i+1:]
        if alt_name:
            candidates.append({
                "domain": f"{alt_name}.{tld}",
                "type": "Omission",
                "reason": f"Removed character at index {i}"
            })
            
    # 3. Common Security Prefixes / Suffixes
    prefixes = ["login-", "secure-", "support-", "verify-"]
    suffixes = ["-security", "-support", "-update", "-login"]
    
    for p in prefixes:
        candidates.append({
            "domain": f"{p}{name}.{tld}",
            "type": "Prefix Addition",
            "reason": f"Added prefix '{p}'"
        })
        
    for s in suffixes:
        candidates.append({
            "domain": f"{name}{s}.{tld}",
            "type": "Suffix Addition",
            "reason": f"Added suffix '{s}'"
        })
        
    # Check if they resolve (simulating threat intel check)
    # To keep it quick, we'll only check resolution for the first 5 in the background
    # and provide labels for the rest
    for item in candidates[:6]:
        try:
            # Short timeout check
            socket.gethostbyname(item["domain"])
            item["status"] = "Active (Resolves!)"
            item["severity"] = "High Risk"
        except Exception:
            item["status"] = "Inactive (No DNS)"
            item["severity"] = "Low Risk"
            
    for item in candidates[6:]:
        item["status"] = "Unchecked"
        item["severity"] = "Medium Risk"
        
    return candidates
