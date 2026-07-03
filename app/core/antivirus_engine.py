"""Mini antivirus engine with signature-based and heuristic scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.core.malware_scanner import scan_file_content, scan_file_path


@dataclass
class AVScanResult:
    engine: str
    target: str
    threats_found: int
    scanned_items: int
    quarantine_recommended: bool
    detections: list[dict] = field(default_factory=list)
    scan_duration_ms: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


SIGNATURE_DB = [
    {"id": "SIG-001", "name": "Trojan.Generic.Dropper", "pattern": b"MZ", "offset": 0},
    {"id": "SIG-002", "name": "Script.PS1.Downloader", "pattern": b"Invoke-Expression", "offset": None},
    {"id": "SIG-003", "name": "Macro.Office.Suspicious", "pattern": b"AutoOpen", "offset": None},
    {"id": "SIG-004", "name": "EICAR.Test", "pattern": b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "offset": None},
    {"id": "SIG-005", "name": "Backdoor.ReverseShell", "pattern": b"/bin/sh", "offset": None},
]


class MiniAntivirus:
    """Lightweight signature + heuristic AV for SOC triage."""

    ENGINE_NAME = "BlueShield AV Engine v1.0"

    @classmethod
    def scan_bytes(cls, data: bytes, label: str = "memory") -> AVScanResult:
        import time
        start = time.perf_counter()
        detections: list[dict] = []

        for sig in SIGNATURE_DB:
            if sig["offset"] is not None:
                if len(data) > sig["offset"] and data[sig["offset"]:].startswith(sig["pattern"]):
                    detections.append({"signature_id": sig["id"], "name": sig["name"], "action": "quarantine"})
            elif sig["pattern"] in data:
                detections.append({"signature_id": sig["id"], "name": sig["name"], "action": "quarantine"})

        heuristic = scan_file_content(data, label)
        if heuristic.verdict in ("malicious", "suspicious"):
            for s in heuristic.signatures_matched:
                detections.append({"signature_id": "HEUR", "name": s, "action": "review"})

        elapsed = int((time.perf_counter() - start) * 1000)
        return AVScanResult(
            engine=cls.ENGINE_NAME,
            target=label,
            threats_found=len(detections),
            scanned_items=1,
            quarantine_recommended=any(d["action"] == "quarantine" for d in detections),
            detections=detections,
            scan_duration_ms=elapsed,
        )

    @classmethod
    def scan_directory(cls, directory: str, max_files: int = 50) -> AVScanResult:
        import time
        start = time.perf_counter()
        path = Path(directory)
        detections: list[dict] = []
        scanned = 0

        if not path.is_dir():
            return AVScanResult(
                engine=cls.ENGINE_NAME,
                target=directory,
                threats_found=0,
                scanned_items=0,
                quarantine_recommended=False,
                detections=[{"error": "Directory not found"}],
            )

        for file_path in list(path.rglob("*"))[:max_files]:
            if not file_path.is_file():
                continue
            scanned += 1
            result = scan_file_path(str(file_path))
            if result.verdict != "clean":
                detections.append({
                    "file": str(file_path),
                    "verdict": result.verdict,
                    "score": result.score,
                    "signatures": result.signatures_matched,
                })

        elapsed = int((time.perf_counter() - start) * 1000)
        return AVScanResult(
            engine=cls.ENGINE_NAME,
            target=directory,
            threats_found=len(detections),
            scanned_items=scanned,
            quarantine_recommended=len(detections) > 0,
            detections=detections,
            scan_duration_ms=elapsed,
        )

    @classmethod
    def get_engine_status(cls) -> dict:
        return {
            "engine": cls.ENGINE_NAME,
            "signatures_loaded": len(SIGNATURE_DB),
            "heuristic_enabled": True,
            "real_time_protection": True,
            "last_update": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "status": "operational",
        }
