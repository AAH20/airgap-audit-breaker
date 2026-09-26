"""
Telemetry Queue Scanner: Audits OS and application spool directories for dormant telemetry buffers.
Identifies stored telemetry waiting to beacon outbound upon reconnection.
Pure Python standard library.
"""

from __future__ import annotations
import os
import glob
from typing import List, Tuple
from ..models import TelemetryBleedVector, RiskCategory, SeverityLevel


class TelemetryQueueScanner:
    """Scans filesystem locations for queued analytics, crash dumps, and cloud credential caches."""

    SUSPICIOUS_PATHS = [
        # OS Diagnostic & Telemetry Spool Dirs
        ("/var/log/diagnostic*", "System Diagnostic Telemetry Spool"),
        ("/Library/Logs/DiagnosticReports*", "macOS Crash & Diagnostic Report Buffer"),
        ("/var/crash*", "Kernel & User Core Dump Queue"),
        ("/var/spool/mail*", "Mail Transport Spool"),
        # Cloud CLI & Token Caches (Exposed in supposed air-gap)
        ("~/.aws/credentials", "AWS Cloud Credentials Cache"),
        ("~/.azure/accessTokens.json", "Azure OAuth Access Token Cache"),
        ("~/.config/gcloud/credentials.db", "Google Cloud Token Cache"),
        ("~/.huggingface/token", "HuggingFace API Token Cache"),
        # Driver & Vendor Telemetry
        ("/var/log/nvidia-telemetry*", "NVIDIA GPU Driver Telemetry Log"),
        ("~/.cache/pip/http*", "pip HTTP Download Metadata Cache"),
        ("~/.cursor/telemetry*", "Cursor AI Client Telemetry Buffer"),
        ("~/.vscode/telemetry*", "VS Code Client Analytics Buffer"),
    ]

    def scan(self) -> Tuple[List[TelemetryBleedVector], int]:
        vectors: List[TelemetryBleedVector] = []
        total_queued_bytes = 0

        for path_pattern, desc in self.SUSPICIOUS_PATHS:
            expanded = os.path.expanduser(path_pattern)
            matched_files = glob.glob(expanded)

            for matched in matched_files:
                try:
                    if os.path.isfile(matched):
                        size = os.path.getsize(matched)
                        total_queued_bytes += size
                        vectors.append(TelemetryBleedVector(
                            vector_id=f"TELEMETRY-{os.path.basename(matched)}",
                            category=RiskCategory.TELEMETRY_QUEUE,
                            severity=SeverityLevel.HIGH if size > 1024 * 1024 else SeverityLevel.MEDIUM,
                            target_interface=matched,
                            description=f"{desc} ({size} bytes). Risk of instant burst exfiltration upon reconnect.",
                            queued_bytes=size,
                            destination_target="Vendor Cloud Telemetry Collector",
                            nist_control="SI.L2-3.14.1 (Flaw Remediation / Memory Hygiene)",
                            remediation_command=f"rm -rf {matched} && shred -u {matched} 2>/dev/null"
                        ))
                    elif os.path.isdir(matched):
                        dir_size = sum(
                            os.path.getsize(os.path.join(dirpath, filename))
                            for dirpath, _, filenames in os.walk(matched)
                            for filename in filenames
                        )
                        if dir_size > 0:
                            total_queued_bytes += dir_size
                            vectors.append(TelemetryBleedVector(
                                vector_id=f"SPOOL-DIR-{os.path.basename(matched)}",
                                category=RiskCategory.TELEMETRY_QUEUE,
                                severity=SeverityLevel.HIGH,
                                target_interface=matched,
                                description=f"{desc} directory contains {dir_size} bytes of queued operational metadata.",
                                queued_bytes=dir_size,
                                destination_target="Diagnostic Endpoint",
                                nist_control="AU.L2-3.3.1 (Audit Log Hygiene)",
                                remediation_command=f"rm -rf {matched}/*"
                            ))
                except Exception:
                    continue

        return vectors, total_queued_bytes
