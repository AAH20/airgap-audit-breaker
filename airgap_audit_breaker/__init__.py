"""
Air-Gap Audit Breaker: Physical air-gap verification and compliance deception detector.
Exposes fake air-gaps, hidden basebands, telemetry queues, and Big 4 / C3PAO audit theater.
"""

from .models import (
    SeverityLevel,
    RiskCategory,
    CMMCControlStatus,
    TelemetryBleedVector,
    BasebandOOBMVector,
    ModelIntegrityScan,
    CMMCControlAudit,
    ComplianceDeceptionReport,
)
from .scanner.network_bleed import NetworkBleedScanner
from .scanner.oobm_detector import OOBMDetector
from .scanner.telemetry_queue import TelemetryQueueScanner
from .model_auditor.weight_sanitizer import WeightSanitizer
from .verifier.cmmc_parity_engine import CMMCParityEngine
from .attestation.cryptographic_receipt import CryptographicReceiptIssuer

__version__ = "1.0.0"
__all__ = [
    "SeverityLevel",
    "RiskCategory",
    "CMMCControlStatus",
    "TelemetryBleedVector",
    "BasebandOOBMVector",
    "ModelIntegrityScan",
    "CMMCControlAudit",
    "ComplianceDeceptionReport",
    "NetworkBleedScanner",
    "OOBMDetector",
    "TelemetryQueueScanner",
    "WeightSanitizer",
    "CMMCParityEngine",
    "CryptographicReceiptIssuer",
]
