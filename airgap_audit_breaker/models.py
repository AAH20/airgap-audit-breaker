"""
Core Data Models for Air-Gap Audit Breaker.
Evaluates physical air-gap integrity vs. paper compliance claims (CMMC / NIST SP 800-171).
Zero external dependencies (pure Python 3.10+ standard library).
"""

from __future__ import annotations
import dataclasses
from enum import Enum
from typing import Dict, List, Optional, Any


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskCategory(str, Enum):
    NETWORK_BLEED = "NETWORK_BLEED"
    BASEBAND_OOBM = "BASEBAND_OOBM"
    TELEMETRY_QUEUE = "TELEMETRY_QUEUE"
    MODEL_PICKLE_EXEC = "MODEL_PICKLE_EXEC"
    LICENSE_DRM = "LICENSE_DRM"
    TEMPEST_EMANATION = "TEMPEST_EMANATION"
    AUDIT_THEATER = "AUDIT_THEATER"


class CMMCControlStatus(str, Enum):
    COMPLIANT_PHYSICAL = "COMPLIANT_PHYSICAL"
    PAPER_PASS_PHYSICAL_FAIL = "PAPER_PASS_PHYSICAL_FAIL"  # The Big 4 deception state
    NON_COMPLIANT = "NON_COMPLIANT"


@dataclasses.dataclass
class TelemetryBleedVector:
    """Represents an active or queued data exfiltration vector crossing the air gap."""
    vector_id: str
    category: RiskCategory
    severity: SeverityLevel
    target_interface: str
    description: str
    queued_bytes: int
    destination_target: str
    nist_control: str  # e.g., "SC.L2-3.13.1", "AC.L2-3.1.3"
    remediation_command: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_id": self.vector_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "target_interface": self.target_interface,
            "description": self.description,
            "queued_bytes": self.queued_bytes,
            "destination_target": self.destination_target,
            "nist_control": self.nist_control,
            "remediation_command": self.remediation_command,
        }


@dataclasses.dataclass
class BasebandOOBMVector:
    """Out-of-band management controller or baseband interface bypassing OS routing."""
    controller_type: str  # e.g., "iDRAC", "iLO", "Intel AMT", "IPMI BMC"
    mac_address: str
    active_phy_state: bool
    vlan_tagged: bool
    shared_nic_detected: bool
    severity: SeverityLevel
    cve_exposure: str
    mitigation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "controller_type": self.controller_type,
            "mac_address": self.mac_address,
            "active_phy_state": self.active_phy_state,
            "vlan_tagged": self.vlan_tagged,
            "shared_nic_detected": self.shared_nic_detected,
            "severity": self.severity.value,
            "cve_exposure": self.cve_exposure,
            "mitigation": self.mitigation,
        }


@dataclasses.dataclass
class ModelIntegrityScan:
    """Audit of AI model weights brought into or residing in the air-gapped enclave."""
    file_path: str
    format: str  # e.g. "safetensors", "pytorch_pickle", "gguf", "onnx"
    file_size_bytes: int
    sha256_hash: str
    has_unsafe_opcodes: bool
    detected_opcodes: List[str]
    has_network_heartbeat_hooks: bool
    safe_for_airgap: bool
    verdict: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "format": self.format,
            "file_size_bytes": self.file_size_bytes,
            "sha256_hash": self.sha256_hash,
            "has_unsafe_opcodes": self.has_unsafe_opcodes,
            "detected_opcodes": self.detected_opcodes,
            "has_network_heartbeat_hooks": self.has_network_heartbeat_hooks,
            "safe_for_airgap": self.safe_for_airgap,
            "verdict": self.verdict,
        }


@dataclasses.dataclass
class CMMCControlAudit:
    """Individual CMMC / NIST SP 800-171 control evaluation: Paper vs Physics."""
    control_id: str
    title: str
    domain: str  # AC, MP, SC, SI, etc.
    paper_ssp_claimed: bool
    physical_reality_verified: bool
    status: CMMCControlStatus
    discrepancy_rationale: str
    advisory_grift_rating: float  # 0.0 to 1.0 (how much consultants charge to fake this)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "domain": self.domain,
            "paper_ssp_claimed": self.paper_ssp_claimed,
            "physical_reality_verified": self.physical_reality_verified,
            "status": self.status.value,
            "discrepancy_rationale": self.discrepancy_rationale,
            "advisory_grift_rating": self.advisory_grift_rating,
        }


@dataclasses.dataclass
class ComplianceDeceptionReport:
    """Master benchmark report comparing auditor claims vs. operational physics."""
    report_id: str
    timestamp_utc: str
    target_enclave: str
    paper_compliance_score: float   # e.g. 98.0% according to Big 4 C3PAO
    physical_airgap_score: float    # e.g. 24.5% based on actual physics
    deception_delta: float          # paper_score - physical_score
    airgap_leakage_coefficient: float  # Lambda_air [0.0 = total airgap, 1.0 = sieve]
    total_telemetry_queued_bytes: int
    total_vectors_detected: int
    critical_vulnerabilities: int
    advisory_fees_paid_usd: float
    true_engineering_value_usd: float
    budget_waste_ratio: float
    controls_audited: List[CMMCControlAudit]
    telemetry_vectors: List[TelemetryBleedVector]
    oobm_vectors: List[BasebandOOBMVector]
    model_scans: List[ModelIntegrityScan]
    executive_assessment: str
    merkle_root: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp_utc": self.timestamp_utc,
            "target_enclave": self.target_enclave,
            "paper_compliance_score": round(self.paper_compliance_score, 2),
            "physical_airgap_score": round(self.physical_airgap_score, 2),
            "deception_delta": round(self.deception_delta, 2),
            "airgap_leakage_coefficient": round(self.airgap_leakage_coefficient, 4),
            "total_telemetry_queued_bytes": self.total_telemetry_queued_bytes,
            "total_vectors_detected": self.total_vectors_detected,
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "advisory_fees_paid_usd": self.advisory_fees_paid_usd,
            "true_engineering_value_usd": self.true_engineering_value_usd,
            "budget_waste_ratio": round(self.budget_waste_ratio, 2),
            "controls_audited": [c.to_dict() for c in self.controls_audited],
            "telemetry_vectors": [t.to_dict() for t in self.telemetry_vectors],
            "oobm_vectors": [o.to_dict() for o in self.oobm_vectors],
            "model_scans": [m.to_dict() for m in self.model_scans],
            "executive_assessment": self.executive_assessment,
            "merkle_root": self.merkle_root,
        }
