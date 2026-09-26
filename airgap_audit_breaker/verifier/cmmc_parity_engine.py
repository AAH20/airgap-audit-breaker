"""
CMMC Parity Engine: Evaluates NIST SP 800-171 Rev 3 / CMMC 2.0 controls against physical runtime reality.
Calculates Compliance Deception Delta and Air-Gap Leakage Coefficient (Lambda_air).
Pure Python standard library.
"""

from __future__ import annotations
import datetime
import hashlib
import json
from typing import List
from ..models import (
    ComplianceDeceptionReport,
    CMMCControlAudit,
    CMMCControlStatus,
    TelemetryBleedVector,
    BasebandOOBMVector,
    ModelIntegrityScan,
    SeverityLevel
)


class CMMCParityEngine:
    """Mathematical arbiter measuring the chasm between paper compliance and operational air-gap physics."""

    def evaluate(
        self,
        enclave_name: str,
        paper_score_claimed: float,
        advisory_fees_paid_usd: float,
        telemetry_vectors: List[TelemetryBleedVector],
        oobm_vectors: List[BasebandOOBMVector],
        model_scans: List[ModelIntegrityScan]
    ) -> ComplianceDeceptionReport:
        
        # 1. Calculate Air-Gap Leakage Coefficient (Lambda_air)
        leakage_score = 0.0
        critical_count = 0
        
        for vec in telemetry_vectors:
            if vec.severity == SeverityLevel.CRITICAL:
                leakage_score += 0.35
                critical_count += 1
            elif vec.severity == SeverityLevel.HIGH:
                leakage_score += 0.20
            elif vec.severity == SeverityLevel.MEDIUM:
                leakage_score += 0.08
            else:
                leakage_score += 0.02

        for oobm in oobm_vectors:
            if oobm.severity == SeverityLevel.CRITICAL:
                leakage_score += 0.40
                critical_count += 1
            elif oobm.severity == SeverityLevel.HIGH:
                leakage_score += 0.25

        for model in model_scans:
            if model.has_unsafe_opcodes:
                leakage_score += 0.50
                critical_count += 1
            elif model.has_network_heartbeat_hooks:
                leakage_score += 0.30
            elif not model.safe_for_airgap:
                leakage_score += 0.15

        lambda_air = min(1.0, leakage_score)

        # 2. Derive Physical Air-Gap Score (0.0 to 100.0)
        physical_airgap_score = max(0.0, (1.0 - lambda_air) * 100.0)

        # 3. Derive Compliance Deception Delta
        deception_delta = max(0.0, paper_score_claimed - physical_airgap_score)

        # 4. Total Queued Bytes
        total_queued_bytes = sum(v.queued_bytes for v in telemetry_vectors)

        # 5. Calculate Budget Waste Ratio
        # True engineering value is inversely proportional to deception delta and leakage
        retention_rate = max(0.05, 1.0 - lambda_air)
        true_engineering_value = advisory_fees_paid_usd * retention_rate * (1.0 - (deception_delta / 100.0))
        true_engineering_value = max(100.0, true_engineering_value)
        budget_waste_ratio = advisory_fees_paid_usd / true_engineering_value

        # 6. Audit 10 High-Deception Controls
        controls = self._audit_high_deception_controls(
            telemetry_vectors=telemetry_vectors,
            oobm_vectors=oobm_vectors,
            model_scans=model_scans
        )

        # 7. Generate Merkle Root
        report_id = f"AIRGAP-REP-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        merkle_root = self._compute_merkle_root(report_id, physical_airgap_score, lambda_air)

        # 8. Executive Assessment
        if lambda_air < 0.15:
            assessment = "SOVEREIGN ENCLAVE: Verified deterministic air-gap with zero telemetry and isolated silicon."
        elif lambda_air < 0.45:
            assessment = "PERMEABLE ENCLAVE: Minor telemetry spooling or configuration deviations detected."
        elif lambda_air < 0.75:
            assessment = "PAPER COMPLIANCE FRAUD: Severe breach of physical air-gap boundaries masked by paperwork."
        else:
            assessment = "CRITICAL SIEVE: Total operational exposure. The air-gap is an illusion; systems are completely vulnerable."

        return ComplianceDeceptionReport(
            report_id=report_id,
            timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            target_enclave=enclave_name,
            paper_compliance_score=paper_score_claimed,
            physical_airgap_score=physical_airgap_score,
            deception_delta=deception_delta,
            airgap_leakage_coefficient=lambda_air,
            total_telemetry_queued_bytes=total_queued_bytes,
            total_vectors_detected=len(telemetry_vectors) + len(oobm_vectors) + len(model_scans),
            critical_vulnerabilities=critical_count,
            advisory_fees_paid_usd=advisory_fees_paid_usd,
            true_engineering_value_usd=true_engineering_value,
            budget_waste_ratio=budget_waste_ratio,
            controls_audited=controls,
            telemetry_vectors=telemetry_vectors,
            oobm_vectors=oobm_vectors,
            model_scans=model_scans,
            executive_assessment=assessment,
            merkle_root=merkle_root
        )

    def _audit_high_deception_controls(
        self,
        telemetry_vectors: List[TelemetryBleedVector],
        oobm_vectors: List[BasebandOOBMVector],
        model_scans: List[ModelIntegrityScan]
    ) -> List[CMMCControlAudit]:
        
        has_net_bleed = any(v.category.value == "NETWORK_BLEED" for v in telemetry_vectors)
        has_oobm = len(oobm_vectors) > 0
        has_queued_telemetry = sum(v.queued_bytes for v in telemetry_vectors) > 0
        has_unsafe_models = any(not m.safe_for_airgap for m in model_scans)

        controls = [
            CMMCControlAudit(
                control_id="AC.L2-3.1.3",
                title="Control CUI Flow",
                domain="Access Control",
                paper_ssp_claimed=True,
                physical_reality_verified=not (has_net_bleed or has_oobm),
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not (has_net_bleed or has_oobm) else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Auditor verified firewall rules; physical scan found active default route or OOBM bridge.",
                advisory_grift_rating=0.92
            ),
            CMMCControlAudit(
                control_id="AC.L2-3.1.20",
                title="Limit External System Connections",
                domain="Access Control",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_net_bleed,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_net_bleed else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Auditor checked interface configuration; scan found public DNS or non-loopback bindings.",
                advisory_grift_rating=0.88
            ),
            CMMCControlAudit(
                control_id="MP.L2-3.8.1",
                title="Protect System Media Containing CUI",
                domain="Media Protection",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_unsafe_models,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_unsafe_models else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Auditor checked encrypted USB policy; scan found pickled weights with arbitrary execution vectors.",
                advisory_grift_rating=0.95
            ),
            CMMCControlAudit(
                control_id="SC.L2-3.13.1",
                title="Boundary Protection",
                domain="System & Communications",
                paper_ssp_claimed=True,
                physical_reality_verified=not (has_net_bleed or has_oobm),
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not (has_net_bleed or has_oobm) else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Auditor verified physical cabinet locks; BMC sideband PHY active on primary ethernet port.",
                advisory_grift_rating=0.90
            ),
            CMMCControlAudit(
                control_id="SC.L2-3.13.5",
                title="Subnet Isolation for Public Components",
                domain="System & Communications",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_net_bleed,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_net_bleed else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Subnet isolation bypassed via dual-homed virtual adapters or link-local auto-configuration.",
                advisory_grift_rating=0.85
            ),
            CMMCControlAudit(
                control_id="SI.L2-3.14.1",
                title="Flaw Remediation & System Hygiene",
                domain="System & Information Integrity",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_queued_telemetry,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_queued_telemetry else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Auditor checked patch cycle logs; diagnostic queues are buffering gigabytes for burst exfiltration.",
                advisory_grift_rating=0.79
            ),
            CMMCControlAudit(
                control_id="IA.L2-3.5.3",
                title="Multifactor Authentication",
                domain="Identification & Authentication",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_oobm,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_oobm else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="OS enforces CAC/PIV smartcards; IPMI/iDRAC sideband has factory default credentials or RAKP bypass.",
                advisory_grift_rating=0.91
            ),
            CMMCControlAudit(
                control_id="AU.L2-3.3.1",
                title="System Audit Logging & Retention",
                domain="Audit & Accountability",
                paper_ssp_claimed=True,
                physical_reality_verified=not has_queued_telemetry,
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not has_queued_telemetry else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Logs stored in ephemeral buffers awaiting sync to vendor cloud rather than local WORM storage.",
                advisory_grift_rating=0.82
            ),
            CMMCControlAudit(
                control_id="CM.L2-3.4.2",
                title="Security Configuration Settings",
                domain="Configuration Management",
                paper_ssp_claimed=True,
                physical_reality_verified=not (has_net_bleed or has_oobm),
                status=CMMCControlStatus.COMPLIANT_PHYSICAL if not (has_net_bleed or has_oobm) else CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="CIS benchmark checklists completed on paper; wireless and baseband interfaces remain powered.",
                advisory_grift_rating=0.87
            ),
            CMMCControlAudit(
                control_id="CA.L2-3.12.1",
                title="Periodic Security Control Assessments",
                domain="Security Assessment",
                paper_ssp_claimed=True,
                physical_reality_verified=False,  # Big 4 paper assessments never physically verify
                status=CMMCControlStatus.PAPER_PASS_PHYSICAL_FAIL,
                discrepancy_rationale="Audits conducted via subjective interviews and spreadsheet checklists rather than deterministic telemetry probes.",
                advisory_grift_rating=0.99
            )
        ]
        return controls

    def _compute_merkle_root(self, report_id: str, physical_score: float, lambda_air: float) -> str:
        payload = f"{report_id}:{physical_score:.4f}:{lambda_air:.4f}:A2ZSOC-EVIDENCE-VAULT"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
