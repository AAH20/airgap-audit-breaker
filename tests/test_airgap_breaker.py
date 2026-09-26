"""
Unit Tests for Air-Gap Audit Breaker.
100% pure Python standard library test suite.
"""

import unittest
import tempfile
import os
import json
from airgap_audit_breaker import (
    NetworkBleedScanner,
    OOBMDetector,
    TelemetryQueueScanner,
    WeightSanitizer,
    CMMCParityEngine,
    CryptographicReceiptIssuer,
    SeverityLevel,
    RiskCategory,
    TelemetryBleedVector,
    BasebandOOBMVector,
    ModelIntegrityScan,
)


class TestAirGapAuditBreaker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_network_bleed_scanner(self):
        scanner = NetworkBleedScanner()
        vectors = scanner.scan()
        self.assertIsInstance(vectors, list)
        for v in vectors:
            self.assertIsInstance(v, TelemetryBleedVector)
            self.assertIn(v.severity, [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL])

    def test_oobm_detector(self):
        detector = OOBMDetector()
        vectors = detector.scan()
        self.assertIsInstance(vectors, list)
        for v in vectors:
            self.assertIsInstance(v, BasebandOOBMVector)
            self.assertTrue(len(v.controller_type) > 0)

    def test_telemetry_queue_scanner(self):
        scanner = TelemetryQueueScanner()
        vectors, total_bytes = scanner.scan()
        self.assertIsInstance(vectors, list)
        self.assertIsInstance(total_bytes, int)
        self.assertGreaterEqual(total_bytes, 0)

    def test_weight_sanitizer_safe_and_malicious(self):
        sanitizer = WeightSanitizer()

        # 1. Create a safe safetensors mock file
        safe_file = os.path.join(self.temp_dir.name, "model.safetensors")
        with open(safe_file, "wb") as f:
            f.write(b'{"__metadata__": {"format": "pt"}}\x00\x00\x00\x00\x01\x02\x03')

        scans = sanitizer.scan_path(safe_file)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].format, "safetensors")
        self.assertTrue(scans[0].safe_for_airgap)
        self.assertFalse(scans[0].has_unsafe_opcodes)

        # 2. Create an unsafe pickle payload file
        unsafe_file = os.path.join(self.temp_dir.name, "backdoor.pt")
        with open(unsafe_file, "wb") as f:
            f.write(b'\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.')

        scans = sanitizer.scan_path(unsafe_file)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].format, "pytorch_pickle")
        self.assertFalse(scans[0].safe_for_airgap)
        self.assertTrue(scans[0].has_unsafe_opcodes)
        self.assertIn("cposix -> system", scans[0].detected_opcodes)

    def test_cmmc_parity_engine_math(self):
        engine = CMMCParityEngine()

        mock_telemetry = [
            TelemetryBleedVector(
                vector_id="TEST-VEC-1",
                category=RiskCategory.NETWORK_BLEED,
                severity=SeverityLevel.CRITICAL,
                target_interface="eth0",
                description="Default gateway bleed",
                queued_bytes=2048,
                destination_target="192.168.1.1",
                nist_control="AC.L2-3.1.3",
                remediation_command="route del default"
            )
        ]

        mock_oobm = [
            BasebandOOBMVector(
                controller_type="IPMI BMC",
                mac_address="00:11:22:33:44:55",
                active_phy_state=True,
                vlan_tagged=False,
                shared_nic_detected=True,
                severity=SeverityLevel.CRITICAL,
                cve_exposure="CVE-2013-4786",
                mitigation="Disable IPMI"
            )
        ]

        report = engine.evaluate(
            enclave_name="MOCK-DEFENSE-NODE",
            paper_score_claimed=98.0,
            advisory_fees_paid_usd=400000.0,
            telemetry_vectors=mock_telemetry,
            oobm_vectors=mock_oobm,
            model_scans=[]
        )

        # Mathematical invariants:
        # Leakage = 0.35 (critical telem) + 0.40 (critical oobm) = 0.75
        self.assertAlmostEqual(report.airgap_leakage_coefficient, 0.75, places=2)
        # Physical score = (1.0 - 0.75) * 100 = 25.0
        self.assertAlmostEqual(report.physical_airgap_score, 25.0, places=2)
        # Deception delta = 98.0 - 25.0 = 73.0
        self.assertAlmostEqual(report.deception_delta, 73.0, places=2)
        # Budget waste ratio should be significantly greater than 1.0
        self.assertGreater(report.budget_waste_ratio, 1.0)
        self.assertTrue(len(report.merkle_root) == 64)
        self.assertEqual(len(report.controls_audited), 10)

    def test_cryptographic_receipt_issuer(self):
        engine = CMMCParityEngine()
        report = engine.evaluate(
            enclave_name="ATTESTATION-NODE",
            paper_score_claimed=95.0,
            advisory_fees_paid_usd=200000.0,
            telemetry_vectors=[],
            oobm_vectors=[],
            model_scans=[]
        )

        issuer = CryptographicReceiptIssuer()
        cert = issuer.issue_certificate(report)

        self.assertIn("vault_verification_url", cert)
        self.assertIn("cryptographic_proof", cert)
        self.assertEqual(len(cert["cryptographic_proof"]["sha256_attestation_signature"]), 64)
        self.assertEqual(cert["verdict"]["physical_airgap_score"], 100.0)


if __name__ == "__main__":
    unittest.main()
