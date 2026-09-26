#!/usr/bin/env python3
"""
Air-Gap Audit Breaker CLI:
Interactive command-line tool for physical air-gap verification and compliance deception detection.
Exposes fake air-gaps, hidden basebands, telemetry queues, and Big 4 / C3PAO audit theater.
Zero external dependencies (pure Python standard library).
"""

from __future__ import annotations
import argparse
import json
import sys
from airgap_audit_breaker import (
    NetworkBleedScanner,
    OOBMDetector,
    TelemetryQueueScanner,
    WeightSanitizer,
    CMMCParityEngine,
    CryptographicReceiptIssuer,
)


def print_banner():
    banner = """
================================================================================
        AIR-GAP AUDIT BREAKER: PHYSICAL VERIFICATION & DECEPTION SENTINEL       
         Exposing Big 4 Advisory Theater, Fake Air-Gaps & Telemetry Sinks       
================================================================================
"""
    print(banner)


def cmd_scan(args):
    print_banner()
    enclave = args.enclave or "SECURE-ENCLAVE-01"
    paper_score = args.paper_score
    fees = args.fees

    print(f"[*] Initiating physical air-gap probe on enclave: {enclave}")
    print(f"[*] Claimed CMMC / NIST SP 800-171 Paper Score : {paper_score:.1f}%")
    print(f"[*] Advisory / C3PAO Audit Fees Paid            : ${fees:,.2f} USD\n")

    # 1. Network Bleed
    net_scanner = NetworkBleedScanner()
    net_vectors = net_scanner.scan()
    print(f"[+] Network Boundary Scan: {len(net_vectors)} leak vectors detected.")

    # 2. OOBM Detector
    oobm_scanner = OOBMDetector()
    oobm_vectors = oobm_scanner.scan()
    print(f"[+] Baseband / BMC Scan  : {len(oobm_vectors)} out-of-band management vectors detected.")

    # 3. Telemetry Queues
    telemetry_scanner = TelemetryQueueScanner()
    telem_vectors, total_bytes = telemetry_scanner.scan()
    print(f"[+] Telemetry Spool Scan : {len(telem_vectors)} queues detected ({total_bytes:,} queued bytes).")

    # 4. Optional Model Weights
    model_scans = []
    if args.model_path:
        w_sanitizer = WeightSanitizer()
        model_scans = w_sanitizer.scan_path(args.model_path)
        print(f"[+] Model Weight Scan    : {len(model_scans)} files analyzed.")

    # 5. Evaluate Parity
    engine = CMMCParityEngine()
    report = engine.evaluate(
        enclave_name=enclave,
        paper_score_claimed=paper_score,
        advisory_fees_paid_usd=fees,
        telemetry_vectors=net_vectors + telem_vectors,
        oobm_vectors=oobm_vectors,
        model_scans=model_scans
    )

    # Output formatting
    print("\n" + "=" * 80)
    print("                    PHYSICAL AIR-GAP AUDIT REPORT")
    print("=" * 80)
    print(f"  Target Enclave              : {report.target_enclave}")
    print(f"  Report Serial               : {report.report_id}")
    print(f"  Timestamp (UTC)             : {report.timestamp_utc}")
    print(f"  Executive Assessment        : {report.executive_assessment}")
    print("-" * 80)
    print("  COMPLIANCE DECEPTION METRICS:")
    print(f"    - Paper Score Claimed     : {report.paper_compliance_score:.2f}% (Big 4 / C3PAO Checkbox)")
    print(f"    - Physical Air-Gap Score  : {report.physical_airgap_score:.2f}% (Actual Silicon/Network Isolation)")
    print(f"    - Deception Delta         : {report.deception_delta:.2f}% [The Compliance Chasm]")
    print(f"    - Leakage Coefficient     : {report.airgap_leakage_coefficient:.4f} (Lambda_air: 0.0=Airgap, 1.0=Sieve)")
    print(f"    - Total Queued Telemetry  : {report.total_telemetry_queued_bytes:,} bytes")
    print(f"    - Critical Vulnerabilities: {report.critical_vulnerabilities}")
    print("-" * 80)
    print("  FINANCIAL FORENSICS (THE COMPLIANCE GRIFT):")
    print(f"    - Advisory Fees Wasted    : ${report.advisory_fees_paid_usd:,.2f} USD")
    print(f"    - True Engineering Value  : ${report.true_engineering_value_usd:,.2f} USD")
    print(f"    - Budget Waste Ratio      : {report.budget_waste_ratio:.2f}x multiplier")
    print("=" * 80)

    if args.verbose and report.controls_audited:
        print("\n[+] HIGH-DECEPTION NIST SP 800-171 / CMMC CONTROLS BREAKDOWN:")
        print(f"  {'Control ID':<14} | {'Status':<24} | {'Grift':<6} | {'Title / Discrepancy'}")
        print("  " + "-" * 76)
        for ctrl in report.controls_audited:
            print(f"  {ctrl.control_id:<14} | {ctrl.status.value:<24} | {ctrl.advisory_grift_rating:<6.2f} | {ctrl.title}")
            if ctrl.status.value != "COMPLIANT_PHYSICAL":
                print(f"    -> [Physics Reality]: {ctrl.discrepancy_rationale}")

    if args.output:
        issuer = CryptographicReceiptIssuer()
        cert = issuer.issue_certificate(report)
        with open(args.output, "w") as f:
            json.dump(cert, f, indent=2)
        print(f"\n[✔] Cryptographic Attestation Certificate written to: {args.output}")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))


def cmd_audit_weights(args):
    print_banner()
    path = args.path
    print(f"[*] Auditing neural network weights at path: {path}")
    sanitizer = WeightSanitizer()
    scans = sanitizer.scan_path(path)

    if not scans:
        print("[-] No model files found at specified path.")
        return

    print(f"\n[+] Scanned {len(scans)} files:\n")
    for s in scans:
        status_flag = "[✔] SAFE" if s.safe_for_airgap else "[✖] COMPROMISED"
        print(f"  {status_flag} {os.path.basename(s.file_path)} ({s.format}, {s.file_size_bytes:,} bytes)")
        print(f"      SHA-256 : {s.sha256_hash[:16]}...{s.sha256_hash[-16:]}")
        print(f"      Verdict : {s.verdict}")
        if s.detected_opcodes:
            print(f"      Opcodes : {', '.join(s.detected_opcodes)}")
        print()

    if args.json:
        print(json.dumps([s.to_dict() for s in scans], indent=2))


def cmd_attest(args):
    print_banner()
    enclave = args.enclave or "SOVEREIGN-NODE-ALPHA"
    fees = args.fees or 250000.0
    paper_score = args.paper_score or 98.0

    net_scanner = NetworkBleedScanner()
    oobm_scanner = OOBMDetector()
    telemetry_scanner = TelemetryQueueScanner()
    
    net_v = net_scanner.scan()
    oobm_v = oobm_scanner.scan()
    telem_v, _ = telemetry_scanner.scan()

    engine = CMMCParityEngine()
    report = engine.evaluate(
        enclave_name=enclave,
        paper_score_claimed=paper_score,
        advisory_fees_paid_usd=fees,
        telemetry_vectors=net_v + telem_v,
        oobm_vectors=oobm_v,
        model_scans=[]
    )

    issuer = CryptographicReceiptIssuer()
    certificate = issuer.issue_certificate(report)

    output_path = args.output or "airgap_certificate.json"
    with open(output_path, "w") as f:
        json.dump(certificate, f, indent=2)

    print(f"[✔] Tamper-evident attestation passport successfully generated.")
    print(f"    Report Serial      : {report.report_id}")
    print(f"    Attestation Hash   : {certificate['cryptographic_proof']['sha256_attestation_signature']}")
    print(f"    Evidence Vault URL : {certificate['vault_verification_url']}")
    print(f"    Saved To           : {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Air-Gap Audit Breaker: Physical Verification & Compliance Deception Sentinel"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Scan local system for physical air-gap violations")
    scan_parser.add_argument("--enclave", type=str, default="SECURE-ENCLAVE-01", help="Name of target enclave")
    scan_parser.add_argument("--paper-score", type=float, default=95.0, help="Paper score claimed by Big 4 auditor")
    scan_parser.add_argument("--fees", type=float, default=500000.0, help="Advisory fees paid to consultants (USD)")
    scan_parser.add_argument("--model-path", type=str, default=None, help="Path to AI model weights to inspect")
    scan_parser.add_argument("--verbose", action="store_true", help="Print detailed control-by-control discrepancy breakdown")
    scan_parser.add_argument("--output", type=str, default=None, help="Path to save cryptographic attestation certificate")
    scan_parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    scan_parser.set_defaults(func=cmd_scan)

    # Subcommand: audit-weights
    weights_parser = subparsers.add_parser("audit-weights", help="Inspect AI weights for pickle execution & cloud DRM")
    weights_parser.add_argument("--path", type=str, required=True, help="Directory or file path of AI model weights")
    weights_parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    weights_parser.set_defaults(func=cmd_audit_weights)

    # Subcommand: attest
    attest_parser = subparsers.add_parser("attest", help="Generate verifiable cryptographic certificate for Evidence Vault")
    attest_parser.add_argument("--enclave", type=str, default="SOVEREIGN-NODE-ALPHA", help="Name of target enclave")
    attest_parser.add_argument("--paper-score", type=float, default=98.0, help="Paper score claimed by auditor")
    attest_parser.add_argument("--fees", type=float, default=250000.0, help="Advisory fees paid (USD)")
    attest_parser.add_argument("--output", type=str, default="airgap_certificate.json", help="Output certificate file")
    attest_parser.set_defaults(func=cmd_attest)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
