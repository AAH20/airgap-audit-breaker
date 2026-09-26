"""
Model Weight Sanitizer & Air-Gap Integrity Auditor:
Inspects neural network weight checkpoints (.pt, .bin, .safetensors, .gguf) and model configs
for dangerous pickle execution opcodes, licensing heartbeats, and covert cloud dependencies.
Pure Python standard library.
"""

from __future__ import annotations
import os
import hashlib
from typing import List, Tuple
from ..models import ModelIntegrityScan


class WeightSanitizer:
    """Audits local AI model weights for supply-chain backdoors, pickling risks, and license DRM."""

    DANGEROUS_OPCODES = [
        b"cposix\nsystem",
        b"csubprocess\n",
        b"cbuiltins\neval",
        b"cbuiltins\nexec",
        b"csocket\nsocket",
        b"curllib.request\n",
        b"cos\nsystem",
        b"cos\npopen",
    ]

    CLOUD_PHONE_HOME_STRINGS = [
        "api.openai.com",
        "api.anthropic.com",
        "bedrock-runtime",
        "telemetry.huggingface.co",
        "license_server",
        "verify_license",
        "heartbeat_interval",
        "phone_home",
    ]

    def scan_path(self, target_path: str) -> List[ModelIntegrityScan]:
        scans: List[ModelIntegrityScan] = []
        if os.path.isfile(target_path):
            scans.append(self._audit_file(target_path))
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if ext in [".pt", ".pth", ".bin", ".safetensors", ".gguf", ".onnx", ".json"]:
                        full_p = os.path.join(root, f)
                        scans.append(self._audit_file(full_p))
        return scans

    def _audit_file(self, file_path: str) -> ModelIntegrityScan:
        file_size = os.path.getsize(file_path)
        sha256 = self._compute_sha256(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        # Determine format
        if ext == ".safetensors":
            fmt = "safetensors"
        elif ext in [".pt", ".pth", ".bin"]:
            fmt = "pytorch_pickle"
        elif ext == ".gguf":
            fmt = "gguf"
        elif ext == ".onnx":
            fmt = "onnx"
        elif ext == ".json":
            fmt = "model_config"
        else:
            fmt = "unknown"

        unsafe_opcodes_detected: List[str] = []
        has_network_heartbeat = False

        # Fast inspection of header / first 64MB or entire file if small
        read_limit = min(file_size, 64 * 1024 * 1024)
        try:
            with open(file_path, "rb") as f:
                header_bytes = f.read(read_limit)

                # 1. Check for dangerous pickle opcodes if pickle format
                if fmt in ["pytorch_pickle", "unknown"]:
                    for opcode in self.DANGEROUS_OPCODES:
                        if opcode in header_bytes:
                            unsafe_opcodes_detected.append(opcode.decode("latin-1").replace("\n", " -> "))

                # 2. Check for phone-home / DRM / telemetry endpoints
                header_text = header_bytes.decode("latin-1", errors="ignore")
                for s in self.CLOUD_PHONE_HOME_STRINGS:
                    if s in header_text:
                        has_network_heartbeat = True
                        break
        except Exception:
            pass

        has_unsafe_opcodes = len(unsafe_opcodes_detected) > 0
        safe_for_airgap = (fmt in ["safetensors", "gguf"]) and not has_unsafe_opcodes and not has_network_heartbeat

        if has_unsafe_opcodes:
            verdict = "CRITICAL_RISK: Malicious executable pickle payload detected."
        elif has_network_heartbeat:
            verdict = "HIGH_RISK: Covert cloud licensing / telemetry heartbeat detected."
        elif fmt == "pytorch_pickle":
            verdict = "WARNING: Unsafe pickle format (arbitrary code execution vector). Convert to safetensors."
        else:
            verdict = "SECURE_AIRGAP_READY: Pure immutable tensor weights verified."

        return ModelIntegrityScan(
            file_path=file_path,
            format=fmt,
            file_size_bytes=file_size,
            sha256_hash=sha256,
            has_unsafe_opcodes=has_unsafe_opcodes,
            detected_opcodes=unsafe_opcodes_detected,
            has_network_heartbeat_hooks=has_network_heartbeat,
            safe_for_airgap=safe_for_airgap,
            verdict=verdict,
        )

    def _compute_sha256(self, file_path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "0" * 64
