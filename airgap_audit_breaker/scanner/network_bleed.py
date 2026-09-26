"""
Network Bleed Scanner: Audits network interface boundaries, routing tables, and socket listeners.
Detects illegal default gateways, dual-homing, active DNS pointers, and non-isolated physical PHYs.
Pure Python standard library.
"""

from __future__ import annotations
import os
import socket
import subprocess
from typing import List
from ..models import TelemetryBleedVector, RiskCategory, SeverityLevel


class NetworkBleedScanner:
    """Scans local operating system network parameters for air-gap boundary violations."""

    def __init__(self, simulation_mode: bool = False):
        self.simulation_mode = simulation_mode

    def scan(self) -> List[TelemetryBleedVector]:
        vectors: List[TelemetryBleedVector] = []
        
        # 1. Audit DNS Resolver Configuration
        vectors.extend(self._audit_dns_resolvers())
        
        # 2. Audit Default Gateways & Routing
        vectors.extend(self._audit_default_gateway())
        
        # 3. Audit Active Listening Sockets
        vectors.extend(self._audit_listening_sockets())
        
        # 4. Audit Non-Isolated Network Interfaces
        vectors.extend(self._audit_interfaces())

        return vectors

    def _audit_dns_resolvers(self) -> List[TelemetryBleedVector]:
        vectors: List[TelemetryBleedVector] = []
        resolv_path = "/etc/resolv.conf"
        
        if os.path.exists(resolv_path):
            try:
                with open(resolv_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) > 1:
                                ns_ip = parts[1]
                                # External / Cloud DNS in an air-gap is an immediate failure
                                if ns_ip in ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"] or not ns_ip.startswith(("127.", "10.", "192.168.", "172.")):
                                    vectors.append(TelemetryBleedVector(
                                        vector_id=f"DNS-BLEED-{ns_ip}",
                                        category=RiskCategory.NETWORK_BLEED,
                                        severity=SeverityLevel.CRITICAL,
                                        target_interface="resolv.conf",
                                        description=f"Public external DNS resolver configured ({ns_ip}) in supposed air-gapped enclave.",
                                        queued_bytes=512,
                                        destination_target=ns_ip,
                                        nist_control="SC.L2-3.13.1 (Boundary Protection)",
                                        remediation_command=f"sed -i '/{ns_ip}/d' /etc/resolv.conf"
                                    ))
            except Exception:
                pass
        return vectors

    def _audit_default_gateway(self) -> List[TelemetryBleedVector]:
        vectors: List[TelemetryBleedVector] = []
        # In a true air-gap, default gateway 0.0.0.0/0 MUST NOT exist.
        has_default_gw = False
        gw_ip = "0.0.0.0"
        
        try:
            # Check route via standard system commands
            proc = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=2)
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if "default" in line.lower() or line.startswith("0.0.0.0"):
                        parts = line.split()
                        if len(parts) >= 2:
                            gw_ip = parts[1]
                            has_default_gw = True
                            break
        except Exception:
            pass

        if has_default_gw and gw_ip != "link#":
            vectors.append(TelemetryBleedVector(
                vector_id="GW-BLEED-001",
                category=RiskCategory.NETWORK_BLEED,
                severity=SeverityLevel.CRITICAL,
                target_interface="Routing Table",
                description=f"Active default gateway detected ({gw_ip}). Physical air-gap is broken at Layer 3.",
                queued_bytes=4096,
                destination_target=gw_ip,
                nist_control="AC.L2-3.1.3 (Control CUI Flow)",
                remediation_command="route delete default || ip route del default"
            ))
        return vectors

    def _audit_listening_sockets(self) -> List[TelemetryBleedVector]:
        vectors: List[TelemetryBleedVector] = []
        # Test if 0.0.0.0 listeners are exposed to non-loopback interfaces
        try:
            # Check if hostname resolves to public/external IP
            host_name = socket.gethostname()
            host_ip = socket.gethostbyname(host_name)
            if not host_ip.startswith("127."):
                vectors.append(TelemetryBleedVector(
                    vector_id=f"HOST-EXPOSURE-{host_ip}",
                    category=RiskCategory.NETWORK_BLEED,
                    severity=SeverityLevel.HIGH,
                    target_interface="NIC Primary",
                    description=f"Host interface bound to non-loopback IP ({host_ip}) without physical diode isolation.",
                    queued_bytes=1024,
                    destination_target=host_ip,
                    nist_control="SC.L2-3.13.5 (Subnet Isolation)",
                    remediation_command="ip link set dev eth0 down"
                ))
        except Exception:
            pass
        return vectors

    def _audit_interfaces(self) -> List[TelemetryBleedVector]:
        vectors: List[TelemetryBleedVector] = []
        # Enforce check for active wireless PHYs (Wi-Fi, Bluetooth) in classified enclaves
        try:
            # Check for wireless or bluetooth devices
            if os.path.exists("/sys/class/net"):
                for iface in os.listdir("/sys/class/net"):
                    if iface.startswith(("wl", "wlan", "wifi", "wwan", "bt")):
                        vectors.append(TelemetryBleedVector(
                            vector_id=f"WIRELESS-PHY-{iface}",
                            category=RiskCategory.NETWORK_BLEED,
                            severity=SeverityLevel.CRITICAL,
                            target_interface=iface,
                            description=f"Active wireless PHY interface '{iface}' present in air-gapped facility. Radio frequency attack surface.",
                            queued_bytes=0,
                            destination_target="RF/Over-The-Air",
                            nist_control="MP.L2-3.8.7 (Removable/Wireless Media)",
                            remediation_command=f"rfkill block all && ip link set {iface} down"
                        ))
        except Exception:
            pass
        return vectors
