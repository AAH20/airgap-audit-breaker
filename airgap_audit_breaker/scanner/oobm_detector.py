"""
OOBM & Baseband Management Controller (BMC) Scanner:
Audits physical server hardware for hidden out-of-band management channels (IPMI, iDRAC, iLO, Intel AMT)
that bypass host operating system firewalls and physical air-gap policies.
Pure Python standard library.
"""

from __future__ import annotations
import os
import glob
from typing import List
from ..models import BasebandOOBMVector, SeverityLevel


class OOBMDetector:
    """Detects baseband management chips, IPMI devices, and Intel ME hardware sidebands."""

    def scan(self) -> List[BasebandOOBMVector]:
        vectors: List[BasebandOOBMVector] = []
        
        # 1. Check for IPMI character devices
        vectors.extend(self._check_ipmi_nodes())
        
        # 2. Check for Intel Management Engine (ME / AMT) interface nodes
        vectors.extend(self._check_intel_mei())
        
        # 3. Check for ASPEED / BMC PCI devices
        vectors.extend(self._check_pci_bmc())

        return vectors

    def _check_ipmi_nodes(self) -> List[BasebandOOBMVector]:
        vectors: List[BasebandOOBMVector] = []
        ipmi_devs = glob.glob("/dev/ipmi*") + glob.glob("/dev/openipmi*")
        
        if ipmi_devs or os.path.exists("/sys/class/ipmi"):
            vectors.append(BasebandOOBMVector(
                controller_type="IPMI 2.0 Baseboard Controller",
                mac_address="OOBM-ACTIVE-PHY",
                active_phy_state=True,
                vlan_tagged=False,
                shared_nic_detected=True,
                severity=SeverityLevel.CRITICAL,
                cve_exposure="CVE-2013-4786 (Cipher Zero RAKP Authentication Bypass)",
                mitigation="Disable IPMI over LAN in BIOS/UEFI; disconnect dedicated BMC ethernet cable."
            ))
        return vectors

    def _check_intel_mei(self) -> List[BasebandOOBMVector]:
        vectors: List[BasebandOOBMVector] = []
        mei_nodes = glob.glob("/dev/mei*")
        
        if mei_nodes:
            vectors.append(BasebandOOBMVector(
                controller_type="Intel Active Management Technology (AMT / ME)",
                mac_address="INTEL-ME-PHY",
                active_phy_state=True,
                vlan_tagged=False,
                shared_nic_detected=True,
                severity=SeverityLevel.HIGH,
                cve_exposure="CVE-2017-5689 (Intel AMT Remote Authentication Bypass)",
                mitigation="Disable Intel AMT / vPro provisioning in BIOS; deploy me_cleaner firmware module."
            ))
        return vectors

    def _check_pci_bmc(self) -> List[BasebandOOBMVector]:
        vectors: List[BasebandOOBMVector] = []
        # Check /sys/bus/pci/devices for ASPEED Technology vendor ID (1a03)
        aspeed_vendor_id = "0x1a03"
        pci_vendors = glob.glob("/sys/bus/pci/devices/*/vendor")
        
        for vendor_file in pci_vendors:
            try:
                with open(vendor_file, "r") as f:
                    content = f.read().strip().lower()
                    if content == aspeed_vendor_id:
                        vectors.append(BasebandOOBMVector(
                            controller_type="ASPEED AST2400/2500/2600 BMC Chip",
                            mac_address="NC-SI-SHARED-PHY",
                            active_phy_state=True,
                            vlan_tagged=True,
                            shared_nic_detected=True,
                            severity=SeverityLevel.CRITICAL,
                            cve_exposure="CVE-2019-6260 (Pantsdown AST2400/AST2500 AHB Bridge Arbitrary Access)",
                            mitigation="Physically bridge BMC disable jumper on motherboard or flash hardened OpenBMC."
                        ))
                        break
            except Exception:
                continue
        return vectors
