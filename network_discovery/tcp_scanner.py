"""
TCP Port Scan va OS Fingerprinting - network_discovery paketi.

`nmap` orqali ishlaydi:
  - `-sT` (TCP connect scan) - raw socket talab qilmaydi, har qanday
    muhitda ishlaydi (raw socket huquqi cheklangan bo'lsa ham).
  - `-sV` - xizmat versiyasini aniqlash (banner grabbing).
  - `-O` - OS fingerprinting (TCP/IP stack xususiyatlariga qarab).

Real test: `192.0.2.1` (sandbox gateway)da real skanerlash o'tkazilib,
nmap to'g'ri "yopiq" portlarni qaytargani tasdiqlangan.
"""
import logging
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("tcp_scanner")

COMMON_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"


@dataclass
class OpenPort:
    port: int
    protocol: str  # "tcp" | "udp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class ScanResult:
    ip: str
    open_ports: List[OpenPort] = field(default_factory=list)
    os_guess: Optional[str] = None


def tcp_scan(ip: str, ports: str = COMMON_PORTS, detect_service: bool = True, timeout: int = 120) -> ScanResult:
    """
    Berilgan IP'da TCP portlarni skanerlaydi. `-oX -` orqali XML
    chiqishni ishlatamiz - matn parsing'dan ancha ishonchli.
    """
    cmd = ["nmap", "-sT", "-n", "-p", ports, "-oX", "-"]
    if detect_service:
        cmd.append("-sV")
    cmd.append(ip)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        logger.error("nmap topilmadi")
        return ScanResult(ip=ip)
    except subprocess.TimeoutExpired:
        logger.error(f"tcp_scan timeout ({timeout}s): {ip}")
        return ScanResult(ip=ip)

    return _parse_nmap_xml(result.stdout, ip)


def _parse_nmap_xml(xml_output: str, ip: str) -> ScanResult:
    scan_result = ScanResult(ip=ip)
    if not xml_output.strip():
        return scan_result

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        logger.error("nmap XML chiqishini parslab bo'lmadi")
        return scan_result

    for host in root.findall("host"):
        for ports_el in host.findall("ports"):
            for port_el in ports_el.findall("port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                scan_result.open_ports.append(OpenPort(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol"),
                    service=service_el.get("name") if service_el is not None else None,
                    product=service_el.get("product") if service_el is not None else None,
                    version=service_el.get("version") if service_el is not None else None,
                ))
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                scan_result.os_guess = osmatch.get("name")

    return scan_result


def os_fingerprint(ip: str, timeout: int = 60) -> Optional[str]:
    """
    OS fingerprinting - nmap'ning `-O` bayrog'i orqali. MUHIM: bu odatda
    root huquqi va raw socket kirish talab qiladi. Agar mavjud bo'lmasa,
    None qaytaradi (xatoni yashirmaydi, log'ga yozadi).
    """
    try:
        result = subprocess.run(
            ["nmap", "-O", "-oX", "-", ip],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    scan_result = _parse_nmap_xml(result.stdout, ip)
    if scan_result.os_guess is None and "root" not in result.stdout.lower():
        logger.info(f"OS fingerprint aniqlanmadi ({ip}) - ehtimol root huquqi kerak yoki juda kam ma'lumot")
    return scan_result.os_guess
