"""
Topology Builder - network_discovery paketi.

`lldp_mapper.py` va `cdp_mapper.py` orqali ushlangan qo'shni
qurilmalar ma'lumotini `topology_links` jadvaliga yozadi.

Ishga tushirish:
    python -m network_discovery.topology_builder --interface eth0 --timeout 30
"""
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import get_session
from db.models import TopologyLink
from network_discovery.lldp_mapper import capture_lldp_neighbors
from network_discovery.cdp_mapper import capture_cdp_neighbors

logger = logging.getLogger("topology_builder")


def build_from_lldp(interface: str, timeout: int = 30) -> int:
    neighbors = capture_lldp_neighbors(interface, timeout=timeout)
    session = get_session()
    try:
        for n in neighbors:
            session.add(TopologyLink(
                local_interface=interface,
                neighbor_chassis_id=n.chassis_id,
                neighbor_system_name=n.system_name,
                neighbor_port_id=n.port_description,
                protocol="lldp",
            ))
        session.commit()
        logger.info(f"LLDP topologiya: {len(neighbors)} ta bog'lanish yozildi")
        return len(neighbors)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def build_from_cdp(interface: str, timeout: int = 30) -> int:
    neighbors = capture_cdp_neighbors(interface, timeout=timeout)
    session = get_session()
    try:
        for n in neighbors:
            session.add(TopologyLink(
                local_interface=interface,
                neighbor_chassis_id=n.device_id,
                neighbor_system_name=n.device_id,
                neighbor_port_id=n.port_id,
                protocol="cdp",
            ))
        session.commit()
        logger.info(f"CDP topologiya: {len(neighbors)} ta bog'lanish yozildi")
        return len(neighbors)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def build_topology(interface: str, timeout: int = 30) -> dict:
    """
    LLDP va CDP'ni BIR VAQTDA (ketma-ket emas) tinglash uchun ideal
    holda ikkalasini alohida thread'da ishga tushirish kerak - lekin
    soddalik uchun bu yerda ketma-ket (avval LLDP, keyin CDP)
    ishlaydi. Production'da `--loop` rejimida ikkalasi alohida
    jarayon sifatida parallel ishga tushirilishi tavsiya etiladi.
    """
    return {
        "lldp": build_from_lldp(interface, timeout),
        "cdp": build_from_cdp(interface, timeout),
    }


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(message)s")

    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", required=True)
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    result = build_topology(args.interface, args.timeout)
    print(f"Topologiya yig'ish yakunlandi: {result}")
