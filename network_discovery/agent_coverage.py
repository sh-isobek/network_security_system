"""
Agent Coverage Report - network_discovery paketi (yangi TZ 6-bo'lim:
AD orqali avtomatlashtirilgan tarqatish).

Active Directory'dagi BARCHA domenga a'zo kompyuterlar ro'yxatini
(`ad_discovery.py`) bazadagi **agent o'rnatilgan va faol** qurilmalar
(`Device.agent_last_heartbeat`) bilan solishtiradi - natijada:

  - `covered`   - AD'da bor VA agent so'nggi N soatda heartbeat yuborgan
  - `stale`     - AD'da bor, agent o'rnatilgan edi, lekin N soatdan
                  ko'proq vaqt heartbeat yubormagan (o'chirilgan/
                  ishdan chiqqan bo'lishi mumkin)
  - `missing`   - AD'da bor, lekin agent HECH QACHON heartbeat
                  yubormagan (hali o'rnatilmagan)

Bu hisobot GPO orqali tarqatishning (`deploy/windows_agent_gpo/`)
"qamrovi qancha foizni tashkil qiladi" savoliga aniq javob beradi.
"""
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from typing import List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import get_session
from db.models import Device, utcnow
from network_discovery.ad_discovery import discover_ad_computers

logger = logging.getLogger("agent_coverage")

STALE_THRESHOLD_HOURS = int(os.getenv("AGENT_STALE_THRESHOLD_HOURS", "24"))


@dataclass
class CoverageReport:
    total_ad_computers: int = 0
    covered: List[str] = field(default_factory=list)
    stale: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)

    @property
    def coverage_percent(self) -> float:
        if self.total_ad_computers == 0:
            return 0.0
        return round(len(self.covered) / self.total_ad_computers * 100, 1)


def generate_coverage_report() -> CoverageReport:
    ad_computers = discover_ad_computers()
    report = CoverageReport(total_ad_computers=len(ad_computers))

    if not ad_computers:
        logger.warning("AD'dan hech qanday kompyuter topilmadi - AD_SERVER sozlanganini tekshiring")
        return report

    session = get_session()
    try:
        stale_cutoff = utcnow() - timedelta(hours=STALE_THRESHOLD_HOURS)

        # Hostname bo'yicha qidirish (case-insensitive - AD va agent
        # hostname'lari turlicha registrda bo'lishi mumkin)
        devices_by_hostname = {
            (d.hostname or "").lower(): d
            for d in session.query(Device).filter(Device.agent_last_heartbeat.isnot(None)).all()
        }

        for computer in ad_computers:
            # AD'dagi 'name' odatda "PCNAME", dNSHostName esa "PCNAME.domain.local"
            # - ikkalasini ham tekshiramiz
            candidates = [computer.name.lower()]
            if computer.dns_hostname:
                candidates.append(computer.dns_hostname.lower())
                candidates.append(computer.dns_hostname.split(".")[0].lower())

            device = None
            for candidate in candidates:
                if candidate in devices_by_hostname:
                    device = devices_by_hostname[candidate]
                    break

            if device is None:
                report.missing.append(computer.name)
            elif device.agent_last_heartbeat < stale_cutoff:
                report.stale.append(computer.name)
            else:
                report.covered.append(computer.name)

        logger.info(
            f"Agent Coverage: {len(report.covered)}/{report.total_ad_computers} "
            f"({report.coverage_percent}%) qamrab olingan, {len(report.stale)} eskirgan, "
            f"{len(report.missing)} yo'q"
        )
        return report
    finally:
        session.close()


if __name__ == "__main__":
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(message)s")
    report = generate_coverage_report()
    print(f"\nJami AD kompyuterlar: {report.total_ad_computers}")
    print(f"Qamrov: {report.coverage_percent}% ({len(report.covered)} ta)")
    if report.stale:
        print(f"\nEskirgan (agent {STALE_THRESHOLD_HOURS}+ soat javob bermagan):")
        for name in report.stale:
            print(f"  - {name}")
    if report.missing:
        print(f"\nAgent o'rnatilmagan:")
        for name in report.missing:
            print(f"  - {name}")
