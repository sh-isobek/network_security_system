"""
Process Killer - berilgan faylni ochgan/yozgan jarayonni topib to'xtatadi.

`psutil` cross-platform kutubxona (Windows/Linux/macOS) - shuning uchun
bir xil kod ham Windows Agent'da (production), ham test muhitida ishlaydi.

MUHIM CHEKLOV: Ba'zi hollarda (masalan fayl allaqachon yozib bo'linib,
jarayon uni yopib qo'ygan bo'lsa - masalan brauzer yuklab olib, faylni
yopib qo'yishi) hech qanday jarayon topilmasligi mumkin. Bu holatda
kill_process_holding_file() faqat faylni o'chiradi, jarayonni to'xtatmaydi
(chunki topilmagan) - bu normal holat, xatolik emas.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import psutil

logger = logging.getLogger("process_killer")


@dataclass
class KillResult:
    process_killed: bool
    process_name: Optional[str]
    process_pid: Optional[int]
    message: str


def find_processes_holding_file(filepath: str) -> List[psutil.Process]:
    """Berilgan faylni ochiq ushlab turgan barcha jarayonlarni qaytaradi."""
    filepath = os.path.abspath(filepath)
    matches = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if os.path.abspath(f.path) == filepath:
                    matches.append(proc)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return matches


def kill_process_holding_file(filepath: str, timeout: float = 5.0) -> KillResult:
    """
    Faylni ochiq ushlab turgan jarayon(lar)ni topib, muloyimlik bilan
    to'xtatishga harakat qiladi (terminate), agar javob bermasa majburiy
    o'chiradi (kill).
    """
    procs = find_processes_holding_file(filepath)

    if not procs:
        return KillResult(False, None, None, "Faylni ochgan jarayon topilmadi")

    killed_names = []
    for proc in procs:
        try:
            name = proc.name()
            pid = proc.pid
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except psutil.TimeoutExpired:
                proc.kill()  # muloyim so'rov ishlamasa - majburiy to'xtatish
            killed_names.append((name, pid))
            logger.warning(f"Jarayon to'xtatildi: {name} (PID={pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            logger.error(f"Jarayonni to'xtatib bo'lmadi: {exc}")

    if killed_names:
        name, pid = killed_names[0]
        return KillResult(True, name, pid, f"{len(killed_names)} ta jarayon to'xtatildi")

    return KillResult(False, None, None, "Jarayon(lar) topildi, lekin to'xtatib bo'lmadi (ruxsat yo'q)")
