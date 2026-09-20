"""
File Monitor - kompyuterdagi xavfli papkalarni (Downloads, Desktop, Temp,
Outlook Attachments) kuzatib, yangi fayl paydo bo'lganda xabar beradi.

`watchdog` kutubxonasi cross-platform: Windows'da ReadDirectoryChangesW,
Linux'da inotify orqali ishlaydi - shuning uchun shu kodni ham Windows'da
(production), ham Linux'da (test/dev) ishlatish mumkin.

MUHIM (fayl "barqarorlashishi"): Katta fayl yuklanayotganda OS bir nechta
"created"/"modified" hodisasini yuboradi, fayl hali to'liq yozilmagan
bo'lishi mumkin. Shuning uchun _wait_until_stable() fayl hajmi bir necha
tekshiruv orasida o'zgarmay qolguncha kutadi - aks holda hash noto'g'ri
hisoblanishi mumkin.
"""
import logging
import os
import sys
import time
from typing import Callable, List

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("file_monitor")

STABLE_CHECK_INTERVAL = 0.5   # soniya
STABLE_CHECK_ROUNDS = 3        # necha marta ketma-ket hajm o'zgarmasligi kerak
STABLE_TIMEOUT = 30             # maksimal kutish vaqti (soniya) - juda katta fayllar uchun


def _wait_until_stable(filepath: str) -> bool:
    """Fayl hajmi barqarorlashguncha kutadi. Fayl o'chirilsa/topilmasa False qaytaradi."""
    start = time.time()
    stable_rounds = 0
    last_size = -1

    while time.time() - start < STABLE_TIMEOUT:
        try:
            size = os.path.getsize(filepath)
        except OSError:
            return False  # fayl allaqachon o'chirilgan yoki hali yaratilmagan

        if size == last_size and size > 0:
            stable_rounds += 1
            if stable_rounds >= STABLE_CHECK_ROUNDS:
                return True
        else:
            stable_rounds = 0

        last_size = size
        time.sleep(STABLE_CHECK_INTERVAL)

    return False  # timeout - juda uzoq davom etdi, xavfsizlik uchun False


# Tizim shovqini (o'zi yozadigan/OS boshqaradigan joylar). Bu yerdagi fayllar tekshirilmaydi:
# butun disk kuzatilganda agentning O'Z logi ham cheksiz tsikl hosil qilmasligi uchun ham kerak.
_DEFAULT_EXCLUDES = [
    "\\$recycle.bin\\", "\\system volume information\\", "\\windows\\winsxs\\",
    "\\windows\\servicing\\", "\\windows\\installer\\", "\\windows\\logs\\",
    "\\windows\\prefetch\\", "\\windows\\softwaredistribution\\", "\\windows\\system32\\config\\",
    "\\windows\\system32\\winevt\\", "\\programdata\\networksecurityagent\\",
    "\\program files\\networksecurityagent\\", "\\programdata\\microsoft\\windows defender\\",
    "\\appdata\\local\\google\\chrome\\user data\\", "\\appdata\\local\\microsoft\\edge\\user data\\",
    "\\appdata\\local\\microsoft\\windows\\", "\\sysvol\\",
    "/proc/", "/sys/", "/dev/", "/var/lib/docker/", "/var/cache/",
]
_EXTRA = [e.strip().lower().replace("/", "\\") for e in os.getenv("AGENT_EXCLUDE_PATHS", "").split(";") if e.strip()]
_EXCLUDES = [e.lower() for e in _DEFAULT_EXCLUDES] + _EXTRA
_PAGEFILES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")


def is_excluded(path: str) -> bool:
    p = path.lower().replace("/", "\\") + ("\\" if os.path.isdir(path) else "")
    q = path.lower()
    if os.path.basename(p.rstrip("\\")) in _PAGEFILES:
        return True
    return any(e in p or e in q for e in _EXCLUDES)


def list_local_drives() -> List[str]:
    """Windows: mahalliy (qattiq disk) va olinadigan (USB/flesh) disklarning ildizlari, masalan ['C:\\', 'E:\\']."""
    if sys.platform != "win32":
        return []
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        drives = []
        for i in range(26):
            if mask & (1 << i):
                root = f"{chr(65 + i)}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(root) in (2, 3):  # 2=removable, 3=fixed
                    drives.append(root)
        return drives
    except Exception as exc:
        logger.warning(f"Disklarni aniqlab bo'lmadi: {exc}")
        return []


class _NewFileHandler(FileSystemEventHandler):
    def __init__(self, on_new_file: Callable[[str], None]):
        self._on_new_file = on_new_file
        self._seen = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        # "modified" hodisasi ko'p marta kelishi mumkin - faqat yangi fayllar
        # uchun (hali "seen" bo'lmagan) qayta ishlaymiz, xotira sarfini kamaytirish uchun
        if event.src_path not in self._seen:
            self._handle(event.src_path)

    def on_deleted(self, event):
        # Fayl o'chirilsa (masalan biz uni zararli deb o'chirgan bo'lsak),
        # "seen" ro'yxatidan olib tashlaymiz - shu nom bilan yangi fayl
        # yaratilsa, u qayta yangi fayl sifatida aniqlanishi kerak.
        if not event.is_directory:
            self._seen.discard(event.src_path)

    def _handle(self, filepath: str):
        # MUHIM: filepath'ni DARHOL "seen" ro'yxatiga qo'shamiz va u yerda
        # QOLDIRAMIZ (barqarorlashishni kutish paytida ham). Bu on_created
        # va on_modified hodisalari deyarli bir vaqtda kelganda ikkalasi
        # ham alohida-alohida qayta ishlanib, faylni ikki marta "yangi"
        # deb aniqlashning oldini oladi (avval shu yerda xato bor edi -
        # "finally" bloki seen'dan olib tashlagani uchun ikkinchi hodisa
        # qayta ishlangan edi).
        if filepath in self._seen or is_excluded(filepath):
            return
        self._seen.add(filepath)

        logger.info(f"Yangi fayl aniqlandi: {filepath}")
        if _wait_until_stable(filepath):
            self._on_new_file(filepath)
        else:
            logger.warning(f"Fayl barqarorlashmadi yoki o'chirildi: {filepath}")
            self._seen.discard(filepath)  # barqarorlashmagan bo'lsa qayta urinish imkoni qolsin


class FileMonitor:
    """Bir nechta papkani parallel kuzatuvchi asosiy klass."""

    def __init__(self, watch_dirs: List[str], on_new_file: Callable[[str], None]):
        self.observer = Observer()
        self.handler = _NewFileHandler(on_new_file)
        self.watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]

        skipped = set(watch_dirs) - set(self.watch_dirs)
        if skipped:
            logger.warning(f"Quyidagi papkalar topilmadi, o'tkazib yuborildi: {skipped}")

    def start(self):
        for d in self.watch_dirs:
            self.observer.schedule(self.handler, d, recursive=True)
            logger.info(f"Kuzatilmoqda: {d}")
        self.observer.start()

    def add_dir(self, d: str) -> bool:
        """Ish vaqtida yangi papka/disk (masalan yangi ulangan USB) qo'shish."""
        if d in self.watch_dirs or not os.path.isdir(d):
            return False
        self.observer.schedule(self.handler, d, recursive=True)
        self.watch_dirs.append(d)
        logger.info(f"Kuzatilmoqda (yangi): {d}")
        return True

    def stop(self):
        self.observer.stop()
        self.observer.join()
