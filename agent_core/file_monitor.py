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
        if filepath in self._seen:
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

    def stop(self):
        self.observer.stop()
        self.observer.join()
