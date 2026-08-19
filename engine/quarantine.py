"""Safe quarantine helpers for confirmed malware.

Files are moved/copied into a private quarantine directory with a random
subdirectory and never executed from there.  Metadata is kept in a JSON sidecar.
"""
import hashlib
import json
import os
import shutil
import time
import uuid


def quarantine_file(path: str, sha256: str | None = None, reason: str = "") -> dict:
    if not path or not os.path.isfile(path):
        return {"quarantined": False, "error": "Fayl topilmadi", "quarantine_path": None}

    # MUHIM: QUARANTINE_DIR HAR CHAQIRUVDA dinamik o'qiladi (modul
    # darajasidagi "muzlab qolgan" konstanta emas) - bu loyihada bir
    # necha marta uchragan xato turkumini oldini oladi.
    quarantine_dir = os.getenv("QUARANTINE_DIR", "/var/lib/network-security/quarantine")

    try:
        os.makedirs(quarantine_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        # MUHIM (real production/CI'da aniqlangan xato): standart
        # /var/lib/... yo'li root bo'lmagan foydalanuvchi (masalan
        # GitHub Actions runner) uchun yozib bo'lmasligi mumkin. Bu
        # holatda butun pipeline'ni qulatib qo'yish o'rniga, xatoni
        # aniq qaytaramiz - chaqiruvchi (deep_scan_engine) buni "fayl
        # tekshirildi, lekin karantinga olib bo'lmadi" deb log qiladi.
        return {"quarantined": False, "error": f"Karantin papkasini yaratib bo'lmadi: {exc}", "quarantine_path": None}

    token = uuid.uuid4().hex
    target_dir = os.path.join(quarantine_dir, token)
    os.makedirs(target_dir, mode=0o700, exist_ok=False)
    original_name = os.path.basename(path)
    target = os.path.join(target_dir, original_name)
    try:
        shutil.copy2(path, target)
        if sha256 is None:
            h = hashlib.sha256()
            with open(target, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        os.chmod(target, 0o600)
        metadata = {
            "original_path": os.path.abspath(path),
            "quarantined_at": time.time(),
            "sha256": sha256,
            "reason": reason,
            "filename": original_name,
        }
        with open(os.path.join(target_dir, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, ensure_ascii=False, indent=2)
        removed = False
        try:
            os.remove(path)
            removed = True
        except OSError:
            # Copy-first quarantine is still useful when source is read-only.
            pass
        return {"quarantined": True, "quarantine_path": target, "source_removed": removed, "error": None}
    except Exception as exc:
        shutil.rmtree(target_dir, ignore_errors=True)
        return {"quarantined": False, "quarantine_path": None, "error": str(exc)}
