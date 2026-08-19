"""Windows/Linux endpoint quarantine for confirmed malware."""
import hashlib
import json
import os
import shutil
import time
import uuid


def _root() -> str:
    # MUHIM: AGENT_QUARANTINE_DIR orqali qayta belgilash mumkin (test
    # va CI muhitlari uchun, standart papka yozib bo'lmasa) - bu
    # muhit o'zgaruvchisi HAR CHAQIRUVDA dinamik o'qiladi.
    override = os.getenv("AGENT_QUARANTINE_DIR")
    if override:
        return override
    if os.name == "nt":
        return os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "NetworkSecurityAgent", "Quarantine")
    return os.path.join("/var/lib", "network-security-agent", "quarantine")


def quarantine_file(filepath: str, sha256: str, threat_name: str) -> dict:
    if not os.path.isfile(filepath):
        return {"quarantined": False, "source_removed": False, "quarantine_path": None, "error": "Fayl topilmadi"}
    root = _root()
    token = uuid.uuid4().hex
    target_dir = os.path.join(root, token)

    try:
        os.makedirs(target_dir, mode=0o700, exist_ok=False)
    except OSError as exc:
        # MUHIM (real production/CI'da aniqlangan xato): standart
        # /var/lib/... yo'li root bo'lmagan foydalanuvchi uchun yozib
        # bo'lmasligi mumkin - butun agentni qulatib qo'yish o'rniga
        # aniq xato qaytaramiz.
        return {"quarantined": False, "source_removed": False, "quarantine_path": None, "error": f"Karantin papkasini yaratib bo'lmadi: {exc}"}

    target = os.path.join(target_dir, os.path.basename(filepath))
    try:
        shutil.copy2(filepath, target)
        # Verify the quarantine copy before touching the original.
        h = hashlib.sha256()
        with open(target, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        if h.hexdigest().lower() != sha256.lower():
            raise RuntimeError("Karantin nusxasi SHA256 bilan mos kelmadi")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        metadata = {
            "original_path": os.path.abspath(filepath),
            "quarantined_at": time.time(),
            "sha256": sha256,
            "threat_name": threat_name,
            "filename": os.path.basename(filepath),
        }
        with open(os.path.join(target_dir, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, ensure_ascii=False, indent=2)
        os.remove(filepath)
        return {"quarantined": True, "source_removed": True, "quarantine_path": target, "error": None}
    except Exception as exc:
        shutil.rmtree(target_dir, ignore_errors=True)
        return {"quarantined": False, "source_removed": False, "quarantine_path": None, "error": str(exc)}
