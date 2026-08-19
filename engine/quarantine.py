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

DEFAULT_QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", "/var/lib/network-security/quarantine")


def quarantine_file(path: str, sha256: str | None = None, reason: str = "") -> dict:
    if not path or not os.path.isfile(path):
        return {"quarantined": False, "error": "Fayl topilmadi", "quarantine_path": None}
    os.makedirs(DEFAULT_QUARANTINE_DIR, mode=0o700, exist_ok=True)
    token = uuid.uuid4().hex
    target_dir = os.path.join(DEFAULT_QUARANTINE_DIR, token)
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
