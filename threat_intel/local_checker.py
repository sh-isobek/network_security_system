"""
Mahalliy hash blacklist tekshiruvchi - eng tez va cheklovsiz manba.

VirusTotal/MalwareBazaar so'rovlaridan oldin har doim shu tekshiriladi,
chunki bu bazadagi so'rov API limit'iga tushmaydi va tarmoqqa chiqmaydi.
"""
import os
import sys
from typing import Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.models import HashBlacklist


def check_local(session, sha256: str) -> Optional[dict]:
    """Agar hash mahalliy blacklist'da topilsa, natija qaytaradi, aks holda None."""
    if not sha256:
        return None
    hit = session.query(HashBlacklist).filter(HashBlacklist.sha256 == sha256.lower()).first()
    if hit:
        return {
            "malicious": True,
            "threat_name": hit.threat_name,
            "source": "local_blacklist",
        }
    return None
