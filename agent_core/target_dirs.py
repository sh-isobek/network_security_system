"""
Agent nimani tekshirishini belgilaydi: FAQAT har bir foydalanuvchi profilidagi
"Yuklanmalar" (Downloads) va "Telegram" papkalari.

Foydalanuvchi talabi: "barcha fayllarni tekshirmasin - barcha profillardagi
zagruzka va telegram papkalarini tekshirsin, qolgan fayllarni tekshirmasin".
Avval agent BARCHA disklarni (C:, D:, USB ...) va Desktop/Temp/Outlook'ni
kuzatardi - bu minglab keraksiz tekshiruv va navbatning to'lib ketishiga olib
kelgan edi.

Nima tekshiriladi (har bir profil uchun):
  1. `Downloads` - REKURSIV. Telegram Desktop standart holatda fayllarni
     `Downloads\\Telegram Desktop`ga saqlaydi - u allaqachon shu yerga kiradi.
  2. `Telegram*` nomli papka (masalan `Telegram Desktop`), agar u Downloads
     ICHIDA bo'lmasdan, Documents/Desktop/Pictures/Videos/Music ichida
     bo'lsa - Telegram'da "Download path" shu joylarga o'zgartirilishi mumkin.

Bu modul faqat `os` ishlatadi (Windows'ga xos import yo'q) - shuning uchun
Linux'da ham haqiqiy papka daraxti bilan sinab ko'rish mumkin.
"""
import logging
import os
from typing import List

logger = logging.getLogger("agent")

# Tizim/xizmat profillari - ularda foydalanuvchi yuklamalari bo'lmaydi
SYSTEM_PROFILES = {"default", "default user", "public", "all users", "defaultuser0", "wdagutilityaccount"}

# Telegram "Download path"i ko'pincha shu papkalarning ichiga o'zgartiriladi
TELEGRAM_PARENT_FOLDERS = ("Documents", "Desktop", "Pictures", "Videos", "Music")


def scan_dirs_for_profile(profile_path: str) -> List[str]:
    """Bitta profil uchun tekshiriladigan papkalar: Downloads + Telegram* papkalar."""
    result: List[str] = []

    downloads = os.path.join(profile_path, "Downloads")
    if os.path.isdir(downloads):
        result.append(downloads)

    for parent in TELEGRAM_PARENT_FOLDERS:
        parent_path = os.path.join(profile_path, parent)
        try:
            names = os.listdir(parent_path)
        except OSError:
            continue    # papka yo'q yoki kirish huquqi yo'q - jim o'tkazib yuboriladi
        for name in names:
            if name.lower().startswith("telegram"):
                candidate = os.path.join(parent_path, name)
                if os.path.isdir(candidate):
                    result.append(candidate)
    return result


def scan_dirs_for_users_root(users_root: str) -> List[str]:
    """`users_root` (masalan C:\\Users) ichidagi BARCHA profillar uchun tekshiriladigan papkalar."""
    result: List[str] = []
    try:
        usernames = sorted(os.listdir(users_root))
    except OSError as exc:
        logger.warning(f"{users_root} ro'yxatini o'qib bo'lmadi: {exc}")
        return result

    for username in usernames:
        if username.lower() in SYSTEM_PROFILES:
            continue
        profile = os.path.join(users_root, username)
        try:
            if not os.path.isdir(profile):
                continue
            dirs = scan_dirs_for_profile(profile)
        except OSError as exc:
            logger.warning(f"'{username}' profilini tekshirishda xatolik: {exc}")
            continue
        if dirs:
            logger.debug(f"Profil '{username}': {dirs}")
        else:
            logger.debug(f"Profil '{username}': Downloads/Telegram papkasi topilmadi")
        result.extend(dirs)

    return list(dict.fromkeys(result))
