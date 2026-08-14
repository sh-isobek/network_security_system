# NetworkSecurityAgent.spec
#
# PyInstaller spec fayli - windows_agent/service_wrapper.py'ni yagona,
# mustaqil .exe fayliga aylantiradi (Python o'rnatish shart bo'lmasin
# uchun har bir Windows kompyuterda).
#
# Nega service_wrapper.py (agent.py emas): .exe Windows Service
# sifatida ishlashi kerak (kompyuter yoqilganda, foydalanuvchi login
# qilmasa ham) - shuning uchun kirish nuqtasi pywin32-asosidagi
# service wrapper, oddiy foreground skript emas.
#
# Qurish (FAQAT Windows'da, yoki GitHub Actions windows-latest
# runner'ida - .github/workflows/build-windows-agent.yml orqali):
#
#     pip install -r requirements-agent.txt pyinstaller
#     pyinstaller windows_agent/build/NetworkSecurityAgent.spec
#
# Natija: dist/NetworkSecurityAgent.exe

import os

block_cipher = None
project_root = os.path.abspath(os.path.join(os.path.dirname(SPEC), "..", ".."))

a = Analysis(
    [os.path.join(project_root, "windows_agent", "service_wrapper.py")],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, "windows_agent", "VERSION"), "."),
    ],
    hiddenimports=[
        # pywin32 xizmatlari uchun ba'zan avtomatik aniqlanmaydigan
        # modullar - PyInstaller+pywin32 birgalikda ishlatilganda
        # keng tarqalgan muammo, aniq ko'rsatish kerak
        "win32timezone",
        "win32com",
        "win32com.client",
        "servicemanager",
        "watchdog.observers.polling",  # ba'zi Windows fayl tizimlarida (masalan tarmoq disklari) kerak bo'ladi
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NetworkSecurityAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX ba'zan antivirus tomonidan soxta-pozitiv (false-positive)
                 # deb belgilanadi - xavfsizlik dasturi uchun bu jiddiy muammo
    console=True,  # xizmat sifatida ishga tushganda konsolga ehtiyoj yo'q,
                     # lekin qo'lda diagnostika (masalan `--help`) uchun foydali.
                     # SCM orqali xizmat sifatida ishga tushganda konsol oynasi
                     # ko'rinmaydi (Windows Service'lar konsolsiz ishlaydi).
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # tashkilotingiz logotipini qo'shish uchun .ico fayl yo'lini bering
)
