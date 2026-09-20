"""
Windows bajariladigan fayl (PE: .exe/.dll/.sys/.scr) statik tahlili.

Faqat standart kutubxona (struct, math) - Endpoint Agent .exe'siga va serverga
bir xil qo'shiladi (tashqi `pefile` bog'liqligi yo'q).

O'qiladi: COFF/Optional header, bo'limlar (nomi, entropiyasi, xom/virtual hajmi),
import jadvali (API nomlari), Authenticode imzosi bor-yo'qligi, .NET (CLR)
belgisi, entry point joylashuvi, vaqt tamg'asi.

Ball tizimi tushuntiriladigan topilmalar bilan. ATAYLAB FAQAT "suspicious"
beradi (hech qachon yakka o'zi "malicious" emas): paketlangan installer'lar
(UPX/NSIS), debugger/antivirus kabi qonuniy dasturlar ham shu API'lardan
foydalanadi - soxta-pozitivni oldini olish uchun "malicious" xulosasi imzo
skanerlari (YARA/ClamAV/VirusTotal) zimmasida.

HALOL CHEKLOV: Authenticode imzosining MAVJUDLIGI tekshiriladi, YAROQLILIGI emas
(zanjir/sertifikat tekshiruvi bu yerda yo'q); obfuskatsiya qilingan/yuklanish
vaqtida API topadigan dasturlar import jadvalida ko'rinmasligi mumkin.
"""
import math
import struct
import time
from collections import Counter
from typing import Optional

_PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".upx0", ".upx1", ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2",
    ".aspack", ".adata", ".petite", ".enigma1", ".enigma2", "mpress1", "mpress2", ".nsp0", ".nsp1",
    ".packed", ".perplex", ".yp", ".boom", ".rmnet",
}

# (nom, {API'lar to'plami - HAMMASI bo'lishi kerak}, ball, tavsif)
_API_COMBOS = [
    ("injection", {"virtualallocex", "writeprocessmemory", "createremotethread"}, 40, "boshqa jarayonga kod kiritish (process injection)"),
    ("hollowing", {"ntunmapviewofsection", "writeprocessmemory", "setthreadcontext"}, 40, "process hollowing"),
    ("keylogger", {"setwindowshookexa", "getasynckeystate"}, 25, "klaviatura kuzatuvi (keylogger)"),
    ("keylogger2", {"setwindowshookexw", "getasynckeystate"}, 25, "klaviatura kuzatuvi (keylogger)"),
    ("downloader", {"urldownloadtofilea"}, 20, "internetdan fayl yuklab olish (URLDownloadToFile)"),
    ("downloader2", {"urldownloadtofilew"}, 20, "internetdan fayl yuklab olish (URLDownloadToFile)"),
    ("antidebug", {"isdebuggerpresent", "checkremotedebuggerpresent"}, 10, "debugger'ni aniqlash (anti-debug)"),
    ("ransom", {"cryptencrypt", "findfirstfilew", "deletefilew"}, 20, "fayllarni shifrlash + o'chirish belgilari"),
    ("clipboard", {"getclipboarddata", "setclipboarddata", "openclipboard"}, 10, "clipboard almashtirish (kripto-o'g'ri belgisi)"),
    ("shellcode", {"virtualalloc", "virtualprotect", "createthread"}, 15, "xotirada kod ajratish va bajarish"),
]
_DYNAMIC_LOAD = {"loadlibrarya", "loadlibraryw", "getprocaddress"}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class _PE:
    def __init__(self, data: bytes):
        self.d = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("MZ emas")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if self.e_lfanew + 24 > len(data) or data[self.e_lfanew:self.e_lfanew + 4] != b"PE\0\0":
            raise ValueError("PE imzosi yo'q")
        c = self.e_lfanew + 4
        (self.machine, self.nsections, self.timestamp, _sym, _nsym,
         self.opt_size, self.characteristics) = struct.unpack_from("<HHIIIHH", data, c)
        self.opt = c + 20
        magic = struct.unpack_from("<H", data, self.opt)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError("Optional header noto'g'ri")
        self.is64 = magic == 0x20B
        self.entry_rva = struct.unpack_from("<I", data, self.opt + 16)[0]
        dd_off = self.opt + (112 if self.is64 else 96)
        n_dirs = struct.unpack_from("<I", data, dd_off - 4)[0]
        self.dirs = []
        for i in range(min(n_dirs, 16)):
            self.dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))
        sec_off = self.opt + self.opt_size
        self.sections = []
        for i in range(min(self.nsections, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].split(b"\0")[0].decode("latin-1", errors="replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append({"name": name, "vsize": vsize, "vaddr": vaddr, "rsize": rsize, "rptr": rptr, "chars": chars})

    def rva_to_off(self, rva: int) -> Optional[int]:
        for s in self.sections:
            size = max(s["vsize"], s["rsize"])
            if s["vaddr"] <= rva < s["vaddr"] + size:
                return s["rptr"] + (rva - s["vaddr"])
        return None

    def imports(self, limit: int = 4000) -> list:
        """Import qilingan API nomlari (kichik harfda)."""
        if len(self.dirs) < 2 or self.dirs[1][0] == 0:
            return []
        off = self.rva_to_off(self.dirs[1][0])
        d = self.d
        names = []
        ptr_size = 8 if self.is64 else 4
        while off is not None and off + 20 <= len(d) and len(names) < limit:
            oft, _ts, _fw, name_rva, ft = struct.unpack_from("<IIIII", d, off)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            thunk_off = self.rva_to_off(oft or ft)
            n_this = 0
            while thunk_off is not None and thunk_off + ptr_size <= len(d) and n_this < 3000:
                val = int.from_bytes(d[thunk_off:thunk_off + ptr_size], "little")
                if val == 0:
                    break
                ordinal_flag = 1 << (63 if self.is64 else 31)
                if not (val & ordinal_flag):
                    hn = self.rva_to_off(val & 0x7FFFFFFF)
                    if hn is not None and hn + 2 < len(d):
                        end = d.find(b"\0", hn + 2, hn + 2 + 128)
                        if end > hn + 2:
                            names.append(d[hn + 2:end].decode("latin-1", errors="replace").lower())
                thunk_off += ptr_size
                n_this += 1
            off += 20
        return names


def analyze_pe(data: bytes) -> Optional[dict]:
    """
    `data` - fayl boshidan o'qilgan baytlar (odatda <= 5 MB). PE bo'lmasa None.
    Qaytaradi: {"score": 0-100, "findings": [str], "verdict_hint": "suspicious"|"clean",
    "signed": bool, "dotnet": bool, "packer": bool}
    """
    try:
        pe = _PE(data)
    except (ValueError, struct.error):
        return None

    findings = []
    score = 0
    packer = False

    # 1) Paketlovchi bo'lim nomlari
    packed_names = [s["name"] for s in pe.sections if s["name"].lower() in _PACKER_SECTIONS]
    if packed_names:
        packer = True
        score += 35
        findings.append(f"Paketlovchi (packer) bo'limlari: {', '.join(packed_names)}")

    # 2) Bo'limlar entropiyasi va xom/virtual nomuvofiqligi
    for s in pe.sections:
        executable = bool(s["chars"] & 0x20000000)
        if s["rsize"] and s["rptr"] + s["rsize"] <= len(data) and s["rsize"] >= 4096:
            ent = shannon_entropy(data[s["rptr"]:s["rptr"] + s["rsize"]])
            if ent >= 7.3 and (executable or s["name"].lower() in (".text", "code")):
                score += 25
                packer = True
                findings.append(f"'{s['name']}' bo'limi yuqori entropiyali ({ent:.2f}/8.0) - shifrlangan/paketlangan kod belgisi")
                break
        if executable and s["rsize"] == 0 and s["vsize"] > 0x2000:
            score += 15
            packer = True
            findings.append(f"'{s['name']}' bo'limi diskda bo'sh, xotirada katta (paketlangan kod ochilishi uchun ajratilgan)")
            break

    # 3) Entry point joylashuvi
    ep_sec = None
    for i, s in enumerate(pe.sections):
        if s["vaddr"] <= pe.entry_rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            ep_sec = (i, s)
    if ep_sec is not None and len(pe.sections) > 1 and ep_sec[0] == len(pe.sections) - 1 and ep_sec[1]["name"].lower() not in (".text", ".code"):
        score += 15
        findings.append(f"Entry point oxirgi '{ep_sec[1]['name']}' bo'limida (odatiy emas - paketlovchi belgisi)")

    # 4) Importlar
    imps = pe.imports()
    impset = set(imps)
    for _key, need, pts, desc in _API_COMBOS:
        if need <= impset:
            score += pts
            findings.append(f"Shubhali API majmuasi: {desc}")
    if len(imps) < 6 and (impset & _DYNAMIC_LOAD) and not (pe.dirs[14][0] if len(pe.dirs) > 14 else 0):
        score += 15
        packer = True
        findings.append(f"Juda kam import ({len(imps)} ta) va LoadLibrary/GetProcAddress - API'lar yuklanish vaqtida yashirin topiladi")

    # 5) Vaqt tamg'asi
    if pe.timestamp == 0 or pe.timestamp > time.time() + 86400 * 2:
        score += 10
        findings.append("Kompilyatsiya vaqt tamg'asi soxta ko'rinadi (0 yoki kelajakda)")

    signed = len(pe.dirs) > 4 and pe.dirs[4][0] != 0 and pe.dirs[4][1] > 0
    dotnet = len(pe.dirs) > 14 and pe.dirs[14][0] != 0
    if not signed and (score >= 20):
        findings.append("Raqamli imzo (Authenticode) yo'q")
    elif signed:
        findings.append("Authenticode imzosi mavjud (yaroqliligi tekshirilmagan)")

    score = min(100, score)
    return {"score": score, "findings": findings,
            "verdict_hint": "suspicious" if score >= 40 else "clean",
            "signed": signed, "dotnet": dotnet, "packer": packer}
