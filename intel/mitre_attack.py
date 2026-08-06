"""
MITRE ATT&CK Mapping - alertlarni MITRE ATT&CK freymvorkiga bog'lash.

Yondashuv: har bir alert turi (parser_engine, file_analysis_engine,
deep_scan_engine tomonidan yaratilgan) o'zining `reason` matnida
o'ziga xos "imzo" so'zlar qoldiradi (masalan "YARA[...]:",
"ClamAV[critical]:", "Blacklist'dagi domenga"). Shu kalit so'zlar
asosida mos texnika/taktikani aniqlaymiz - bu markazlashtirilgan,
kengaytirish oson bo'lgan yondashuv: yangi alert turi qo'shilsa,
faqat shu yerga bitta qator qo'shiladi.

Rasmiy MITRE ATT&CK ma'lumotlari: https://attack.mitre.org/
"""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    tactic: str


# Tartib MUHIM: yuqoridagi qoidalar avval tekshiriladi (aniqroqdan
# umumiyroqqa qarab tartiblangan) - shu tufayli bitta alert matnida
# bir nechta kalit so'z bo'lsa ham eng mos texnika tanlanadi.
_RULES: List[tuple] = [
    # (reason matnida qidiriladigan kalit so'z, MitreMapping)
    ("Ransomware_Note_Strings", MitreMapping("T1486", "Data Encrypted for Impact", "Impact")),
    ("Suspicious_PowerShell_Obfuscation", MitreMapping("T1059.001", "PowerShell", "Execution")),
    ("Suspicious_JS_Obfuscation", MitreMapping("T1059.007", "JavaScript", "Execution")),
    ("PDF_Suspicious_JavaScript", MitreMapping("T1203", "Exploitation for Client Execution", "Execution")),
    ("Suspicious_Macro_AutoExec", MitreMapping("T1204.002", "User Execution: Malicious File", "Execution")),
    ("Xavfli VBA buyruq", MitreMapping("T1204.002", "User Execution: Malicious File", "Execution")),
    ("Embedded_PE_In_Document", MitreMapping("T1027.009", "Obfuscated Files: Embedded Payloads", "Defense Evasion")),
    ("Arxivdan", MitreMapping("T1027", "Obfuscated Files or Information", "Defense Evasion")),
    ("ClamAV", MitreMapping("T1204.002", "User Execution: Malicious File", "Execution")),
    ("Zararli fayl aniqlandi", MitreMapping("T1204.002", "User Execution: Malicious File", "Execution")),
    ("Endpoint Agent zararli faylni aniqladi", MitreMapping("T1204.002", "User Execution: Malicious File", "Execution")),
    ("Blacklist'dagi domenga so'rov", MitreMapping("T1071.004", "Application Layer Protocol: DNS", "Command and Control")),
]

_DEFAULT = MitreMapping("T1204", "User Execution", "Execution")


def classify(reason: str) -> MitreMapping:
    """Alert.reason matnini tekshirib, mos MITRE texnikasini qaytaradi.
    Hech biri mos kelmasa, umumiy standart qiymat qaytariladi."""
    if not reason:
        return _DEFAULT
    for keyword, mapping in _RULES:
        if keyword in reason:
            return mapping
    return _DEFAULT
