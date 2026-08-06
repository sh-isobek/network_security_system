"""
YARA Scanner - fayl tarkibini rules/malware_rules.yar qoidalari bilan tekshiradi.
"""
import os
from typing import List

import yara

_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "malware_rules.yar")
_compiled_rules = None


def _get_rules():
    global _compiled_rules
    if _compiled_rules is None:
        _compiled_rules = yara.compile(filepath=_RULES_PATH)
    return _compiled_rules


def scan_file(filepath: str) -> List[dict]:
    """
    Faylni YARA qoidalari bilan tekshiradi.
    Qaytaradi: [{"rule": "...", "severity": "...", "description": "..."}]
    """
    if not os.path.isfile(filepath):
        return []

    rules = _get_rules()
    matches = rules.match(filepath)

    findings = []
    for m in matches:
        findings.append({
            "rule": m.rule,
            "severity": m.meta.get("severity", "unknown"),
            "description": m.meta.get("description", ""),
        })
    return findings


def scan_bytes(data: bytes) -> List[dict]:
    """Bevosita xotiradagi bytes'ni tekshirish (fayl diskda bo'lmasa ham ishlaydi)."""
    rules = _get_rules()
    matches = rules.match(data=data)
    findings = []
    for m in matches:
        findings.append({
            "rule": m.rule,
            "severity": m.meta.get("severity", "unknown"),
            "description": m.meta.get("description", ""),
        })
    return findings
