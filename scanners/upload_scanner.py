"""Synchronous upload scans. Never quarantine, extract, or retain submitted bytes."""
import hashlib
import os
import re
import tempfile

from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from scanners.heuristic_analyzer import analyze_file
from scanners.yara_scanner import scan_file as yara_scan
from scanners.clamav_scanner import scan_file as clamav_scan
from scanners.office_scanner import scan_office_file, OFFICE_EXTENSIONS

MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def scan_upload(stream, expected_sha256, filename, root, max_bytes=MAX_UPLOAD_BYTES):
    """Own all temporary files until cleanup completes, including on exceptions.

    The configured root should be a private tmpfs in production. A raw request
    stream avoids multipart spooling to a second, unmanaged temporary file.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise BadRequest("Invalid SHA256")
    # Only a bounded extension is used on disk, never a caller-provided path.
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    suffix = "." + ext if re.fullmatch(r"[a-z0-9]{1,10}", ext) else ".bin"
    os.makedirs(root, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scan-", dir=root) as work:
        path = os.path.join(work, "sample" + suffix)
        digest = hashlib.sha256()
        size = 0
        with open(path, "xb") as output:
            while True:
                chunk = stream.read(min(65536, max_bytes - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise RequestEntityTooLarge()
                digest.update(chunk)
                output.write(chunk)
        if not size or digest.hexdigest() != expected_sha256:
            raise BadRequest("Empty upload or SHA256 mismatch")

        heuristic = analyze_file(path, filename=filename)
        hits = yara_scan(path, timeout=10)
        clam = clamav_scan(path, temp_dir=work)
        findings = list(heuristic["findings"])
        findings.extend("YARA: " + hit["rule"] for hit in hits)
        confirmed = any(hit["severity"] in ("high", "critical") for hit in hits)
        confirmed = confirmed or bool(clam.get("infected"))
        if clam.get("infected"):
            findings.append("ClamAV: " + str(clam.get("signature")))
        if ext in OFFICE_EXTENSIONS:
            office = scan_office_file(path)
            if office and office.get("suspicious"):
                findings.extend(office["findings"])
        else:
            office = None

        # Heuristic scores alone are not signature confirmation.
        suspicious = (heuristic["verdict_hint"] in ("suspicious", "malicious")
                      or bool(hits) or bool(office and office.get("suspicious")))
        complete = bool(clam.get("scanned")) and not clam.get("error")
        verdict = ("malicious" if confirmed else "suspicious" if suspicious
                   else "clean" if complete else "unknown")
        result = {
            "sha256": expected_sha256, "verdict": verdict,
            "malicious": confirmed, "confirmed": confirmed,
            "threat_name": clam.get("signature") if confirmed else None,
            "source": "server_upload_scan", "scan_complete": complete,
            "score": 100 if confirmed else heuristic["score"],
            "findings": findings,
        }
        if not complete:
            result["scan_warning"] = "ClamAV scan unavailable or incomplete"
    # A failed cleanup raises instead of returning a successful response.
    return result
