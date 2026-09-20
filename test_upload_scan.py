"""Upload lifecycle tests; run with python -m unittest test_upload_scan -v."""
import hashlib
import io
import os
import tempfile
import unittest
import zipfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from scanners import upload_scanner as scanner


class UploadLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = self.work.name
        self.content = b"ordinary document\n"
        self.sha = hashlib.sha256(self.content).hexdigest()

    def scan(self, **kwargs):
        return scanner.scan_upload(io.BytesIO(self.content), self.sha,
                                   "document.txt", self.root, **kwargs)

    def assert_empty(self):
        self.assertEqual(list(Path(self.root).iterdir()), [])

    def test_real_scanners_remove_sample(self):
        result = self.scan()
        self.assertIn(result["verdict"], ("clean", "unknown"))
        self.assertFalse(result["confirmed"])
        self.assert_empty()

    def test_real_yara_match_is_deleted(self):
        # Inert text that matches an existing rule, never executed.
        self.content = b"-EncodedCommand IEX(New-Object DownloadString"
        self.sha = hashlib.sha256(self.content).hexdigest()
        result = self.scan()
        self.assertTrue(result["confirmed"])
        self.assert_empty()

    def test_manifest_decompression_is_bounded(self):
        from scanners.apk_analyzer import analyze_apk
        path = os.path.join(self.root, "large.apk")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"x" * 4097)
        with patch("scanners.apk_analyzer.MANIFEST_LIMIT", 4096):
            result = analyze_apk(path)
        self.assertEqual(result["verdict_hint"], "suspicious")
        self.assertIn("size limit", result["findings"][0])

    def test_error_and_timeout_remove_sample(self):
        for error in (RuntimeError("scanner failed"), TimeoutError("timeout")):
            with self.subTest(error=error), patch.object(scanner, "yara_scan", side_effect=error):
                with self.assertRaises(type(error)):
                    self.scan()
                self.assert_empty()

    def test_bad_hash_and_oversized_upload_remove_sample(self):
        with self.assertRaises(BadRequest):
            scanner.scan_upload(io.BytesIO(self.content), "0" * 64, "x.txt", self.root)
        self.assert_empty()
        with self.assertRaises(RequestEntityTooLarge):
            self.scan(max_bytes=2)
        self.assert_empty()

    def test_disconnect_removes_partial_sample(self):
        stream = SimpleNamespace(read=unittest.mock.Mock(side_effect=[b"partial", ConnectionError()]))
        with self.assertRaises(ConnectionError):
            scanner.scan_upload(stream, self.sha, "x.txt", self.root)
        self.assert_empty()

    def test_malicious_sample_is_deleted_not_quarantined(self):
        with patch.object(scanner, "yara_scan", return_value=[
                {"rule": "test_signature", "severity": "critical"}]):
            result = self.scan()
        self.assertTrue(result["confirmed"])
        self.assertEqual(result["verdict"], "malicious")
        self.assert_empty()

    def test_unavailable_scanner_does_not_mean_clean(self):
        with patch.object(scanner, "clamav_scan", return_value={"scanned": False, "error": "timeout"}):
            result = self.scan()
        self.assertEqual(result["verdict"], "unknown")
        self.assertFalse(result["scan_complete"])
        self.assert_empty()

    def test_clamav_temporary_children_removed_on_timeout(self):
        def interrupted_scan(path, temp_dir):
            self.assertEqual(os.path.dirname(path), temp_dir)
            Path(temp_dir, "decompressed-child").write_bytes(b"temporary child")
            return {"scanned": False, "error": "timeout"}
        with patch.object(scanner, "clamav_scan", side_effect=interrupted_scan):
            self.assertEqual(self.scan()["verdict"], "unknown")
        self.assert_empty()

    def test_archive_members_never_written_to_disk(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("../../escape.txt", b"hello")
            archive.writestr("AndroidManifest.xml", b"invalid axml")
        data = buf.getvalue()
        result = scanner.scan_upload(io.BytesIO(data), hashlib.sha256(data).hexdigest(),
                                     "../../sample.apk", self.root)
        self.assertEqual(result["verdict"], "suspicious")
        self.assert_empty()

    def test_cleanup_failure_is_not_success(self):
        with patch("shutil.rmtree", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                self.scan()


class UploadAPITests(unittest.TestCase):
    def setUp(self):
        from api import server
        self.server = server
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = self.work.name
        self.addCleanup(patch.stopall)
        patch.dict(server.app.config, TESTING=True, UPLOAD_SCAN_ROOT=self.root).start()
        patch.object(server, "AGENT_API_KEY", "test-upload-key").start()
        patch.object(server.limiter, "enabled", False).start()
        self.client = server.app.test_client()
        self.data = b"harmless text"
        self.headers = {"X-API-Key": "test-upload-key", "X-Agent-Hostname": "test-pc",
                        "X-File-Name": "document.txt",
                        "X-File-SHA256": hashlib.sha256(self.data).hexdigest()}

    def post(self, **kwargs):
        return self.client.post("/api/v1/scan_file", data=self.data, headers=self.headers,
                                content_type="application/octet-stream", **kwargs)

    def test_api_real_database_retains_no_sample_path(self):
        response = self.post()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(list(Path(self.root).iterdir()), [])
        with self.server.get_session() as session:
            row = session.query(self.server.FileEvent).filter_by(
                channel="endpoint_upload", sha256=self.headers["X-File-SHA256"]).order_by(
                    self.server.FileEvent.id.desc()).first()
            self.assertIsNotNone(row)
            self.assertIsNone(row.stored_path)
            self.assertIsNone(row.filename)
            self.assertTrue(row.deep_scanned)

    def test_real_http_agent_upload_and_cleanup(self):
        from agent_core import agent
        from werkzeug.serving import make_server
        server = make_server("127.0.0.1", 0, self.server.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as endpoint:
                path = os.path.join(endpoint, "document.txt")
                Path(path).write_bytes(self.data)
                with patch.object(agent, "API_SERVER_URL", f"http://127.0.0.1:{server.server_port}"), \
                        patch.object(agent, "AGENT_API_KEY", "test-upload-key"):
                    result = agent.upload_for_scan(path, self.headers["X-File-SHA256"], "test-pc")
                self.assertIsNotNone(result)
                self.assertEqual(result["sha256"], self.headers["X-File-SHA256"])
                self.assertTrue(os.path.isfile(path))
                self.assertEqual(list(Path(self.root).iterdir()), [])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_database_failure_happens_after_cleanup(self):
        with patch.object(self.server, "get_session", side_effect=RuntimeError("DB down")):
            with self.assertRaises(RuntimeError):
                self.post()
        self.assertEqual(list(Path(self.root).iterdir()), [])

    def test_bound_token_hostname_checked_before_sample_read(self):
        self.headers["X-API-Key"] = "bound-token"
        with patch.object(self.server.token_manager, "verify_token", return_value=SimpleNamespace(agent_hostname="other-pc")):
            self.assertEqual(self.post().status_code, 401)
        self.assertEqual(list(Path(self.root).iterdir()), [])
        with patch.object(self.server.token_manager, "verify_token", return_value=SimpleNamespace(agent_hostname="test-pc")):
            self.assertEqual(self.post().status_code, 200)
        self.assertEqual(list(Path(self.root).iterdir()), [])

    def test_api_rejects_oversize_and_bad_digest(self):
        with patch.dict(self.server.app.config, UPLOAD_SCAN_MAX_BYTES=2):
            self.assertEqual(self.post().status_code, 413)
        self.headers["X-File-SHA256"] = "0" * 64
        self.assertEqual(self.post().status_code, 400)
        self.assertEqual(list(Path(self.root).iterdir()), [])

    def test_hash_requests_upload_only_when_needed(self):
        cases = [(None, None, True), ({"malicious": False}, None, False),
                 ({"malicious": False}, "suspicious", True),
                 ({"malicious": True, "positives": 1, "total": 70}, None, True),
                 ({"malicious": True, "positives": 10, "total": 70}, None, False)]
        for vt, heuristic, expected in cases:
            with self.subTest(vt=vt, heuristic=heuristic), \
                    patch.object(self.server, "check_local", return_value=None), \
                    patch.object(self.server, "check_virustotal", return_value=vt), \
                    patch.object(self.server, "check_malwarebazaar", return_value=None):
                response = self.client.post("/api/v1/check_hash", headers=self.headers,
                    json={"sha256": self.headers["X-File-SHA256"], "heuristic_verdict": heuristic})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(bool(response.json.get("upload_required")), expected)

    def test_agent_upload_failure_preserves_hash_decision(self):
        from agent_core import agent
        original = {"malicious": True, "confirmed": False, "upload_required": True}
        response = SimpleNamespace(status_code=200, json=lambda: original)
        with patch.object(agent.requests, "post", return_value=response), \
                patch.object(agent, "upload_for_scan", return_value=None) as upload, \
                patch.object(agent, "_save_cache"):
            result = agent.check_hash_with_server_or_cache(self.headers["X-File-SHA256"], {},
                                                          filepath="sample.txt", hostname="test-pc")
        self.assertEqual(result, original)
        upload.assert_called_once()


def run_tests():
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__)))
    assert result.wasSuccessful(), "Upload scan tests failed"


if __name__ == "__main__":
    unittest.main()
