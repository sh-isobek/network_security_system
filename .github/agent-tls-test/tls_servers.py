"""CI: uchta HTTPS test serveri (good/wrong_ca/wrong_name) - /api/v1/health va POST /api/v1/* -> 200.

usage: python tls_servers.py <certs dir>   (fon jarayoni sifatida)
"""
import http.server
import json
import ssl
import sys
import threading

CERTS = sys.argv[1]
PORTS = {"good": 19443, "wrong_ca": 19444, "wrong_name": 19445}


class Handler(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        body = json.dumps({"status": "ok", "restart_requested": False}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._ok()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._ok()

    def log_message(self, *args):
        pass


def serve(name, port):
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{CERTS}/{name}.crt", f"{CERTS}/{name}.key")
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


for name, port in PORTS.items():
    threading.Thread(target=serve, args=(name, port), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
