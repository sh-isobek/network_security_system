"""CI: Python agent (agent_core.agent._tls_request_kwargs) AGENT_CA_BUNDLE_FILE bilan
faqat ichki CA imzolagan, nomi to'g'ri serverga ulanadi.

usage: python check_python_agent.py <certs dir>
"""
import os
import sys

certs = sys.argv[1]
os.environ["AGENT_CA_BUNDLE_FILE"] = os.path.join(certs, "ca_a.crt")
sys.path.insert(0, os.getcwd())

import requests  # noqa: E402
from agent_core.agent import _tls_request_kwargs  # noqa: E402


def reachable(port):
    try:
        r = requests.get(f"https://127.0.0.1:{port}/api/v1/health", timeout=10,
                         proxies={"http": None, "https": None}, **_tls_request_kwargs())
        return r.status_code == 200
    except requests.exceptions.SSLError:
        return False


results = {
    "to'g'ri CA -> qabul": reachable(19443),
    "begona CA -> rad": not reachable(19444),
    "nom mos emas -> rad": not reachable(19445),
}
for name, ok in results.items():
    print(("OK   " if ok else "FAIL ") + name)
sys.exit(0 if all(results.values()) else 1)
