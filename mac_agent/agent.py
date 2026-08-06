"""
macOS Agent kirish nuqtasi - asosiy mantiq agent_core/agent.py'da
(barcha OS agentlari bir xil yadrodan foydalanadi; macOS uchun standart
kuzatiladigan papkalar - ~/Downloads, ~/Desktop, /tmp).

MUHIM (macOS'ga xos cheklov): psutil orqali boshqa foydalanuvchi
jarayonlarini to'xtatish uchun odatda "Full Disk Access" va ba'zan
System Integrity Protection (SIP) bilan bog'liq maxsus ruxsatlar kerak
bo'lishi mumkin - System Settings > Privacy & Security orqali agent
ishga tushiriladigan binary/Python'ga ruxsat berilishi kerak.

Ishga tushirish (qo'lda, test uchun):
    python3 -m mac_agent.agent

Production uchun launchd xizmati sifatida - docs_MAC_AGENT_SETUP.md'ga qarang.
"""
from agent_core.agent import EndpointAgent, _default_watch_dirs

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch-dirs", nargs="+", default=None, help="Kuzatiladigan papkalar ro'yxati")
    args = ap.parse_args()

    dirs = args.watch_dirs or _default_watch_dirs()
    agent = EndpointAgent(dirs)
    agent.run()
