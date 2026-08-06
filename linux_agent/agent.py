"""
Linux Agent kirish nuqtasi - asosiy mantiq agent_core/agent.py'da
(Windows va Linux agentlari bir xil yadrodan foydalanadi; standart
kuzatiladigan papkalar `agent_core.agent._default_watch_dirs()` orqali
platform.system() asosida avtomatik tanlanadi - Linux uchun
~/Downloads, ~/Desktop, /tmp, /var/tmp).

Ishga tushirish (qo'lda, test uchun):
    python -m linux_agent.agent

Production uchun systemd xizmati sifatida - docs_LINUX_AGENT_SETUP.md'ga qarang.
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
