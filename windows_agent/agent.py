"""
Windows Agent kirish nuqtasi - asosiy mantiq endi agent_core/agent.py'da
(Windows va Linux agentlari umumiy yadrodan foydalanadi, faqat standart
kuzatiladigan papkalar farq qiladi - bu allaqachon agent_core ichida
platform.system() orqali avtomatik hal qilinadi).

Ishga tushirish:
    python -m windows_agent.agent
"""
from agent_core.agent import *  # noqa: F401,F403
from agent_core.agent import EndpointAgent, _default_watch_dirs

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch-dirs", nargs="+", default=None)
    args = ap.parse_args()

    dirs = args.watch_dirs or _default_watch_dirs()
    agent = EndpointAgent(dirs)
    agent.run()
