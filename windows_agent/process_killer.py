"""
Backward-compatibility shim: asosiy kod endi agent_core/process_killer.py'da
(Windows va Linux agentlari umumiy yadrodan foydalanadi).
"""
from agent_core.process_killer import *  # noqa: F401,F403
from agent_core.process_killer import KillResult, find_processes_holding_file, kill_process_holding_file  # noqa: F401
