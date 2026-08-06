"""
Backward-compatibility shim: asosiy kod endi agent_core/file_monitor.py'da
(Windows va Linux agentlari umumiy yadrodan foydalanadi).
"""
from agent_core.file_monitor import *  # noqa: F401,F403
from agent_core.file_monitor import FileMonitor, _wait_until_stable  # noqa: F401
