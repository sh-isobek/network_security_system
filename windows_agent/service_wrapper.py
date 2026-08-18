"""
Windows Service wrapper for NetworkSecurityEndpointAgent.

The service is designed for AD/GPO deployment and runs under LocalSystem.
It deliberately avoids user-session dependent paths and stores its state in
ProgramData. The service reports RUNNING before starting file monitoring so
Windows SCM does not hit the 30-second startup timeout while Python/watchdog
initialises.
"""
import os
import sys

# Service processes normally start in C:\Windows\System32. Keep logs/cache in
# a writable, stable location before importing agent_core (which configures
# logging at import time).
PROGRAM_DATA = os.environ.get("ProgramData", r"C:\ProgramData")
AGENT_DATA_DIR = os.path.join(PROGRAM_DATA, "NetworkSecurityAgent")
os.makedirs(AGENT_DATA_DIR, exist_ok=True)
os.environ.setdefault("AGENT_LOG_FILE", os.path.join(AGENT_DATA_DIR, "agent.log"))
os.environ.setdefault("AGENT_CACHE_FILE", os.path.join(AGENT_DATA_DIR, "agent_hash_cache.json"))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import win32event
    import win32service
    import win32serviceutil
    import servicemanager
except ImportError:
    print("XATO: pywin32 o'rnatilmagan. Bu fayl faqat Windows'da ishlaydi.")
    sys.exit(1)

from windows_agent.agent import EndpointAgent


SERVICE_NAME = "NetworkSecurityEndpointAgent"


def _windows_watch_dirs():
    """Enumerate real Windows user profiles plus system temp directories."""
    result = []
    users_root = os.path.join(os.environ.get("SystemDrive", "C:"), "Users")

    if os.path.isdir(users_root):
        for username in os.listdir(users_root):
            profile = os.path.join(users_root, username)
            if not os.path.isdir(profile):
                continue
            # Ignore system profiles that are not useful for endpoint file monitoring.
            if username.lower() in {"default", "default user", "public", "all users"}:
                continue
            for folder in ("Downloads", "Desktop"):
                path = os.path.join(profile, folder)
                if os.path.isdir(path):
                    result.append(path)

            outlook = os.path.join(
                profile, "AppData", "Local", "Microsoft", "Outlook"
            )
            if os.path.isdir(outlook):
                result.append(outlook)

    for path in (
        os.environ.get("TEMP", r"C:\Windows\Temp"),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
    ):
        if os.path.isdir(path):
            result.append(path)

    # Preserve order and remove duplicates.
    return list(dict.fromkeys(result))


class EndpointAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Network Security Endpoint Agent"
    _svc_description_ = (
        "Network Security System endpoint file monitoring and malicious-file protection."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        try:
            if self.agent is not None:
                self.agent.stop()
        except Exception as exc:
            servicemanager.LogErrorMsg(
                f"Agent stop error: {exc!r}"
            )
        finally:
            win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        # Tell SCM immediately that the service has crossed startup. This is
        # critical for PyInstaller/watchdog startup on slower PCs.
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogInfoMsg(
            f"{SERVICE_NAME} service started"
        )

        try:
            watch_dirs = _windows_watch_dirs()
            if not watch_dirs:
                servicemanager.LogWarningMsg(
                    "No Windows user folders found; monitoring system Temp only if available."
                )

            self.agent = EndpointAgent(watch_dirs)
            self.agent.start_background(self.stop_event)

            # Wait until SvcStop signals the event.
            win32event.WaitForSingleObject(
                self.stop_event,
                win32event.INFINITE,
            )
        except Exception as exc:
            servicemanager.LogErrorMsg(
                f"{SERVICE_NAME} fatal error: {exc!r}"
            )
            raise
        finally:
            try:
                if self.agent is not None:
                    self.agent.stop()
            except Exception:
                pass


if __name__ == "__main__":
    # MUHIM (real production'da aniqlangan, PyInstaller+pywin32'ning
    # tanilgan muammosi): `install`/`remove`/`debug` (argumentlar bilan
    # chaqirilganda) mukammal ishlaydi - bu HandleCommandLine()ning
    # argumentlarni to'g'ri qayta ishlaganini tasdiqlaydi. Lekin Windows
    # SCM xizmatni HAQIQATAN ishga tushirganda, uni HECH QANDAY
    # argumentsiz chaqiradi (faqat ro'yxatga olingan ImagePath orqali) -
    # bu holatda dastur "men Service Control Dispatcher orqali
    # chaqirilyapman" deb ANIQ tushunishi kerak. `HandleCommandLine()`ning
    # o'zi buni avtomatik aniqlashi kerak edi, lekin PyInstaller bilan
    # "muzlatilgan" (frozen) yagona-fayl exe'larda bu avtomatik aniqlash
    # ishonchsiz bo'lishi ma'lum (bu - real production'da aynan shu
    # sabab bilan "Cannot start service" xatosi uchraganini tushuntiradi -
    # install/remove/debug argumentlar bilan ishlaganidan, lekin haqiqiy
    # SCM ishga tushirish argumentsiz muvaffaqiyatsiz bo'lganidan aniq
    # ko'rinadi). Shuning uchun bu holatni ANIQ, qo'lda tekshiramiz va
    # past darajadagi dispatcher'ni o'zimiz chaqiramiz.
    if len(sys.argv) == 1:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(EndpointAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as exc:
            # Agar past darajadagi dispatcher ham muvaffaqiyatsiz bo'lsa,
            # xatoni Windows Event Log'ga yozamiz (aks holda hech qanday
            # iz qolmasdan jim qulab tushishi mumkin edi).
            try:
                servicemanager.LogErrorMsg(f"Service dispatcher xatoligi: {exc!r}")
            except Exception:
                pass
            raise
    else:
        win32serviceutil.HandleCommandLine(EndpointAgentService)
