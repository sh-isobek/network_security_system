"""
Windows Service Wrapper - agent.py'ni Windows xizmati (service) sifatida
ishga tushiradi (foydalanuvchi login qilmagan bo'lsa ham, kompyuter
yoqilishi bilan avtomatik ishlaydi).

MUHIM: Bu fayl faqat Windows'da ishlaydi (pywin32 kutubxonasi talab
qilinadi). Linux/test muhitida import qilinmaydi va ishlatilmaydi -
production Windows kompyuterida ishlatiladi.

O'rnatish:
    pip install pywin32
    python service_wrapper.py install
    python service_wrapper.py start

O'chirish:
    python service_wrapper.py stop
    python service_wrapper.py remove
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    print("XATO: pywin32 o'rnatilmagan. Bu fayl faqat Windows'da ishlaydi.")
    print("O'rnatish: pip install pywin32")
    sys.exit(1)

from windows_agent.agent import EndpointAgent, _default_watch_dirs


class EndpointAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetworkSecurityEndpointAgent"
    _svc_display_name_ = "Network Security Endpoint Agent"
    _svc_description_ = (
        "Tarmoq xavfsizligi tizimi - fayl monitoring va avtomatik "
        "zararli dasturlarni bloklash xizmati."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.agent:
            self.agent.monitor.stop()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        # MUHIM (real production'da aniqlangan tub sabab): Windows Service
        # Control Manager (SCM) xizmatni ishga tushirgandan keyin 30 soniya
        # ichida ANIQ "men ishlayapman" (SERVICE_RUNNING) signalini kutadi.
        # Bu chaqiruv YETISHMAGAN edi - shuning uchun SCM har doim
        # "The service did not respond to the start or control request in
        # a timely fashion" (30000 ms) xatosi bilan xizmatni majburan
        # o'chirar edi, garchi pastdagi kod o'zi to'g'ri ishlagan bo'lsa ham.
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        self.agent = EndpointAgent(_default_watch_dirs())
        self.agent.monitor.start()
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(EndpointAgentService)
