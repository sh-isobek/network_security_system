"""
UniFi Controller API adapteri - Wi-Fi orqali ulangan qurilmalar uchun.

UniFi Network Controller (UDM Pro / Cloud Key / self-hosted) standart
REST API'ga ega. MUHIM: ikki xil "shakl" bor, va API yo'llari BOSHQACHA:

  1. UniFi OS konsoli (UDM, UDM-Pro, UDR, Cloud Key Gen2+) - standart
     443-port, login POST /api/auth/login, buyruqlar
     POST /proxy/network/api/s/{site}/cmd/stamgr

  2. Self-hosted / klassik dastur (masalan Docker orqali) - odatda
     8443 (yoki boshqa portga moslashtirilgan), login POST /api/login,
     buyruqlar to'g'ridan-to'g'ri POST /api/s/{site}/cmd/stamgr

`UNIFI_OS_CONSOLE=false` muhit o'zgaruvchisi orqali self-hosted
rejimga o'ting (standart bo'lmagan port ishlatilsa, odatda shu kerak).

Hujjat: https://ubntwiki.com/products/software/unifi-controller/api
"""
import os

import requests

from response.base_adapter import BlockingAdapter, ActionResult, TargetDevice

UNIFI_CONTROLLER_URL = os.getenv("UNIFI_CONTROLLER_URL", "")   # masalan https://172.16.0.64:11443
UNIFI_USERNAME = os.getenv("UNIFI_USERNAME", "")
UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD", "")
UNIFI_SITE = os.getenv("UNIFI_SITE", "default")
UNIFI_OS_CONSOLE = os.getenv("UNIFI_OS_CONSOLE", "true").lower() in ("true", "1", "yes")


class UniFiAdapter(BlockingAdapter):
    name = "unifi"

    def __init__(self):
        self._session = requests.Session()
        self._logged_in = False

    def can_handle(self, device: TargetDevice) -> bool:
        return device.connection_type == "wifi" and bool(device.mac_address)

    def _login(self) -> bool:
        if not UNIFI_CONTROLLER_URL or not UNIFI_USERNAME:
            return False
        login_path = "/api/auth/login" if UNIFI_OS_CONSOLE else "/api/login"
        try:
            resp = self._session.post(
                f"{UNIFI_CONTROLLER_URL}{login_path}",
                json={"username": UNIFI_USERNAME, "password": UNIFI_PASSWORD},
                verify=False,
                timeout=10,
            )
            self._logged_in = resp.status_code == 200
            return self._logged_in
        except requests.RequestException:
            return False

    def _send_cmd(self, cmd: str, mac: str) -> ActionResult:
        if not self._logged_in and not self._login():
            return ActionResult(False, "UniFi Controller'ga ulanib bo'lmadi (sozlama yoki tarmoq xatoligi)", self.name)

        cmd_path = f"/proxy/network/api/s/{UNIFI_SITE}/cmd/stamgr" if UNIFI_OS_CONSOLE else f"/api/s/{UNIFI_SITE}/cmd/stamgr"
        try:
            resp = self._session.post(
                f"{UNIFI_CONTROLLER_URL}{cmd_path}",
                json={"cmd": cmd, "mac": mac.lower()},
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                return ActionResult(True, f"UniFi: {cmd} muvaffaqiyatli bajarildi ({mac})", self.name)
            return ActionResult(False, f"UniFi API xatoligi: HTTP {resp.status_code}", self.name)
        except requests.RequestException as exc:
            return ActionResult(False, f"UniFi so'rov xatoligi: {exc}", self.name)

    def disconnect(self, device: TargetDevice) -> ActionResult:
        # "kick-sta" - darhol uzadi, lekin qurilma qayta ulanishga urinishi mumkin
        return self._send_cmd("kick-sta", device.mac_address)

    def quarantine(self, device: TargetDevice) -> ActionResult:
        # "block-sta" - to'liq bloklaydi, admin "unblock-sta" bilan qaytarmaguncha ulana olmaydi
        return self._send_cmd("block-sta", device.mac_address)

    def restore(self, device: TargetDevice) -> ActionResult:
        return self._send_cmd("unblock-sta", device.mac_address)
