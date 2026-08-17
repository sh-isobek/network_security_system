"""
UniFi Controller API adapteri - Wi-Fi orqali ulangan qurilmalarni
bloklash/uzish uchun.

MUHIM: ikkita mutlaqo boshqacha UniFi API avlodi mavjud:

  1. **Integration API (v1) - API Key orqali** (2025-yildan, Network
     Application 9.1.105+). O'qish (klientlar ro'yxati) uchun to'liq
     hujjatlashtirilgan va sinovdan o'tkazilgan (`network_discovery/
     unifi_discovery.py`ga qarang). LEKIN klientni bloklash/uzish
     (yozish amali) uchun aniq endpoint/parametr nomlari rasmiy
     hujjatlarda hali TO'LIQ BARQAROR EMAS (bu funksiya bu loyihada
     "Early Access" deb belgilangan API asosida, ehtiyotkorlik bilan
     yozilgan - agar ishlamasa, quyidagi 2-usulga avtomatik qaytadi).

  2. **Eski, legacy API - login/parol orqali** (barqaror, ko'p yillik
     sinovdan o'tgan). Ikki ko'rinishi bor - UniFi OS konsoli
     (`/api/auth/login`) va self-hosted klassik dastur (`/api/login`).

Ustuvorlik: agar `UNIFI_API_KEY` sozlangan bo'lsa, avval shu orqali
sinaladi; muvaffaqiyatsiz bo'lsa (yoki sozlanmagan bo'lsa) - login/
parol orqali (agar sozlangan bo'lsa) davom etiladi.

Hujjat: https://developer.ui.com/unifi-api/ (rasmiy, API Key uchun),
https://ubntwiki.com/products/software/unifi-controller/api (legacy)
"""
import os

import requests

from response.base_adapter import BlockingAdapter, ActionResult, TargetDevice

# Legacy "cmd/stamgr" buyruq nomlari (login/parol usuli uchun)
_LEGACY_CMD = {"disconnect": "kick-sta", "quarantine": "block-sta", "restore": "unblock-sta"}

# Integration API (v1, API Key) uchun taxminiy amal nomlari - MUHIM:
# bu rasmiy hujjatda hali to'liq barqaror emas, shuning uchun
# muvaffaqiyatsiz bo'lsa avtomatik legacy usulga qaytiladi (pastga q.)
_API_KEY_ACTION = {"disconnect": "KICK", "quarantine": "BLOCK", "restore": "UNBLOCK"}


class UniFiAdapter(BlockingAdapter):
    name = "unifi"

    def __init__(self):
        self._session = requests.Session()
        self._logged_in = False

    def can_handle(self, device: TargetDevice) -> bool:
        return device.connection_type == "wifi" and bool(device.mac_address)

    def _try_api_key_action(self, action_type: str, mac: str) -> bool:
        """
        Yangi Integration API (v1) orqali urinadi. Muvaffaqiyatli
        bo'lsa True, aks holda (sozlanmagan, xato, yoki bu amal
        qo'llab-quvvatlanmasa) False qaytaradi - chaqiruvchisi legacy
        usulga qaytishi kerak.
        """
        controller_url = os.getenv("UNIFI_CONTROLLER_URL", "").rstrip("/")
        api_key = os.getenv("UNIFI_API_KEY", "")
        site_id = os.getenv("UNIFI_SITE_ID", "")
        verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        if not controller_url or not api_key or not site_id:
            return False

        action = _API_KEY_ACTION.get(action_type)
        if not action:
            return False

        url = f"{controller_url}/proxy/network/integration/v1/sites/{site_id}/clients/{mac.lower()}/actions"
        headers = {"X-API-Key": api_key, "Accept": "application/json", "Content-Type": "application/json"}

        try:
            resp = requests.post(url, headers=headers, json={"action": action}, verify=verify_ssl, timeout=10)
            return resp.status_code in (200, 201, 202, 204)
        except requests.RequestException:
            return False

    def _login(self) -> bool:
        controller_url = os.getenv("UNIFI_CONTROLLER_URL", "").rstrip("/")
        username = os.getenv("UNIFI_USERNAME", "")
        password = os.getenv("UNIFI_PASSWORD", "")
        os_console = os.getenv("UNIFI_OS_CONSOLE", "true").lower() in ("true", "1", "yes")
        verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        if not controller_url or not username:
            return False
        login_path = "/api/auth/login" if os_console else "/api/login"
        try:
            resp = self._session.post(
                f"{controller_url}{login_path}",
                json={"username": username, "password": password},
                verify=verify_ssl,
                timeout=10,
            )
            self._logged_in = resp.status_code == 200
            return self._logged_in
        except requests.RequestException:
            return False

    def _send_legacy_cmd(self, cmd: str, mac: str) -> ActionResult:
        controller_url = os.getenv("UNIFI_CONTROLLER_URL", "").rstrip("/")
        site = os.getenv("UNIFI_SITE", "default")
        os_console = os.getenv("UNIFI_OS_CONSOLE", "true").lower() in ("true", "1", "yes")
        verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

        if not self._logged_in and not self._login():
            return ActionResult(False, "UniFi Controller'ga ulanib bo'lmadi (sozlama yoki tarmoq xatoligi)", self.name)

        cmd_path = f"/proxy/network/api/s/{site}/cmd/stamgr" if os_console else f"/api/s/{site}/cmd/stamgr"
        try:
            resp = self._session.post(
                f"{controller_url}{cmd_path}",
                json={"cmd": cmd, "mac": mac.lower()},
                verify=verify_ssl,
                timeout=10,
            )
            if resp.status_code == 200:
                return ActionResult(True, f"UniFi (legacy): {cmd} muvaffaqiyatli bajarildi ({mac})", self.name)
            return ActionResult(False, f"UniFi API xatoligi: HTTP {resp.status_code}", self.name)
        except requests.RequestException as exc:
            return ActionResult(False, f"UniFi so'rov xatoligi: {exc}", self.name)

    def _do_action(self, action_type: str, mac: str) -> ActionResult:
        """
        Avval API Key orqali urinadi (agar sozlangan bo'lsa), keyin
        legacy login/parol usuliga qaytadi.
        """
        if self._try_api_key_action(action_type, mac):
            return ActionResult(True, f"UniFi (API Key): {action_type} muvaffaqiyatli bajarildi ({mac})", self.name)

        legacy_cmd = _LEGACY_CMD[action_type]
        return self._send_legacy_cmd(legacy_cmd, mac)

    def disconnect(self, device: TargetDevice) -> ActionResult:
        # darhol uzadi, lekin qurilma qayta ulanishga urinishi mumkin
        return self._do_action("disconnect", device.mac_address)

    def quarantine(self, device: TargetDevice) -> ActionResult:
        # to'liq bloklaydi, admin "restore" bilan qaytarmaguncha ulana olmaydi
        return self._do_action("quarantine", device.mac_address)

    def restore(self, device: TargetDevice) -> ActionResult:
        return self._do_action("restore", device.mac_address)
