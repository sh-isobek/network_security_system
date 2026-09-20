"""
UniFi Controller API adapteri - Wi-Fi orqali ulangan qurilmalarni
bloklash/uzish uchun.

FAQAT Integration API (v1) - API Key (token) orqali. Login/parol
orqali kirish OLIB TASHLANGAN: UniFi hisobida 2-bosqichli
autentifikatsiya (pochtaga tasdiqlash kodi) yoqilgan, shuning uchun
login/parol bilan avtomatik kirib bo'lmaydi va u yo'l endi
qo'llab-quvvatlanmaydi.

Sozlama: UNIFI_CONTROLLER_URL, UNIFI_API_KEY, UNIFI_SITE_ID (UUID),
UNIFI_VERIFY_SSL. API kalit: UniFi Network > Control Plane > Integrations.

MUHIM (halol cheklov): klientni bloklash/uzish (yozish amali) uchun
aniq endpoint/amal nomlari rasmiy hujjatlarda hali TO'LIQ BARQAROR
EMAS ("Early Access"). Agar amal ishlamasa, avtomatik zaxira yo'q -
natija "muvaffaqiyatsiz" deb qaytariladi va qo'lda aralashuv kerak
bo'ladi (response_engine buni alertga yozadi).

Hujjat: https://developer.ui.com/unifi-api/
"""
import os

import requests

from response.base_adapter import BlockingAdapter, ActionResult, TargetDevice

# Integration API (v1, API Key) amal nomlari - rasmiy hujjatda hali to'liq
# barqaror emas (yuqoridagi izohga q.)
_API_KEY_ACTION = {"disconnect": "KICK", "quarantine": "BLOCK", "restore": "UNBLOCK"}


class UniFiAdapter(BlockingAdapter):
    name = "unifi"

    def can_handle(self, device: TargetDevice) -> bool:
        return device.connection_type == "wifi" and bool(device.mac_address)

    def _try_api_key_action(self, action_type: str, mac: str) -> bool:
        """
        Yangi Integration API (v1) orqali urinadi. Muvaffaqiyatli
        bo'lsa True, aks holda (sozlanmagan, xato, yoki bu amal
        qo'llab-quvvatlanmasa) False qaytaradi.
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

    @staticmethod
    def _configured() -> bool:
        return bool(os.getenv("UNIFI_CONTROLLER_URL", "") and os.getenv("UNIFI_API_KEY", "") and os.getenv("UNIFI_SITE_ID", ""))

    def _do_action(self, action_type: str, mac: str) -> ActionResult:
        """Faqat API Key (token) orqali. Zaxira (login/parol) usuli yo'q."""
        if not self._configured():
            return ActionResult(
                False,
                "UniFi Controller'ga ulanib bo'lmadi (UNIFI_CONTROLLER_URL/UNIFI_API_KEY/UNIFI_SITE_ID sozlanmagan)",
                self.name,
            )
        if self._try_api_key_action(action_type, mac):
            return ActionResult(True, f"UniFi (API Key): {action_type} muvaffaqiyatli bajarildi ({mac})", self.name)
        return ActionResult(
            False,
            f"UniFi API Key orqali {action_type} muvaffaqiyatsiz (ulanish xatosi yoki bu amal qo'llab-quvvatlanmaydi)",
            self.name,
        )

    def disconnect(self, device: TargetDevice) -> ActionResult:
        # darhol uzadi, lekin qurilma qayta ulanishga urinishi mumkin
        return self._do_action("disconnect", device.mac_address)

    def quarantine(self, device: TargetDevice) -> ActionResult:
        # to'liq bloklaydi, admin "restore" bilan qaytarmaguncha ulana olmaydi
        return self._do_action("quarantine", device.mac_address)

    def restore(self, device: TargetDevice) -> ActionResult:
        return self._do_action("restore", device.mac_address)
