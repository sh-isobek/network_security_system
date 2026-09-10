"""
Device Identity - qurilmani IP emas, MAC manzil orqali aniqlash.

MUHIM PRODUKSIYA XATOSI (bu modul aynan shu sababli qo'shildi):
`devices` jadvali `ip_address` ustuni bo'yicha UNIQUE edi, va barcha
"upsert" funksiyalari (parser_engine, asset_inventory) qurilmani FAQAT
IP orqali qidirardi. DHCP muhitida IP - vaqtinchalik: qurilma
oflayn bo'lib, keyin qayta ulanganda (yoki lease yangilanganda) ko'pincha
BOSHQA IP oladi. Natijada: eski IP'dagi qator "oflayn" bo'lib qoladi,
YANGI IP uchun esa BUTUNLAY YANGI `Device` qatori yaraladi - garchi bu
aynan O'SHA fizik qurilma (bir xil MAC) bo'lsa ham. Vaqt o'tishi bilan
bu `devices` jadvalini haqiqiy qurilmalar sonidan ancha ko'p, "arvoh"
duplikatlar bilan to'ldirib boradi (foydalanuvchi xabar qilgan holat:
Dashboard'da "724 ta qurilma" - buning katta qismi shu duplikatlar).

Yechim: MAC manzil (mavjud bo'lsa) - asosiy, barqaror identifikator.
Qurilma avval MAC bo'yicha qidiriladi; topilsa va uning IP'si
o'zgargan bo'lsa, xuddi shu qatorning `ip_address`si yangilanadi (yangi
qator yaratilmaydi). MAC berilmagan manbalar (Suricata/Zeek/fayl
tekshiruvi kabi - bular faqat IP biladi) uchun eski, IP-asosli
xatti-harakat saqlanadi (o'zgarmaydi - ular baribir MAC bermaydi).

IP kolliziyasi (DHCP o'sha IP'ni oldin BOSHQA MAC'ga bergan, o'sha eski
qator hali "database"da bor): `ip_address` UNIQUE bo'lgani uchun ikkala
qatorda bir xil IP qololmaydi. Bu holatda eski (kolliziyaga tushgan)
qatorning tarixi (Event/Alert/WebAccessLog/DeviceBaseline) YO'QOTILMAYDI
- ular MAC-qatoriga ko'chiriladi, so'ng bo'sh qolgan eski qator
o'chiriladi (`_merge_device`). Bu real, kam uchraydigan holat, lekin
xavfsizlik monitoring tizimida tarixiy Alert/Event'ni jimgina yo'qotish
maqbul emas - shuning uchun o'chirishdan oldin har doim ko'chiriladi.
"""
from sqlalchemy import func

from db.models import Device, Event, Alert, WebAccessLog, DeviceBaseline, utcnow


def _clean_mac(mac):
    """
    Faqat bo'sh/None qiymatlarni tozalaydi - MAC formatini (chiziqcha/
    ikki nuqta, katta/kichik harf) O'ZGARTIRMAYDI. Manbalar (Kerio
    parser, ARP scanner) o'zlari allaqachon o'z formatida izchil
    normallashtiradi (masalan Kerio har doim katta harf+ikki nuqta
    beradi); Ruijie esa butunlay boshqa, nuqtali Cisco notatsiyasida
    beradi (`aabb.ccdd.9001`) - buni qayta yozish saqlangan qiymatni
    manba hujjatidan/UI'dan farqli qilib qo'yar edi. Qidiruv esa
    quyida katta/kichik harfga SEZGIR EMAS (`func.upper`) - shuning
    uchun format o'zgartirilmasa ham ishonchli mos keladi.
    """
    if not mac:
        return None
    mac = mac.strip()
    return mac or None


def _merge_device(session, keep: Device, remove: Device):
    """
    `remove` qurilmaning barcha tarixini `keep`ga ko'chirib, so'ng
    `remove`ni o'chiradi. Faqat IP kolliziyasi (yuqoriga qarang) sodir
    bo'lganda chaqiriladi - hech qanday Event/Alert/WebAccessLog
    yo'qolmaydi.
    """
    session.query(Event).filter(Event.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )
    session.query(Alert).filter(Alert.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )
    session.query(WebAccessLog).filter(WebAccessLog.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )

    # DeviceBaseline.device_id UNIQUE - ikkalasida ham bo'lishi mumkin.
    keep_baseline = session.query(DeviceBaseline).filter(DeviceBaseline.device_id == keep.id).first()
    remove_baseline = session.query(DeviceBaseline).filter(DeviceBaseline.device_id == remove.id).first()
    if remove_baseline is not None:
        if keep_baseline is None:
            remove_baseline.device_id = keep.id
        else:
            session.delete(remove_baseline)

    # Boy ma'lumotni saqlab qolish (keep'da hali bo'sh bo'lgan maydonlar uchun)
    for attr in ("hostname", "vendor", "device_type", "os_guess", "open_ports", "discovery_source"):
        if not getattr(keep, attr, None) and getattr(remove, attr, None):
            setattr(keep, attr, getattr(remove, attr))

    session.delete(remove)
    session.flush()


def find_or_create_device(session, ip: str, mac: str = None, source: str = None, **extra_fields) -> Device:
    """
    Qurilmani MAC (mavjud bo'lsa) orqali, aks holda IP orqali topadi
    yoki yaratadi. `extra_fields` - `Device` modelidagi boshqa
    ustunlarga to'g'ridan-to'g'ri yoziladigan qo'shimcha qiymatlar
    (masalan `hostname`, `vendor`, `discovery_source`) - `None`
    qiymatlar e'tiborsiz qoldiriladi (mavjud ma'lumotni "pasaytirmaslik"
    uchun).
    """
    mac = _clean_mac(mac)
    device = None
    if mac:
        device = (
            session.query(Device)
            .filter(func.upper(Device.mac_address) == mac.upper())
            .first()
        )

    if device is None:
        device = session.query(Device).filter(Device.ip_address == ip).first()

    if device is None:
        device = Device(ip_address=ip, mac_address=mac, source=source)
        session.add(device)
        session.flush()
    else:
        if device.ip_address != ip:
            conflict = (
                session.query(Device)
                .filter(Device.ip_address == ip, Device.id != device.id)
                .first()
            )
            if conflict is not None:
                _merge_device(session, keep=device, remove=conflict)
            device.ip_address = ip
        if mac and not device.mac_address:
            device.mac_address = mac
        if source and not device.source:
            device.source = source

    for key, value in extra_fields.items():
        if value is None:
            continue
        if key == "discovery_source" and device.discovery_source:
            # MUHIM: allaqachon boyroq manba orqali topilgan bo'lsa
            # (masalan ARP - MAC bilan), ICMP kabi kambag'alroq manba
            # buni "pasaytirmasligi" kerak.
            continue
        setattr(device, key, value)

    device.last_seen = utcnow()
    return device
