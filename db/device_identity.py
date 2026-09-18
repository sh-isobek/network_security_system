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

from db.models import Device, Event, Alert, WebAccessLog, DeviceBaseline, Incident, utcnow


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


def _lock_devices_in_order(session, id_a: int, id_b: int):
    """
    PRODUKSIYADA HAQIQATAN TOPILGAN POYGA HOLATI (bu funksiya aynan shu
    sababli qo'shildi): `find_or_create_device()`ni bir vaqtning o'zida
    chaqiradigan bir necha mustaqil jarayon bor (`parser_engine`,
    `network_discovery`/`asset_inventory`, va bilvosita `ueba_engine`
    `DeviceBaseline` yozadi). Ikkalasi ham bir xil IP-kolliziya juftligini
    (masalan qurilma 25 va 741) BIR VAQTDA birlashtirmoqchi bo'lganda,
    ikkita real xato kuzatildi:
      1) `psycopg2.errors.DeadlockDetected` - ikkala jarayon "events"
         jadvalini QARAMA-QARSHI tartibda (A: 741->25, B: 25->741)
         yangilashga urinib, PostgreSQL'ning o'zi buni aniqlab, bittasini
         bekor qiladi.
      2) `ForeignKeyViolation` - `_merge_device` tarixni ko'chirib
         bo'lgach, `remove` qatorni o'chirishga ulguradi, lekin XUDDI
         SHU ORALIQDA boshqa jarayon (masalan UEBA) ESKI (hali
         o'chirilmagan) `remove.id`ga ishora qiluvchi YANGI
         `DeviceBaseline` yozib ulguradi - o'chirish keyin "hali ham
         foydalanilmoqda" xatosi bilan muvaffaqiyatsiz bo'ladi.

    Yechim: ikkala qurilma qatorini har doim BIR XIL (kichik ID'dan
    kattaga) tartibda `SELECT ... FOR UPDATE` bilan qulflaymiz:
      - Bir xil tartib -> ikkita jarayon hech qachon "aylanma kutish"
        (circular wait) holatiga tushmaydi -> (1) deadlock butunlay
        oldini oladi (navbat bilan ishlaydi, xato bermaydi).
      - `remove` qatorni FOR UPDATE bilan qulflash - PostgreSQL'ning
        o'zi xorijiy kalit (FK) uchun BOSHQA jarayonning shu qatorga
        ishora qiluvchi INSERT (masalan yangi DeviceBaseline)ini FOR
        KEY SHARE qulfi orqali avtomatik TO'XTATIB TURADI (FOR UPDATE
        va FOR KEY SHARE bir-biriga zid) - biz commit qilib
        (qatorni allaqachon o'chirib) bo'lgunimizcha kutadi -> (2)
        ForeignKeyViolation ham yo'qoladi.

    SQLite'da `FOR UPDATE` sintaksisi qo'llab-quvvatlanmaydi, lekin
    SQLAlchemy'ning sqlite dialekti buni xatosiz, jim o'tkazib
    yuboradi (tekshirilgan) - shuning uchun bu funksiya ikkala bazada
    ham xavfsiz.

    Qaytaradi: qulflangan paytda HAQIQATAN mavjud bo'lgan qatorlar
    ro'yxati (0, 1 yoki 2 ta) - chaqiruvchi buni "kutilgan ikkala qator
    ham hali bormi" tekshiruvi uchun ishlatadi (pastga qarang).
    """
    lo, hi = (id_a, id_b) if id_a <= id_b else (id_b, id_a)
    return session.query(Device).filter(Device.id.in_([lo, hi])).with_for_update().all()


def _merge_device(session, keep: Device, remove: Device):
    """
    `remove` qurilmaning barcha tarixini `keep`ga ko'chirib, so'ng
    `remove`ni o'chiradi. Faqat IP kolliziyasi (yuqoriga qarang) sodir
    bo'lganda chaqiriladi - hech qanday Event/Alert/WebAccessLog
    yo'qolmaydi.
    """
    locked = _lock_devices_in_order(session, keep.id, remove.id)

    # MUHIM (birinchi tuzatishdan KEYIN, real concurrency testi orqali
    # topilgan IKKINCHI qatlam): qulf o'zi deadlock/FK xatosini
    # oldini oladi, lekin QARAMA-QARSHI yo'nalishda (A<-B VA B<-A)
    # ikkita mustaqil chaqiruv bo'lganda - ikkinchi bo'lib navbatga
    # yetgan chaqiruvning `keep`/`remove` Python obyektlari ESKI
    # bo'lishi mumkin (ular qulfdan OLDIN, hali kolliziya hal
    # qilinmagan paytda yuklangan edi). Agar shu oraliqda BOSHQA
    # jarayon aynan shu juftlikni (teskari yo'nalishda) allaqachon
    # birlashtirib ulgurgan bo'lsa, `keep` yoki `remove`ning BIRI
    # ENDI MAVJUD EMAS - bu holda kolliziya ALLAQACHON hal qilingan,
    # shuning uchun bu chaqiruv XATOSIZ, hech narsa qilmasdan chiqib
    # ketishi kerak (aks holda "eskirgan `keep.id`ga device_id
    # o'rnatish" xuddi shu ForeignKeyViolation'ni QAYTA hosil qiladi).
    locked_ids = {d.id for d in locked}
    if keep.id not in locked_ids or remove.id not in locked_ids:
        return

    session.query(Event).filter(Event.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )
    session.query(Alert).filter(Alert.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )
    session.query(WebAccessLog).filter(WebAccessLog.device_id == remove.id).update(
        {"device_id": keep.id}, synchronize_session=False
    )
    # MUHIM (production'da HAQIQATAN topilgan real bug - shu tuzatish
    # aynan shu sabab bilan qo'shildi): `Incident` (Correlation Engine,
    # `_merge_device()`dan KEYINGI bosqichda qo'shilgan) ham
    # `device_id` orqali `devices.id`ga FK bog'langan, lekin bu yerda
    # HECH QACHON reassign qilinmagan edi - Event/Alert/WebAccessLog
    # yozilgandan keyin, `Incident` FK bosqichi qo'shimcha keyingi ish
    # sifatida kiritilib, shu funksiyaga qo'shilishi UNUTILGAN edi.
    # Natijada: IP-kolliziya bo'lib, `remove` qurilmada bog'liq Incident
    # bo'lsa, `session.delete(remove)` har doim `ForeignKeyViolation`
    # bilan MUVAFFAQIYATSIZ bo'lardi - bu `parser_engine`/`unifi_sync`
    # kabi xizmatlarni HAR TSIKLDA (session rollback qilib, hech narsa
    # commit qilinmasdan) qulatib, haqiqiy production'da uzluksiz xato
    # tsikliga olib kelgan edi (real, kuzatilgan holat).
    session.query(Incident).filter(Incident.device_id == remove.id).update(
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

        # MUHIM (production'da HAQIQATAN takrorlangan xato, real diagnostika
        # orqali topilgan - AYNAN SHU narsa deadlock-tuzatishidan KEYIN ham
        # xatoni davom ettirgan edi): `DeviceBaseline`da `Device`ga
        # `relationship()` E'LON QILINMAGAN (faqat xom `ForeignKey` ustun) -
        # `Event`/`Alert`dan farqli. Bunday holda SQLAlchemy'ning avtomatik
        # flush-tartiblash (dependency sorting) mexanizmi ikkala mustaqil
        # `session.delete(...)` chaqiruvi orasidagi FK bog'liqlikni ISHONCHLI
        # ANIQLAY OLMAYDI (bu haqiqiy, PostgreSQL'ga qarshi qo'lda
        # tasdiqlangan SQLAlchemy xatti-harakati) - natijada bitta
        # `session.flush()`da "devices" qatori "device_baselines"dan OLDIN
        # o'chirilishga urinishi mumkin, garchi kod "avval baseline, keyin
        # device" tartibida yozilgan bo'lsa ham. Aniq oraliq `flush()` -
        # baseline o'zgarishini (reassign YOKI delete) DARHOL, `remove`
        # o'chirilishidan OLDIN bazaga yuboradi - shu bilan tartib
        # KAFOLATLANADI (endi navbatga/vaqtga bog'liq emas).
        session.flush()

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

                # MUHIM (real concurrency testi orqali topilgan): agar
                # boshqa mustaqil jarayon AYNAN SHU juftlikni TESKARI
                # yo'nalishda (bizning `device`imizni "remove" deb
                # hisoblab) allaqachon birlashtirib ulgurgan bo'lsa,
                # bizning `device` obyektimiz ENDI BAZADA MAVJUD EMAS -
                # shu holda unga `ip_address` yozish (pastdagi qator)
                # "0 qator yangilandi" bilan jimgina hech narsa
                # qilmaydi-yu, keyingi kod (`device.id`) BOSHQA joyda
                # (masalan Event.device_id) ENDI YO'Q qatorga ishora
                # qilib, xuddi shu ForeignKeyViolation'ni QAYTA hosil
                # qiladi. Shuning uchun bunday holatda YANGI, ALLAQACHON
                # (boshqa jarayon tomonidan) to'g'ri IP bilan yangilangan
                # qatorni MAC orqali qayta topib olamiz - bu haqiqiy
                # tirik qator, xavfsiz davom etish mumkin.
                if session.query(Device.id).filter(Device.id == device.id).first() is None:
                    device = (
                        session.query(Device)
                        .filter(func.upper(Device.mac_address) == mac.upper())
                        .first()
                    )
                    if device is None:
                        # Amalda deyarli imkonsiz zaxira holat (boshqa
                        # jarayon nima uchundir MAC'ni ham tozalab
                        # yuborgan bo'lsa) - hech bo'lmasa yangi qator
                        # bilan xavfsiz davom etamiz, jarayon qulamaydi.
                        device = Device(ip_address=ip, mac_address=mac, source=source)
                        session.add(device)
                        session.flush()
                    # HALOL CHEKLOV (juda kam uchraydigan holat): agar
                    # ikkita qurilma AYNAN BIR VAQTDA bir-birining
                    # IP'ini "almashtirib" ulgursa (ikki tomonlama
                    # kolliziya), yuqoridagi yangi qator o'sha
                    # qurilmaning ESKI tarixidan (u allaqachon boshqa
                    # tomonga ko'chirilgan) AJRALGAN holda boshlanadi -
                    # bu ma'lumot yo'qolishi EMAS (tarix saqlanadi,
                    # faqat boshqa qatorda), lekin tarix ikki qatorga
                    # bo'linib qolishi mumkin. Bu - xavfsiz (qulamaydi,
                    # xato bermaydi) tomonni tanlash narxi bo'lgan,
                    # nazariy jihatdan mumkin, lekin amalda deyarli
                    # uchramaydigan chekka holat.

            # Bu nuqtada `device` KAFOLATLANGAN holda haqiqiy, mavjud
            # qatorga ishora qiladi (asl holicha o'zgarmagan, yoki
            # yuqorida real so'rov orqali qayta topilgan/yaratilgan).
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
