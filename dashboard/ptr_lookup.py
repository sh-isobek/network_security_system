"""
Live Map: tashqi IP manzillar uchun nom aniqlash (taxmin EMAS, ikkita
haqiqiy manba orqali).

Muammo: `/api/topology` avval tashqi manzillarni doim xom IP sifatida
ko'rsatardi - hatto Kerio o'zi ulanish paytida teskari DNS nomini aniq
bergan (`Event.dest_domain`) hollarda ham, chunki so'rov bu ustunni
umuman o'qimasdi. Bundan tashqari, Kerio hech qanday nom bermagan
IP'lar uchun ham (masalan Kerio'ning o'zi DNS so'rovini ko'rmagan -
DoH yoki to'g'ridan-to'g'ri IP ulanish) ko'pincha HAQIQIY PTR yozuvi
mavjud bo'ladi (masalan bulutli provayderlar - Google/AWS/Cloudflare).

Bu modul FAQAT ikkinchi holat uchun - `Event.dest_domain`da yo'q
IP'lar uchun - haqiqiy teskari DNS (PTR) so'rovini yuboradi:
- Natija keshlanadi (muvaffaqiyatli - 24 soat, PTR topilmadi - 6 soat)
  - Live Map 15 soniyada bir yangilanadi, keshsiz har safar bir xil
    IP'lar uchun qayta-qayta DNS so'rov yuborilardi.
- Har bir IP uchun bitta so'rov (parallel `ThreadPoolExecutor`,
  dublikat so'rov yubormaslik uchun `_PENDING`).
- Dashboard so'rovi PTR javobini FAQAT qisqa (`_WAIT_TIMEOUT`) muddat
  kutadi - sekin/javobsiz DNS butun sahifani osiltirmasligi uchun.
  Kutish tugagach ham fon oqimi davom etadi va natija keyingi
  so'rovlar uchun keshga tushadi.

Real tekshiruv (`run_full_test.py`): `socket.gethostbyaddr`ni soxta
funksiya bilan almashtirib - keshlash, muvaffaqiyatsiz javobning
qisqaroq TTL bilan saqlanishi, va timeout ichida ulgurmagan so'rov
xom IP bilan (lekin xatosiz) qaytishi tasdiqlangan.
"""
import concurrent.futures
import socket
import threading
import time

_CACHE_LOCK = threading.Lock()
_CACHE = {}          # ip -> (hostname_yoki_None, muddati_tugash_vaqti)
_PENDING = {}         # ip -> Future (davom etayotgan so'rovlar, dublikatni oldini olish uchun)
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="ptr-lookup")

_POSITIVE_TTL_SECONDS = 24 * 3600
_NEGATIVE_TTL_SECONDS = 6 * 3600
_LOOKUP_TIMEOUT_SECONDS = 1.0   # bitta DNS so'rovining o'zi uchun
_WAIT_TIMEOUT_SECONDS = 1.5     # dashboard so'rovi umumiy qancha kutishi


def _lookup_one(ip: str):
    try:
        socket.setdefaulttimeout(_LOOKUP_TIMEOUT_SECONDS)
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname.rstrip(".").lower()
    except Exception:
        return None


def _submit(ip: str):
    """(future, yangi_yuborildimi) qaytaradi."""
    with _CACHE_LOCK:
        fut = _PENDING.get(ip)
        if fut is not None and not fut.done():
            return fut, False
        fut = _EXECUTOR.submit(_lookup_one, ip)
        _PENDING[ip] = fut

    def _on_done(f, ip=ip):
        try:
            hostname = f.result()
        except Exception:
            hostname = None
        ttl = _POSITIVE_TTL_SECONDS if hostname else _NEGATIVE_TTL_SECONDS
        with _CACHE_LOCK:
            _CACHE[ip] = (hostname, time.time() + ttl)
            if _PENDING.get(ip) is f:
                del _PENDING[ip]

    fut.add_done_callback(_on_done)
    return fut, True


def resolve_ptr_batch(ips, wait_seconds=None) -> dict:
    """Berilgan IP'lar uchun {ip: hostname_yoki_None} qaytaradi.

    Keshda (hali muddati o'tmagan) bo'lganlar darhol qaytadi. Yo'q
    bo'lganlar uchun HAQIQIY DNS so'rovi yuboriladi, lekin javob
    `_WAIT_TIMEOUT_SECONDS` ichida kelmasa, o'sha IP natijada yo'q
    (chaqiruvchi buni "hozircha nomalum" deb, xom IP bilan ko'rsatishi
    kerak) - fon so'rovi baribir davom etadi, keshga keyinroq tushadi.

    `wait_seconds=0` - umuman kutmaydi: faqat keshdagi natijalar
    qaytadi, yangi IP'lar uchun so'rov fonda yuboriladi.
    """
    now = time.time()
    result = {}
    to_resolve = []
    with _CACHE_LOCK:
        for ip in ips:
            cached = _CACHE.get(ip)
            if cached is not None and cached[1] > now:
                result[ip] = cached[0]
            else:
                to_resolve.append(ip)

    if not to_resolve:
        return result

    # FAQAT shu chaqiruvda YANGI yuborilgan so'rovlar kutiladi. Oldingi
    # chaqiruvdan beri javobsiz turgan (sekin/javobsiz DNS) IP'lar uchun
    # qayta kutilmaydi - aks holda Live Map (15 soniyada bir) har safar
    # to'liq `_WAIT_TIMEOUT_SECONDS`ni yo'qotib, sekin ochilardi.
    futures = {}
    for ip in to_resolve:
        fut, is_new = _submit(ip)
        if is_new:
            futures[fut] = ip
        elif fut.done():
            futures[fut] = ip
    if not futures:
        return result
    timeout = _WAIT_TIMEOUT_SECONDS if wait_seconds is None else wait_seconds
    done, _pending = concurrent.futures.wait(futures, timeout=timeout)
    for fut in done:
        ip = futures[fut]
        try:
            result[ip] = fut.result()
        except Exception:
            result[ip] = None
    return result
