"""
RabbitMQ Client - yangi TZ 17-bo'lim (Queue: RabbitMQ).

Hozirgi tizim navbat-asosida polling orqali ishlaydi (har bir engine
`checked=False` kabi bayroqlarni SQL orqali tekshiradi). Bu kichik-o'rta
yuklamada (minglab hodisa/soniya) yaxshi ishlaydi, lekin yuqori yuklamada
(100 000+ events/sec, yangi TZ 21-bo'lim) baza ustidagi doimiy polling
so'rovlari cho'ntak (bottleneck) bo'lib qoladi.

Bu modul **producer/consumer** arxitekturasini qo'shadi - collector
(masalan syslog server) xabarni to'g'ridan-to'g'ri bazaga yozish o'rniga
navbatga (queue) joylaydi, alohida worker jarayon(lar) esa navbatdan
o'qib, bazaga yozadi. Bu ikki muhim afzallik beradi:
  1. Collector sekinlashmaydi (baza band bo'lsa ham xabarni "otib
     yuboradi" va davom etadi - UDP paket yo'qotmaslik uchun muhim).
  2. Worker'larni istalgancha ko'paytirish mumkin (`--scale` orqali) -
     gorizontal miqyoslanish (yangi TZ 21-bo'lim: Horizontal Scaling).

`pika` kutubxonasi (RabbitMQ uchun rasmiy tavsiya etilgan Python client).
"""
import json
import logging
import os
import time
from typing import Callable, Optional

import pika
from pika.exceptions import AMQPConnectionError

logger = logging.getLogger("rabbitmq_client")
logging.getLogger("pika").setLevel(logging.WARNING)  # pika juda ko'p so'zli INFO log beradi

# `guest` faqat brokerning localhost'idan ishlaydi va konteynerlararo
# ulanishda muvaffaqiyatsiz bo'ladi. URL production'da majburiy Secret/.env
# orqali beriladi.
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "")
RABBITMQ_RETRY_ATTEMPTS = int(os.getenv("RABBITMQ_RETRY_ATTEMPTS", "5"))
RABBITMQ_RETRY_DELAY = float(os.getenv("RABBITMQ_RETRY_DELAY", "2"))


def get_connection() -> pika.BlockingConnection:
    """
    RabbitMQ'ga ulanadi, vaqtincha xatoliklarda avtomatik qayta urinadi
    (masalan konteyner ishga tushayotganda RabbitMQ hali tayyor
    bo'lmasligi mumkin - Docker Compose'da `depends_on` health-check
    bilan birga ishlatilishi kerak, lekin bu qo'shimcha himoya qatlami).
    """
    if not RABBITMQ_URL:
        raise RuntimeError("RABBITMQ_URL sozlanmagan; queue profili ishga tushirilmadi")

    last_exc = None
    for attempt in range(1, RABBITMQ_RETRY_ATTEMPTS + 1):
        try:
            params = pika.URLParameters(RABBITMQ_URL)
            return pika.BlockingConnection(params)
        except AMQPConnectionError as exc:
            last_exc = exc
            logger.warning(f"RabbitMQ'ga ulanish urinishi {attempt}/{RABBITMQ_RETRY_ATTEMPTS} muvaffaqiyatsiz: {exc}")
            if attempt < RABBITMQ_RETRY_ATTEMPTS:
                time.sleep(RABBITMQ_RETRY_DELAY)
    raise last_exc


def declare_queue(channel, queue_name: str, durable: bool = True):
    """Navbatni e'lon qiladi (mavjud bo'lmasa yaratadi). `durable=True` -
    RabbitMQ qayta ishga tushsa ham navbat saqlanib qoladi."""
    channel.queue_declare(queue=queue_name, durable=durable)


def publish_json(queue_name: str, data: dict, persistent: bool = True) -> bool:
    """
    Ma'lumotni JSON sifatida navbatga joylaydi.
    Muvaffaqiyatli bo'lsa True, xatolik bo'lsa False qaytaradi
    (exception ko'tarmaydi - chaqiruvchi kodni to'xtatmaslik uchun).
    """
    try:
        conn = get_connection()
        channel = conn.channel()
        declare_queue(channel, queue_name)
        channel.basic_publish(
            exchange="",
            routing_key=queue_name,
            body=json.dumps(data, ensure_ascii=False).encode("utf-8"),
            properties=pika.BasicProperties(
                delivery_mode=2 if persistent else 1,  # 2 = disk'ga yozish (durable)
                content_type="application/json",
            ),
        )
        conn.close()
        return True
    except Exception as exc:
        logger.error(f"RabbitMQ'ga yozishda xatolik ({queue_name}): {exc}")
        return False


def consume_batch(
    queue_name: str,
    handler: Callable[[dict], None],
    max_messages: Optional[int] = None,
    timeout_seconds: float = 5.0,
) -> int:
    """
    Navbatdan xabarlarni o'qib, har birini `handler(data: dict)` orqali
    qayta ishlaydi. `handler` xatolik bermasa xabar tasdiqlanadi (ack) -
    xatolik bersa xabar navbatga qaytariladi (nack, requeue=True) - shu
    orqali vaqtincha xatoliklarda (masalan baza band) xabar yo'qolmaydi.

    Qaytaradi: muvaffaqiyatli qayta ishlangan xabarlar soni.
    """
    conn = get_connection()
    channel = conn.channel()
    declare_queue(channel, queue_name)

    processed = 0
    start_time = time.time()

    while True:
        if max_messages is not None and processed >= max_messages:
            break
        if time.time() - start_time > timeout_seconds:
            break

        method, properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
        if method is None:
            time.sleep(0.2)
            continue

        try:
            data = json.loads(body.decode("utf-8"))
            handler(data)
            channel.basic_ack(delivery_tag=method.delivery_tag)
            processed += 1
        except Exception as exc:
            logger.error(f"Xabarni qayta ishlashda xatolik: {exc}")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    conn.close()
    return processed


def queue_depth(queue_name: str) -> Optional[int]:
    """Navbatdagi (hali o'qilmagan) xabarlar sonini qaytaradi (monitoring uchun)."""
    try:
        conn = get_connection()
        channel = conn.channel()
        result = channel.queue_declare(queue=queue_name, durable=True, passive=True)
        count = result.method.message_count
        conn.close()
        return count
    except Exception as exc:
        logger.error(f"Navbat chuqurligini o'qib bo'lmadi ({queue_name}): {exc}")
        return None


def health_check() -> bool:
    """RabbitMQ serveriga ulanish mumkinligini tekshiradi (dashboard/monitoring uchun)."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False
