"""
Anomaly Detection - statistik (Z-score) yondashuv, ma'lumotlar bazasidan
mustaqil (test qilish oson bo'lishi uchun).

Z-score formulasi: z = (kuzatilgan_qiymat - o'rtacha) / standart_og'ish

Agar |z| standart chegaradan (odatda 3.0 - "3-sigma qoidasi") oshsa,
bu qiymat statistik jihatdan "kutilmagan" hisoblanadi.
"""
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class Baseline:
    mean_events_per_hour: float
    stddev_events_per_hour: float
    typical_active_hours: List[int]   # 0-23 orasidagi soatlar
    sample_size: int


def compute_baseline(event_timestamps: List[datetime], min_stddev: float = 0.5) -> Optional[Baseline]:
    """
    Berilgan vaqt belgilaridan (timestamp) soatlik faollik profilini
    hisoblaydi.

    `min_stddev` - agar haqiqiy standart og'ish juda kichik bo'lsa
    (masalan qurilma har doim aynan bir xil sonda so'rov yuborsa),
    Z-score sun'iy ravishda haddan tashqari katta chiqib ketishining
    oldini olish uchun minimal qiymat qo'llaniladi.
    """
    if not event_timestamps:
        return None

    # Har bir (kun, soat) juftligi uchun nechta hodisa bo'lganini sanaymiz
    hourly_counts = Counter()
    hour_activity = defaultdict(int)  # soat -> necha marta shu soatda faollik bo'lgan

    for ts in event_timestamps:
        bucket = (ts.date(), ts.hour)
        hourly_counts[bucket] += 1

    for (_, hour), count in hourly_counts.items():
        hour_activity[hour] += count

    counts = list(hourly_counts.values())
    mean_val = statistics.mean(counts)
    stddev_val = statistics.pstdev(counts) if len(counts) > 1 else 0.0
    stddev_val = max(stddev_val, min_stddev)

    # "Odatiy faol soatlar" - umumiy faollikning kamida 5%'i shu soatga to'g'ri keladigan soatlar
    total_activity = sum(hour_activity.values())
    threshold = max(1, total_activity * 0.05)
    typical_hours = sorted(h for h, cnt in hour_activity.items() if cnt >= threshold)

    return Baseline(
        mean_events_per_hour=mean_val,
        stddev_events_per_hour=stddev_val,
        typical_active_hours=typical_hours,
        sample_size=len(counts),
    )


def z_score(observed: float, mean: float, stddev: float) -> float:
    if stddev == 0:
        stddev = 0.5  # nolga bo'lishdan saqlanish
    return (observed - mean) / stddev


@dataclass
class AnomalyResult:
    is_anomalous: bool
    z_score: float
    reason: str


def detect_anomaly(
    observed_count: int,
    observed_hour: int,
    baseline: Baseline,
    z_threshold: float = 3.0,
    off_hours_min_count: int = 5,
) -> AnomalyResult:
    """
    Joriy soatdagi faollikni baseline bilan solishtiradi.

    Ikki xil anomaliya turi aniqlanadi:
      1. Hajm anomaliyasi: hodisalar soni statistik jihatdan kutilmagan
         darajada ko'p (Z-score > chegara).
      2. Vaqt anomaliyasi: qurilma odatda faol bo'lmagan soatda
         (typical_active_hours'da yo'q) sezilarli faollik ko'rsatgan.
    """
    z = z_score(observed_count, baseline.mean_events_per_hour, baseline.stddev_events_per_hour)

    if z > z_threshold:
        return AnomalyResult(
            True, z,
            f"Hajm anomaliyasi: soat {observed_hour}:00'da {observed_count} ta hodisa "
            f"(odatiy o'rtacha: {baseline.mean_events_per_hour:.1f}, Z-score={z:.1f})",
        )

    if (
        baseline.typical_active_hours
        and observed_hour not in baseline.typical_active_hours
        and observed_count >= off_hours_min_count
    ):
        return AnomalyResult(
            True, z,
            f"Vaqt anomaliyasi: odatda faol bo'lmagan soat {observed_hour}:00'da "
            f"{observed_count} ta hodisa (odatiy faol soatlar: {baseline.typical_active_hours})",
        )

    return AnomalyResult(False, z, "Normal faollik")
