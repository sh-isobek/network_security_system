"""
UEBA Engine - yangi TZ 11-bo'lim (Behavior Analysis, Anomaly Detection,
UEBA, Risk Score).

Uchta asosiy funksiya:
  1. compute_baselines()  - har bir qurilma uchun "normal" statistik
                             profilni hisoblaydi (oxirgi N kunlik Event
                             ma'lumotidan).
  2. detect_anomalies()   - joriy soatdagi faollikni baseline bilan
                             solishtirib, anomaliya topilsa Alert yaratadi.
  3. compute_risk_scores() - har bir qurilma uchun 0-100 oralig'ida
                             xavf balli hisoblaydi (so'nggi alertlar +
                             MITRE taktika xilma-xilligi + anomaliyalar).

Ishga tushirish:
    python -m engine.ueba_engine --baselines    # baseline'larni yangilash
    python -m engine.ueba_engine --detect        # anomaliyalarni tekshirish
    python -m engine.ueba_engine --risk-scores   # risk score'larni yangilash
    python -m engine.ueba_engine --all           # barchasi ketma-ket
    python -m engine.ueba_engine --loop          # doimiy tsikl (barchasi)
"""
import argparse
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import Device, Event, Alert, DeviceBaseline, utcnow
from ueba.anomaly_detection import compute_baseline, detect_anomaly

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ueba_engine")

BASELINE_LOOKBACK_DAYS = int(os.getenv("UEBA_BASELINE_LOOKBACK_DAYS", "30"))
MIN_EVENTS_FOR_BASELINE = int(os.getenv("UEBA_MIN_EVENTS", "20"))
Z_THRESHOLD = float(os.getenv("UEBA_Z_THRESHOLD", "3.0"))

# Risk Score og'irliklari
SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 2}
MAX_RISK_SCORE = 100


def compute_baselines_for_all_devices() -> int:
    """Yetarli tarixiy ma'lumotga ega barcha qurilmalar uchun baseline hisoblaydi."""
    session = get_session()
    updated = 0
    try:
        since = utcnow() - timedelta(days=BASELINE_LOOKBACK_DAYS)
        devices = session.query(Device).all()

        for device in devices:
            events = (
                session.query(Event.timestamp)
                .filter(Event.device_id == device.id, Event.timestamp >= since)
                .all()
            )
            timestamps = [e[0] for e in events]

            if len(timestamps) < MIN_EVENTS_FOR_BASELINE:
                continue  # yetarli ma'lumot yo'q - ishonchli baseline hisoblab bo'lmaydi

            baseline = compute_baseline(timestamps)
            if baseline is None:
                continue

            existing = session.query(DeviceBaseline).filter(DeviceBaseline.device_id == device.id).first()
            hours_str = ",".join(str(h) for h in baseline.typical_active_hours)

            if existing:
                existing.mean_events_per_hour = round(baseline.mean_events_per_hour)
                existing.stddev_events_per_hour = round(baseline.stddev_events_per_hour)
                existing.typical_active_hours = hours_str
                existing.lookback_days = BASELINE_LOOKBACK_DAYS
                existing.sample_size = baseline.sample_size
                existing.computed_at = utcnow()
            else:
                session.add(DeviceBaseline(
                    device_id=device.id,
                    mean_events_per_hour=round(baseline.mean_events_per_hour),
                    stddev_events_per_hour=round(baseline.stddev_events_per_hour),
                    typical_active_hours=hours_str,
                    lookback_days=BASELINE_LOOKBACK_DAYS,
                    sample_size=baseline.sample_size,
                ))
            updated += 1

        session.commit()
        logger.info(f"{updated} ta qurilma uchun baseline hisoblandi/yangilandi")
        return updated
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def detect_anomalies(reference_time: datetime = None) -> int:
    """
    Joriy (yoki berilgan) soatdagi faollikni har bir qurilma uchun
    baseline bilan solishtiradi, anomaliya topilsa Alert yaratadi.
    """
    session = get_session()
    anomalies_found = 0
    try:
        ref_time = reference_time or utcnow()
        hour_start = ref_time.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)

        baselines = session.query(DeviceBaseline).all()

        for bl in baselines:
            count = (
                session.query(Event)
                .filter(Event.device_id == bl.device_id, Event.timestamp >= hour_start, Event.timestamp < hour_end)
                .count()
            )
            if count == 0:
                continue

            from ueba.anomaly_detection import Baseline as BaselineDTO
            baseline_dto = BaselineDTO(
                mean_events_per_hour=bl.mean_events_per_hour,
                stddev_events_per_hour=bl.stddev_events_per_hour,
                typical_active_hours=[int(h) for h in bl.typical_active_hours.split(",") if h],
                sample_size=bl.sample_size,
            )

            result = detect_anomaly(count, hour_start.hour, baseline_dto, z_threshold=Z_THRESHOLD)
            if result.is_anomalous:
                # Bir xil soat uchun ikki marta alert yaratmaslik
                already_alerted = (
                    session.query(Alert)
                    .filter(Alert.device_id == bl.device_id, Alert.reason.like(f"UEBA%{hour_start.strftime('%Y-%m-%d %H')}%"))
                    .first()
                )
                if already_alerted:
                    continue

                alert = Alert(
                    device_id=bl.device_id,
                    severity="medium",
                    reason=f"UEBA[{hour_start.strftime('%Y-%m-%d %H')}:00]: {result.reason}",
                    action_taken="TODO: qo'lda tekshirish tavsiya etiladi (xatti-harakat anomaliyasi)",
                    notified=False,
                )
                session.add(alert)
                anomalies_found += 1
                logger.warning(f"UEBA ANOMALIYA: device_id={bl.device_id} - {result.reason}")

        session.commit()
        return anomalies_found
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def compute_risk_scores(lookback_days: int = 30) -> int:
    """
    Har bir qurilma uchun 0-100 oralig'ida Risk Score hisoblaydi:
      - so'nggi N kundagi alertlar (severity bo'yicha og'irlangan)
      - turli MITRE taktikalarining soni (xilma-xillik = yuqoriroq xavf)
    """
    session = get_session()
    updated = 0
    try:
        since = utcnow() - timedelta(days=lookback_days)
        devices = session.query(Device).all()

        for device in devices:
            alerts = session.query(Alert).filter(Alert.device_id == device.id, Alert.timestamp >= since).all()
            if not alerts:
                if device.risk_score != 0:
                    device.risk_score = 0
                    device.risk_score_updated_at = utcnow()
                    updated += 1
                continue

            severity_score = sum(SEVERITY_WEIGHT.get(a.severity, 0) for a in alerts)
            tactic_diversity = len({a.mitre_tactic for a in alerts if a.mitre_tactic})
            diversity_bonus = tactic_diversity * 8

            raw_score = severity_score + diversity_bonus
            final_score = min(MAX_RISK_SCORE, raw_score)

            device.risk_score = final_score
            device.risk_score_updated_at = utcnow()
            updated += 1

        session.commit()
        logger.info(f"{updated} ta qurilma uchun risk score yangilandi")
        return updated
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--baselines", action="store_true")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--risk-scores", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=300)
    args = ap.parse_args()

    def run_all():
        compute_baselines_for_all_devices()
        detect_anomalies()
        compute_risk_scores()

    if args.loop:
        logger.info("UEBA engine tsiklda ishga tushdi")
        while True:
            try:
                run_all()
            except Exception as exc:
                logger.error(f"Tsikl xatoligi: {exc}")
            time.sleep(args.interval)
    elif args.all:
        run_all()
    else:
        if args.baselines:
            compute_baselines_for_all_devices()
        if args.detect:
            detect_anomalies()
        if args.risk_scores:
            compute_risk_scores()
        if not (args.baselines or args.detect or args.risk_scores):
            logger.info("Hech qanday flag berilmadi - --all, --baselines, --detect yoki --risk-scores ishlating")
