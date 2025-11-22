import logging
from datetime import datetime

logger = logging.getLogger("emuocpp.time_shift")


class TimeShiftDetector:
    """
    TIME-SHIFT (Zaman Kayması) anomalisini tespit eden sınıf.

    Mantık:
        - Gelen timestamp bir önceki timestamp'tan daha eskiyse anomali oluşur.
        - timestamp(t+1) < timestamp(t) → TIME_SHIFT
        - Diff saniye cinsinden hesaplanır.

    Kullanım:
        detector = TimeShiftDetector()
        detector.check_timestamp("STATION_01", "2025-04-11T02:14:55Z")
    """

    def __init__(self, threshold_seconds: int = -1):
        self.last_timestamp = None
        self.threshold_seconds = threshold_seconds

    @staticmethod
    def parse_iso8601(ts: str) -> datetime:
        """ISO-8601 formatındaki zaman damgasını datetime'a çevirir."""
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def check_timestamp(self, station_id: str, timestamp: str) -> bool:
        """
        Zaman kayması olup olmadığını kontrol eder.

        Parametreler:
            station_id (str): Şarj istasyonu ID'si
            timestamp (str): OCPP'den gelen ISO8601 timestamp

        Returns:
            bool:
                True → Anomali yok.
                False → TIME-SHIFT tespit edildi.
        """
        try:
            current_ts = self.parse_iso8601(timestamp)
        except Exception:
            logger.error(f"{station_id} | invalid timestamp format: {timestamp}")
            return False

        if self.last_timestamp is None:
            self.last_timestamp = current_ts
            return True

        diff_seconds = (current_ts - self.last_timestamp).total_seconds()

        # TIME-SHIFT kontrolü
        if diff_seconds < self.threshold_seconds:
            logger.error(
                f"{datetime.utcnow()} | STATION_ID={station_id} | "
                f"time_diff={diff_seconds} | anomaly=TIME_SHIFT"
            )
            return False

        self.last_timestamp = current_ts
        return True