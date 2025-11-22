import logging
from ocpp.v16 import ChargePoint
from ocpp.v16 import call_result
from detectors.time_shift_detector import TimeShiftDetector

logger = logging.getLogger("emuocpp.server")

# Global detector instance
time_shift_detector = TimeShiftDetector()


class CentralSystemCP(ChargePoint):
    """
    EmuOCPP Central System ve TIME-SHIFT anomaly kontrolü.
    """

    @on('MeterValues')
    async def on_meter_values(self, connector_id, meter_value, **kwargs):
        station_id = self.id

        # OCPP MeterValues formatı:
        # meter_value: [{"timestamp": "2025-04-11T02:14:55Z", "sampledValue": [...]}]
        timestamp = meter_value[0].get("timestamp")

        if timestamp:
            valid = time_shift_detector.check_timestamp(station_id, timestamp)

            if not valid:
                logger.warning(f"{station_id} | DB write skipped due to TIME-SHIFT anomaly")
                await self.force_ntp_sync()
                return call_result.MeterValues()

        logger.info(f"{station_id} | DB write OK | ts={timestamp}")
        return call_result.MeterValues()

    async def force_ntp_sync(self):
        """
        Örnek NTP Sync tetikleyici.
        Gerçekte sistem komutu çalıştırılabilir.
        """
        logger.info("NTP sync restarted...")