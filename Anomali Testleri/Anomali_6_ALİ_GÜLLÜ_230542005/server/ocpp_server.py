import asyncio
import json
import logging
import os
import websockets
from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call_result

# ---- OCPP ChargePoint Class ----
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
SERVER_LOG_FILE = os.path.join(LOG_DIR, "server_run.log")

# ---- Logging setup (file + console) ----
_root_logger_initialized = False
if not _root_logger_initialized:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(SERVER_LOG_FILE, encoding="utf-8"),
            logging.StreamHandler()
        ],
    )
    _root_logger_initialized = True

app_logger = logging.getLogger("app")
security_logger = logging.getLogger("security")


# ---- OCPP ChargePoint Class ----
class ChargePoint(cp):
    @on('BootNotification')
    async def on_boot_notification(self, chargePointModel=None, chargePointVendor=None, **kwargs):
        app_logger.info(f"BootNotification from {self.id}: {chargePointVendor}/{chargePointModel}")
        return call_result.BootNotificationPayload(
            current_time='2025-11-11T00:00:00Z',
            interval=10,
            status='Accepted'
        )

    async def route_message(self, raw_msg):
        """
        Wrap base router to emit structured security logs for received frames.
        """
        # Try to parse action if this is an array form: [MessageTypeId, UniqueId, Action, Payload]
        action = None
        try:
            parsed = json.loads(raw_msg)
            if isinstance(parsed, list) and len(parsed) >= 3:
                action = parsed[2]
        except Exception:
            pass

        # Log security event (receive)
        try:
            peer = getattr(self._connection, "remote_address", None)
            remote = f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer)
        except Exception:
            remote = "unknown"

        security_event = {
            "event": "ocpp_rx",
            "station_id": self.id,
            "remote": remote,
            "action": action,
            "raw_len": len(raw_msg) if isinstance(raw_msg, str) else 0
        }
        security_logger.info(json.dumps(security_event, ensure_ascii=False))

        return await super().route_message(raw_msg)

# ---- Connection handler (for websockets >=12) ----
async def on_connect(connection):
    # Yeni API: connection.request.path ile erişiliyor
    path = getattr(connection, "request", None)
    if path:
        charge_point_id = path.path.strip('/')
    else:
        charge_point_id = "Unknown_CP"

    # Attempt to capture origin header for anomaly checks
    try:
        headers = getattr(path, "headers", None) or getattr(connection, "request_headers", {})
        origin_id = headers.get("Origin-CSMS-ID") or headers.get("Origin-CsMs-Id") or headers.get("X-Origin-CSMS-ID")
    except Exception:
        origin_id = None

    app_logger.info(f"Connection from: {charge_point_id}")
    security_logger.info(json.dumps({
        "event": "ws_connect",
        "station_id": charge_point_id,
        "origin_id": origin_id or "unknown"
    }, ensure_ascii=False))

    cp_obj = ChargePoint(charge_point_id, connection)
    try:
        await cp_obj.start()
    except Exception as e:
        app_logger.error(f"Connection closed or error: {e}")

# ---- Main entry ----
async def main():
    app_logger.info("CSMS running at ws://localhost:9000")
    async with websockets.serve(
        on_connect,
        "0.0.0.0",
        9000,
        subprotocols=["ocpp1.6", "ocpp1.6j", "ocpp2.0.1"]
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
