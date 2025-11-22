import sys
sys.stdout.reconfigure(encoding='utf-8')
import asyncio
import logging
import websockets
import json
from datetime import datetime
import os

# ======================================================
# LOG AYARLARI
# ======================================================
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/server.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# ======================================================
# OCPP 2.x BENZERİ MESAJ CEVAPLARI
# (CALL -> CALLRESULT: messageTypeId 2 -> 3)
# ======================================================
def make_response(request, payload):
    """
    İstek ile aynı messageId'yi kullanarak CALLRESULT oluşturur.
    """
    return {
        "messageTypeId": 3,                       # CALLRESULT
        "messageId": request.get("messageId", ""),
        "action": request.get("action", ""),
        "payload": payload
    }


def boot_notification_response(request):
    return make_response(request, {
        "status": "Accepted",
        "currentTime": datetime.utcnow().isoformat() + "Z"
    })


def heartbeat_response(request):
    return make_response(request, {
        "currentTime": datetime.utcnow().isoformat() + "Z"
    })


def error_response(request, error_code="InternalError", details=None):
    if details is None:
        details = {}
    return {
        "messageTypeId": 4,  # OCPP'de CALLERROR'a denk
        "messageId": request.get("messageId", ""),
        "action": request.get("action", ""),
        "errorCode": error_code,
        "errorDescription": "Server error",
        "errorDetails": details
    }

# ======================================================
# BUSY / STUCK TEST SENARYOLARI
# ======================================================
async def handle_busy_stuck_scenario(kind: str):
    if kind == "delay":
        logging.warning("Server: Yapay gecikme (5 saniye)")
        await asyncio.sleep(5)

    elif kind == "stuck":
        logging.error("Server: STUCK mod — bu bağlantı için sonsuz bekleme!")
        while True:
            await asyncio.sleep(3600)  # çok uzun bekleme (busy/stuck)

    elif kind == "error":
        logging.error("Server: Hatalı cevap senaryosu (CALLERROR).")
        # Burada sadece işaret veriyoruz, asıl error_response handle_message içinde oluşturulacak.

# ======================================================
# CLIENT MESAJ İŞLEME
# ======================================================
async def handle_message(message: str, websocket):
    logging.info(f"Server mesaj aldı: {message}")

    # JSON formatına çevir
    try:
        data = json.loads(message)
    except json.JSONDecodeError:
        logging.exception("JSON parse hatası!")
        # Bağlantıyı patlatmamak için sadece logla
        return

    # Temel alanlar
    msg_type = data.get("messageTypeId")
    action = data.get("action")
    test_mode = data.get("test")

    # Sadece CALL (2) olan mesajları bekliyoruz
    if msg_type != 2:
        logging.warning(f"Beklenmeyen messageTypeId: {msg_type}")
        resp = error_response(data, "FormationViolation", {"reason": "messageTypeId != 2"})
        await websocket.send(json.dumps(resp))
        return

    # Busy/Stuck testleri
    if test_mode == "delay":
        await handle_busy_stuck_scenario("delay")

    elif test_mode == "stuck":
        # Bu fonksiyon dönmez, bu connection "stuck" olur
        await handle_busy_stuck_scenario("stuck")
        return

    elif test_mode == "error":
        await handle_busy_stuck_scenario("error")
        resp = error_response(data, "InternalError", {"scenario": "error"})
        await websocket.send(json.dumps(resp))
        return

    # Normal OCPP benzeri akış
    if action == "BootNotification":
        response = boot_notification_response(data)

    elif action == "Heartbeat":
        response = heartbeat_response(data)

    else:
        logging.warning(f"Bilinmeyen aksiyon: {action}")
        response = error_response(data, "NotImplemented", {"action": action})

    await websocket.send(json.dumps(response))
    logging.info(f"Cevap gönderildi: {response}")

# ======================================================
# WEBSOCKET SUNUCU
# ======================================================
async def server_handler(websocket):
    client_info = f"{websocket.remote_address}"
    logging.info(f"Yeni bağlantı: {client_info}")
    try:
        async for message in websocket:
            try:
                await handle_message(message, websocket)
            except Exception as e:
                logging.exception(f"Mesaj işlenirken hata: {e}")
                # İç hata olursa bağlantıyı koparmak yerine sadece logla
    except websockets.exceptions.ConnectionClosed as e:
        logging.info(f"Bağlantı kapandı: {client_info} - Kod: {e.code}, Sebep: {e.reason}")

async def main():
    logging.info("OCPP Server başlatılıyor -> ws://localhost:9000")
    async with websockets.serve(server_handler, "localhost", 9000):
        await asyncio.Future()  # sonsuza kadar çalış

if __name__ == "__main__":
    asyncio.run(main())
