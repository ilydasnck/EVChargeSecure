import sys
sys.stdout.reconfigure(encoding='utf-8')
import asyncio
import websockets
import json
import logging
import os

# ======================================================
# LOG AYARLARI
# ======================================================
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/client.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

SERVER_URL = "ws://localhost:9000"

async def send(message, ws, description=""):
    if description:
        logging.info(f"=== {description} ===")
    logging.info(f"Client gönderiyor: {message}")

    try:
        await ws.send(json.dumps(message))
    except Exception as e:
        logging.error(f"Mesaj gönderirken hata: {e}")
        return

    try:
        response = await asyncio.wait_for(ws.recv(), timeout=4)
        logging.info(f"Client cevap aldı: {response}")
    except asyncio.TimeoutError:
        logging.error("Client: CEVAP ALAMADI! (busy/stuck senaryosu veya server cevap vermedi)")
    except websockets.exceptions.ConnectionClosed as e:
        logging.error(f"Client bağlantı kapandı: kod={e.code}, sebep={e.reason}")
        # Daha fazla mesaj göndermeye çalışmamak için exception fırlat
        raise
    except Exception as e:
        logging.error(f"Client genel hata: {e}")

async def main():
    logging.info(f"Server bağlantısı deneniyor: {SERVER_URL}")
    try:
        async with websockets.connect(SERVER_URL) as ws:
            # 1) Normal BootNotification
            await send({
                "messageTypeId": 2,
                "messageId": "msg01",
                "action": "BootNotification",
                "payload": {"chargePointModel": "Sim1"}
            }, ws, "Normal BootNotification")

            # 2) Normal Heartbeat
            await send({
                "messageTypeId": 2,
                "messageId": "msg02",
                "action": "Heartbeat",
                "payload": {}
            }, ws, "Normal Heartbeat")

            # 3) Delay test
            await send({
                "messageTypeId": 2,
                "messageId": "msg03",
                "action": "Heartbeat",
                "payload": {},
                "test": "delay"
            }, ws, "Delay (gecikme) testi")

            # 4) Error test
            await send({
                "messageTypeId": 2,
                "messageId": "msg04",
                "action": "Heartbeat",
                "payload": {},
                "test": "error"
            }, ws, "Error (CALLERROR) testi")

            # 5) Stuck test - server bu mesajdan sonra "stuck" olur,
            # client timeout alacak.
            try:
                await send({
                    "messageTypeId": 2,
                    "messageId": "msg05",
                    "action": "Heartbeat",
                    "payload": {},
                    "test": "stuck"
                }, ws, "Stuck (busy) testi")
            except websockets.exceptions.ConnectionClosed:
                # Eğer server bağlantıyı kapatırsa burada sonlanırız
                logging.error("Stuck testi sırasında bağlantı kapandı.")
    except ConnectionRefusedError:
        logging.error("Server'a bağlanılamadı. Önce server.py'yi çalıştırdığından emin ol.")
    except Exception as e:
        logging.error(f"Client başlangıç hatası: {e}")

if __name__ == "__main__":
    asyncio.run(main())
