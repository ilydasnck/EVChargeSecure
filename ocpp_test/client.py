import asyncio
import json
from websockets import connect
from datetime import datetime
import random

async def run_client():
    uri = "ws://127.0.0.1:9000/"

    async with connect(uri) as ws:
        print("[CLIENT] Server'a bağlandı.")

        boot = {
            "action": "BootNotification",
            "payload": {"chargePointId": "CP-01"}
        }
        await ws.send(json.dumps(boot))
        print(await ws.recv())

        duration = random.randint(10, 50)

        start = {
            "action": "StartTransaction",
            "payload": {
                "transactionId": 1,
                "timestamp": datetime.now().isoformat()
            }
        }
        await ws.send(json.dumps(start))
        print(await ws.recv())

        print(f"[CLIENT] {duration} saniyelik simülasyon...")
        await asyncio.sleep(duration / 10)

        stop = {
            "action": "StopTransaction",
            "payload": {
                "transactionId": 1,
                "timestamp": datetime.now().isoformat(),
                "duration": duration,
                "volume": 0.0
            }
        }

        print("[CLIENT] StopTransaction (ANOMALİ) gönderiliyor...")
        await ws.send(json.dumps(stop))
        print(await ws.recv())

if __name__ == "__main__":
    asyncio.run(run_client())
