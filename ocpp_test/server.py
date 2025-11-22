import asyncio, json, csv, os
from websockets.server import serve
from datetime import datetime

CSV_PATH = "events.csv"

def write_csv_row(row: dict):
    exists = os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ts","peer","action","duration","volume","anomaly"])
        if not exists:
            w.writeheader()
        w.writerow(row)

async def handle(ws):
    addr = getattr(ws, "remote_address", None)
    print(f"[SERVER] Yeni bağlantı: {addr}")

    try:
        async for message in ws:
            data = json.loads(message)
            action = data.get("action")
            payload = data.get("payload", {})

            print(f"[SERVER] Aksiyon: {action} | Payload: {payload}")

            anomaly = ""
            duration = payload.get("duration")
            volume = payload.get("volume")

            if action == "StopTransaction":
                if (duration is not None) and duration > 0 and (volume == 0 or volume is None):
                    anomaly = "COUNTER_MISMATCH"
                    print("\n[⚠️ ANOMALİ TESPİT EDİLDİ] COUNTER_MISMATCH")
                    print(f"duration={duration}, volume={volume}\n")

            # CSV’ye yaz
            write_csv_row({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "peer": str(addr),
                "action": action,
                "duration": duration,
                "volume": volume,
                "anomaly": anomaly
            })

            # basit ACK
            response = {"action": f"{action}Response", "payload": {"status": "OK"}}
            await ws.send(json.dumps(response))
    except Exception as e:
        print(f"[SERVER] Hata/bağlantı sonlandı: {e}")

async def main():
    host, port = "127.0.0.1", 9000
    print(f"[SERVER] Dinliyor → ws://{host}:{port}")
    async with serve(handle, host, port):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
