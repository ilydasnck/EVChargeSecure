import asyncio
import websockets
import json

async def run():
    uri = "ws://localhost:9000/CP_1"
    async with websockets.connect(uri, subprotocols=["ocpp1.6"]) as ws:
        msg = ["2", "1", "BootNotification", {"chargePointModel":"TestModel","chargePointVendor":"You"}]
        await ws.send(json.dumps(msg))
        print("Sent:", msg)
        res = await ws.recv()
        print("Received:", res)

asyncio.run(run())
