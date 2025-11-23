import asyncio
import websockets
import json
from datetime import datetime

# BU KOD, HATA VEREN HİÇBİR 'ocpp' KÜTÜPHANESİ IMPORT ETMEZ.

CHARGE_POINT_ID = 'TEST-CP-001'
CENTRAL_SYSTEM_URL = 'ws://127.0.0.1:9001/'

async def send_message(websocket, action, payload):
    """OCPP kütüphanesi olmadan ham JSON mesajı oluşturur ve gönderir."""
    # Unique ID'yi anlık zamana göre oluşturur
    unique_id = str(datetime.now().timestamp()) 
    message = [2, unique_id, action, payload]
    
    print(f"Client -> CSMS: {action}")
    await websocket.send(json.dumps(message))
    
    # Cevabı bekler ve döner
    response_json = await websocket.recv()
    response = json.loads(response_json)
    
    return response

async def connect_and_run():
    try:
        # Websocket bağlantısını kurar
        async with websockets.connect(
            CENTRAL_SYSTEM_URL + CHARGE_POINT_ID, 
            subprotocols=['ocpp1.6']
        ) as websocket:
            
            print(f"[{CHARGE_POINT_ID}] Merkezi Sisteme Bağlanıyor...")

            # 1. BootNotification Gönderimi (Ham JSON)
            boot_payload = {"chargePointVendor": "TestVendor", "chargePointModel": "TestModel"}
            await send_message(websocket, "BootNotification", boot_payload)
            print(f"[{CHARGE_POINT_ID}] BootNotification Mesajı Gönderildi. Cevap Alındı.")

            # 2. Authorize Gönderimi (Ham JSON)
            auth_payload = {"idTag": "DEADBEEF007"}
            await send_message(websocket, "Authorize", auth_payload)
            print(f"[{CHARGE_POINT_ID}] Authorize Mesajı Gönderildi. Cevap Alındı.")
            
            # 3. MeterValues Gönderimi (ANOMALİ TETİKLEME - Ham JSON)
            meter_value = 9999999 # SPIKE DEĞERİ
            
            meter_payload = {
                "connectorId": 1, "transactionId": 101,
                "meterValue": [
                    {"timestamp": datetime.utcnow().isoformat(),
                     "sampledValue": [
                         {"measurand": "Energy.Active.Import.Register",
                          "value": str(meter_value), "unit": "Wh"}
                     ]}
                ]
            }
            await send_message(websocket, "MeterValues", meter_payload)
            
            print(f"\n[TEST] Sayaç Değeri Gönderildi.")
            print(f"  - ANOMALİ TETİKLEYİCİ DEĞER: {meter_value} Wh")
            
            print(f"\n[{CHARGE_POINT_ID}] Tüm Testler Bitti. Çıkmak için Ctrl+C.")
            await asyncio.Future()

    except Exception as e:
        # Bağlantı sorunlarını (timed out, Errno 111, 1011) yakalar
        print(f"\nHATA: Bağlantı veya Çalıştırma Sorunu: {e}")

if __name__ == '__main__':
    asyncio.run(connect_and_run())
