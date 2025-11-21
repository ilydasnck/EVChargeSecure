import asyncio
import websockets
import json
from ocpp.v16 import call_result
from ocpp.v16.enums import RegistrationStatus

# Sunucu, gelen her bağlantıda bu fonksiyonu çalıştırır
async def on_connect(websocket):
    # Basit bir charge point ID kullan
    charge_point_id = 'CP001'
    print(f"\n[{charge_point_id}] YENI BAGLANTI KURULDU!")
    
    # Baglantiyi dinleme dongusu
    try:
        # 1. BootNotification mesajini İstemciden (Monta) almayi bekle
        message = await websocket.recv()
        print(f"[{charge_point_id}] Mesaj Alındı: {message[:50]}...")
        
        # 2. BootNotificationResponse (Kabul Yaniti) gonder
        # Gelen mesajdan unique_id'yi al
        message_data = json.loads(message)
        unique_id = message_data[1]
        
        # Manuel olarak response payload olustur
        response_payload = {
            "status": "Accepted",
            "currentTime": "2025-11-21T11:15:00Z",
            "interval": 300
        }
        
        # Cevabi JSON formatinda gonder (OCPP'nin bekledigi format budur)
        response = json.dumps([3, unique_id, response_payload])
        await websocket.send(response)
        print(f"[{charge_point_id}] BootNotification KABUL EDILDI. Cevap Gonderildi.")
        print(f"[{charge_point_id}] Gonderilen cevap: {response}")
        
        # 3. Baglantiyi canli tutmak icin sonsuz dongu (Heartbeat ve diger mesajlar icin)
        while True:
            # Gelen mesajlari dinlemeye devam et
            next_message = await websocket.recv()
            print(f"[{charge_point_id}] Yeni mesaj alindi: {next_message[:100]}...")
            
    except websockets.exceptions.ConnectionClosedOK:
        print(f"[{charge_point_id}] Baglanti normal sekilde kapandi.")
    except Exception as e:
        print(f"[{charge_point_id}] HATA: {e}")
    finally:
        print(f"[{charge_point_id}] BAGLANTI KOPTU.")

# Sunucu uygulamasini baslat
async def main():
    server = await websockets.serve(
        on_connect,
        '127.0.0.1',
        9000
    )
    print("OCPP Server baslatildi. Dinleniyor: ws://127.0.0.1:9000")
    await server.wait_closed()

if __name__ == '__main__':
    try:
        asyncio.get_event_loop().run_until_complete(main())
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\nOCPP Server durduruldu.")