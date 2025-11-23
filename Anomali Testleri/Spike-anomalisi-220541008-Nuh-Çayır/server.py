import asyncio
import websockets
import json
from datetime import datetime
import logging

# Log seviyesini ayarla
logging.basicConfig(level=logging.INFO)

# Anomali Tespiti için Eşik Değer (100.000 Wh üzeri Spike'tır)
THRESHOLD_WH = 100000 
PORT = 9001

async def handle_ocpp_message(charge_point_id, message):
    """Gelen ham OCPP mesajlarını manuel ve sağlam bir şekilde işler."""
    try:
        # 1. JSON ayrıştırma kontrolü
        try:
            # OCPP mesajı formatı: [MessageTypeId, UniqueId, Action, Payload]
            data = json.loads(message)
        except json.JSONDecodeError:
            logging.error(f"[CSMS] JSON DECODE HATASI: Geçersiz mesaj alındı.")
            return None # Geçersiz mesajı yoksay veya hata mesajı gönder

        # 2. OCPP Formatı kontrolü (En az 4 eleman olmalı)
        if not isinstance(data, list) or len(data) < 4:
            logging.error(f"[CSMS] FORMAT HATASI: OCPP formatı bozuk.")
            return None

        # Mesaj bileşenlerini ayır
        unique_id = data[1]
        action = data[2]
        payload = data[3]
        
        # 3. Aksiyonlara göre cevap verme
        if action == 'BootNotification':
            response_payload = {"currentTime": datetime.utcnow().isoformat(),"interval": 300,"status": "Accepted"}
            response = [3, unique_id, response_payload]
            return json.dumps(response)

        # --- MeterValues İşlemi (ANOMALİ TESPİTİ BURADA) ---
        elif action == 'MeterValues':
            print(f"\n[CSMS] {charge_point_id} MeterValues Aldı (Anomali Kontrolü):")
            
            meter_value_wh = 0
            if payload.get('meterValue'):
                sampled_value = payload['meterValue'][0]['sampledValue'][0]
                meter_value_wh = int(sampled_value['value'])
            
            # 🚨 SPIKE (Hacim Sıçraması) ANOMALİ TESPİTİ
            if meter_value_wh > THRESHOLD_WH:
                print(f"  *** ANOMALİ TESPİT EDİLDİ (SPIKE): ANORMAL YÜKSEK SAYAÇ DEĞERİ: {meter_value_wh} Wh ***")
            else:
                print(f"  - Sayaç Değeri: {meter_value_wh} Wh (Normal)")

            response = [3, unique_id, {}] # Ham JSON'da MeterValues için boş payload yeterlidir.
            return json.dumps(response)

        elif action == 'Authorize':
            response_payload = {"idTagInfo": {"status": "Accepted"}}
            response = [3, unique_id, response_payload]
            return json.dumps(response)
        
        else:
            # Tanınmayan aksiyonlar için varsayılan cevap
            response = [3, unique_id, {}]
            return json.dumps(response)

    except Exception as e:
        logging.error(f"[CSMS] Mesaj İşlenirken KRİTİK HATA: {e}")
        return None

# CRITICAL FIX: on_connect fonksiyon tanımı DOĞRUDUR.
async def on_connect(websocket, path):
    charge_point_id = path.strip('/')
    print(f"\n[CSMS] Yeni Bağlantı: {charge_point_id}")
    
    try:
        async for message in websocket:
            response = await handle_ocpp_message(charge_point_id, message)
            if response:
                await websocket.send(response)

    except websockets.exceptions.ConnectionClosed:
        print(f"[CSMS] Bağlantı Kesildi: {charge_point_id}")
    except Exception as e:
        logging.error(f"[CSMS] Bağlantı İşlenirken HATA: {e}")

async def main():
    server = await websockets.serve(
        on_connect,
        '127.0.0.1', 
        PORT, 
        subprotocols=['ocpp1.6']
    )
    print(f"[CSMS] Merkezi Sistem dinlemede: ws://127.0.0.1:{PORT}")
    await server.wait_closed()

if __name__ == '__main__':
    asyncio.run(main())
