import asyncio
import websockets
import datetime
import json

async def ocpp_handler(websocket):
    """
    Şarj İstasyonlarından (veya Emülatörden) gelen WebSocket bağlantılarını karşılar.
    ZAFİYET: Hiçbir sertifika veya şifre kontrolü yapmaz.
    """
    
    # Varsayılan istasyon adı
    station_id = "Bilinmeyen_Istasyon"
    
    # Farklı library versiyonları için path (kimlik) alma mantığı
    try:
        if hasattr(websocket, 'path'):
            station_id = websocket.path.strip("/")
        elif hasattr(websocket, 'request') and hasattr(websocket.request, 'path'):
            station_id = websocket.request.path.strip("/")
    except Exception:
        pass

    print(f"\n[!] YENİ BAĞLANTI: {station_id} sisteme sızdı!")
    print(f"    Bağlantı Zamanı: {datetime.datetime.now()}")

    try:
        async for message in websocket:
            print(f"\n>>> GELEN MESAJ ({station_id}):")
            print(f"    {message}")

            # ---------------------------------------------------------
            # SALDIRI TESPİT MANTIĞI
            # ---------------------------------------------------------
            if "StartTransaction" in message:
                print(f"\n⚠️  KRİTİK UYARI: {station_id} AĞIR YÜK ÇEKMEYE BAŞLADI!")
                print(f"    Şebeke Yükü Artıyor... (Simülasyon)")
            # ---------------------------------------------------------

            # OCPP El Sıkışma Cevabı (BootNotification Response)
            # Bağlantının kopmaması için 'Accepted' (Kabul) cevabı dönmek zorundayız.
            if "BootNotification" in message:
                try:
                    msg_json = json.loads(message)
                    msg_id = msg_json[1]  # Mesaj ID'sini al
                    
                    # Standart "Accepted" cevabını oluştur
                    response = json.dumps([
                        3, 
                        msg_id, 
                        {
                            "status": "Accepted", 
                            "currentTime": datetime.datetime.now().isoformat(), 
                            "interval": 300
                        }
                    ])
                    await websocket.send(response)
                except Exception as e:
                    print(f"JSON Hatası: {e}")

    except Exception as e:
        print(f"\n[X] BAĞLANTI KOPTU: {station_id} - {e}")

async def main():
    print("--- SALDIRI İZLEME SUNUCUSU (CSMS) BAŞLATILDI ---")
    print("--- Port: 9000 dinleniyor... ---")
    
    # WebSocket sunucusunu başlat
    async with websockets.serve(ocpp_handler, "0.0.0.0", 9000):
        await asyncio.get_running_loop().create_future()  # Sonsuza kadar çalış

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nSunucu kullanıcı tarafından kapatıldı.")