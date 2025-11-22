"""
OTA Hash Zaafiyeti Test Ortamı Kurulum Scripti
===============================================

Bu script, OTA hash zaafiyeti testleri için gerekli dizinleri ve dosyaları oluşturur.

Kullanım:
    python charging/scenarios/setup_ota_test_environment.py
"""

import os
import sys
from pathlib import Path

def create_directories():
    """Gerekli dizinleri oluştur"""
    directories = [
        './charging/firmware',
        './charging/firmware_server',
        './charging/firmware/E2507-8420-1274',
        './charging/firmware/E2507-8420-1275',
    ]
    
    print("[*] Dizinler oluşturuluyor...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"    ✓ {directory}")
    
    print("[*] Dizinler başarıyla oluşturuldu!\n")

def create_readme():
    """Test ortamı için README dosyası oluştur"""
    readme_content = """# OTA Hash Zaafiyeti Test Ortamı

## Dizin Yapısı

- `charging/firmware/` - İndirilen firmware dosyalarının saklandığı dizin
- `charging/firmware_server/` - Firmware server'ının servis ettiği firmware dosyalarının dizini
- `charging/firmware/E2507-8420-1274/` - E2507-8420-1274 serial numaralı charging station için firmware dizini
- `charging/firmware/E2507-8420-1275/` - E2507-8420-1275 serial numaralı charging station için firmware dizini

## Kullanım

1. Server'ı başlatın:
   ```bash
   python charging/server.py
   ```

2. Senaryo dosyasını çalıştırın:
   ```bash
   python charging/scenarios/ota_hash_complete_attack.py [zaafiyet_modu]
   ```

3. Veya tüm senaryoları test edin:
   ```bash
   python charging/scenarios/test_ota_hash_vulnerabilities.py
   ```

## Zaafiyet Modları

- `no_validation` - Hash doğrulaması yapılmıyor
- `weak_md5` - Zayıf MD5 hash kullanılıyor
- `header_hash` - HTTP header'dan hash alınıyor
- `case_insensitive` - Case-insensitive hash karşılaştırması
- `partial_hash` - Sadece hash'in ilk 8 karakteri kontrol ediliyor

## Notlar

- Firmware dosyaları `charging/firmware/{SERIAL_NUMBER}/` dizinine kaydedilir
- Malicious firmware dosyaları `charging/firmware_server/` dizinine oluşturulur
- Test senaryoları otomatik olarak firmware server'ı başlatır
"""
    
    readme_path = Path('./charging/firmware/README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print(f"[*] README dosyası oluşturuldu: {readme_path}\n")

def main():
    """Ana fonksiyon"""
    print("=" * 70)
    print("OTA HASH ZAAFİYETİ TEST ORTAMI KURULUMU")
    print("=" * 70)
    print()
    
    try:
        create_directories()
        create_readme()
        
        print("=" * 70)
        print("KURULUM TAMAMLANDI")
        print("=" * 70)
        print("\n[✓] Tüm dizinler ve dosyalar başarıyla oluşturuldu!")
        print("\n[*] Sonraki adımlar:")
        print("    1. Server'ı başlatın: python charging/server.py")
        print("    2. Senaryo dosyasını çalıştırın:")
        print("       python charging/scenarios/ota_hash_complete_attack.py no_validation")
        print("    3. Veya tüm senaryoları test edin:")
        print("       python charging/scenarios/test_ota_hash_vulnerabilities.py")
        print()
        
    except Exception as e:
        print(f"\n[!] Hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
