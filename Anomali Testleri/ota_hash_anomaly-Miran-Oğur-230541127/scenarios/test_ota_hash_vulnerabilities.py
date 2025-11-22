"""
OTA Hash Zaafiyetleri - Otomatik Test Scripti
==============================================

Bu script, tüm OTA hash zaafiyet türlerini otomatik olarak test eder.

Kullanım:
    python charging/scenarios/test_ota_hash_vulnerabilities.py
"""

import sys
sys.path.append('.')

import subprocess
import time
import os

# Test edilecek zaafiyet modları
VULNERABILITY_MODES = [
    'no_validation',
    'weak_md5',
    'header_hash',
    'case_insensitive',
    'partial_hash'
]

def test_vulnerability_mode(mode):
    """Belirli bir zaafiyet modunu test et"""
    print(f"\n{'=' * 70}")
    print(f"TEST: {mode.upper()}")
    print(f"{'=' * 70}")
    print(f"\n[*] Zaafiyet modu test ediliyor: {mode}")
    print(f"[*] Test scripti çalıştırılıyor...")
    print(f"[*] Not: Server'ın çalıştığından emin olun!")
    print()
    
    # Test scriptini çalıştır
    try:
        # Client'ta zaafiyet modunu ayarla
        env = os.environ.copy()
        env['OTA_HASH_VULN_MODE'] = mode
        
        # Test scriptini çalıştır (5 saniye timeout)
        result = subprocess.run(
            [sys.executable, 'charging/scenarios/ota_hash_complete_attack.py', mode],
            env=env,
            timeout=30,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[✓] Test başarılı: {mode}")
            print(result.stdout)
            return True
        else:
            print(f"[✗] Test başarısız: {mode}")
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print(f"[!] Test zaman aşımına uğradı: {mode}")
        return False
    except Exception as e:
        print(f"[!] Test hatası: {mode} - {e}")
        return False

def test_mitm_attack():
    """MITM saldırı senaryosunu test et"""
    print(f"\n{'=' * 70}")
    print(f"TEST: MITM ATTACK")
    print(f"{'=' * 70}")
    print(f"\n[*] MITM saldırı senaryosu test ediliyor...")
    print(f"[*] Test scripti çalıştırılıyor...")
    print(f"[*] Not: Server'ın çalıştığından emin olun!")
    print()
    
    try:
        # Client'ta zaafiyet modunu ayarla
        env = os.environ.copy()
        env['OTA_HASH_VULN_MODE'] = 'header_hash'
        
        # Test scriptini çalıştır
        result = subprocess.run(
            [sys.executable, 'charging/scenarios/ota_hash_mitm_attack.py'],
            env=env,
            timeout=30,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"[✓] MITM saldırı testi başarılı")
            print(result.stdout)
            return True
        else:
            print(f"[✗] MITM saldırı testi başarısız")
            print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print(f"[!] MITM saldırı testi zaman aşımına uğradı")
        return False
    except Exception as e:
        print(f"[!] MITM saldırı testi hatası: {e}")
        return False

def main():
    """Ana fonksiyon"""
    print("=" * 70)
    print("OTA HASH ZAAFİYETLERİ - OTOMATİK TEST SCRIPTI")
    print("=" * 70)
    print("\n[!] Bu script, tüm OTA hash zaafiyet türlerini otomatik olarak test eder.")
    print("[!] Not: Server'ın çalıştığından emin olun!")
    print("\n[*] Test edilecek zaafiyet modları:")
    for mode in VULNERABILITY_MODES:
        print(f"    - {mode}")
    print("    - mitm_attack")
    print()
    
    # Kullanıcıdan onay al
    response = input("Testleri başlatmak için 'E' tuşuna basın (Enter = Çıkış): ")
    if response.lower() != 'e':
        print("[*] Testler iptal edildi")
        return
    
    # Test sonuçları
    results = {}
    
    # Her zaafiyet modunu test et
    for mode in VULNERABILITY_MODES:
        results[mode] = test_vulnerability_mode(mode)
        time.sleep(2)  # Biraz bekle
    
    # MITM saldırı senaryosunu test et
    results['mitm_attack'] = test_mitm_attack()
    
    # Test sonuçlarını özetle
    print(f"\n{'=' * 70}")
    print("TEST SONUÇLARI ÖZETİ")
    print(f"{'=' * 70}\n")
    
    for mode, success in results.items():
        status = "✓ BAŞARILI" if success else "✗ BAŞARISIZ"
        print(f"  {mode:20s} : {status}")
    
    # Başarı oranını hesapla
    total_tests = len(results)
    successful_tests = sum(1 for success in results.values() if success)
    success_rate = (successful_tests / total_tests) * 100
    
    print(f"\n[*] Toplam test: {total_tests}")
    print(f"[*] Başarılı test: {successful_tests}")
    print(f"[*] Başarısız test: {total_tests - successful_tests}")
    print(f"[*] Başarı oranı: {success_rate:.1f}%")
    
    print(f"\n{'=' * 70}")
    print("TEST TAMAMLANDI")
    print(f"{'=' * 70}")

if __name__ == "__main__":
    main()
