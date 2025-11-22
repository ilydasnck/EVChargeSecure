import subprocess
import time
import os
import signal
import sys

# ======================================================
# TEST BAŞLIYOR
# ======================================================
print("\n=== BUSY/STUCK OCPP TEST BAŞLIYOR ===\n")

# ======================================================
# 1) SERVER'I BAŞLAT
# ======================================================
print("[1] Server başlatılıyor...")

server_process = subprocess.Popen(
    ["python", "server.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

time.sleep(2)  # Server’ın açılması için bekle

# ======================================================
# SERVER AÇILDI MI KONTROL
# ======================================================
if server_process.poll() is not None:
    print("\n❌ Server başlatılamadı!")
    sys.exit(1)

print("✔ Server çalışıyor\n")


# ======================================================
# 2) CLIENT ÇALIŞTIR
# ======================================================
print("[2] Client çalıştırılıyor...")

client_process = subprocess.Popen(
    ["python", "client.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

stdout, stderr = client_process.communicate()

print("\n--- CLIENT ÇIKTILARI ---")
print(stdout)

if stderr:
    print("\n--- CLIENT HATALARI ---")
    print(stderr)

print("\n✔ Client testleri tamamlandı.\n")


# ======================================================
# 3) SERVERI DURDUR
# ======================================================
print("[3] Server kapatılıyor...")

if os.name == "nt":  # Windows
    server_process.send_signal(signal.CTRL_BREAK_EVENT)
else:
    server_process.terminate()

time.sleep(1)

print("✔ Server kapatıldı.")
print("\n=== TEST TAMAMLANDI ===\n")
