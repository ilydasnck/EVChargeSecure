Bu dizin `ota_hash_anomaly` yalnızca OTA hash zaafiyeti senaryoları ve ilgili belgeler için oluşturulmuştur.

İçerik:
- `scenarios/` : OTA hash ile ilgili saldırı/test senaryoları
- `charging/` : minimal `client_config.yaml` ve `server_config.yaml` kopyaları (senaryoların ihtiyaç duyduğu ayarlar)
- `OTA_HASH_TEST_KILAVUZU.md` : Hızlı başlangıç ve test adımları
- `OTA_HASH_ZAAFİYETİ_DETAYLI_KILAVUZ.md` : Detaylı saldırı ve korunma kılavuzu
- `KURULUM_KILAVUZU.md` : Genel kurulum talimatları
- `run_scenario.py` : Bu alt dizinden senaryoları çalıştırmak için yardımcı betik

Nasıl çalıştırılır:
- Tercihen proje kökünden çalıştırın (örnek):

```powershell
# Sanal ortamı etkinleştirin
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Server'ı proje kökünden başlatın
python charging/server.py
# Senaryoyu proje kökünden çalıştırın (örnek)
python ota_hash_anomaly\scenarios\ota_hash_attack.py
```

- Eğer `ota_hash_anomaly` alt dizininden çalıştırmak isterseniz, `run_scenario.py` betiğini kullanın; bu betik çalışma yolunu proje köküne çeker ve verilen senaryoyu çalıştırır:

```powershell
python ota_hash_anomaly\run_scenario.py scenarios/ota_hash_attack.py
```

Not: Ana uygulama kodu ve sunucu (`charging/server.py`) kök dizinde kalmalıdır — burada sadece senaryolar, konfig ve belgeler bulunmaktadır.
