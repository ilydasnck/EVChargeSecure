# Elektrikli Araç Şarj İstasyonlarında Anomali Tespiti
**Bilgi Sistemleri Güvenliği (BSG) Dersi — Dönem Projesi**

---

## Proje Tanımı
Bu proje, elektrikli araç şarj altyapısında kullanılan **OCPP (Open Charge Point Protocol)** iletişim trafiğini analiz ederek şarj istasyonlarına yönelik olası güvenlik zafiyetlerini tespit etmeyi amaçlamaktadır.

Çalışma kapsamında hem normal işletim senaryoları hem de siber saldırı niteliği taşıyabilecek anomaliler üretilmekte; elde edilen veriler üzerinden güvenlik tehditlerinin sınıflandırılması ve gelecekte makine öğrenimi tabanlı bir tespit mekanizması geliştirilmesi hedeflenmektedir.

---

## Şu Ana Kadar Tamamlanan Çalışmalar

### 1. Literatür İncelemesi
- OCPP 1.6 ve OCPP 2.0.1 protokol mimarileri analiz edildi.  
- Elektrikli araç şarj altyapısına yönelik global siber tehditler incelendi.  
- CAN-Bus güvenliği, MITM saldırıları, sahte mesaj enjeksiyonu ve zayıf şifreleme gibi riskler değerlendirildi.

### 2. Anomali Senaryolarının Oluşturulması
- Toplam **10 adet anomali senaryosu** üretildi.
- Senaryolar; veri manipülasyonu, yetkisiz erişim, bağlantı manipülasyonu, olağandışı enerji tüketimi ve protokol ihlallerini içermektedir.

### 3. Simülasyon Ortamının Kurulumu ve Testler
- EmuOCPP, CARLA vb. araçlar kullanılarak simülasyon ortamı oluşturuldu.  
- OCPP trafiği üretilerek ilk testler gerçekleştirildi.  
- Elde edilen trafik analiz edilerek çıktılar **Anomali_Çıktıları/** dizinine kaydedildi.

### 4. Repository Yapısının Oluşturulması
- **Videolar/** → Ekip üyelerinin ilerleme videoları  
- **Dökümanlar/** → Teknik raporlar, analizler ve bireysel çalışmalar  
- **Anomali_Çıktıları/** → Simülasyon çıktı dosyaları ve log kayıtları  

---

## Planlanan Çalışmalar (Sonraki Aşama)

### 1. Veri Toplama ve Etiketleme
- Daha geniş kapsamlı bir OCPP trafik veri seti oluşturulacak.  
- Tüm kayıtlar **“normal”** / **“anomali”** olarak etiketlenecek.  

### 2. Tehdit Modelleme ve Risk Analizi
- STRIDE modeli ile tehdit kategorileri belirlenecek.  
- Veri akış diyagramları (DFD) oluşturulacak.  
- Risk matrisi hazırlanacak ve öncelikli tehditler sıralanacak.

### 3. Güvenlik Kontrol Listesi (Checklist)
- OCPP, ISO 27001, NIST ve OWASP standartlarına dayalı **en az 50 maddelik** kontrol listesi hazırlanacak.

### 4. Yapay Zekâ Tabanlı Anomali Tespit Modeli
- Etiketlenmiş veri üzerinden ilk makine öğrenimi modelleri eğitilecek.  
- Hedef: **%90 ve üzeri doğruluk**.

### 5. Dashboard ve İzleme Modülü
- Gerçek zamanlı OCPP trafiğini izleyen bir dashboard geliştirilecek.  
- Şüpheli aktivitelerde otomatik uyarı / müdahale mekanizması oluşturulacak.

---

## Ekip ve Organizasyon
Proje; Fırat Üniversitesi Yazılım Mühendisliği Bölümü öğrencilerinden oluşan bir ekip tarafından yürütülmektedir.

Ekip üyeleri aşağıdaki görevlerden sorumludur:
- Literatür araştırması  
- Anomali senaryolarının geliştirilmesi  
- Simülasyon testleri  
- Dokümantasyon ve raporlama  

---

## Klasör Yapısı
/Videolar → Ekip sunumları ve ilerleme kayıtları
/Dökümanlar → Teknik raporlar, araştırmalar ve bireysel çalışmalar
/Anomali_Çıktıları → OCPP trafik kayıtları, loglar ve analiz sonuçları

---


