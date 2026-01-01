# Anomali-12: Drift (Yavaş Kayma) Simülasyonu ve Tespiti

Bu çalışmada, elektrikli araç şarj istasyonlarında uzun vadede yavaş ve sürekli
şekilde oluşan tüketim değişimlerinin (drift) tespit edilmesi amaçlanmıştır.
Drift anomalileri ani sıçramalar içermediği için fark edilmesi zor olup,
sistem performansını sessizce olumsuz etkileyebilir.

---

## Yöntem

Çalışmada sentetik günlük tüketim verisi üretilmiştir.
İlk dönem **referans (baseline)** olarak kabul edilmiş, ilerleyen günlerde
tüketim değerlerine kademeli bir artış eklenmiştir.

Drift tespiti için:
- **90 günlük hareketli ortalama**
- **±%10 eşik değeri**
kullanılmıştır.

Hareketli ortalamanın referans değere göre %10’dan fazla sapma göstermesi
durumunda **SLOW_DRIFT** anomalisi üretilmektedir.

---

## Çıktılar

- Tüketim verisi, hareketli ortalama ve eşik değerlerini gösteren zaman serisi grafiği
- Drift algılandığında oluşturulan uyarı (log) kayıtları

---

## Sonuç

Elde edilen sonuçlar, tüketimde zamanla oluşan yavaş artışların
başarıyla tespit edilebildiğini göstermektedir.
Bu yaklaşım, şarj istasyonlarında donanım eskimesi, ölçüm sapmaları ve
sessiz enerji kayıplarının erken tespiti için kullanılabilir.

