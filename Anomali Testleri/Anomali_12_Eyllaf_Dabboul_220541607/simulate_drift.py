import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

# -------------------------
# Yapılandırma (Config)
# -------------------------
STATION_ID = "10"
DAYS_TOTAL = 120
BASELINE_DAYS = 30          # İlk 30 gün = referans (normal durum)
DRIFT_START_DAY = 31        # Drift, referans döneminden sonra başlar
DRIFT_TARGET_PCT = 0.25     # Sonunda %25’e kadar kademeli artış
WINDOW_DAYS = 90            # 90 günlük pencere
THRESHOLD_PCT = 0.10        # ±%10 eşik değeri
SEED = 42

OUT_DIR = "outputs"
PLOT_PATH = os.path.join(OUT_DIR, "drift_timeseries.png")
LOG_PATH = os.path.join(OUT_DIR, "drift_alerts.log")

os.makedirs(OUT_DIR, exist_ok=True)
np.random.seed(SEED)

# -------------------------
# 1) Sentetik günlük tüketim verisi oluşturma
# -------------------------
start_date = datetime(2025, 5, 1)
dates = [start_date + timedelta(days=i) for i in range(DAYS_TOTAL)]

baseline_mean = 38.2
noise = np.random.normal(loc=0.0, scale=1.2, size=DAYS_TOTAL)

volume = np.full(DAYS_TOTAL, baseline_mean) + noise

# Referans döneminden sonra kademeli drift eklenmesi
for i in range(DRIFT_START_DAY - 1, DAYS_TOTAL):
    progress = (i - (DRIFT_START_DAY - 1)) / max(1, (DAYS_TOTAL - (DRIFT_START_DAY - 1) - 1))
    drift_multiplier = 1.0 + (DRIFT_TARGET_PCT * progress)
    volume[i] = (baseline_mean * drift_multiplier) + noise[i]

df = pd.DataFrame({
    "date": dates,
    "station_id": STATION_ID,
    "volume": volume
})

# -------------------------
# 2) Drift tespiti
# (90 günlük hareketli ortalama referans ile karşılaştırılır)
# -------------------------
baseline_ref = df.loc[
    df["date"] < (start_date + timedelta(days=BASELINE_DAYS)),
    "volume"
].mean()

df["vol_mean_90d"] = df["volume"].rolling(
    window=WINDOW_DAYS,
    min_periods=WINDOW_DAYS
).mean()

df["drift_pct"] = (df["vol_mean_90d"] - baseline_ref) / baseline_ref
df["drift_alarm"] = df["drift_pct"].abs() >= THRESHOLD_PCT

# -------------------------
# 3) Anomali loglarının yazılması
# -------------------------
with open(LOG_PATH, "w", encoding="utf-8") as f:
    for _, row in df[df["drift_alarm"]].iterrows():
        ts = row["date"].strftime("%Y-%m-%d 12:09:12")
        drift_pct = row["drift_pct"] * 100
        f.write(
            f"{ts} | ISTASYON_ID={row['station_id']} | "
            f"ortalama_90g={row['vol_mean_90d']:.1f} | referans={baseline_ref:.1f} | "
            f"kayma={drift_pct:+.1f}% | anomali=YAVAS_KAYMA\n"
        )

# -------------------------
# 4) Sonuçların görselleştirilmesi
# -------------------------
plt.figure(figsize=(12, 5))

plt.plot(df["date"], df["volume"], label="Günlük tüketim")
plt.plot(df["date"], df["vol_mean_90d"], label="90 günlük hareketli ortalama")

plt.axhline(
    baseline_ref * (1 + THRESHOLD_PCT),
    linestyle="--",
    label="+%10 eşik değeri"
)

plt.axhline(
    baseline_ref * (1 - THRESHOLD_PCT),
    linestyle="--",
    label="-%10 eşik değeri"
)

plt.title("Anomali-12: Drift (Yavaş Kayma) Simülasyonu ve Tespiti")
plt.xlabel("Tarih")
plt.ylabel("Tüketim Miktarı")

plt.legend()
plt.tight_layout()
plt.savefig(PLOT_PATH, dpi=200)

print("İŞLEM TAMAMLANDI")
print(f"Referans (baseline) değeri: {baseline_ref:.2f}")
print(f"Grafik kaydedildi: {PLOT_PATH}")
print(f"Anomali logları kaydedildi: {LOG_PATH}")
