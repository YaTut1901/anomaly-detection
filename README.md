# Anomaly detection

Два незалежні пайплайни: синтетичні події кіберзагроз для лабораторних робіт і класифікація реального мережевого трафіку (нормальний проти DDoS) з генерацією правил nftables.

Ноутбуки синтетичного пайплайну запускаються з каталогу `synthetic/`, ноутбуки трафіку — з `traffic/`.

## Структура

```
synthetic/          генератор CSV, датасети, ноутбуки аналізу та кластеризації
traffic/            захоплення pcap, CSV ознак, класифікатор, rules.nft
traffic/csv/        per-class витяги tshark і зведений cybersecurity_dataset.csv
docs/               тексти лабораторних і звіти з розбору дампів
```

## Синтетичні загрози

`synthetic/generate_threats.py` будує навчальний CSV: протокол, прапорці, публічні IPv4, порти, розмір пакета, тип загрози, час і країну. Геолокація за замовчуванням детермінована від IP; з `--geoip-country-db` використовується GeoLite2.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pandas numpy
python synthetic/generate_threats.py 200 --missing-cell-prob 0.08
```

Файл за замовчуванням: `synthetic/cyber_threats_dataset.csv`.

| Ноутбук | Що робить |
|---------|-----------|
| `cyber_threats_preprocessing.ipynb` | пропуски, дати, аномалії, масштабування; пише `processed_dataset.csv` і `cleaned_data.csv` |
| `cyber_threats_analysis.ipynb` | розподіли типів загроз, протоколів, країн, IP |
| `cyber_clustering.ipynb` | KMeans, DBSCAN, agglomerative clustering |

Деталі лабораторних: `docs/lab_cyber_threats.md`, `docs/lab_threats_preprocessing.md`, `docs/lab_threats_analysis.md`, `docs/lab_cyber_clustering.md`.

## Трафік і класифікатор

`traffic/generate_attacks.sh` (потрібні root, tshark і hping3) пише по одному pcap на клас атаки в `traffic/pcap/`. Ознаки з дампів уже зведені в `traffic/csv/`.

Класифікатор у `traffic/cybersecurity_dataset_overview.ipynb` — MLP на flow-вікнах (1 секунда, групування за `ip.src`):

`Dense(64, ReLU) → Dense(32, ReLU) → Dense(8, softmax)`

Adam, `sparse_categorical_crossentropy`, 20 епох. Класи: `normal`, `syn`, `ack`, `fin`, `rst`, `push`, `udp`, `icmp`.

На відкладених 197 flow (20%):

| | |
|--|--|
| Test accuracy | 99.49% |
| Macro F1 | 0.99 |
| Weighted F1 | 1.00 |

Найслабший клас — precision 0.92 / F1 0.96. Решта класів мають F1 1.00. Модель зберігається в `traffic/models/cyber_flow_classifier.keras` разом зі scaler і label encoder.

`traffic/cybersecurity_dataset_analysis.ipynb` — розвідувальний аналіз того самого CSV.

Збережена модель перетворює новий CSV пакетів на nftables-правила (drop для всього, крім `normal`):

```bash
pip install pandas numpy scikit-learn tensorflow joblib
python traffic/generate_nft_from_classification.py --csv traffic/csv/sample_live_traffic.csv
sudo nft -c -f traffic/rules.nft
```

Розбір полів tshark і дампу нормального трафіку: `docs/tshark_feature_extraction_report.md`, `docs/normal_traffic_wireshark_analysis.md`.
