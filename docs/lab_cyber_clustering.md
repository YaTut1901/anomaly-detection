# Лабораторна робота: кластеризація

## Артефакт

- Код і виконання: `synthetic/cyber_clustering.ipynb`.

## Джерело даних

- Файл: `synthetic/cyber_threats_dataset.csv`.
- Використання рядків після `pandas.DataFrame.dropna()`.

## Колонки

- Кодування `LabelEncoder().fit_transform(...)`: `Protocol`, `Packet`, `Target Variable` (у CSV колонка типу загрози названа `Target Variable`, не `Threat Type`).
- Матриця ознак `X`, колонки в порядку: `Protocol`, `Packet`, `Source Port`, `Destination Port`, `Packet Size`.
- Масштабування: `sklearn.preprocessing.StandardScaler().fit_transform(X)` → `X_scaled`.

## Моделі та аргументи виклику

| Клас | Аргументи |
|------|-----------|
| `sklearn.cluster.KMeans` | `n_clusters=4`, `random_state=0`, `n_init=10` |
| `sklearn.cluster.DBSCAN` | `eps=1.5`, `min_samples=5` |
| `sklearn.cluster.AgglomerativeClustering` | `n_clusters=4` |

- Вихідні мітки: `kmeans_labels`, `dbscan_labels`, `agglo_labels` (`fit_predict` на `X_scaled`).

## Обчислення між мітками

- `sklearn.metrics.rand_score(kmeans_labels, agglo_labels)`
- `sklearn.metrics.rand_score(dbscan_labels, agglo_labels)`
- `sklearn.metrics.adjusted_mutual_info_score(kmeans_labels, agglo_labels)`
- `sklearn.metrics.adjusted_mutual_info_score(dbscan_labels, agglo_labels)`

## Графік

- `matplotlib.pyplot.scatter`: абсциса `X_scaled[:, 0]`, ордината `X_scaled[:, 1]`, колір `kmeans_labels`, `cmap="viridis"`.
- Підписи осей: `features[0]`, `features[1]` (відповідають першим двом колонкам у `features`).

## Друк у консоль

- Чотири рядки з числовими значеннями Rand score та adjusted mutual information для пар вище.
- Змінна `best_method`: рядок `"K-Means"` якщо `rand_kmeans > rand_dbscan`, інакше `"DBSCAN"`.
- Два рядки: текстовий вивід `best_method` і рядок з параметрами (`n_clusters=4` або `eps=1.5, min_samples=5` залежно від `best_method`).
