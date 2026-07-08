# Звіт: витяг ознак із pcap за допомогою tshark для задачі розрізнення нормального та DDoS-трафіку

## Вхідні дані

Каталог `ddos_attack/` містить 8 дампів:

| Файл | Джерело | Тип атаки / трафіку |
|------|---------|---------------------|
| `normal_traffic.pcap` | реальний клієнт (веб/DNS/TLS/QUIC) | baseline «нормальний» |
| `syn_ddos_traffic.pcap` | `hping3 --flood -S` | TCP SYN flood |
| `ack_ddos_traffic.pcap` | `hping3 --flood -A` | TCP ACK flood |
| `fin_ddos_traffic.pcap` | `hping3 --flood -F` | TCP FIN flood |
| `rst_ddos_traffic.pcap` | `hping3 --flood -R` | TCP RST flood |
| `push_ddos_traffic.pcap` | `hping3 --flood -P` | TCP PUSH flood |
| `udp_ddos_traffic.pcap` | `hping3 --flood --udp` | UDP flood |
| `icmp_ddos_traffic.pcap` | `hping3 --flood -1` | ICMP (echo) flood |

Швидка інспекція дампів підтверджує характерні сигнатури hping3:

- **спуфлені IP-джерела** (прапорець `--rand-source`), ціль завжди `127.0.0.1`;
- однакові **MAC 00:00:00:00:00:00** на src/dst (artefact loopback-запису);
- **TTL=64**, `DSCP=0`, `IP flags=0x00` — фіксовані значення;
- мінімальні розміри кадрів: 42 байти (UDP/ICMP), 54 байти (TCP);
- **лише один TCP-прапор** виставлено в кожному пакеті відповідного flood-сценарію;
- `tcp.window_size=512` як сталий дефолт hping3;
- повна відсутність повноцінних 3-way handshake, DNS, TLS тощо.

Те, що ваша поточна команда витягує (`frame.time_epoch, ip.src, ip.dst, ip.proto, frame.len`), **не містить** ні прапорів TCP, ні типу ICMP, ні портів, ні полів IP-заголовка — а саме в них і «живе» різниця між атаками. Нижче — розширений список.

## Обмеження поточного пайплайну

1. Для TCP-атак `ip.proto=6` в усіх сценаріях (SYN/ACK/FIN/RST/PUSH) — одне й те саме число, відрізнити їх без `tcp.flags` неможливо.
2. Без `tcp.dstport`/`udp.dstport` не видно «куди бʼють» (hping3 за замовчуванням ціль — порт 80).
3. Без `icmp.type`/`icmp.code` ICMP-flood не відрізнити від pings.
4. `frame.len` дає зріз довжин, але без `tcp.len`, `udp.length`, `ip.hdr_len` важко порахувати payload-статистики.
5. Немає часових дельт всередині потоку (`frame.time_delta`) — критичних для виявлення flood.

## Які поля tshark витягувати (per-packet рівень)

Нижче — робочий набір, що покриває всі наявні сценарії. Коментарі пояснюють, чому поле корисне саме для цього датасету.

### Frame / час

| Поле | Призначення |
|------|-------------|
| `frame.number` | порядковий номер (для дебагу та join-ів) |
| `frame.time_epoch` | абсолютний час у секундах (для агрегації по вікнах) |
| `frame.time_delta` | інтервал до попереднього кадру — **ключова ознака flood**: у hping3 --flood медіана ~мікросекунди, у нормі — мілі/сотні мілісекунд |
| `frame.time_relative` | час відносно початку дампу |
| `frame.len` | фізична довжина кадру |
| `frame.cap_len` | захоплена довжина (для контролю truncation) |
| `frame.protocols` | повний стек (`eth:ip:tcp:tls`, `eth:ip:udp:dns`, …) — компактна мітка структури |

### Ethernet

| Поле | Призначення |
|------|-------------|
| `eth.src`, `eth.dst` | MAC-и; у ваших DDoS-дампах `00:00:00:00:00:00` — готова ознака artificial |
| `eth.type` | 0x0800 / 0x0806 (IPv4 vs ARP) |

### IP (IPv4)

| Поле | Призначення |
|------|-------------|
| `ip.src`, `ip.dst` | адреси; у DDoS `ip.src` рандомний → висока **ентропія джерел**; `ip.dst` константний |
| `ip.proto` | 1=ICMP, 6=TCP, 17=UDP |
| `ip.len` | довжина IP-пакета (без Ethernet-хедера) |
| `ip.hdr_len` | довжина IP-хедера |
| `ip.ttl` | hping3 за замовчуванням 64; «реальні» хости в дампі нормального трафіку — 30-128 з варіативністю |
| `ip.id` | IP ID; hping3 часто генерує рандомно, нормальні стеки — послідовно |
| `ip.flags`, `ip.flags.df`, `ip.flags.mf` | у DDoS `0x00`, в нормі зазвичай `DF=1` |
| `ip.frag_offset` | зазвичай 0; ненульове — fragmentation-based атаки |
| `ip.dsfield`, `ip.dsfield.dscp`, `ip.dsfield.ecn` | DSCP/ECN-маркування |
| `ip.checksum` | можна використати для детекції «самописних» пакетів, де контрольна сума дивна |

### TCP (для SYN/ACK/FIN/RST/PUSH flood)

| Поле | Призначення |
|------|-------------|
| `tcp.srcport`, `tcp.dstport` | порти; hping3-flood зазвичай на один і той самий dst-порт (80) |
| `tcp.len` | payload TCP (нуль у SYN/ACK/FIN/RST, >0 у PUSH з payload, 0 у PUSH hping3 без `-d`) |
| `tcp.hdr_len` | довжина TCP-хедера (20 без опцій у hping3; >20 у нормального трафіку з TS/SACK) |
| `tcp.flags` | байт прапорів (hex, напр. `0x0002` — SYN) |
| `tcp.flags.str` | текстовий запис (`··········S·`) — зручно для категоричної ознаки |
| `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.fin`, `tcp.flags.reset`, `tcp.flags.push`, `tcp.flags.urg`, `tcp.flags.ecn`, `tcp.flags.cwr` | бінарні; **основна сигнатура кожного flood-сценарію** (у tshark 3.6 поле RST — `tcp.flags.reset`, не `tcp.flags.rst`) |
| `tcp.window_size_value` | «сире» вікно — 512 у hping3, 8192-65535+ у нормі |
| `tcp.seq`, `tcp.ack` | послідовність/квитанції; у flood вони не узгоджені → можна вважати нерелевантні numeric, але корисно мати біт «ack=0 while ACK flag not set» |
| `tcp.stream` | індекс потоку (tshark сам формує conversation-id) — для flow-aggregation |
| `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.out_of_order`, `tcp.analysis.lost_segment` | у DDoS експертні алерти зашкалюють |
| `tcp.options.mss_val`, `tcp.options.wscale`, `tcp.options.sack_perm`, `tcp.options.timestamp.tsval` | hping3 не ставить опцій — нормальні SYN завжди мають MSS/WScale/SACK |

### UDP (для UDP-flood, а також DNS/QUIC у нормальному трафіку)

| Поле | Призначення |
|------|-------------|
| `udp.srcport`, `udp.dstport` | у flood dst-порт константний, src — рандомний |
| `udp.length` | довжина датаграми (8 у hping3 без `-d`) |
| `udp.checksum` | |
| `udp.stream` | flow-id |

### ICMP

| Поле | Призначення |
|------|-------------|
| `icmp.type`, `icmp.code` | echo-request у flood (type=8/code=0) |
| `icmp.ident`, `icmp.seq` | hping3 ставить ident рандомно, seq=0 |
| `icmp.checksum` | |

### Контент-протоколи (лише для нормального трафіку — як негативні приклади)

| Поле | Призначення |
|------|-------------|
| `dns.qry.name`, `dns.qry.type`, `dns.flags.response`, `dns.flags.rcode` | DNS-діагностика |
| `tls.handshake.type`, `tls.record.version`, `tls.handshake.extensions_server_name` | TLS-ознаки — у DDoS їх немає |
| `http.request.method`, `http.response.code`, `http.user_agent` | (якщо є) |
| `quic.version`, `quic.long.packet_type` | QUIC-трафік нормального клієнта |

## Готові команди tshark

### 1. Збагачений per-packet CSV (основний датасет)

```bash
FIELDS=(
  -e frame.number -e frame.time_epoch -e frame.time_delta -e frame.time_relative
  -e frame.len -e frame.cap_len -e frame.protocols
  -e eth.src -e eth.dst -e eth.type
  -e ip.src -e ip.dst -e ip.proto -e ip.len -e ip.hdr_len
  -e ip.ttl -e ip.id -e ip.flags -e ip.flags.df -e ip.flags.mf
  -e ip.frag_offset -e ip.dsfield.dscp -e ip.dsfield.ecn
  -e tcp.srcport -e tcp.dstport -e tcp.len -e tcp.hdr_len
  -e tcp.flags -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin
  -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.urg
  -e tcp.flags.ecn -e tcp.flags.cwr
  -e tcp.window_size_value -e tcp.seq -e tcp.ack -e tcp.stream
  -e tcp.analysis.retransmission -e tcp.analysis.duplicate_ack
  -e tcp.options.mss_val -e tcp.options.wscale
  -e udp.srcport -e udp.dstport -e udp.length -e udp.stream
  -e icmp.type -e icmp.code -e icmp.ident -e icmp.seq
)

for f in ddos_attack/*.pcap; do
  label=$(basename "$f" .pcap)
  tshark -r "$f" -T fields "${FIELDS[@]}" \
    -E header=y -E separator=, -E quote=d -E occurrence=f \
    > "csv/${label}.csv"
done
```

Опції:

- `-E occurrence=f` — у випадку мультизначень брати перше, щоб не ламати CSV;
- `-E quote=d` — лапки на випадок ком у значеннях;
- `-n` можна додати, щоб tshark не робив DNS-резолв (пришвидшує х10 на великих дампах).

### 2. Агрегована статистика (для швидкої візуалізації без ML)

- Загальна статистика + розподіл по часу (ваша поточна команда):
  ```bash
  tshark -r f.pcap -q -z io,stat,1
  ```
- Ієрархія протоколів:
  ```bash
  tshark -r f.pcap -q -z io,phs
  ```
- Розмови по IP / TCP / UDP (для порівняння кількості unique src IP у flood vs norm):
  ```bash
  tshark -r f.pcap -q -z conv,ip
  tshark -r f.pcap -q -z conv,tcp
  tshark -r f.pcap -q -z conv,udp
  ```
- Розподіл TCP-прапорів (ключ для різниці SYN/ACK/FIN/RST/PUSH flood):
  ```bash
  tshark -r f.pcap -q -z io,stat,0,\
  "COUNT(tcp.flags.syn)tcp.flags.syn==1",\
  "COUNT(tcp.flags.ack)tcp.flags.ack==1 && tcp.flags.syn==0",\
  "COUNT(tcp.flags.fin)tcp.flags.fin==1",\
  "COUNT(tcp.flags.reset)tcp.flags.reset==1",\
  "COUNT(tcp.flags.push)tcp.flags.push==1"
  ```
- ICMP-типи:
  ```bash
  tshark -r f.pcap -q -z io,stat,0,"COUNT(icmp.type==8)icmp.type==8","COUNT(icmp.type==0)icmp.type==0"
  ```

## Похідні (engineered) ознаки для ML

Per-packet CSV — це сирий вхід. Для класифікатора корисно згорнути його у вікна часу (наприклад, 1 с) або у потоки (flow = 5-tuple `src, dst, sport, dport, proto`).

### Вікна часу (sliding 1s, 5s)

- `pps` — пакетів за вікно;
- `bps` — байтів за вікно;
- `mean_frame_len`, `std_frame_len`, `min`, `max`;
- `mean_iat`, `std_iat` — inter-arrival time (з `frame.time_delta`);
- `unique_src_ip`, `unique_src_port` — **ентропія джерел** (Шеннон ентропія або просто n_unique);
- `unique_dst_port`;
- `tcp_syn_ratio`, `tcp_ack_ratio`, `tcp_fin_ratio`, `tcp_rst_ratio`, `tcp_push_ratio` — частка пакетів з кожним прапором;
- `icmp_ratio`, `udp_ratio`, `tcp_ratio`;
- `ttl_mean`, `ttl_std` (у hping3 завжди 64 → std=0);
- `window_mean` (у hping3 512 завжди);
- `mss_present_ratio`, `wscale_present_ratio` — частка TCP-пакетів з опціями (в hping3 = 0, в нормі ≈1 для SYN).

### Per-flow (за `tcp.stream` / `udp.stream`)

- `flow_duration`;
- `packets_fwd`, `packets_bwd`, `bytes_fwd`, `bytes_bwd`;
- `packets_per_second` у потоці;
- `flag_counts` (SYN/ACK/FIN/RST/PSH/URG);
- `handshake_complete` (чи був SYN→SYN+ACK→ACK);
- `mean_iat`, `std_iat`, `mean_pkt_size`, `std_pkt_size`.

Ці ознаки дають очевидні сепаратори у PCA/UMAP і стабільно працюють для деревоподібних моделей (RandomForest, XGBoost) та для кластеризації (KMeans/DBSCAN у вашому `cyber_clustering.ipynb`).

## Очікувані розрізнювальні ознаки (hypothesis sheet)

| Клас | Сильні ознаки |
|------|---------------|
| Normal | `frame.protocols` містить tls/dns/quic; `tcp.options.mss_val` присутній; `ip.ttl` варіативний; `tcp.window_size_value` ≫ 512; `mean_iat` у мілісекундах |
| SYN flood | `tcp.flags.syn=1 & ack=0`; `tcp.window_size_value=512`; `tcp.options` порожні; pps ≫ 1000; `unique_src_ip` ≫ 100 |
| ACK flood | `tcp.flags.ack=1 & syn=0`; довжина 54 Б |
| FIN flood | `tcp.flags.fin=1` єдиний прапор |
| RST flood | `tcp.flags.reset=1` єдиний прапор |
| PUSH flood | `tcp.flags.push=1` (часто разом з ACK) |
| UDP flood | `ip.proto=17`, `udp.length=8`, `frame.len=42` |
| ICMP flood | `ip.proto=1`, `icmp.type=8`, `icmp.code=0` |

Контрольна перевірка: після витягу CSV побудуйте `value_counts` по `tcp.flags.str` у кожному файлі — має бути майже моно-мода для кожного DDoS-сценарію і різноманіття для normal.

## Практичні поради

1. **Додайте колонку `label`** до кожного CSV перед конкатенацією (значення — ім'я файлу без розширення). Інакше класи буде важко відновити.
2. **Уникайте витягу payload** (`-e data.data`, `-e tcp.payload`) — вибухає розмір CSV і не додає інформації для цього датасету.
3. **Використовуйте `-n`** щоб вимкнути DNS-резолвінг tshark: `tshark -n -r …`.
4. **Великі pcap** (ACK/RST — 40+ МБ) можна попередньо порізати: `editcap -c 100000 in.pcap out.pcap` (по 100k пакетів у шматку).
5. Для **балансу класів** підрахуйте кількість кадрів на файл (`capinfos *.pcap`) — DDoS-дампи мають сотні тисяч пакетів, нормальний ~2200; при тренуванні зробіть undersampling DDoS або oversampling normal.
6. **`capinfos`** — швидка метаінформація (тривалість, середній pps, avg packet size) без парсингу:
   ```bash
   capinfos -csMuaeES ddos_attack/*.pcap
   ```

## Резюме

Замість 5 полів у поточному скрипті, мінімально достатній набір для цього датасету — **~35-45 полів** із frame/ip/tcp/udp/icmp, що дозволяє:

- візуально показати різницю між класами (heatmap прапорів, розподіли TTL / window_size / IAT, ентропію src IP);
- згорнути в window-/flow-features для ML;
- впевнено розрізнити всі 7 DDoS-сценаріїв hping3 від нормального клієнтського трафіку навіть лінійними моделями.
