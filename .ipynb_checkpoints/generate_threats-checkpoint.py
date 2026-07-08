"""Генерація синтетичного датасету кіберзагроз у форматі CSV."""

import argparse
import hashlib
import ipaddress
import os
import random
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Callable

import numpy as np
import pandas as pd

_TIMESTAMP_START = datetime(2025, 1, 1, tzinfo=timezone.utc)
_TIMESTAMP_END = datetime(2026, 4, 21, 23, 59, 59, tzinfo=timezone.utc)

protocols = ["TCP", "UDP"]
flags = ["SYN", "ACK", "RST", "FIN"]
packets = ["HTTP", "DNS", "SSH", "FTP", "SMTP", "ICMP"]
threat_types = [
    "Phishing",
    "DoS",
    "DDoS",
    "SQL Injection",
    "Ransomware",
    "Malware",
    "XSS",
    "CSRF",
    "Brute Force",
    "Man-in-the-Middle",
    "Port Scanning",
    "Credential Stuffing",
    "Spyware",
    "Trojan",
    "Zero-day Exploit",
    "Insider Threat",
    "Botnet Activity",
]

# Явно відсікаємо CGNAT (частина реалізацій уже виключає її через is_global, але залишаємо для наочності).
_CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")

# Детермінований «країна за IP», якщо немає GeoLite2 (не реальна геобаза, лише стабільне відображення).
_SYNTHETIC_COUNTRY_NAMES = (
    "United States",
    "Germany",
    "Japan",
    "Brazil",
    "India",
    "United Kingdom",
    "France",
    "Canada",
    "Australia",
    "Netherlands",
    "Poland",
    "Ukraine",
    "Sweden",
    "Spain",
    "Italy",
    "Mexico",
    "South Korea",
    "Singapore",
    "South Africa",
    "Argentina",
)

CountryLookup = Callable[[str], str]


def country_from_ip_deterministic(ip: str) -> str:
    digest = hashlib.sha256(ip.encode("ascii")).digest()
    idx = int.from_bytes(digest[:2], "big") % len(_SYNTHETIC_COUNTRY_NAMES)
    return _SYNTHETIC_COUNTRY_NAMES[idx]


@contextmanager
def geoip_country_lookup(db_path: str | None):
    """Повертає функцію ip -> country name. Якщо db_path задано — MaxMind GeoLite2 Country (geoip2)."""
    if not db_path:
        yield country_from_ip_deterministic
        return

    if not os.path.isfile(db_path):
        raise SystemExit(f"Файл бази GeoIP не знайдено: {db_path}")

    try:
        import geoip2.database
        import geoip2.errors
    except ImportError as exc:  # pragma: no cover - залежність опційна
        raise SystemExit(
            "Потрібен пакет geoip2: pip install geoip2"
        ) from exc

    reader = geoip2.database.Reader(db_path)

    def lookup(ip: str) -> str:
        try:
            rec = reader.country(ip)
            return rec.country.name or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            return country_from_ip_deterministic(ip)

    try:
        yield lookup
    finally:
        reader.close()


def is_valid_public_unicast_ipv4(addr: ipaddress.IPv4Address) -> bool:
    """Перевірка IPv4 для синтетичного «публічного» трафіку: без зарезервованих/некоректних діапазонів."""
    if not isinstance(addr, ipaddress.IPv4Address):
        return False
    if (
        addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
    ):
        return False
    if addr.is_private or addr.is_reserved:
        return False
    if addr in _CARRIER_GRADE_NAT:
        return False
    if not addr.is_global:
        return False
    return True


def validate_ipv4_string(value: str) -> str:
    """Парсинг і валідація IPv4-рядка; повертає нормалізований рядок або кидає ValueError."""
    addr = ipaddress.ip_address(value.strip())
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError("Очікується IPv4, не IPv6")
    if not is_valid_public_unicast_ipv4(addr):
        raise ValueError(f"IP-адреса не пройшла валідацію: {value!r}")
    return str(addr)


def random_global_ipv4_str() -> str:
    """Випадкова IPv4, що проходить is_valid_public_unicast_ipv4 (відхилення до успіху)."""
    for _ in range(50_000):
        addr = ipaddress.IPv4Address(random.getrandbits(32))
        if is_valid_public_unicast_ipv4(addr):
            return str(addr)
    raise RuntimeError("Не вдалося згенерувати валідну публічну IPv4-адресу")


def generate_row(
    row_index: int,
    row_count: int,
    country_for_ip: CountryLookup,
):
    t0 = _TIMESTAMP_START.timestamp()
    t1 = _TIMESTAMP_END.timestamp()
    if row_count == 1:
        timestamp = datetime.fromtimestamp(
            random.uniform(t0, t1), tz=timezone.utc
        ).isoformat()
    else:
        frac = row_index / (row_count - 1)
        timestamp = datetime.fromtimestamp(
            t0 + frac * (t1 - t0), tz=timezone.utc
        ).isoformat()

    source_ip = random_global_ipv4_str()
    destination_ip = random_global_ipv4_str()
    while destination_ip == source_ip:
        destination_ip = random_global_ipv4_str()

    return {
        "Timestamp": timestamp,
        "Protocol": random.choice(protocols),
        "Flag": random.choice(flags),
        "Packet": random.choice(packets),
        "Sender ID": random.randint(1, 1000),
        "Receiver ID": random.randint(1, 1000),
        "Source IP Address": source_ip,
        "Source Country": country_for_ip(source_ip),
        "Destination IP Address": destination_ip,
        "Destination Country": country_for_ip(destination_ip),
        "Source Port": random.randint(1, 65535),
        "Destination Port": random.randint(1, 65535),
        "Packet Size": random.randint(64, 4096),
        "Target Variable": random.choice(threat_types),
    }


def generate_dataset(row_count: int, country_for_ip: CountryLookup):
    return pd.DataFrame(
        [generate_row(i, row_count, country_for_ip) for i in range(row_count)]
    )


def inject_missing_and_duplicates(
    df: pd.DataFrame,
    missing_cell_prob: float,
    duplicate_ratio: float,
    random_state: int | None = None,
) -> pd.DataFrame:
    """
    Штучні пропуски: для кожної комірки в обраних колонках з імовірністю missing_cell_prob
    записується NaN (приклад з методички: if random.random() < 0.1: ... None).
    Дублікати: додається int(n * duplicate_ratio) випадкових копій існуючих рядків.
    """
    if missing_cell_prob < 0 or missing_cell_prob > 1:
        raise ValueError("missing_cell_prob має бути в діапазоні [0, 1]")
    if duplicate_ratio < 0:
        raise ValueError("duplicate_ratio не може бути від'ємним")

    rng = np.random.default_rng(random_state)
    out = df.copy()

    missable = [
        c
        for c in (
            "Protocol",
            "Flag",
            "Packet",
            "Sender ID",
            "Receiver ID",
            "Source IP Address",
            "Source Country",
            "Destination IP Address",
            "Destination Country",
            "Source Port",
            "Destination Port",
            "Packet Size",
            "Target Variable",
            "Timestamp",
        )
        if c in out.columns
    ]

    if missing_cell_prob > 0 and missable:
        for col in missable:
            p = missing_cell_prob * (0.25 if col == "Timestamp" else 1.0)
            mask = rng.random(len(out)) < p
            out.loc[mask, col] = np.nan

    if duplicate_ratio > 0 and len(out) > 0:
        n_extra = int(len(out) * duplicate_ratio)
        if n_extra > 0:
            pick = rng.integers(0, len(out), size=n_extra)
            out = pd.concat([out, out.iloc[pick].copy()], ignore_index=True)

    return out


def main():
    parser = argparse.ArgumentParser(
        description="Генерація синтетичних даних кіберзагроз",
        epilog=(
            "Геолокація: без --geoip-country-db країна обирається детерміновано з IP "
            "(навчальний режим). Для реальних назв встановіть geoip2 і вкажіть шлях до "
            "GeoLite2-Country.mmdb (безкоштовна база MaxMind). "
            "Для лабораторної з обробки даних: --missing-cell-prob та --duplicate-ratio "
            "(штучні пропуски та дублікати рядків)."
        ),
    )
    parser.add_argument(
        "rows",
        type=int,
        help="Кількість записів для генерації",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="cyber_threats_dataset.csv",
        help="Назва вихідного CSV файлу",
    )
    parser.add_argument(
        "--geoip-country-db",
        type=str,
        default=None,
        metavar="PATH",
        help="Шлях до GeoLite2-Country.mmdb (MaxMind); якщо не вказано — синтетична країна за IP",
    )
    parser.add_argument(
        "--missing-cell-prob",
        type=float,
        default=0.0,
        metavar="P",
        help="0..1: імовірність NaN у випадковій комірці (Timestamp рідше). 0 = без пропусків",
    )
    parser.add_argument(
        "--duplicate-ratio",
        type=float,
        default=0.0,
        metavar="R",
        help="0..1: частка додаткових рядків-дублікатів від початкової кількості рядків",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=None,
        help="Seed для відтворюваності пропусків і дублікатів",
    )
    args = parser.parse_args()

    if args.rows < 1:
        parser.error("Кількість записів має бути додатним цілим числом.")

    with geoip_country_lookup(args.geoip_country_db) as country_for_ip:
        df = generate_dataset(args.rows, country_for_ip)

    if args.missing_cell_prob > 0 or args.duplicate_ratio > 0:
        df = inject_missing_and_duplicates(
            df,
            missing_cell_prob=args.missing_cell_prob,
            duplicate_ratio=args.duplicate_ratio,
            random_state=args.random_state,
        )

    df.to_csv(args.output, index=False)

    print(
        f"Датасет успішно створено: {len(df)} рядків збережено у файл {args.output}"
    )


if __name__ == "__main__":
    main()
