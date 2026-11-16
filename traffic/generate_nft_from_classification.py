#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import pandas as pd

from flow_classifier import FlowClassifier, packets_to_flows

ROOT = Path(__file__).resolve().parent


def render_rules_nft(
    block_entries: list[tuple[str, str]],
    table_name: str,
    chain_name: str,
) -> str:
    lines = [
        "#!/usr/sbin/nft -f",
        "# Автогенерація з класифікації. Перевірка: nft -c -f rules.nft",
        "# Застосування (root): nft -f rules.nft",
        "# Окрема таблиця, щоб не чіпати правила за замовчуванням.",
        "",
        f"flush table inet {table_name}",
        "",
        f"table inet {table_name} {{",
        f"  chain {chain_name} {{",
        "    type filter hook input priority -100; policy accept;",
    ]
    for ip_lit, reason in block_entries:
        safe = reason.replace('"', "'")
        lines.append(f'    ip saddr {ip_lit} drop comment "{safe}"')
    lines += [
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description="Класифікація трафіку та генерація rules.nft")
    p.add_argument(
        "--csv",
        type=Path,
        required=True,
        help="CSV пакетів (як cybersecurity_dataset без колонки label; якщо label є — ігнорується).",
    )
    p.add_argument("--model", type=Path, default=ROOT / "models" / "cyber_flow_classifier.keras")
    p.add_argument("--artifacts", type=Path, default=ROOT / "models" / "cyber_flow_artifacts.joblib")
    p.add_argument("--output", type=Path, default=ROOT / "rules.nft")
    p.add_argument(
        "--allow-classes",
        default="normal",
        dest="allow_classes",
        help="Класи з виходу моделі (inverse_transform), без drop (через кому).",
    )
    p.add_argument("--table", default="cyber_cls", help="Ім'я таблиці inet у nftables")
    p.add_argument("--chain", default="input_cls", help="Ім'я chain з hook input")
    args = p.parse_args()

    allow = {x.strip() for x in args.allow_classes.split(",") if x.strip()}

    if not args.model.is_file():
        print(f"Немає файлу моделі: {args.model}", file=sys.stderr)
        return 1
    if not args.artifacts.is_file():
        print(f"Немає артефактів: {args.artifacts}", file=sys.stderr)
        return 1

    df = pd.read_csv(args.csv, na_values=["", " "], low_memory=False)
    flows = packets_to_flows(df)
    if flows.empty:
        print("Після агрегації flows порожній — нічого класифікувати.", file=sys.stderr)
        return 1

    classified = FlowClassifier.load(args.model, args.artifacts).predict(flows)

    block_entries: list[tuple[str, str]] = []
    for _, row in classified.iterrows():
        cls_name = str(row["pred_class"])
        src = row["__src_ip"]
        if cls_name in allow:
            continue
        try:
            ipaddress.IPv4Address(src)
        except ValueError:
            print(f"Пропуск не-IPv4 джерела: {src}", file=sys.stderr)
            continue
        block_entries.append((src, f"cls:{cls_name}"))

    text = render_rules_nft(block_entries, args.table, args.chain)
    args.output.write_text(text, encoding="utf-8")
    print(f"Записано {args.output.resolve()} — правил drop: {len(block_entries)}")
    for ip_lit, reason in block_entries:
        print(f"  {ip_lit}  {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
