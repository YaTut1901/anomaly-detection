#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from tensorflow import keras

W = 1.0
ROOT = Path(__file__).resolve().parent


def _iat_stats(times: pd.Series) -> tuple[float, float]:
    if len(times) < 2:
        return (0.0, 0.0)
    d = np.diff(np.sort(times.to_numpy()))
    return (float(d.mean()), float(d.std()))


def _nunique_no_sentinel(s: pd.Series) -> int:
    p = s[s != -1]
    return int(p.nunique())


def _ipv4_to_int(x) -> int:
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return -1
    try:
        return int(ipaddress.IPv4Address(str(x).strip()))
    except (ValueError, ipaddress.AddressValueError):
        return -1


def packets_to_flows(df: pd.DataFrame) -> pd.DataFrame:
    flows_src = df.copy()
    flows_src = flows_src.drop(columns=["label"], errors="ignore")

    flows_src["t_bucket"] = (flows_src["frame.time_epoch"] // W).astype(np.int64)
    flows_src["dst_port"] = flows_src["tcp.dstport"].where(
        flows_src["tcp.dstport"] != -1, flows_src["udp.dstport"]
    )

    flows_src["_proto_tcp"] = (flows_src["ip.proto"] == 6).astype(np.float32)
    flows_src["_proto_udp"] = (flows_src["ip.proto"] == 17).astype(np.float32)
    flows_src["_proto_icmp"] = (flows_src["ip.proto"] == 1).astype(np.float32)
    flows_src["_syn"] = (flows_src["tcp.flags.syn"] == 1).astype(np.float32)
    flows_src["_ack"] = (flows_src["tcp.flags.ack"] == 1).astype(np.float32)
    flows_src["_fin"] = (flows_src["tcp.flags.fin"] == 1).astype(np.float32)
    flows_src["_rst"] = (flows_src["tcp.flags.reset"] == 1).astype(np.float32)
    flows_src["_psh"] = (flows_src["tcp.flags.push"] == 1).astype(np.float32)

    g = flows_src.groupby(["ip.src", "t_bucket"], observed=True)

    flows = g.agg(
        n_packets=("frame.len", "size"),
        mean_pkt_size=("frame.len", "mean"),
        std_pkt_size=("frame.len", "std"),
        n_unique_dst_ips=("ip.dst", "nunique"),
        n_unique_dst_ports=("dst_port", _nunique_no_sentinel),
        frac_proto_tcp=("_proto_tcp", "mean"),
        frac_proto_udp=("_proto_udp", "mean"),
        frac_proto_icmp=("_proto_icmp", "mean"),
        frac_syn=("_syn", "mean"),
        frac_ack=("_ack", "mean"),
        frac_fin=("_fin", "mean"),
        frac_rst=("_rst", "mean"),
        frac_psh=("_psh", "mean"),
    )

    iat = g["frame.time_epoch"].apply(_iat_stats).apply(pd.Series)
    iat.columns = ["iat_mean", "iat_std"]
    flows = flows.join(iat).reset_index()

    flows["std_pkt_size"] = flows["std_pkt_size"].fillna(0.0)
    flows["__src_ip"] = flows["ip.src"].astype(str)
    flows["ip_src_numeric"] = flows["ip.src"].map(_ipv4_to_int).astype(np.int64)
    flows = flows.drop(columns=["ip.src"])

    return flows


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

    art = joblib.load(args.artifacts)
    feature_cols: list[str] = art["feature_cols"]
    scaler = art["feature_scaler"]

    df = pd.read_csv(args.csv, na_values=["", " "], low_memory=False)
    flows = packets_to_flows(df)
    if flows.empty:
        print("Після агрегації flows порожній — нічого класифікувати.", file=sys.stderr)
        return 1

    X = flows[feature_cols].astype(np.float32)
    Xs = scaler.transform(X)

    model = keras.models.load_model(args.model, compile=False)
    probs = model.predict(Xs, verbose=0)
    pred_idx = np.argmax(probs, axis=1)

    le = art["label_encoder"]
    pred_class_names = le.inverse_transform(pred_idx)

    block_entries: list[tuple[str, str]] = []
    for pos, (_, row) in enumerate(flows.iterrows()):
        cls_name = str(pred_class_names[pos])
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
