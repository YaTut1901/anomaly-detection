"""Агрегація пакетів у flow-вікна і класифікація збереженою MLP."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import numpy as np
import pandas as pd

W = 1.0

NA_PROTO = -1.0
PROTO_COLUMNS = (
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "udp.srcport",
    "udp.dstport",
    "icmp.type",
    "icmp.code",
)


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


def fill_proto_na(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in PROTO_COLUMNS:
        if col not in out.columns:
            out[col] = NA_PROTO
        else:
            out[col] = pd.to_numeric(out[col], errors="coerce").fillna(NA_PROTO)
    return out


def packets_to_flows(df: pd.DataFrame, window: float = W) -> pd.DataFrame:
    flows_src = fill_proto_na(df)
    flows_src = flows_src.drop(columns=["label"], errors="ignore")

    flows_src["t_bucket"] = (flows_src["frame.time_epoch"] // window).astype(np.int64)
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


class FlowClassifier:
    def __init__(self, model, artifacts: dict):
        self.model = model
        self.artifacts = artifacts
        self.feature_cols: list[str] = list(artifacts["feature_cols"])
        self.scaler = artifacts["feature_scaler"]
        self.label_encoder = artifacts["label_encoder"]

    @classmethod
    def load(cls, model_path: Path, artifacts_path: Path) -> "FlowClassifier":
        import joblib
        from tensorflow import keras

        artifacts = joblib.load(artifacts_path)
        model = keras.models.load_model(model_path, compile=False)
        return cls(model, artifacts)

    def predict(self, flows: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in self.feature_cols if c not in flows.columns]
        if missing:
            raise KeyError(f"У flows немає колонок моделі: {missing}")
        X = flows[self.feature_cols].astype(np.float32)
        Xs = self.scaler.transform(X)
        probs = self.model.predict(Xs, verbose=0)
        pred_idx = np.argmax(probs, axis=1)
        out = flows.copy()
        out["pred_class"] = self.label_encoder.inverse_transform(pred_idx)
        out["pred_confidence"] = probs[np.arange(len(pred_idx)), pred_idx]
        return out
