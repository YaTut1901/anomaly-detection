#!/usr/bin/env python3
"""Перевірки розбору пакетів і рішення про drop без tshark, nft і моделі."""

from __future__ import annotations

import unittest

import pandas as pd

from filter_daemon import (
    decide_blocks,
    is_protected,
    nft_element_command,
    parse_tshark_line,
    split_closed,
)
from flow_classifier import packets_to_flows


class ParseTests(unittest.TestCase):
    def test_parses_tab_line(self) -> None:
        line = "1777276200.100\t192.168.50.10\t203.0.113.50\t6\t60\t443\t\t0\t1\t0\t0\t0\n"
        rec = parse_tshark_line(line)
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec["ip.src"], "192.168.50.10")
        self.assertEqual(rec["tcp.dstport"], 443.0)
        self.assertEqual(rec["udp.dstport"], -1.0)
        self.assertEqual(rec["tcp.flags.ack"], 1.0)

    def test_skips_non_ipv4(self) -> None:
        line = "1\tfe80::1\t203.0.113.50\t6\t60\t443\t\t1\t0\t0\t0\t0"
        self.assertIsNone(parse_tshark_line(line))


class WindowTests(unittest.TestCase):
    def test_keeps_current_bucket(self) -> None:
        packets = [
            {"frame.time_epoch": 100.2},
            {"frame.time_epoch": 101.1},
        ]
        closed, keep = split_closed(packets, now=101.8, window=1.0)
        self.assertEqual(closed, [{"frame.time_epoch": 100.2}])
        self.assertEqual(keep, [{"frame.time_epoch": 101.1}])


class DecisionTests(unittest.TestCase):
    def test_blocks_attack_and_skips_protected(self) -> None:
        frame = pd.DataFrame(
            [
                {"__src_ip": "203.0.113.9", "pred_class": "syn", "pred_confidence": 0.91, "n_packets": 40},
                {"__src_ip": "127.0.0.1", "pred_class": "syn", "pred_confidence": 0.99, "n_packets": 40},
                {"__src_ip": "198.51.100.8", "pred_class": "normal", "pred_confidence": 0.99, "n_packets": 40},
                {"__src_ip": "203.0.113.10", "pred_class": "udp", "pred_confidence": 0.2, "n_packets": 40},
            ]
        )
        decisions = decide_blocks(
            frame,
            allow={"normal"},
            min_confidence=0.5,
            min_packets=1,
            protected={"192.168.1.1"},
            already=set(),
            max_blocks=500,
        )
        self.assertEqual(decisions, [("203.0.113.9", "syn", 0.91, 40)])

    def test_loopback_is_protected(self) -> None:
        self.assertTrue(is_protected("127.0.0.1", set()))
        self.assertFalse(is_protected("203.0.113.9", set()))
        self.assertTrue(is_protected("203.0.113.9", {"203.0.113.9"}))


class FlowTests(unittest.TestCase):
    def test_syn_fraction_and_src(self) -> None:
        df = pd.DataFrame(
            [
                {
                    "frame.time_epoch": 100.1,
                    "ip.src": "203.0.113.9",
                    "ip.dst": "198.51.100.1",
                    "ip.proto": 6,
                    "frame.len": 54,
                    "tcp.dstport": 80,
                    "udp.dstport": None,
                    "tcp.flags.syn": 1,
                    "tcp.flags.ack": 0,
                    "tcp.flags.fin": 0,
                    "tcp.flags.reset": 0,
                    "tcp.flags.push": 0,
                },
                {
                    "frame.time_epoch": 100.2,
                    "ip.src": "203.0.113.9",
                    "ip.dst": "198.51.100.1",
                    "ip.proto": 6,
                    "frame.len": 54,
                    "tcp.dstport": 80,
                    "udp.dstport": None,
                    "tcp.flags.syn": 1,
                    "tcp.flags.ack": 0,
                    "tcp.flags.fin": 0,
                    "tcp.flags.reset": 0,
                    "tcp.flags.push": 0,
                },
            ]
        )
        flows = packets_to_flows(df)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows.loc[0, "__src_ip"], "203.0.113.9")
        self.assertEqual(int(flows.loc[0, "n_packets"]), 2)
        self.assertEqual(float(flows.loc[0, "frac_syn"]), 1.0)


class NftTests(unittest.TestCase):
    def test_element_command(self) -> None:
        self.assertEqual(
            nft_element_command("cyber_cls", "blocked_v4", "203.0.113.9"),
            ["nft", "add", "element", "inet", "cyber_cls", "blocked_v4", "{", "203.0.113.9", "}"],
        )


if __name__ == "__main__":
    unittest.main()
