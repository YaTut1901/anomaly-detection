#!/usr/bin/env python3
"""Фоновий фільтр: живий трафік → збережена MLP → drop IP у nftables.

Процес читає пакети через tshark, згортає їх у ті самі 1-секундні вікна,
що й навчання, і для класу поза allow-list додає джерело в nft set.
Потрібні root, tshark і nft.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pandas as pd

from flow_classifier import W, FlowClassifier, packets_to_flows

ROOT = Path(__file__).resolve().parent
RUN_DIR = ROOT / "run"

TSHARK_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "frame.len",
    "tcp.dstport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
)

log = logging.getLogger("anomaly-filter")
_STOP = False


def _handle_stop(signum, _frame) -> None:
    global _STOP
    _STOP = True
    log.info("Сигнал %s, зупинка", signum)


def parse_tshark_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    parts = line.split("\t")
    if len(parts) < len(TSHARK_FIELDS):
        parts = parts + [""] * (len(TSHARK_FIELDS) - len(parts))
    rec = dict(zip(TSHARK_FIELDS, parts[: len(TSHARK_FIELDS)]))
    src = rec["ip.src"].strip()
    if not src:
        return None
    try:
        ipaddress.IPv4Address(src)
    except ValueError:
        return None
    rec["ip.src"] = src
    rec["ip.dst"] = rec["ip.dst"].strip()
    for key, value in list(rec.items()):
        if key in ("ip.src", "ip.dst"):
            continue
        if value == "":
            rec[key] = -1.0
        else:
            try:
                rec[key] = float(value)
            except ValueError:
                return None
    return rec


def split_closed(packets: list[dict], now: float, window: float = W) -> tuple[list[dict], list[dict]]:
    current_bucket = int(now // window)
    closed: list[dict] = []
    keep: list[dict] = []
    for pkt in packets:
        bucket = int(float(pkt["frame.time_epoch"]) // window)
        if bucket < current_bucket:
            closed.append(pkt)
        else:
            keep.append(pkt)
    return closed, keep


def _ipv4_networks() -> list[ipaddress.IPv4Network]:
    return [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("224.0.0.0/4"),
    ]


def local_ipv4_addresses() -> set[str]:
    found: set[str] = set()
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return found
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        addr = parts[parts.index("inet") + 1].split("/")[0]
        found.add(addr)
    return found


def default_gateway() -> str | None:
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def default_interface() -> str | None:
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None


def is_protected(src: str, extra: set[str]) -> bool:
    try:
        ip = ipaddress.IPv4Address(src)
    except ValueError:
        return True
    if src in extra:
        return True
    return any(ip in net for net in _ipv4_networks())


def decide_blocks(
    classified: pd.DataFrame,
    *,
    allow: set[str],
    min_confidence: float,
    min_packets: int,
    protected: set[str],
    already: set[str],
    max_blocks: int,
) -> list[tuple[str, str, float, int]]:
    """Повертає (ip, class, confidence, n_packets) для нових drop."""
    chosen: list[tuple[str, str, float, int]] = []
    seen = set(already)
    for _, row in classified.iterrows():
        if len(seen) >= max_blocks:
            break
        src = str(row["__src_ip"])
        cls_name = str(row["pred_class"])
        if cls_name in allow or src in seen or is_protected(src, protected):
            continue
        confidence = float(row["pred_confidence"])
        n_packets = int(row["n_packets"])
        if confidence < min_confidence or n_packets < min_packets:
            continue
        seen.add(src)
        chosen.append((src, cls_name, confidence, n_packets))
    return chosen


def nft_base_commands(table: str, chain: str, set_name: str) -> list[list[str]]:
    return [
        ["nft", "add", "table", "inet", table],
        [
            "nft", "add", "set", "inet", table, set_name,
            "{", "type", "ipv4_addr", ";", "}",
        ],
        [
            "nft", "add", "chain", "inet", table, chain,
            "{", "type", "filter", "hook", "input", "priority", "-100", ";", "policy", "accept", ";", "}",
        ],
        [
            "nft", "add", "rule", "inet", table, chain,
            "ip", "saddr", f"@{set_name}", "drop",
        ],
    ]


def nft_element_command(table: str, set_name: str, ip: str) -> list[str]:
    return ["nft", "add", "element", "inet", table, set_name, "{", ip, "}"]


class NftBlocker:
    def __init__(self, table: str, chain: str, set_name: str, dry_run: bool):
        self.table = table
        self.chain = chain
        self.set_name = set_name
        self.dry_run = dry_run
        self.blocked: set[str] = set()
        self._ready = False

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, check=False, capture_output=True, text=True)

    def _must(self, argv: list[str]) -> None:
        created = self._run(argv)
        if created.returncode != 0 and "File exists" not in created.stderr:
            raise RuntimeError(f"{' '.join(argv)} не вдалося: {created.stderr.strip()}")

    def ensure(self) -> None:
        if self.dry_run or self._ready:
            self._ready = True
            return
        if self._run(["nft", "list", "table", "inet", self.table]).returncode != 0:
            self._must(["nft", "add", "table", "inet", self.table])
        if self._run(["nft", "list", "set", "inet", self.table, self.set_name]).returncode != 0:
            self._must(nft_base_commands(self.table, self.chain, self.set_name)[1])
        chain = self._run(["nft", "list", "chain", "inet", self.table, self.chain])
        if chain.returncode != 0:
            self._must(nft_base_commands(self.table, self.chain, self.set_name)[2])
            chain_text = ""
        else:
            chain_text = chain.stdout
        if f"@{self.set_name}" not in chain_text:
            self._must(nft_base_commands(self.table, self.chain, self.set_name)[3])
        elements = self._run(["nft", "list", "set", "inet", self.table, self.set_name])
        if elements.returncode == 0:
            self.blocked.update(_parse_set_elements(elements.stdout))
        self._ready = True
        log.info(
            "nft inet %s / %s, уже в set: %s",
            self.table,
            self.set_name,
            len(self.blocked),
        )

    def block(self, ip: str) -> None:
        if ip in self.blocked:
            return
        if self.dry_run:
            self.blocked.add(ip)
            return
        self.ensure()
        argv = nft_element_command(self.table, self.set_name, ip)
        result = self._run(argv)
        if result.returncode != 0 and "File exists" not in result.stderr:
            raise RuntimeError(f"{' '.join(argv)} не вдалося: {result.stderr.strip()}")
        self.blocked.add(ip)

    def flush(self) -> None:
        if self.dry_run:
            self.blocked.clear()
            return
        result = self._run(["nft", "delete", "table", "inet", self.table])
        if result.returncode != 0 and "No such file" not in result.stderr:
            log.warning("Не вдалося зняти таблицю %s: %s", self.table, result.stderr.strip())
        self.blocked.clear()


def _parse_set_elements(text: str) -> set[str]:
    found: set[str] = set()
    if "elements = {" not in text:
        return found
    body = text.split("elements = {", 1)[1].split("}", 1)[0]
    for token in body.replace(",", " ").split():
        try:
            found.add(str(ipaddress.IPv4Address(token)))
        except ValueError:
            continue
    return found


def start_tshark(interface: str) -> subprocess.Popen[str]:
    argv = [
        "tshark",
        "-i", interface,
        "-l",
        "-n",
        "-f", "ip",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    for field in TSHARK_FIELDS:
        argv.extend(["-e", field])
    log.info("Запуск: %s", " ".join(argv))
    try:
        return subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("tshark не знайдено в PATH") from exc


def _drain_stderr(proc: subprocess.Popen[str]) -> None:
    if proc.stderr is None:
        return
    for line in proc.stderr:
        text = line.strip()
        if text:
            log.info("tshark: %s", text)


def daemonize(pidfile: Path, logfile: Path) -> None:
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    logfile.parent.mkdir(parents=True, exist_ok=True)
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    log_fd = os.open(str(logfile), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(log_fd)
    pidfile.write_text(str(os.getpid()), encoding="utf-8")


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_pid(pidfile: Path) -> int | None:
    try:
        return int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def stop_daemon(pidfile: Path) -> int:
    pid = read_pid(pidfile)
    if pid is None or not pid_alive(pid):
        print(f"Демон не запущений ({pidfile})", file=sys.stderr)
        pidfile.unlink(missing_ok=True)
        return 1
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        if not pid_alive(pid):
            pidfile.unlink(missing_ok=True)
            print(f"Зупинено {pid}")
            return 0
        time.sleep(0.1)
    print(f"Процес {pid} не завершився після SIGTERM", file=sys.stderr)
    return 1


def run_loop(args: argparse.Namespace, classifier: FlowClassifier) -> int:
    protected = set(args.allow_ips)
    protected.update(local_ipv4_addresses())
    if args.protect_gateway:
        gateway = default_gateway()
        if gateway:
            protected.add(gateway)
            log.info("Шлюз не блокується: %s", gateway)
    log.info("Захищені адреси: %s", ", ".join(sorted(protected)) or "—")

    blocker = NftBlocker(args.table, args.chain, args.set_name, args.dry_run)
    if not args.dry_run:
        blocker.ensure()

    proc = start_tshark(args.interface)
    assert proc.stdout is not None
    threading.Thread(target=_drain_stderr, args=(proc,), daemon=True).start()
    stdout_fd = proc.stdout.fileno()

    packets: list[dict] = []
    allow = {x.strip() for x in args.allow_classes.split(",") if x.strip()}
    window = args.window
    cap_logged = False
    try:
        while not _STOP:
            ready, _, _ = select.select([stdout_fd], [], [], args.interval)
            if ready:
                while True:
                    line = proc.stdout.readline()
                    if line == "":
                        log.error("tshark завершився, код %s", proc.poll())
                        return 1
                    rec = parse_tshark_line(line)
                    if rec is not None:
                        packets.append(rec)
                    if not select.select([stdout_fd], [], [], 0)[0]:
                        break
            if proc.poll() is not None:
                log.error("tshark завершився, код %s", proc.returncode)
                return 1
            closed, packets = split_closed(packets, time.time(), window)
            if not closed:
                continue
            flows = packets_to_flows(pd.DataFrame(closed), window)
            if flows.empty:
                continue
            classified = classifier.predict(flows)
            decisions = decide_blocks(
                classified,
                allow=allow,
                min_confidence=args.min_confidence,
                min_packets=args.min_packets,
                protected=protected,
                already=blocker.blocked,
                max_blocks=args.max_blocks,
            )
            for src, cls_name, confidence, n_packets in decisions:
                blocker.block(src)
                log.warning(
                    "block %s class=%s p=%.3f packets=%s%s",
                    src,
                    cls_name,
                    confidence,
                    n_packets,
                    " (dry-run)" if args.dry_run else "",
                )
            if len(blocker.blocked) >= args.max_blocks and not cap_logged:
                log.error("Досягнуто --max-blocks=%s, нові IP не додаються", args.max_blocks)
                cap_logged = True
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        if args.flush_on_stop:
            log.info("Знімаю таблицю nft inet %s", args.table)
            blocker.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Демон класифікації живого трафіку і drop IP у nftables")
    p.add_argument("--model", type=Path, default=ROOT / "models" / "cyber_flow_classifier.keras")
    p.add_argument("--artifacts", type=Path, default=ROOT / "models" / "cyber_flow_artifacts.joblib")
    p.add_argument("--interface", default=None, help="Інтерфейс tshark. За замовчуванням — інтерфейс default route")
    p.add_argument("--window", type=float, default=W, help="Довжина вікна агрегації, секунди")
    p.add_argument("--interval", type=float, default=0.5, help="Як часто закривати готові вікна, секунди")
    p.add_argument("--allow-classes", default="normal", help="Класи без drop, через кому")
    p.add_argument("--min-confidence", type=float, default=0.5)
    p.add_argument("--min-packets", type=int, default=1)
    p.add_argument("--allow-ips", default="", help="Додаткові IP, які ніколи не блокувати")
    p.add_argument(
        "--protect-gateway",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Не блокувати IPv4 шлюзу default route",
    )
    p.add_argument("--max-blocks", type=int, default=500)
    p.add_argument("--table", default="cyber_cls")
    p.add_argument("--chain", default="input_cls")
    p.add_argument("--set-name", default="blocked_v4")
    p.add_argument("--dry-run", action="store_true", help="Класифікувати і логувати, nft не змінювати")
    p.add_argument("--flush-on-stop", action="store_true", help="При зупинці видалити таблицю nft")
    p.add_argument("--daemon", action="store_true", help="Відʼєднатися від термінала")
    p.add_argument("--stop", action="store_true", help="Зупинити процес з pid-файла")
    p.add_argument("--pidfile", type=Path, default=RUN_DIR / "anomaly-filter.pid")
    p.add_argument("--logfile", type=Path, default=RUN_DIR / "anomaly-filter.log")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.allow_ips = {x.strip() for x in args.allow_ips.split(",") if x.strip()}

    if args.stop:
        return stop_daemon(args.pidfile)

    if args.interface is None:
        args.interface = default_interface() or "lo"

    if not args.model.is_file():
        print(f"Немає файлу моделі: {args.model}", file=sys.stderr)
        print("Збережіть її ноутбуком traffic/cybersecurity_dataset_overview.ipynb у traffic/models/.", file=sys.stderr)
        return 1
    if not args.artifacts.is_file():
        print(f"Немає артефактів: {args.artifacts}", file=sys.stderr)
        return 1

    if not args.dry_run and os.geteuid() != 0:
        print("Потрібен root для tshark і nft. Або запустіть із --dry-run.", file=sys.stderr)
        return 1

    existing = read_pid(args.pidfile)
    if existing is not None and pid_alive(existing) and existing != os.getpid():
        print(f"Демон уже працює, pid {existing}", file=sys.stderr)
        return 1

    if args.daemon:
        daemonize(args.pidfile, args.logfile)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    log.info("Завантаження моделі %s", args.model)
    classifier = FlowClassifier.load(args.model, args.artifacts)
    log.info("Інтерфейс %s, dry-run=%s", args.interface, args.dry_run)
    try:
        return run_loop(args, classifier)
    finally:
        if args.daemon:
            args.pidfile.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
