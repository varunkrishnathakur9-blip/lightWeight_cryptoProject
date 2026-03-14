"""Run comparative experiments for baseline and proposed secure channels."""

from __future__ import annotations

import csv
import os
import pathlib
import statistics
import sys
import threading
import time
from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import psutil

# Ensure package imports work when running this script directly.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.baseline_protocol import BaselineSecureChannel, run_baseline_handshake_pair
from experiments.generate_paper import generate_paper
from lightweight_secure_channel.protocol.handshake import (
    HandshakeResult,
    perform_client_handshake,
    perform_server_handshake,
)
from lightweight_secure_channel.protocol.secure_channel import SecureChannel
from lightweight_secure_channel.protocol.session_manager import SessionManager

MESSAGE_COUNTS = [100, 500, 1000]
REPEATS = 3
PAYLOAD_SIZE = 128

GRAPH_DIR = PROJECT_ROOT / "results" / "graphs"
TABLE_DIR = PROJECT_ROOT / "results" / "tables"


@dataclass(frozen=True)
class RunMetrics:
    protocol: str
    message_count: int
    repeat: int
    handshake_latency_ms: float
    encryption_latency_ms: float
    memory_usage_mb: float
    cpu_utilization_pct: float
    throughput_mbps: float


def _mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _run_proposed_handshake_pair(
    client_manager: SessionManager,
    server_manager: SessionManager,
    resume_connection_id: str | None = None,
) -> tuple[float, HandshakeResult]:
    import socket

    client_sock, server_sock = socket.socketpair()
    server_result: dict[str, HandshakeResult] = {}

    def _server_worker() -> None:
        with server_sock:
            stream = server_sock.makefile("rwb")
            try:
                server_result["result"] = perform_server_handshake(
                    stream,
                    session_manager=server_manager,
                    context_info=b"evaluation-proposed",
                )
            finally:
                stream.close()

    thread = threading.Thread(target=_server_worker, daemon=True)
    thread.start()

    start = time.perf_counter()
    with client_sock:
        stream = client_sock.makefile("rwb")
        try:
            client_result = perform_client_handshake(
                stream,
                session_manager=client_manager,
                resume_connection_id=resume_connection_id,
                context_info=b"evaluation-proposed",
            )
        finally:
            stream.close()
    latency_ms = (time.perf_counter() - start) * 1000.0

    thread.join(timeout=5)
    if "result" not in server_result:
        raise RuntimeError("Proposed server handshake did not complete.")
    return latency_ms, client_result


def _evaluate_baseline_message_path(message_count: int, key_material, session_id: str) -> tuple[float, float, float, float]:
    sender = BaselineSecureChannel(session_id=session_id, key_material=key_material)
    receiver = BaselineSecureChannel(session_id=session_id, key_material=key_material)

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    cpu_before = time.process_time()
    wall_before = time.perf_counter()

    encryption_latencies: list[float] = []
    total_bytes = 0

    for _ in range(message_count):
        payload = os.urandom(PAYLOAD_SIZE)
        start = time.perf_counter()
        packet = sender.encrypt_packet(payload)
        encryption_latencies.append((time.perf_counter() - start) * 1000.0)
        _ = receiver.decrypt_packet(packet)
        total_bytes += len(payload)

    wall_after = time.perf_counter()
    cpu_after = time.process_time()
    mem_after = process.memory_info().rss

    wall_delta = max(wall_after - wall_before, 1e-9)
    cpu_pct = ((cpu_after - cpu_before) / wall_delta) * 100.0
    memory_delta_mb = (mem_after - mem_before) / (1024 * 1024)
    throughput_mbps = (total_bytes / wall_delta) / (1024 * 1024)

    return _mean(encryption_latencies), memory_delta_mb, cpu_pct, throughput_mbps


def _evaluate_proposed_message_path(message_count: int, key_material, session_id: str) -> tuple[float, float, float, float]:
    sender = SecureChannel(session_id=session_id, key_material=key_material)
    receiver = SecureChannel(session_id=session_id, key_material=key_material)

    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    cpu_before = time.process_time()
    wall_before = time.perf_counter()

    encryption_latencies: list[float] = []
    total_bytes = 0

    for _ in range(message_count):
        payload = os.urandom(PAYLOAD_SIZE)
        start = time.perf_counter()
        packet = sender.encrypt_packet(payload)
        encryption_latencies.append((time.perf_counter() - start) * 1000.0)
        _ = receiver.decrypt_packet(packet)
        total_bytes += len(payload)

    wall_after = time.perf_counter()
    cpu_after = time.process_time()
    mem_after = process.memory_info().rss

    wall_delta = max(wall_after - wall_before, 1e-9)
    cpu_pct = ((cpu_after - cpu_before) / wall_delta) * 100.0
    memory_delta_mb = (mem_after - mem_before) / (1024 * 1024)
    throughput_mbps = (total_bytes / wall_delta) / (1024 * 1024)

    return _mean(encryption_latencies), memory_delta_mb, cpu_pct, throughput_mbps


def run_experiments() -> list[RunMetrics]:
    records: list[RunMetrics] = []

    for message_count in MESSAGE_COUNTS:
        for repeat in range(1, REPEATS + 1):
            baseline_handshake_ms, baseline_result = run_baseline_handshake_pair()
            base_encrypt_ms, base_mem_mb, base_cpu, base_tp = _evaluate_baseline_message_path(
                message_count=message_count,
                key_material=baseline_result.key_material,
                session_id=baseline_result.session_id,
            )
            records.append(
                RunMetrics(
                    protocol="baseline",
                    message_count=message_count,
                    repeat=repeat,
                    handshake_latency_ms=baseline_handshake_ms,
                    encryption_latency_ms=base_encrypt_ms,
                    memory_usage_mb=base_mem_mb,
                    cpu_utilization_pct=base_cpu,
                    throughput_mbps=base_tp,
                )
            )

            client_manager = SessionManager(session_timeout=300)
            server_manager = SessionManager(session_timeout=300)

            _, warmup_result = _run_proposed_handshake_pair(
                client_manager=client_manager,
                server_manager=server_manager,
                resume_connection_id=None,
            )
            proposed_handshake_ms, proposed_result = _run_proposed_handshake_pair(
                client_manager=client_manager,
                server_manager=server_manager,
                resume_connection_id=warmup_result.connection_id,
            )
            prop_encrypt_ms, prop_mem_mb, prop_cpu, prop_tp = _evaluate_proposed_message_path(
                message_count=message_count,
                key_material=proposed_result.key_material,
                session_id=proposed_result.session_id,
            )
            records.append(
                RunMetrics(
                    protocol="proposed",
                    message_count=message_count,
                    repeat=repeat,
                    handshake_latency_ms=proposed_handshake_ms,
                    encryption_latency_ms=prop_encrypt_ms,
                    memory_usage_mb=prop_mem_mb,
                    cpu_utilization_pct=prop_cpu,
                    throughput_mbps=prop_tp,
                )
            )

    return records


def _write_tables(records: list[RunMetrics]) -> None:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)

    detailed_csv = TABLE_DIR / "metrics_detailed.csv"
    with detailed_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "protocol",
                "message_count",
                "repeat",
                "handshake_latency_ms",
                "encryption_latency_ms",
                "memory_usage_mb",
                "cpu_utilization_pct",
                "throughput_mbps",
            ]
        )
        for row in records:
            writer.writerow(
                [
                    row.protocol,
                    row.message_count,
                    row.repeat,
                    f"{row.handshake_latency_ms:.6f}",
                    f"{row.encryption_latency_ms:.6f}",
                    f"{row.memory_usage_mb:.6f}",
                    f"{row.cpu_utilization_pct:.6f}",
                    f"{row.throughput_mbps:.6f}",
                ]
            )

    grouped: dict[tuple[str, int], list[RunMetrics]] = {}
    for row in records:
        grouped.setdefault((row.protocol, row.message_count), []).append(row)

    summary_rows: list[dict[str, float | str | int]] = []
    for protocol in ["baseline", "proposed"]:
        for message_count in MESSAGE_COUNTS:
            group = grouped[(protocol, message_count)]
            summary_rows.append(
                {
                    "protocol": protocol,
                    "message_count": message_count,
                    "handshake_latency_ms": _mean([item.handshake_latency_ms for item in group]),
                    "encryption_latency_ms": _mean([item.encryption_latency_ms for item in group]),
                    "memory_usage_mb": _mean([item.memory_usage_mb for item in group]),
                    "cpu_utilization_pct": _mean([item.cpu_utilization_pct for item in group]),
                    "throughput_mbps": _mean([item.throughput_mbps for item in group]),
                }
            )

    summary_csv = TABLE_DIR / "metrics_summary.csv"
    with summary_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "protocol",
                "message_count",
                "handshake_latency_ms",
                "encryption_latency_ms",
                "memory_usage_mb",
                "cpu_utilization_pct",
                "throughput_mbps",
            ]
        )
        for row in summary_rows:
            writer.writerow(
                [
                    row["protocol"],
                    row["message_count"],
                    f"{row['handshake_latency_ms']:.6f}",
                    f"{row['encryption_latency_ms']:.6f}",
                    f"{row['memory_usage_mb']:.6f}",
                    f"{row['cpu_utilization_pct']:.6f}",
                    f"{row['throughput_mbps']:.6f}",
                ]
            )

    summary_md = TABLE_DIR / "metrics_summary.md"
    lines = [
        "# Metrics Summary",
        "",
        "| Protocol | Messages | Handshake (ms) | Encryption (ms) | Memory (MB) | CPU (%) | Throughput (MB/s) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            f"| {row['protocol']} | {row['message_count']} | {row['handshake_latency_ms']:.3f} | "
            f"{row['encryption_latency_ms']:.3f} | {row['memory_usage_mb']:.3f} | "
            f"{row['cpu_utilization_pct']:.2f} | {row['throughput_mbps']:.3f} |"
        )
    summary_md.write_text("\n".join(lines), encoding="utf-8")


def _plot_metric(
    summary: dict[str, dict[int, dict[str, float]]],
    metric_key: str,
    ylabel: str,
    title: str,
    out_file: pathlib.Path,
) -> None:
    baseline_values = [summary["baseline"][count][metric_key] for count in MESSAGE_COUNTS]
    proposed_values = [summary["proposed"][count][metric_key] for count in MESSAGE_COUNTS]

    x = list(range(len(MESSAGE_COUNTS)))
    width = 0.36

    plt.figure(figsize=(8, 4.5))
    plt.bar([value - width / 2 for value in x], baseline_values, width=width, label="Baseline AES-GCM")
    plt.bar([value + width / 2 for value in x], proposed_values, width=width, label="Proposed ECC+ASCON")
    plt.xticks(x, [str(count) for count in MESSAGE_COUNTS])
    plt.xlabel("Message Count")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_file, dpi=170)
    plt.close()


def _write_graphs() -> None:
    GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    summary_csv = TABLE_DIR / "metrics_summary.csv"
    summary: dict[str, dict[int, dict[str, float]]] = {"baseline": {}, "proposed": {}}

    with summary_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            protocol = row["protocol"]
            message_count = int(row["message_count"])
            summary[protocol][message_count] = {
                "handshake_latency_ms": float(row["handshake_latency_ms"]),
                "encryption_latency_ms": float(row["encryption_latency_ms"]),
                "memory_usage_mb": float(row["memory_usage_mb"]),
                "cpu_utilization_pct": float(row["cpu_utilization_pct"]),
                "throughput_mbps": float(row["throughput_mbps"]),
            }

    _plot_metric(
        summary,
        metric_key="handshake_latency_ms",
        ylabel="Latency (ms)",
        title="Handshake Latency Comparison",
        out_file=GRAPH_DIR / "handshake_latency_comparison.png",
    )
    _plot_metric(
        summary,
        metric_key="encryption_latency_ms",
        ylabel="Latency (ms)",
        title="Encryption Latency Comparison",
        out_file=GRAPH_DIR / "encryption_latency_comparison.png",
    )
    _plot_metric(
        summary,
        metric_key="memory_usage_mb",
        ylabel="Memory Delta (MB)",
        title="Memory Usage Comparison",
        out_file=GRAPH_DIR / "memory_usage_comparison.png",
    )
    _plot_metric(
        summary,
        metric_key="throughput_mbps",
        ylabel="Throughput (MB/s)",
        title="Throughput Comparison",
        out_file=GRAPH_DIR / "throughput_comparison.png",
    )


def main() -> None:
    records = run_experiments()
    _write_tables(records)
    _write_graphs()
    paper_path = generate_paper()

    print("Experiment run complete.")
    print(f"Detailed table: {TABLE_DIR / 'metrics_detailed.csv'}")
    print(f"Summary table: {TABLE_DIR / 'metrics_summary.csv'}")
    print(f"Graphs directory: {GRAPH_DIR}")
    print(f"Paper draft: {paper_path}")


if __name__ == "__main__":
    main()
