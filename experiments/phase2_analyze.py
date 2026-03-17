"""Analyze Phase 2 edge bridge metrics and generate summary tables/graphs."""

from __future__ import annotations

import argparse
import csv
import pathlib
import statistics
import sys
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
DEFAULT_INPUT = PROJECT_ROOT / "results" / "tables" / "phase2_edge_metrics.csv"
DEFAULT_SUMMARY_CSV = PROJECT_ROOT / "results" / "tables" / "phase2_summary.csv"
DEFAULT_SUMMARY_MD = PROJECT_ROOT / "results" / "tables" / "phase2_summary.md"
DEFAULT_GRAPH_DIR = PROJECT_ROOT / "results" / "graphs"


def _safe_float(row: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        return float(row.get(key, default))
    except Exception:
        return default


def _safe_int(row: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(row.get(key, default))
    except Exception:
        return default


def _mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_values = sorted(values)
    index = int(0.95 * (len(sorted_values) - 1))
    return sorted_values[index]


def _load_rows(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))




def _sensor_ack_latency(row: dict[str, str], run_offsets: dict[str, float]) -> float:
    provided = _safe_float(row, "sensor_to_ack_latency_ms")
    if 0 < provided <= 600000:
        return provided

    ack = _safe_float(row, "ack_rx_ts_ms")
    edge = _safe_float(row, "edge_rx_ts_ms")
    raw = _safe_float(row, "sensor_ts_raw_ms", _safe_float(row, "sensor_ts_ms"))
    if ack <= 0 or edge <= 0 or raw <= 0:
        return 0.0

    run_id = row.get("run_id", "")
    offset = run_offsets.get(run_id)
    if raw < 1_000_000_000_000 and offset is not None:
        adjusted = ack - (raw + offset)
        if 0 <= adjusted <= 600000:
            return adjusted

    return 0.0

def _aggregate(rows: list[dict[str, str]]) -> list[dict[str, float | int | str]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    run_offsets: dict[str, float] = {}

    for row in rows:
        key = (
            row.get("protocol", "unknown"),
            row.get("device_class", "unknown"),
            row.get("scenario", "unknown"),
        )
        grouped[key].append(row)

        run_id = row.get("run_id", "")
        raw = _safe_float(row, "sensor_ts_raw_ms", _safe_float(row, "sensor_ts_ms"))
        edge = _safe_float(row, "edge_rx_ts_ms")
        if run_id and run_id not in run_offsets and 0 < raw < 1_000_000_000_000 and edge > 0:
            run_offsets[run_id] = edge - raw

    summary: list[dict[str, float | int | str]] = []
    for (protocol, device_class, scenario), group in sorted(grouped.items()):
        delivered = [_safe_int(row, "send_success") for row in group]
        delivered_count = sum(delivered)
        total_count = len(group)

        sensor_to_ack = [
            _sensor_ack_latency(row, run_offsets)
            for row in group
            if _sensor_ack_latency(row, run_offsets) > 0 and _safe_int(row, "send_success") == 1
        ]
        encrypt = [
            _safe_float(row, "encrypt_latency_ms")
            for row in group
            if _safe_float(row, "encrypt_latency_ms") > 0 and _safe_int(row, "send_success") == 1
        ]
        roundtrip = [
            _safe_float(row, "roundtrip_latency_ms")
            for row in group
            if _safe_float(row, "roundtrip_latency_ms") > 0 and _safe_int(row, "send_success") == 1
        ]
        handshake = [_safe_float(row, "handshake_latency_ms") for row in group if _safe_float(row, "handshake_latency_ms") > 0]
        handshake_resumed = [
            _safe_float(row, "handshake_latency_ms")
            for row in group
            if _safe_float(row, "handshake_latency_ms") > 0 and _safe_int(row, "resumed") == 1
        ]

        retry_counts = [_safe_int(row, "retry_count") for row in group]
        cpu = [_safe_float(row, "cpu_utilization_pct") for row in group]
        memory = [_safe_float(row, "memory_delta_mb") for row in group]
        energy_per_msg = [_safe_float(row, "energy_per_message_mj") for row in group if _safe_float(row, "energy_per_message_mj") > 0]
        free_ram = [_safe_int(row, "free_ram_bytes") for row in group if _safe_int(row, "free_ram_bytes") > 0]

        duration_s = sum(_safe_float(row, "event_duration_s") for row in group)
        throughput_eps = delivered_count / duration_s if duration_s > 0 else 0.0

        resume_expected = sum(_safe_int(row, "resume_expected") for row in group)
        resumed_count = sum(_safe_int(row, "resumed") for row in group if _safe_float(row, "handshake_latency_ms") > 0)
        resume_hit_rate = (resumed_count / resume_expected * 100.0) if resume_expected > 0 else 0.0

        run_ids = {row.get("run_id", "") for row in group if row.get("run_id", "")}

        summary.append(
            {
                "protocol": protocol,
                "device_class": device_class,
                "scenario": scenario,
                "runs": len(run_ids) if run_ids else 1,
                "events_total": total_count,
                "events_delivered": delivered_count,
                "delivery_rate_pct": (delivered_count / total_count * 100.0) if total_count > 0 else 0.0,
                "handshake_latency_ms": _mean(handshake),
                "resumed_handshake_latency_ms": _mean(handshake_resumed),
                "resume_hit_rate_pct": resume_hit_rate,
                "encrypt_latency_ms": _mean(encrypt),
                "roundtrip_latency_ms": _mean(roundtrip),
                "sensor_to_ack_p50_ms": _mean(sensor_to_ack),
                "sensor_to_ack_p95_ms": _p95(sensor_to_ack),
                "throughput_events_per_s": throughput_eps,
                "retry_count_avg": _mean([float(v) for v in retry_counts]),
                "cpu_utilization_pct": _mean(cpu),
                "memory_delta_mb": _mean(memory),
                "free_ram_min_bytes": min(free_ram) if free_ram else 0,
                "energy_per_message_mj": _mean(energy_per_msg),
            }
        )

    return summary


def _write_summary_csv(path: pathlib.Path, summary: list[dict[str, float | int | str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = [
        "protocol",
        "device_class",
        "scenario",
        "runs",
        "events_total",
        "events_delivered",
        "delivery_rate_pct",
        "handshake_latency_ms",
        "resumed_handshake_latency_ms",
        "resume_hit_rate_pct",
        "encrypt_latency_ms",
        "roundtrip_latency_ms",
        "sensor_to_ack_p50_ms",
        "sensor_to_ack_p95_ms",
        "throughput_events_per_s",
        "retry_count_avg",
        "cpu_utilization_pct",
        "memory_delta_mb",
        "free_ram_min_bytes",
        "energy_per_message_mj",
    ]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for row in summary:
            writer.writerow(
                [
                    row["protocol"],
                    row["device_class"],
                    row["scenario"],
                    row["runs"],
                    row["events_total"],
                    row["events_delivered"],
                    f"{float(row['delivery_rate_pct']):.6f}",
                    f"{float(row['handshake_latency_ms']):.6f}",
                    f"{float(row['resumed_handshake_latency_ms']):.6f}",
                    f"{float(row['resume_hit_rate_pct']):.6f}",
                    f"{float(row['encrypt_latency_ms']):.6f}",
                    f"{float(row['roundtrip_latency_ms']):.6f}",
                    f"{float(row['sensor_to_ack_p50_ms']):.6f}",
                    f"{float(row['sensor_to_ack_p95_ms']):.6f}",
                    f"{float(row['throughput_events_per_s']):.6f}",
                    f"{float(row['retry_count_avg']):.6f}",
                    f"{float(row['cpu_utilization_pct']):.6f}",
                    f"{float(row['memory_delta_mb']):.6f}",
                    row["free_ram_min_bytes"],
                    f"{float(row['energy_per_message_mj']):.6f}",
                ]
            )


def _write_summary_md(path: pathlib.Path, summary: list[dict[str, float | int | str]]) -> None:
    lines = [
        "# Phase 2 Hardware-in-the-Loop Summary",
        "",
        "| Protocol | Device | Scenario | Runs | Delivered | Delivery % | Handshake (ms) | Resume Hit % | Sensor->ACK p50 (ms) | Sensor->ACK p95 (ms) | Throughput (events/s) | Retry Avg | Free RAM Min (bytes) | Energy/msg (mJ) |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in summary:
        lines.append(
            f"| {row['protocol']} | {row['device_class']} | {row['scenario']} | {row['runs']} | "
            f"{row['events_delivered']}/{row['events_total']} | {float(row['delivery_rate_pct']):.2f} | "
            f"{float(row['handshake_latency_ms']):.3f} | {float(row['resume_hit_rate_pct']):.2f} | "
            f"{float(row['sensor_to_ack_p50_ms']):.3f} | {float(row['sensor_to_ack_p95_ms']):.3f} | "
            f"{float(row['throughput_events_per_s']):.3f} | {float(row['retry_count_avg']):.3f} | "
            f"{int(row['free_ram_min_bytes'])} | {float(row['energy_per_message_mj']):.3f} |"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _plot_bar(labels: list[str], values: list[float], ylabel: str, title: str, out_file: pathlib.Path) -> None:
    plt.figure(figsize=(10, 4.6))
    plt.bar(labels, values, color="#2c7fb8")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_file, dpi=170)
    plt.close()


def _write_graphs(summary: list[dict[str, float | int | str]], graph_dir: pathlib.Path) -> None:
    labels = [f"{row['protocol']}|{row['scenario']}" for row in summary]

    _plot_bar(
        labels,
        [float(row["sensor_to_ack_p50_ms"]) for row in summary],
        "Latency (ms)",
        "Phase2 Sensor->ACK Latency p50",
        graph_dir / "phase2_sensor_to_ack_p50.png",
    )
    _plot_bar(
        labels,
        [float(row["sensor_to_ack_p95_ms"]) for row in summary],
        "Latency (ms)",
        "Phase2 Sensor->ACK Latency p95",
        graph_dir / "phase2_sensor_to_ack_p95.png",
    )
    _plot_bar(
        labels,
        [float(row["handshake_latency_ms"]) for row in summary],
        "Latency (ms)",
        "Phase2 Handshake Latency",
        graph_dir / "phase2_handshake_latency.png",
    )
    _plot_bar(
        labels,
        [float(row["throughput_events_per_s"]) for row in summary],
        "Throughput (events/s)",
        "Phase2 Throughput",
        graph_dir / "phase2_throughput_events.png",
    )
    _plot_bar(
        labels,
        [float(row["energy_per_message_mj"]) for row in summary],
        "Energy/message (mJ)",
        "Phase2 Energy per Message",
        graph_dir / "phase2_energy_per_message.png",
    )
    _plot_bar(
        labels,
        [float(row["resume_hit_rate_pct"]) for row in summary],
        "Resume Hit Rate (%)",
        "Phase2 Resume Hit Rate",
        graph_dir / "phase2_resume_hit_rate.png",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Phase 2 edge bridge CSV outputs.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--summary-csv", default=str(DEFAULT_SUMMARY_CSV))
    parser.add_argument("--summary-md", default=str(DEFAULT_SUMMARY_MD))
    parser.add_argument("--graph-dir", default=str(DEFAULT_GRAPH_DIR))
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    rows = _load_rows(input_path)
    if not rows:
        raise ValueError("Input file is empty.")

    summary = _aggregate(rows)
    _write_summary_csv(pathlib.Path(args.summary_csv), summary)
    _write_summary_md(pathlib.Path(args.summary_md), summary)
    _write_graphs(summary, pathlib.Path(args.graph_dir))

    print("Phase2 analysis complete.")
    print(f"Summary CSV: {args.summary_csv}")
    print(f"Summary MD: {args.summary_md}")
    print(f"Graphs: {args.graph_dir}")


if __name__ == "__main__":
    main()
