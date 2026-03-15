"""Analyze Phase 1 metrics and generate summary tables/graphs.

Supports combined logs from:
- proposed phone client (ASCON)
- baseline phone client (AES-GCM)
"""

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

DEFAULT_INPUT = PROJECT_ROOT / "results" / "tables" / "phase1_phone_metrics.csv"
DEFAULT_SUMMARY_CSV = PROJECT_ROOT / "results" / "tables" / "phase1_phone_summary.csv"
DEFAULT_SUMMARY_MD = PROJECT_ROOT / "results" / "tables" / "phase1_phone_summary.md"
DEFAULT_GRAPH_DIR = PROJECT_ROOT / "results" / "graphs"


def _mean(values: list[float]) -> float:
    return statistics.mean(values) if values else 0.0


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


def _load_rows(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    # Backward compatibility for earlier logs with fewer columns.
    for row in rows:
        row.setdefault("protocol", "proposed")
        row.setdefault("device_class", "unknown")
        row.setdefault("avg_power_w_assumed", "0")
        row.setdefault("cycle_duration_s", "0")
        row.setdefault("cpu_time_s", "0")
        row.setdefault("estimated_energy_j", "0")
        row.setdefault("energy_per_message_mj", "0")
    return rows


def _aggregate(rows: list[dict[str, str]]) -> list[dict[str, float | str | int]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = (row["protocol"], row["device_class"], row["scenario"])
        grouped[key].append(row)

    summary: list[dict[str, float | str | int]] = []
    for (protocol, device_class, scenario) in sorted(grouped.keys()):
        group = grouped[(protocol, device_class, scenario)]

        handshake = [_safe_float(item, "handshake_latency_ms") for item in group if _safe_float(item, "handshake_latency_ms") > 0]
        encrypt = [_safe_float(item, "avg_encrypt_ms") for item in group if _safe_float(item, "avg_encrypt_ms") > 0]
        roundtrip = [_safe_float(item, "avg_roundtrip_ms") for item in group if _safe_float(item, "avg_roundtrip_ms") > 0]
        throughput = [_safe_float(item, "throughput_mbps") for item in group if _safe_float(item, "throughput_mbps") > 0]
        cpu = [_safe_float(item, "cpu_utilization_pct") for item in group]
        memory = [_safe_float(item, "memory_delta_mb") for item in group]
        energy = [_safe_float(item, "energy_per_message_mj") for item in group if _safe_float(item, "energy_per_message_mj") > 0]

        resume_expected = sum(_safe_int(item, "resume_expected") for item in group)
        resume_success = sum(_safe_int(item, "resume_success") for item in group)
        reconnect_success = sum(_safe_int(item, "reconnect_success") for item in group)

        summary.append(
            {
                "protocol": protocol,
                "device_class": device_class,
                "scenario": scenario,
                "runs": len(group),
                "handshake_latency_ms": _mean(handshake),
                "encrypt_latency_ms": _mean(encrypt),
                "roundtrip_latency_ms": _mean(roundtrip),
                "throughput_mbps": _mean(throughput),
                "cpu_utilization_pct": _mean(cpu),
                "memory_delta_mb": _mean(memory),
                "energy_per_message_mj": _mean(energy),
                "resume_hit_rate_pct": (resume_success / resume_expected * 100.0) if resume_expected else 0.0,
                "reconnect_success_rate_pct": (reconnect_success / len(group) * 100.0) if group else 0.0,
            }
        )

    return summary


def _write_summary_csv(path: pathlib.Path, summary: list[dict[str, float | str | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "protocol",
                "device_class",
                "scenario",
                "runs",
                "handshake_latency_ms",
                "encrypt_latency_ms",
                "roundtrip_latency_ms",
                "throughput_mbps",
                "cpu_utilization_pct",
                "memory_delta_mb",
                "energy_per_message_mj",
                "resume_hit_rate_pct",
                "reconnect_success_rate_pct",
            ]
        )
        for row in summary:
            writer.writerow(
                [
                    row["protocol"],
                    row["device_class"],
                    row["scenario"],
                    row["runs"],
                    f"{row['handshake_latency_ms']:.6f}",
                    f"{row['encrypt_latency_ms']:.6f}",
                    f"{row['roundtrip_latency_ms']:.6f}",
                    f"{row['throughput_mbps']:.6f}",
                    f"{row['cpu_utilization_pct']:.6f}",
                    f"{row['memory_delta_mb']:.6f}",
                    f"{row['energy_per_message_mj']:.6f}",
                    f"{row['resume_hit_rate_pct']:.6f}",
                    f"{row['reconnect_success_rate_pct']:.6f}",
                ]
            )


def _write_summary_md(path: pathlib.Path, summary: list[dict[str, float | str | int]]) -> None:
    lines = [
        "# Phase 1 Experiment Summary",
        "",
        "| Protocol | Device Class | Scenario | Runs | Handshake (ms) | Encrypt (ms) | Roundtrip (ms) | Throughput (MB/s) | CPU (%) | Memory (MB) | Energy/msg (mJ) | Resume Hit (%) | Reconnect Success (%) |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in summary:
        lines.append(
            f"| {row['protocol']} | {row['device_class']} | {row['scenario']} | {row['runs']} | "
            f"{row['handshake_latency_ms']:.3f} | {row['encrypt_latency_ms']:.3f} | {row['roundtrip_latency_ms']:.3f} | "
            f"{row['throughput_mbps']:.3f} | {row['cpu_utilization_pct']:.2f} | {row['memory_delta_mb']:.3f} | "
            f"{row['energy_per_message_mj']:.3f} | {row['resume_hit_rate_pct']:.2f} | {row['reconnect_success_rate_pct']:.2f} |"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _plot_bar(labels: list[str], values: list[float], ylabel: str, title: str, out_file: pathlib.Path) -> None:
    plt.figure(figsize=(10, 4.8))
    plt.bar(labels, values, color="#2c7fb8")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_file, dpi=170)
    plt.close()


def _write_graphs(summary: list[dict[str, float | str | int]], graph_dir: pathlib.Path) -> None:
    labels = [f"{row['protocol']}|{row['device_class']}|{row['scenario']}" for row in summary]

    _plot_bar(
        labels,
        [float(row["handshake_latency_ms"]) for row in summary],
        ylabel="Latency (ms)",
        title="Phase 1 Handshake Latency by Protocol/Device/Scenario",
        out_file=graph_dir / "phase1_handshake_latency.png",
    )
    _plot_bar(
        labels,
        [float(row["roundtrip_latency_ms"]) for row in summary],
        ylabel="Latency (ms)",
        title="Phase 1 Roundtrip Latency by Protocol/Device/Scenario",
        out_file=graph_dir / "phase1_roundtrip_latency.png",
    )
    _plot_bar(
        labels,
        [float(row["throughput_mbps"]) for row in summary],
        ylabel="Throughput (MB/s)",
        title="Phase 1 Throughput by Protocol/Device/Scenario",
        out_file=graph_dir / "phase1_throughput.png",
    )
    _plot_bar(
        labels,
        [float(row["resume_hit_rate_pct"]) for row in summary],
        ylabel="Rate (%)",
        title="Phase 1 Resume Hit Rate by Protocol/Device/Scenario",
        out_file=graph_dir / "phase1_resume_hit_rate.png",
    )
    _plot_bar(
        labels,
        [float(row["memory_delta_mb"]) for row in summary],
        ylabel="Memory Delta (MB)",
        title="Phase 1 Memory Footprint by Device Class",
        out_file=graph_dir / "phase1_deviceclass_memory.png",
    )
    _plot_bar(
        labels,
        [float(row["energy_per_message_mj"]) for row in summary],
        ylabel="Energy per Message (mJ)",
        title="Phase 1 Energy per Message by Device Class",
        out_file=graph_dir / "phase1_deviceclass_energy_per_message.png",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze Phase 1 metrics.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help=f"Input CSV path (default: {DEFAULT_INPUT})")
    parser.add_argument(
        "--summary-csv",
        default=str(DEFAULT_SUMMARY_CSV),
        help=f"Summary CSV output path (default: {DEFAULT_SUMMARY_CSV})",
    )
    parser.add_argument(
        "--summary-md",
        default=str(DEFAULT_SUMMARY_MD),
        help=f"Summary markdown output path (default: {DEFAULT_SUMMARY_MD})",
    )
    parser.add_argument(
        "--graph-dir",
        default=str(DEFAULT_GRAPH_DIR),
        help=f"Output graph directory (default: {DEFAULT_GRAPH_DIR})",
    )
    args = parser.parse_args()

    input_path = pathlib.Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input metrics file not found: {input_path}")

    rows = _load_rows(input_path)
    if not rows:
        raise ValueError("Input metrics file is empty.")

    summary = _aggregate(rows)
    _write_summary_csv(pathlib.Path(args.summary_csv), summary)
    _write_summary_md(pathlib.Path(args.summary_md), summary)
    _write_graphs(summary, pathlib.Path(args.graph_dir))

    print("Phase 1 analysis complete.")
    print(f"Summary CSV: {args.summary_csv}")
    print(f"Summary MD: {args.summary_md}")
    print(f"Graphs: {args.graph_dir}")


if __name__ == "__main__":
    main()
