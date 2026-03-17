"""Generate a research paper draft from measured evaluation outputs.

Includes:
- host benchmark summary (`metrics_summary.csv`)
- optional Phase 1 real-environment summary (`phase1_phone_summary.csv`)
- optional Phase 2 hardware-in-the-loop summary (`phase2_summary.csv`)
"""

from __future__ import annotations

import csv
import platform
from pathlib import Path

RESULTS_TABLE = Path("results/tables/metrics_summary.csv")
PHASE1_TABLE = Path("results/tables/phase1_phone_summary.csv")
PHASE2_TABLE = Path("results/tables/phase2_summary.csv")
OUTPUT_PAPER = Path("results/paper_draft.md")


def _load_host_summary() -> dict[str, dict[int, dict[str, float]]]:
    data: dict[str, dict[int, dict[str, float]]] = {}
    with RESULTS_TABLE.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            protocol = row["protocol"]
            count = int(row["message_count"])
            data.setdefault(protocol, {})[count] = {
                "handshake_latency_ms": float(row["handshake_latency_ms"]),
                "encryption_latency_ms": float(row["encryption_latency_ms"]),
                "memory_usage_mb": float(row["memory_usage_mb"]),
                "cpu_utilization_pct": float(row["cpu_utilization_pct"]),
                "throughput_mbps": float(row["throughput_mbps"]),
            }
    return data


def _load_optional_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _avg_metric(data: dict[str, dict[int, dict[str, float]]], protocol: str, key: str) -> float:
    values = [metrics[key] for _, metrics in sorted(data[protocol].items())]
    return sum(values) / len(values)


def _pct_change(new: float, base: float) -> float:
    if base == 0:
        return 0.0
    return ((new - base) / base) * 100.0


def _interpret(direction_less_is_better: bool, proposed: float, baseline: float, label: str) -> str:
    delta = _pct_change(proposed, baseline)
    if direction_less_is_better:
        if proposed < baseline:
            return f"{label} improved by {-delta:.2f}% (lower is better)."
        return f"{label} regressed by {delta:.2f}% (higher than baseline)."
    if proposed > baseline:
        return f"{label} improved by {delta:.2f}% (higher is better)."
    return f"{label} regressed by {-delta:.2f}% (lower than baseline)."


def _f(row: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        return float(row.get(key, default))
    except Exception:
        return default


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _protocol_mean(rows: list[dict[str, str]], protocol: str, key: str) -> float:
    values = [_f(row, key) for row in rows if row.get("protocol") == protocol]
    return _mean(values)


def _backend_note() -> str:
    """Describe ASCON backend status used by the proposed stack."""
    try:
        from lightweight_secure_channel.crypto.ascon_cipher import active_backend

        backend = active_backend()
        return f"Native ASCON backend detected for this run: `{backend}`."
    except Exception as error:
        return (
            "ASCON backend could not be verified at draft-generation time "
            f"({error.__class__.__name__}). Ensure native backend is installed and active."
        )


def generate_paper() -> Path:
    host_data = _load_host_summary()
    phase1_rows = _load_optional_rows(PHASE1_TABLE)
    phase2_rows = _load_optional_rows(PHASE2_TABLE)

    baseline_handshake = _avg_metric(host_data, "baseline", "handshake_latency_ms")
    proposed_handshake = _avg_metric(host_data, "proposed", "handshake_latency_ms")
    baseline_encrypt = _avg_metric(host_data, "baseline", "encryption_latency_ms")
    proposed_encrypt = _avg_metric(host_data, "proposed", "encryption_latency_ms")
    baseline_memory = _avg_metric(host_data, "baseline", "memory_usage_mb")
    proposed_memory = _avg_metric(host_data, "proposed", "memory_usage_mb")
    baseline_cpu = _avg_metric(host_data, "baseline", "cpu_utilization_pct")
    proposed_cpu = _avg_metric(host_data, "proposed", "cpu_utilization_pct")
    baseline_throughput = _avg_metric(host_data, "baseline", "throughput_mbps")
    proposed_throughput = _avg_metric(host_data, "proposed", "throughput_mbps")

    handshake_change = _pct_change(proposed_handshake, baseline_handshake)
    encrypt_change = _pct_change(proposed_encrypt, baseline_encrypt)
    memory_change = _pct_change(proposed_memory, baseline_memory)
    cpu_change = _pct_change(proposed_cpu, baseline_cpu)
    throughput_change = _pct_change(proposed_throughput, baseline_throughput)

    handshake_text = _interpret(True, proposed_handshake, baseline_handshake, "Handshake latency")
    encryption_text = _interpret(True, proposed_encrypt, baseline_encrypt, "Encryption latency")
    memory_text = _interpret(True, proposed_memory, baseline_memory, "Memory usage")
    throughput_text = _interpret(False, proposed_throughput, baseline_throughput, "Throughput")
    backend_note = _backend_note()

    scenarios = sorted(host_data["baseline"].keys())

    lines: list[str] = []
    lines.append("# Lightweight Secure Communication for IoT: Experimental Evaluation Draft")
    lines.append("")
    lines.append("## Abstract")
    lines.append(
        "This draft evaluates a lightweight IoT secure communication protocol composed of ECDH on secp256r1, ASCON-128 authenticated encryption, "
        "a sponge-based key derivation function, and DTLS connection identifier-inspired session resumption. A baseline secure channel using "
        "ECDH, HKDF-SHA256, and AES-GCM is implemented for controlled comparison. Host-side experiments are executed for 100, 500, and 1000 message workloads "
        "with measurements for handshake latency, encryption latency, memory usage, CPU utilization, and throughput. In addition, this draft incorporates "
        "Phase 1 phone-based and Phase 2 hardware-in-the-loop summaries when available."
    )
    lines.append("")

    lines.append("## Introduction")
    lines.append(
        "Security protocols for IoT must handle intermittent links, low-power processing, and constrained memory while preserving confidentiality and integrity. "
        "Although widely deployed secure channel stacks provide mature protection, they can be expensive to reconnect and difficult to tune for constrained deployments. "
        "This work studies a lightweight secure channel architecture that integrates modern lightweight cryptography concepts into an implementation-first prototype."
    )
    lines.append(
        "The proposed protocol design is motivated by three ideas: ASCON for lightweight authenticated encryption, connection identifier based session continuity "
        "inspired by DTLS, and absorb-permute-squeeze sponge derivation for compact key scheduling. The study objective is to measure practical behavior against a "
        "traditional AES-GCM baseline rather than to claim universal superiority of one primitive."
    )
    lines.append("")

    lines.append("## Related Work")
    lines.append(
        "ASCON has become central in lightweight cryptography discussions because it is standardized for constrained environments and provides both AEAD and sponge-style "
        "hashing capabilities. DTLS connection identifier concepts motivate session continuity under network tuple changes, while sponge constructions support compact derivation "
        "without introducing multiple heavyweight primitives."
    )
    lines.append("")

    lines.append("## System Architecture")
    lines.append(
        "The prototype uses a two-endpoint model: IoT device client and gateway server. Modules are separated into cryptographic primitives (`crypto`), protocol state machines "
        "(`protocol`), and transport orchestration (`network`). The architecture supports both full handshakes and resumed handshakes with cached session state."
    )
    lines.append("")

    lines.append("## Protocol Design")
    lines.append(
        "The baseline protocol uses ECDHE + HKDF-SHA256 + AES-GCM and performs a full handshake on each connection. The proposed protocol uses ECDHE + sponge-KDF + ASCON and "
        "supports resumed handshakes via persistent connection IDs. Transcript-bound finished verification and replay protection are enforced in both stacks."
    )
    lines.append("")

    lines.append("## Implementation")
    lines.append(
        "All components are implemented in Python for rapid prototyping and instrumentation. Baseline and proposed variants share common measurement harnesses so that metrics are captured "
        "under similar process conditions. The evaluation pipeline generates CSV tables, markdown summaries, publication-ready plots, and this draft paper."
    )
    lines.append(f"Execution environment for this run: Python on {platform.system()} {platform.release()} ({platform.machine()}).")
    lines.append("")

    lines.append("## Experimental Evaluation")
    lines.append("### Host Benchmark Scenarios")
    lines.append("| Scenario | Message Count | Protocols |")
    lines.append("|---|---:|---|")
    for count in scenarios:
        lines.append(f"| S{count} | {count} | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |")
    lines.append("")

    lines.append("### Host Benchmark Consolidated Metrics")
    lines.append("| Metric | Baseline Avg | Proposed Avg | Relative Change (Proposed vs Baseline) |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Handshake Latency (ms) | {baseline_handshake:.3f} | {proposed_handshake:.3f} | {handshake_change:.2f}% |")
    lines.append(f"| Encryption Latency (ms) | {baseline_encrypt:.3f} | {proposed_encrypt:.3f} | {encrypt_change:.2f}% |")
    lines.append(f"| Memory Usage (MB delta) | {baseline_memory:.3f} | {proposed_memory:.3f} | {memory_change:.2f}% |")
    lines.append(f"| CPU Utilization (%) | {baseline_cpu:.2f} | {proposed_cpu:.2f} | {cpu_change:.2f}% |")
    lines.append(f"| Throughput (MB/s) | {baseline_throughput:.3f} | {proposed_throughput:.3f} | {throughput_change:.2f}% |")
    lines.append("")

    if phase1_rows:
        lines.append("### Phase 1 Real-Environment Summary (Phone Client)")
        lines.append("| Protocol | Device Class | Scenario | Handshake (ms) | Encrypt (ms) | Roundtrip (ms) | Throughput (MB/s) | Energy/msg (mJ) | Resume Hit (%) | Reconnect Success (%) |")
        lines.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for row in phase1_rows:
            lines.append(
                f"| {row.get('protocol','')} | {row.get('device_class','')} | {row.get('scenario','')} | "
                f"{_f(row,'handshake_latency_ms'):.3f} | {_f(row,'encrypt_latency_ms'):.3f} | {_f(row,'roundtrip_latency_ms'):.3f} | "
                f"{_f(row,'throughput_mbps'):.3f} | {_f(row,'energy_per_message_mj'):.3f} | {_f(row,'resume_hit_rate_pct'):.2f} | {_f(row,'reconnect_success_rate_pct'):.2f} |"
            )
        lines.append("")

        p1_hs_base = _protocol_mean(phase1_rows, "baseline", "handshake_latency_ms")
        p1_hs_prop = _protocol_mean(phase1_rows, "proposed", "handshake_latency_ms")
        p1_rt_base = _protocol_mean(phase1_rows, "baseline", "roundtrip_latency_ms")
        p1_rt_prop = _protocol_mean(phase1_rows, "proposed", "roundtrip_latency_ms")
        p1_tp_base = _protocol_mean(phase1_rows, "baseline", "throughput_mbps")
        p1_tp_prop = _protocol_mean(phase1_rows, "proposed", "throughput_mbps")
        p1_en_base = _protocol_mean(phase1_rows, "baseline", "energy_per_message_mj")
        p1_en_prop = _protocol_mean(phase1_rows, "proposed", "energy_per_message_mj")

        lines.append(_interpret(True, p1_hs_prop, p1_hs_base, "Phase 1 handshake latency"))
        lines.append(_interpret(True, p1_rt_prop, p1_rt_base, "Phase 1 roundtrip latency"))
        lines.append(_interpret(False, p1_tp_prop, p1_tp_base, "Phase 1 throughput"))
        lines.append(_interpret(True, p1_en_prop, p1_en_base, "Phase 1 energy per message"))
        lines.append("")
    else:
        lines.append("### Phase 1 Real-Environment Summary (Phone Client)")
        lines.append("Phase 1 summary table not found (`results/tables/phase1_phone_summary.csv`).")
        lines.append("")

    if phase2_rows:
        lines.append("### Phase 2 Hardware-in-the-Loop Summary (Mega2560 + R307)")
        lines.append("| Protocol | Device Class | Scenario | Delivered/Total | Delivery (%) | Handshake (ms) | Resume Hit (%) | Sensor->ACK p50 (ms) | Sensor->ACK p95 (ms) | Throughput (events/s) | Energy/msg (mJ) |")
        lines.append("|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for row in phase2_rows:
            lines.append(
                f"| {row.get('protocol','')} | {row.get('device_class','')} | {row.get('scenario','')} | "
                f"{row.get('events_delivered','?')}/{row.get('events_total','?')} | {_f(row,'delivery_rate_pct'):.2f} | "
                f"{_f(row,'handshake_latency_ms'):.3f} | {_f(row,'resume_hit_rate_pct'):.2f} | "
                f"{_f(row,'sensor_to_ack_p50_ms'):.3f} | {_f(row,'sensor_to_ack_p95_ms'):.3f} | "
                f"{_f(row,'throughput_events_per_s'):.3f} | {_f(row,'energy_per_message_mj'):.3f} |"
            )
        lines.append("")

        p2_hs_base = _protocol_mean(phase2_rows, "baseline", "handshake_latency_ms")
        p2_hs_prop = _protocol_mean(phase2_rows, "proposed", "handshake_latency_ms")
        p2_sa_base = _protocol_mean(phase2_rows, "baseline", "sensor_to_ack_p50_ms")
        p2_sa_prop = _protocol_mean(phase2_rows, "proposed", "sensor_to_ack_p50_ms")
        p2_tp_base = _protocol_mean(phase2_rows, "baseline", "throughput_events_per_s")
        p2_tp_prop = _protocol_mean(phase2_rows, "proposed", "throughput_events_per_s")
        p2_en_base = _protocol_mean(phase2_rows, "baseline", "energy_per_message_mj")
        p2_en_prop = _protocol_mean(phase2_rows, "proposed", "energy_per_message_mj")

        lines.append(_interpret(True, p2_hs_prop, p2_hs_base, "Phase 2 handshake latency"))
        lines.append(_interpret(True, p2_sa_prop, p2_sa_base, "Phase 2 sensor-to-ACK latency (p50)"))
        lines.append(_interpret(False, p2_tp_prop, p2_tp_base, "Phase 2 throughput"))
        lines.append(_interpret(True, p2_en_prop, p2_en_base, "Phase 2 energy per message"))
        lines.append("")
    else:
        lines.append("### Phase 2 Hardware-in-the-Loop Summary (Mega2560 + R307)")
        lines.append("Phase 2 summary table not found (`results/tables/phase2_summary.csv`).")
        lines.append("")

    lines.append("## Results")
    lines.append(handshake_text)
    lines.append(encryption_text)
    lines.append(memory_text)
    lines.append(throughput_text)
    lines.append(
        "In this prototype, backend implementation and protocol orchestration both shape performance: AES-GCM and HKDF rely on highly optimized native libraries, while "
        "the proposed stack uses native ASCON primitives plus Python protocol logic. Therefore, measured gaps should be interpreted as full-system outcomes "
        "(crypto backend + handshake/state machine + serialization/I/O), not raw algorithmic limits."
    )
    lines.append(backend_note)
    lines.append("")

    lines.append("## Security Analysis")
    lines.append(
        "The protocol enforces authenticated encryption, transcript verification in handshakes, deterministic nonce derivation, and sequence-based replay filtering. "
        "These controls provide confidentiality, integrity, and replay resistance in the evaluated model."
    )
    lines.append(
        "Session resumption with connection identifiers introduces persistent-state attack surfaces. Mitigations include bounded session lifetimes, cache cleanup, nonce counter continuity, "
        "and explicit invalidation on anomalies. Additional anti-DoS controls (e.g., stateless cookies) should be integrated for internet-facing deployments."
    )
    lines.append("")

    lines.append("## Conclusion")
    lines.append(
        "The implemented evaluation pipeline provides reproducible, end-to-end comparison between a traditional AES-GCM secure channel and a research-oriented lightweight protocol using "
        "ASCON, sponge-KDF, and CID-style resumption. Current host-side and edge-bridge measurements often favor the baseline in raw speed, while the proposed architecture remains valuable "
        "for lightweight protocol design, reconnect semantics, and constrained-device experimentation."
    )
    lines.append("")

    lines.append("## Future Work")
    lines.append("1. Reduce protocol-layer overhead in edge bridge and move more processing to embedded firmware where feasible.")
    lines.append("2. Expand Phase 1 and Phase 2 datasets across multiple scenarios and device classes.")
    lines.append("3. Add network impairment tests (loss, reordering, migration) for resumption robustness.")
    lines.append("4. Extend baseline set with ChaCha20-Poly1305 and DTLS 1.3 style profiles.")
    lines.append("5. Introduce formal protocol verification and side-channel review for key operations.")
    lines.append("")

    lines.append("## References (Conceptual)")
    lines.append("1. NIST Lightweight Cryptography standardization and ASCON specifications.")
    lines.append("2. DTLS connection identifier extensions for session continuity under network changes.")
    lines.append("3. Sponge-based hash and XOF constructions for lightweight key derivation.")

    OUTPUT_PAPER.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PAPER.write_text("\n".join(lines), encoding="utf-8")
    return OUTPUT_PAPER


if __name__ == "__main__":
    path = generate_paper()
    print(f"Paper draft generated at: {path}")
