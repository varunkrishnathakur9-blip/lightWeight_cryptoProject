"""Generate a research paper draft from measured evaluation outputs."""

from __future__ import annotations

import csv
import platform
from pathlib import Path

RESULTS_TABLE = Path("results/tables/metrics_summary.csv")
OUTPUT_PAPER = Path("results/paper_draft.md")


def _load_summary() -> dict[str, dict[int, dict[str, float]]]:
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
    data = _load_summary()

    baseline_handshake = _avg_metric(data, "baseline", "handshake_latency_ms")
    proposed_handshake = _avg_metric(data, "proposed", "handshake_latency_ms")
    baseline_encrypt = _avg_metric(data, "baseline", "encryption_latency_ms")
    proposed_encrypt = _avg_metric(data, "proposed", "encryption_latency_ms")
    baseline_memory = _avg_metric(data, "baseline", "memory_usage_mb")
    proposed_memory = _avg_metric(data, "proposed", "memory_usage_mb")
    baseline_cpu = _avg_metric(data, "baseline", "cpu_utilization_pct")
    proposed_cpu = _avg_metric(data, "proposed", "cpu_utilization_pct")
    baseline_throughput = _avg_metric(data, "baseline", "throughput_mbps")
    proposed_throughput = _avg_metric(data, "proposed", "throughput_mbps")

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

    scenarios = sorted(data["baseline"].keys())

    lines: list[str] = []
    lines.append("# Lightweight Secure Communication for IoT: Experimental Evaluation Draft")
    lines.append("")
    lines.append("## Abstract")
    lines.append(
        "This draft evaluates a lightweight IoT secure communication protocol composed of ECDH on secp256r1, ASCON-128 authenticated encryption, "
        "a sponge-based key derivation function, and DTLS connection identifier-inspired session resumption. A baseline secure channel using "
        "ECDH, HKDF-SHA256, and AES-GCM is implemented for controlled comparison. Experiments are executed for 100, 500, and 1000 message workloads "
        "with measurements for handshake latency, encryption latency, memory usage, CPU utilization, and throughput. The current implementation results "
        "show that baseline AES-GCM outperforms the proposed prototype in latency and throughput on this host, while the proposed design remains useful as "
        "a research platform for lightweight protocol mechanisms and session continuity. The paper discusses why implementation backend effects dominate "
        "algorithm-level interpretation in Python-based prototypes."
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
    lines.append(
        "Accordingly, the evaluation is framed as systems experimentation: what overheads are introduced by the prototype design, where performance bottlenecks appear, "
        "and which elements should be optimized next for realistic deployment on IoT hardware."
    )
    lines.append("")

    lines.append("## Related Work")
    lines.append(
        "ASCON has become central in lightweight cryptography discussions because it is standardized for constrained environments and provides both AEAD and sponge-style "
        "hashing capabilities. In protocol engineering terms, ASCON enables a single lightweight family to cover confidentiality, integrity, and derivation building blocks."
    )
    lines.append(
        "DTLS connection identifier work demonstrates a practical method for preserving security associations across network tuple changes. This is especially relevant in IoT "
        "systems where mobility, NAT behavior, and low-power radio reconnects frequently invalidate address-based assumptions."
    )
    lines.append(
        "Sponge-based constructions have been used extensively for compact hashing and extendable-output applications. Their flexibility supports domain-separated derivation "
        "without introducing multiple heavyweight primitives in constrained software stacks."
    )
    lines.append("")

    lines.append("## System Architecture")
    lines.append(
        "The prototype uses a two-endpoint model: IoT device client and gateway server. Modules are separated into cryptographic primitives (`crypto`), protocol state machines "
        "(`protocol`), and transport orchestration (`network`). The architecture supports both full handshakes and resumed handshakes with cached session state."
    )
    lines.append(
        "Session records include session ID, connection ID, key material, timestamp, and nonce counter. Packet records carry protocol version, session ID, sequence number, nonce, "
        "ciphertext, and authentication tag. Replay resistance is enforced through monotonic sequence validation."
    )
    lines.append("")

    lines.append("## Protocol Design")
    lines.append(
        "The baseline protocol uses ECDHE + HKDF-SHA256 + AES-GCM and performs a full handshake on each connection. The proposed protocol uses ECDHE + sponge-KDF + ASCON and "
        "supports resumed handshakes via persistent connection IDs."
    )
    lines.append(
        "To reduce online handshake work, the proposed implementation precomputes ephemeral ECC key pairs in a bounded key pool. A transcript-based finished verification step "
        "authenticates handshake state. For resumed paths, the protocol validates cached connection ID state, refreshes key context with fresh nonces, and then transitions to data mode."
    )
    lines.append("")

    lines.append("## Implementation")
    lines.append(
        "All components are implemented in Python for rapid prototyping and instrumentation. Baseline and proposed variants share common measurement harnesses so that metrics are captured "
        "under similar process conditions. The evaluation pipeline generates CSV tables, markdown summaries, publication-ready plots, and this draft paper."
    )
    lines.append(
        f"Execution environment for this run: Python on {platform.system()} {platform.release()} ({platform.machine()})."
    )
    lines.append("")

    lines.append("## Experimental Evaluation")
    lines.append(
        "Workloads of 100, 500, and 1000 encrypted messages were executed. For each workload and protocol, repeated runs were aggregated to compute mean handshake latency, "
        "mean encryption latency, process memory delta, process CPU utilization proxy, and throughput in MB/s."
    )
    lines.append("")
    lines.append("### Evaluation Scenarios")
    lines.append("| Scenario | Message Count | Protocols |")
    lines.append("|---|---:|---|")
    for count in scenarios:
        lines.append(f"| S{count} | {count} | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |")
    lines.append("")

    lines.append("### Consolidated Metrics")
    lines.append("| Metric | Baseline Avg | Proposed Avg | Relative Change (Proposed vs Baseline) |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Handshake Latency (ms) | {baseline_handshake:.3f} | {proposed_handshake:.3f} | {handshake_change:.2f}% |")
    lines.append(f"| Encryption Latency (ms) | {baseline_encrypt:.3f} | {proposed_encrypt:.3f} | {encrypt_change:.2f}% |")
    lines.append(f"| Memory Usage (MB delta) | {baseline_memory:.3f} | {proposed_memory:.3f} | {memory_change:.2f}% |")
    lines.append(f"| CPU Utilization (%) | {baseline_cpu:.2f} | {proposed_cpu:.2f} | {cpu_change:.2f}% |")
    lines.append(f"| Throughput (MB/s) | {baseline_throughput:.3f} | {proposed_throughput:.3f} | {throughput_change:.2f}% |")
    lines.append("")

    lines.append("## Results")
    lines.append(handshake_text)
    lines.append(encryption_text)
    lines.append(memory_text)
    lines.append(throughput_text)
    lines.append(
        "In this prototype, backend implementation and protocol orchestration both shape performance: AES-GCM and HKDF rely on highly optimized native libraries, while "
        "the proposed stack uses native ASCON primitives plus Python protocol logic. Therefore, measured gaps on host systems should be interpreted as full-system outcomes "
        "(crypto backend + handshake/state machine + serialization/I/O), not raw algorithmic limits."
    )
    lines.append(backend_note)
    lines.append("")

    lines.append("## Security Analysis")
    lines.append(
        "The protocol enforces authenticated encryption, transcript verification in handshakes, deterministic nonce derivation, and sequence-based replay filtering. These controls provide "
        "confidentiality, integrity, and replay resistance in the evaluated model."
    )
    lines.append(
        "Session resumption with connection identifiers introduces persistent-state attack surfaces. Mitigations include bounded session lifetimes, cache cleanup, nonce counter continuity, "
        "and explicit invalidation on anomalies. Additional anti-DoS controls (e.g., stateless cookies) should be integrated for internet-facing deployments."
    )
    lines.append("")

    lines.append("## Conclusion")
    lines.append(
        "The implemented evaluation pipeline provides reproducible, end-to-end comparison between a traditional AES-GCM secure channel and a research-oriented lightweight protocol using "
        "ASCON, sponge-KDF, and CID-style resumption. Current host-side measurements favor the baseline in raw performance, but the proposed architecture remains valuable for investigating "
        "lightweight protocol design, reconnect semantics, and constrained-friendly cryptographic composition."
    )
    lines.append("")

    lines.append("## Future Work")
    lines.append("1. Further optimize native ASCON integration and reduce protocol-layer Python overhead, then repeat the benchmark matrix.")
    lines.append("2. Benchmark on target IoT hardware and include energy-per-message metrics.")
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
