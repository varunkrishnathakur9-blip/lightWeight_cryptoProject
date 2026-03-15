# Lightweight Secure Communication for IoT: Experimental Evaluation Draft

## Abstract
This draft evaluates a lightweight IoT secure communication protocol composed of ECDH on secp256r1, ASCON-128 authenticated encryption, a sponge-based key derivation function, and DTLS connection identifier-inspired session resumption. A baseline secure channel using ECDH, HKDF-SHA256, and AES-GCM is implemented for controlled comparison. Experiments are executed for 100, 500, and 1000 message workloads with measurements for handshake latency, encryption latency, memory usage, CPU utilization, and throughput. The current implementation results show that baseline AES-GCM outperforms the proposed prototype in latency and throughput on this host, while the proposed design remains useful as a research platform for lightweight protocol mechanisms and session continuity. The paper discusses why implementation backend effects dominate algorithm-level interpretation in Python-based prototypes.

## Introduction
Security protocols for IoT must handle intermittent links, low-power processing, and constrained memory while preserving confidentiality and integrity. Although widely deployed secure channel stacks provide mature protection, they can be expensive to reconnect and difficult to tune for constrained deployments. This work studies a lightweight secure channel architecture that integrates modern lightweight cryptography concepts into an implementation-first prototype.
The proposed protocol design is motivated by three ideas: ASCON for lightweight authenticated encryption, connection identifier based session continuity inspired by DTLS, and absorb-permute-squeeze sponge derivation for compact key scheduling. The study objective is to measure practical behavior against a traditional AES-GCM baseline rather than to claim universal superiority of one primitive.
Accordingly, the evaluation is framed as systems experimentation: what overheads are introduced by the prototype design, where performance bottlenecks appear, and which elements should be optimized next for realistic deployment on IoT hardware.

## Related Work
ASCON has become central in lightweight cryptography discussions because it is standardized for constrained environments and provides both AEAD and sponge-style hashing capabilities. In protocol engineering terms, ASCON enables a single lightweight family to cover confidentiality, integrity, and derivation building blocks.
DTLS connection identifier work demonstrates a practical method for preserving security associations across network tuple changes. This is especially relevant in IoT systems where mobility, NAT behavior, and low-power radio reconnects frequently invalidate address-based assumptions.
Sponge-based constructions have been used extensively for compact hashing and extendable-output applications. Their flexibility supports domain-separated derivation without introducing multiple heavyweight primitives in constrained software stacks.

## System Architecture
The prototype uses a two-endpoint model: IoT device client and gateway server. Modules are separated into cryptographic primitives (`crypto`), protocol state machines (`protocol`), and transport orchestration (`network`). The architecture supports both full handshakes and resumed handshakes with cached session state.
Session records include session ID, connection ID, key material, timestamp, and nonce counter. Packet records carry protocol version, session ID, sequence number, nonce, ciphertext, and authentication tag. Replay resistance is enforced through monotonic sequence validation.

## Protocol Design
The baseline protocol uses ECDHE + HKDF-SHA256 + AES-GCM and performs a full handshake on each connection. The proposed protocol uses ECDHE + sponge-KDF + ASCON and supports resumed handshakes via persistent connection IDs.
To reduce online handshake work, the proposed implementation precomputes ephemeral ECC key pairs in a bounded key pool. A transcript-based finished verification step authenticates handshake state. For resumed paths, the protocol validates cached connection ID state, refreshes key context with fresh nonces, and then transitions to data mode.

## Implementation
All components are implemented in Python for rapid prototyping and instrumentation. Baseline and proposed variants share common measurement harnesses so that metrics are captured under similar process conditions. The evaluation pipeline generates CSV tables, markdown summaries, publication-ready plots, and this draft paper.
Execution environment for this run: Python on Windows 11 (AMD64).

## Experimental Evaluation
Workloads of 100, 500, and 1000 encrypted messages were executed. For each workload and protocol, repeated runs were aggregated to compute mean handshake latency, mean encryption latency, process memory delta, process CPU utilization proxy, and throughput in MB/s.

### Evaluation Scenarios
| Scenario | Message Count | Protocols |
|---|---:|---|
| S100 | 100 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |
| S500 | 500 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |
| S1000 | 1000 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |

### Consolidated Metrics
| Metric | Baseline Avg | Proposed Avg | Relative Change (Proposed vs Baseline) |
|---|---:|---:|---:|
| Handshake Latency (ms) | 1.480 | 33.706 | 2177.23% |
| Encryption Latency (ms) | 0.007 | 1.805 | 25242.02% |
| Memory Usage (MB delta) | 0.012 | 0.054 | 346.43% |
| CPU Utilization (%) | 50.22 | 98.26 | 95.66% |
| Throughput (MB/s) | 11.284 | 0.042 | -99.63% |

## Results
Handshake latency regressed by 2177.23% (higher than baseline).
Encryption latency regressed by 25242.02% (higher than baseline).
Memory usage regressed by 346.43% (higher than baseline).
Throughput regressed by 99.63% (lower than baseline).
In this prototype, backend implementation and protocol orchestration both shape performance: AES-GCM and HKDF rely on highly optimized native libraries, while the proposed stack uses native ASCON primitives plus Python protocol logic. Therefore, measured gaps on host systems should be interpreted as full-system outcomes (crypto backend + handshake/state machine + serialization/I/O), not raw algorithmic limits.
Native ASCON backend detected for this run: `native:ascon`.

## Security Analysis
The protocol enforces authenticated encryption, transcript verification in handshakes, deterministic nonce derivation, and sequence-based replay filtering. These controls provide confidentiality, integrity, and replay resistance in the evaluated model.
Session resumption with connection identifiers introduces persistent-state attack surfaces. Mitigations include bounded session lifetimes, cache cleanup, nonce counter continuity, and explicit invalidation on anomalies. Additional anti-DoS controls (e.g., stateless cookies) should be integrated for internet-facing deployments.

## Conclusion
The implemented evaluation pipeline provides reproducible, end-to-end comparison between a traditional AES-GCM secure channel and a research-oriented lightweight protocol using ASCON, sponge-KDF, and CID-style resumption. Current host-side measurements favor the baseline in raw performance, but the proposed architecture remains valuable for investigating lightweight protocol design, reconnect semantics, and constrained-friendly cryptographic composition.

## Future Work
1. Further optimize native ASCON integration and reduce protocol-layer Python overhead, then repeat the benchmark matrix.
2. Benchmark on target IoT hardware and include energy-per-message metrics.
3. Add network impairment tests (loss, reordering, migration) for resumption robustness.
4. Extend baseline set with ChaCha20-Poly1305 and DTLS 1.3 style profiles.
5. Introduce formal protocol verification and side-channel review for key operations.

## References (Conceptual)
1. NIST Lightweight Cryptography standardization and ASCON specifications.
2. DTLS connection identifier extensions for session continuity under network changes.
3. Sponge-based hash and XOF constructions for lightweight key derivation.