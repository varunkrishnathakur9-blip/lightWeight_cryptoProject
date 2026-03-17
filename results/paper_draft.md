# Lightweight Secure Communication for IoT: Experimental Evaluation Draft

## Abstract
This draft evaluates a lightweight IoT secure communication protocol composed of ECDH on secp256r1, ASCON-128 authenticated encryption, a sponge-based key derivation function, and DTLS connection identifier-inspired session resumption. A baseline secure channel using ECDH, HKDF-SHA256, and AES-GCM is implemented for controlled comparison. Host-side experiments are executed for 100, 500, and 1000 message workloads with measurements for handshake latency, encryption latency, memory usage, CPU utilization, and throughput. In addition, this draft incorporates Phase 1 phone-based and Phase 2 hardware-in-the-loop summaries when available.

## Introduction
Security protocols for IoT must handle intermittent links, low-power processing, and constrained memory while preserving confidentiality and integrity. Although widely deployed secure channel stacks provide mature protection, they can be expensive to reconnect and difficult to tune for constrained deployments. This work studies a lightweight secure channel architecture that integrates modern lightweight cryptography concepts into an implementation-first prototype.
The proposed protocol design is motivated by three ideas: ASCON for lightweight authenticated encryption, connection identifier based session continuity inspired by DTLS, and absorb-permute-squeeze sponge derivation for compact key scheduling. The study objective is to measure practical behavior against a traditional AES-GCM baseline rather than to claim universal superiority of one primitive.

## Related Work
ASCON has become central in lightweight cryptography discussions because it is standardized for constrained environments and provides both AEAD and sponge-style hashing capabilities. DTLS connection identifier concepts motivate session continuity under network tuple changes, while sponge constructions support compact derivation without introducing multiple heavyweight primitives.

## System Architecture
The prototype uses a two-endpoint model: IoT device client and gateway server. Modules are separated into cryptographic primitives (`crypto`), protocol state machines (`protocol`), and transport orchestration (`network`). The architecture supports both full handshakes and resumed handshakes with cached session state.

## Protocol Design
The baseline protocol uses ECDHE + HKDF-SHA256 + AES-GCM and performs a full handshake on each connection. The proposed protocol uses ECDHE + sponge-KDF + ASCON and supports resumed handshakes via persistent connection IDs. Transcript-bound finished verification and replay protection are enforced in both stacks.

## Implementation
All components are implemented in Python for rapid prototyping and instrumentation. Baseline and proposed variants share common measurement harnesses so that metrics are captured under similar process conditions. The evaluation pipeline generates CSV tables, markdown summaries, publication-ready plots, and this draft paper.
Execution environment for this run: Python on Windows 11 (AMD64).

## Experimental Evaluation
### Host Benchmark Scenarios
| Scenario | Message Count | Protocols |
|---|---:|---|
| S100 | 100 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |
| S500 | 500 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |
| S1000 | 1000 | Baseline AES-GCM vs Proposed ECC+ASCON+Sponge-KDF+Resumption |

### Host Benchmark Consolidated Metrics
| Metric | Baseline Avg | Proposed Avg | Relative Change (Proposed vs Baseline) |
|---|---:|---:|---:|
| Handshake Latency (ms) | 1.480 | 33.706 | 2177.23% |
| Encryption Latency (ms) | 0.007 | 1.805 | 25242.02% |
| Memory Usage (MB delta) | 0.012 | 0.054 | 346.43% |
| CPU Utilization (%) | 50.22 | 98.26 | 95.66% |
| Throughput (MB/s) | 11.284 | 0.042 | -99.63% |

### Phase 1 Real-Environment Summary (Phone Client)
| Protocol | Device Class | Scenario | Handshake (ms) | Encrypt (ms) | Roundtrip (ms) | Throughput (MB/s) | Energy/msg (mJ) | Resume Hit (%) | Reconnect Success (%) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | phone_midrange | stable_wifi | 4.792 | 0.021 | 0.356 | 0.297 | 1.109 | 0.00 | 100.00 |
| proposed | phone_midrange | stable_wifi | 43.157 | 1.688 | 4.029 | 0.020 | 15.445 | 100.00 | 100.00 |

Phase 1 handshake latency regressed by 800.56% (higher than baseline).
Phase 1 roundtrip latency regressed by 1031.04% (higher than baseline).
Phase 1 throughput regressed by 93.33% (lower than baseline).
Phase 1 energy per message regressed by 1292.47% (higher than baseline).

### Phase 2 Hardware-in-the-Loop Summary (Mega2560 + R307)
| Protocol | Device Class | Scenario | Delivered/Total | Delivery (%) | Handshake (ms) | Resume Hit (%) | Sensor->ACK p50 (ms) | Sensor->ACK p95 (ms) | Throughput (events/s) | Energy/msg (mJ) |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | mega2560_r307s | periodic | 30/30 | 100.00 | 40.559 | 0.00 | 224.033 | 417.000 | 983.961 | 0.813 |
| baseline | mega2560_sim | periodic | 5/5 | 100.00 | 4.442 | 0.00 | 1.000 | 1.000 | 2008.032 | 0.299 |
| proposed | mega2560_r307s | periodic | 115/115 | 100.00 | 46.110 | 100.00 | 25687.713 | 116922.000 | 83.083 | 9.629 |
| proposed | mega2560_sim | periodic | 5/5 | 100.00 | 37.815 | 100.00 | 7.800 | 9.000 | 127.600 | 4.702 |

Phase 2 handshake latency regressed by 86.50% (higher than baseline).
Phase 2 sensor-to-ACK latency (p50) regressed by 11318.54% (higher than baseline).
Phase 2 throughput regressed by 92.96% (lower than baseline).
Phase 2 energy per message regressed by 1189.13% (higher than baseline).

## Results
Handshake latency regressed by 2177.23% (higher than baseline).
Encryption latency regressed by 25242.02% (higher than baseline).
Memory usage regressed by 346.43% (higher than baseline).
Throughput regressed by 99.63% (lower than baseline).
In this prototype, backend implementation and protocol orchestration both shape performance: AES-GCM and HKDF rely on highly optimized native libraries, while the proposed stack uses native ASCON primitives plus Python protocol logic. Therefore, measured gaps should be interpreted as full-system outcomes (crypto backend + handshake/state machine + serialization/I/O), not raw algorithmic limits.
ASCON backend could not be verified at draft-generation time (ModuleNotFoundError). Ensure native backend is installed and active.

## Security Analysis
The protocol enforces authenticated encryption, transcript verification in handshakes, deterministic nonce derivation, and sequence-based replay filtering. These controls provide confidentiality, integrity, and replay resistance in the evaluated model.
Session resumption with connection identifiers introduces persistent-state attack surfaces. Mitigations include bounded session lifetimes, cache cleanup, nonce counter continuity, and explicit invalidation on anomalies. Additional anti-DoS controls (e.g., stateless cookies) should be integrated for internet-facing deployments.

## Conclusion
The implemented evaluation pipeline provides reproducible, end-to-end comparison between a traditional AES-GCM secure channel and a research-oriented lightweight protocol using ASCON, sponge-KDF, and CID-style resumption. Current host-side and edge-bridge measurements often favor the baseline in raw speed, while the proposed architecture remains valuable for lightweight protocol design, reconnect semantics, and constrained-device experimentation.

## Future Work
1. Reduce protocol-layer overhead in edge bridge and move more processing to embedded firmware where feasible.
2. Expand Phase 1 and Phase 2 datasets across multiple scenarios and device classes.
3. Add network impairment tests (loss, reordering, migration) for resumption robustness.
4. Extend baseline set with ChaCha20-Poly1305 and DTLS 1.3 style profiles.
5. Introduce formal protocol verification and side-channel review for key operations.

## References (Conceptual)
1. NIST Lightweight Cryptography standardization and ASCON specifications.
2. DTLS connection identifier extensions for session continuity under network changes.
3. Sponge-based hash and XOF constructions for lightweight key derivation.