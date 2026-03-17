# Presentation Technical Guide - Lightweight Secure Communication Protocol for IoT

## 1. Project Identity and Presentation Goal

Project title:
- Lightweight Secure Communication Protocol for IoT using ASCON and Optimized ECC

Presentation goal:
- Explain how the protocol is designed and implemented.
- Defend cryptographic and systems decisions.
- Show benchmark methodology and why current host-side results look the way they do.
- Demonstrate a clear path from prototype to stronger IoT-focused performance.

Core claim to present:
- This work is a research-grade protocol prototype focused on lightweight cryptographic composition, session continuity, and reproducible evaluation tooling.

## 2. Problem Statement

IoT channels need:
- low handshake overhead on reconnect,
- authenticated encryption under constrained compute/memory,
- replay resistance,
- practical session continuity across unstable networks.

Traditional secure channels are robust, but reconnect overhead and implementation footprint are often non-trivial for constrained, mobile, or intermittently connected IoT nodes.

## 3. Research Foundations Mapped to This Implementation

1. ASCON lightweight cryptography:
- used for AEAD encryption and sponge/hash primitives.
- native backend is mandatory in current code (`pyascon` or `ascon`).

2. DTLS connection identifier (CID) concept:
- implemented as persistent `connection_id` for session resumption.
- reconnect can skip full ECDH path when cached session is valid.

3. Sponge-based lightweight derivation:
- key schedule and nonce derivation built from ASCON sponge/hash calls.
- absorb/permute/squeeze conceptual phases preserved in API.

## 4. System Architecture

Endpoints:
- IoT Device (client)
- Gateway (server)

Layering:
- `lightweight_secure_channel/crypto`: ECC, ASCON AEAD, sponge-KDF, nonce manager
- `lightweight_secure_channel/protocol`: handshake, packet schema, secure channel, session cache
- `lightweight_secure_channel/network`: socket client/server wrappers
- `experiments`: baseline stack + benchmark pipeline + phase1 scripts + paper generator

Reference files:
- `lightweight_secure_channel/protocol/handshake.py`
- `lightweight_secure_channel/protocol/secure_channel.py`
- `lightweight_secure_channel/crypto/ascon_cipher.py`
- `lightweight_secure_channel/crypto/kdf.py`
- `experiments/run_evaluation.py`

## 5. Protocol Versions and Wire Compatibility

Proposed protocol:
- version: `LSCP-2.0`

Baseline protocol:
- version: `BASE-1.0`

Important operational rule:
- Baseline client and proposed gateway are incompatible (and vice versa).
- Correct pairings must be respected in phase1 runs.

## 6. Proposed Handshake Design (ECC + CID Resumption)

### Full handshake path

1. Client sends `ClientHello`:
- protocol version,
- client ephemeral ECC public key,
- client nonce,
- optional resume CID.

2. Server validates version and resume hint.

3. If no valid resume:
- server responds with `ServerHello` containing:
  - new session ID,
  - new connection ID,
  - server ephemeral ECC public key,
  - server nonce.

4. Both sides compute ECDH shared secret (`secp256r1`).

5. Both sides derive key material from:
- shared secret,
- context info,
- nonces,
- session binding data.

6. Transcript-bound finish verification:
- `ClientFinished` and `ServerFinished` are generated from `auth_key` + transcript hash + role tag.

7. Session is stored with IDs and nonce counter.

### Resumed handshake path

1. Client includes `resume_connection_id` in `ClientHello`.
2. Server checks session table by CID and expiry.
3. If valid, server sends `ResumeAccept` with session/CID and fresh server nonce.
4. Keys are refreshed from cached session key plus fresh resume context.
5. Finished tags verify transcript.
6. Data channel starts without full ECDH exchange.

Optimization implemented:
- precomputed ephemeral key pools (`EphemeralKeyPool`) on both client and server.

## 7. Key Schedule and Native Sponge-KDF

Derived per-session material (`KeyMaterial`):
- `session_key` (16 bytes)
- `auth_key` (16 bytes)
- `nonce_seed` (16 bytes)

KDF design in `crypto/kdf.py`:
- `absorb(shared_secret, context_info)`
- `permute(state)`
- `squeeze(state, output_length)`
- `derive_keys(...)`

All these phases currently route through native ASCON sponge/hash backend via `sponge_hash(...)`.

Domain separation labels:
- `LSCP-SPONGE-ABSORB`
- `LSCP-SPONGE-PERMUTE`
- `LSCP-SPONGE-SQUEEZE`

## 8. ASCON AEAD Module

Module: `crypto/ascon_cipher.py`

Properties:
- native backend mandatory, import fails if none found.
- detached AEAD API exposed as:
  - `encrypt(key, nonce, plaintext, associated_data) -> (ciphertext, tag)`
  - `decrypt(key, nonce, ciphertext, associated_data, authentication_tag)`
- verification failure raises `ValueError("ASCON tag verification failed.")`

Backend dispatch:
- supports different native function signatures by probing call patterns.
- active backend is reported with `active_backend()`.

## 9. Packet Model and AEAD Associated Data

Packet structure:
- `protocol_version`
- `session_id`
- `sequence_number`
- `nonce`
- `ciphertext`
- `authentication_tag`

Associated data (AAD):
- built from `protocol_version|session_id|sequence_number`

Effect:
- packet metadata integrity is bound to ciphertext/tag verification.

## 10. Nonce and Replay Defense

Nonce generation:
- deterministic: `nonce = sponge_hash(nonce_seed || sequence_number)` (16 bytes)
- managed by `NonceManager`

Replay protection:
- receiver tracks last accepted sequence number.
- packet with `sequence_number <= last_received` is rejected (`ReplayProtectionError`).

Resumption safety:
- session manager persists nonce counter across reconnect.
- counter continuity avoids nonce reuse after session resume.

## 11. Session Management Strategy

Storage object (`SessionRecord`):
- session ID
- connection ID
- key material parts
- timestamp
- nonce counter

Lookup maps:
- by session ID
- by connection ID

Expiration:
- default timeout: 300s
- expired sessions are invalidated on access/cleanup

Operations:
- `store_session`
- `resume_session`
- `advance_nonce_counter`
- `invalidate_session`
- `cleanup_expired_sessions`

## 12. Baseline Protocol for Comparative Evaluation

File: `experiments/baseline_protocol.py`

Baseline stack:
- ECDH (`secp256r1`)
- HKDF-SHA256 (48-byte output split)
- AES-GCM (12-byte nonce from SHA-256 based derivation)
- full handshake each connection (no CID-style resume)

Baseline protocol version:
- `BASE-1.0`

Purpose:
- controlled reference to quantify overheads of proposed protocol design.

## 13. Evaluation Pipeline (Host-Side)

Orchestrator:
- `experiments/run_evaluation.py`

Scenarios:
- message counts: 100, 500, 1000
- repeats per scenario: 3

Metrics:
- handshake latency (ms)
- encryption latency (ms)
- memory delta (MB)
- CPU utilization proxy (%)
- throughput (MB/s)

Generated outputs:
- `results/tables/metrics_detailed.csv`
- `results/tables/metrics_summary.csv`
- `results/tables/metrics_summary.md`
- graphs in `results/graphs/`
- `results/paper_draft.md` (auto-generated)

## 14. Current Host-Side Summary (from metrics_summary.md)

Baseline (AES-GCM):
- Handshake: ~1.3-1.7 ms
- Encrypt: ~0.006-0.008 ms
- Throughput: ~10-12 MB/s

Proposed (ECC+ASCON+Sponge+Resumption):
- Handshake: ~32-36 ms
- Encrypt: ~1.66-2.06 ms
- Throughput: ~0.037-0.045 MB/s

Interpretation for presentation:
- Host-side Python still favors AES-GCM path heavily.
- This does not invalidate protocol correctness; it reflects implementation-level and orchestration-level overheads in this prototype.

## 15. Phase 1 Phone Summary (current local table)

From `results/tables/phase1_phone_summary.md` (stable_wifi sample):

Baseline:
- Handshake ~4.792 ms
- Encrypt ~0.021 ms
- Roundtrip ~0.356 ms
- Throughput ~0.297 MB/s

Proposed:
- Handshake ~43.157 ms
- Encrypt ~1.688 ms
- Roundtrip ~4.029 ms
- Throughput ~0.020 MB/s
- Resume hit: 100%

Presentation framing:
- Proposed protocol currently demonstrates robust resume behavior and security composition.
- Performance optimization remains active engineering work.

## 16. Why Baseline Outperformed the Proposed Protocol (In Depth)

This section is the most important defensive part of your presentation.  
Your results are not random; they are consistent with how both stacks are implemented today.

### 16.1 Host-side (results/tables/metrics_summary.md)

Observed pattern:
- Baseline is much faster for handshake and encryption.
- Baseline has much higher throughput.
- Proposed shows higher CPU and memory overhead in several runs.

Practical causes:

1. Crypto implementation maturity difference:
- Baseline uses `AESGCM` + `HKDF` from `cryptography` (OpenSSL-backed, highly optimized native path).
- Proposed includes ASCON native calls, but still has additional Python-level protocol work around each operation.

2. Per-message work difference:
- Proposed channel does nonce derivation via sponge hash, packet AAD construction, replay checks, JSON envelope handling, and state persistence updates.
- Baseline path is comparatively lean and benefits from very fast AEAD operation for short payload loops.

3. Handshake path complexity:
- Proposed handshake includes transcript hash over message history, finished-tag checks, and CID resumption logic.
- Baseline handshake is simpler in this prototype harness.

4. Benchmark harness effect:
- Your workloads are many small packets; in this regime Python object churn + serialization overhead dominates quickly.
- Raw primitive speed is not the only cost; orchestration costs become visible and strongly penalize richer protocol state machines.

### 16.2 Phase 1 (Phone Real-Environment Summary)

Observed pattern (stable_wifi sample):
- Proposed has much higher handshake/encrypt/roundtrip latency.
- Proposed throughput is lower.
- Proposed energy/message is higher.
- Proposed resume hit is excellent (100% in sample), baseline has no resume feature.

Practical causes:

1. Radio and socket scheduling on phone:
- Mobile OS scheduling + Python runtime amplify per-message overhead.
- Baseline completes packet processing faster, so radio active-time per message is shorter.

2. Energy follows time-on-CPU and time-on-radio:
- Energy/message rises when latency is higher, even if instantaneous power is similar.
- Proposed currently spends more time in protocol logic around crypto, so energy/message increases.

3. Feature tradeoff:
- Proposed includes robust resumed-session behavior and stronger reconnect semantics.
- Baseline appears faster because it is doing less protocol-level state work per reconnect/message in your current setup.

### 16.3 Phase 2 (Mega2560 + R307 Hardware-in-the-Loop)

Observed pattern:
- Delivery and latency/throughput vary by protocol and run set.
- Proposed remains slower in many edge-bridge metrics.
- Resume behavior is visible in proposed runs.

Practical causes:

1. Edge-bridge architecture cost:
- Crypto endpoint is still Python edge process, not on Mega2560.
- Added serial ingest + bridge transformation + network forward path introduces extra latency points.

2. Sensor timestamp domain mismatch risk:
- Mega emits `millis()`-style uptime timestamps; edge logs use epoch ms.
- If normalization is imperfect across mixed old/new rows, sensor->ACK latency can become inflated.
- Always treat old mixed Phase 2 rows carefully and regenerate clean datasets after script changes.

3. Mega2560 constraints:
- Mega is used as sensor/event producer, not full crypto endpoint (by design constraints).
- This validates real sensor integration and reconnect behavior, but does not remove Python orchestration overhead.

### 16.4 Metric-by-Metric Root Cause Map

Handshake latency (proposed worse):
- transcript hash + finished-tag verification + CID resume bookkeeping + richer state transitions.

Encryption latency (proposed worse):
- extra per-packet logic around nonce derivation, packet object handling, JSON framing, replay/state checks.

Roundtrip latency (proposed worse in Phase 1/2):
- encryption overhead + serialization overhead + ACK decode/verify overhead accumulate.

Throughput (proposed lower):
- inverse effect of higher per-packet cost; small payload tests magnify this.

Memory (proposed often higher):
- more active state objects (session/CID/nonce/replay/tracking) and temporary serialization buffers.

CPU (can be noisy but often higher for proposed):
- more Python-side orchestration per event.

Energy/message (proposed higher):
- mostly a direct consequence of longer event completion time.

Resume hit rate (proposed advantage):
- proposed supports CID-style resumption; baseline intentionally has no equivalent mechanism in this project.

### 16.5 Exactly How to Explain This to Panel

Use this wording:
- \"Baseline wins current raw speed because its stack is more optimized for this runtime path.\"
- \"Proposed protocol contribution is secure lightweight composition + session continuity architecture + reproducible evaluation across host/phone/hardware-in-loop.\"
- \"Current measurements are implementation-level outcomes, not upper bounds of the ASCON design space.\"

Avoid saying:
- \"ASCON is slower than AES always\" (too broad and not defensible).
- \"Our protocol is better in all aspects\" (contradicts measured data).

### 16.6 Actions That Directly Target the Gap

1. Remove JSON framing overhead (binary frame format).
2. Batch payload processing where appropriate.
3. Separate benchmark of crypto primitive time vs protocol orchestration time.
4. Keep Phase 2 datasets clean (new CSV per campaign) to avoid mixed timestamp artifacts.
5. Expand resumed-session-heavy scenarios to quantify your strongest protocol feature.

## 17. Real-Environment Execution Rules (Critical)

Correct pairings:
- Proposed server (`phase1_run_gateway.py`, port 9010) <-> proposed phone client (`phase1_phone_client.py`, port 9010)
- Baseline server (`phase1_run_baseline_gateway.py`, port 9020) <-> baseline phone client (`phase1_phone_baseline_client.py`, port 9020)

Common failure:
- using baseline client against proposed server causes `Unsupported protocol version` and handshake failure.

Host argument rule:
- Prefer `--host <IP>` with separate `--port`.
- `host:port` input is now normalized in phase1 phone client scripts.

## 18. Demo Plan for Presentation

Minimal live flow:

1. Start proposed gateway.
2. Run phone proposed client (`stable_wifi`, 3 cycles).
3. Show reconnect cycles and resume hit rate.
4. Run baseline pair similarly.
5. Run `phase1_analyze.py`.
6. Show `phase1_phone_summary.md` and selected graphs.

Narration points:
- full handshake first cycle, resumed handshakes after,
- integrity-protected ACK loop,
- deterministic nonce + replay defense,
- comparison with baseline.

## 19. Threat Model and Mitigation Talking Points

Threats addressed:
- passive eavesdropping
- payload tampering
- replay/stale packet injection
- stale/expired session reuse

Mechanisms:
- AEAD integrity + confidentiality
- transcript-based finished checks
- strict sequence monotonicity
- session timeout + cleanup
- nonce-counter persistence across reconnect

Threats not fully addressed (prototype scope):
- anti-DoS cookie/stateless challenge
- formal verification/proof artifacts
- side-channel hardening beyond software best effort

## 20. What to Say About Novelty

Novelty A (handshake optimization):
- precomputed ephemeral ECDH key pools reduce online keygen cost.

Novelty B (lightweight resumption):
- CID-inspired persistent connection identity with resumed key refresh path.

Novelty C (sponge-KDF):
- absorb/permute/squeeze API with native ASCON sponge/hash backend for key schedule.

## 21. Implementation Quality Highlights

- modular package layout
- dataclasses used for key/session/packet records
- replay checks and explicit exceptions
- benchmark pipeline with reproducible outputs
- auto-generated paper draft from measured data
- unit tests covering ECC/ASCON/KDF/protocol flow

## 22. Limitations to Admit Transparently

1. Python implementation overhead dominates throughput.
2. Host-side metrics do not represent upper bound on constrained firmware implementations.
3. Current phone metrics depend on network state, thermal behavior, and process scheduling.
4. No production-grade key storage/secure element integration yet.

## 23. Next Optimization Roadmap

1. Reduce JSON framing overhead (binary framing or compact codec).
2. Batch message path and minimize per-packet object churn.
3. Expand resumed-path usage in workloads to isolate resume gains.
4. Add stronger profiling traces per stage (handshake sub-steps, AEAD call time, serialization time).
5. Evaluate on additional device classes and mobility scenarios.

## 24. Likely Viva/Panel Questions and Ready Answers

Q: If baseline is faster, what is the contribution?
A: The contribution is protocol architecture and lightweight session continuity design with measured reproducible behavior, not a final claim of raw host-side speed supremacy.

Q: Is ASCON actually native in your implementation?
A: Yes. AEAD and sponge/hash paths require native ASCON backend; startup fails if backend is missing.

Q: How do you prevent replay after resumption?
A: Sequence monotonic checks plus persisted nonce counters in session state.

Q: Why session ID and connection ID both?
A: Session ID identifies cryptographic session context; connection ID enables robust session lookup across reconnect/network tuple change.

Q: What proves handshake authenticity?
A: Finished tags derived from `auth_key` bound to transcript hash and role.

## 25. Presentation Slide Skeleton (Suggested)

1. Problem + motivation
2. Design goals and research inspirations
3. Architecture and module map
4. Handshake/full vs resumed sequence diagrams
5. Crypto internals (ECC, ASCON AEAD, sponge-KDF)
6. Security controls and threat handling
7. Experimental setup (baseline vs proposed)
8. Host-side and phase1 results
9. Limitations and optimization roadmap
10. Conclusion and Q&A

## 26. Command Appendix for Live Demo

Proposed gateway (PC):
```bash
python experiments/phase1_run_gateway.py --host 0.0.0.0 --port 9010
```

Proposed phone client:
```bash
python experiments/phase1_phone_client.py --host <PC_LAN_IP> --port 9010 --device-id phone-1 --device-class phone_midrange --scenario stable_wifi --cycles 3 --messages 100 --payload-size 128
```

Baseline gateway (PC):
```bash
python experiments/phase1_run_baseline_gateway.py --host 0.0.0.0 --port 9020
```

Baseline phone client:
```bash
python experiments/phase1_phone_baseline_client.py --host <PC_LAN_IP> --port 9020 --device-id phone-1 --device-class phone_midrange --scenario stable_wifi --cycles 3 --messages 100 --payload-size 128
```

Analyze phase1 logs:
```bash
python experiments/phase1_analyze.py
```

Run host benchmark suite:
```bash
python experiments/run_evaluation.py
```

## 27. Final Presenter Note

Use precise language:
- "research prototype"
- "measured system-level behavior"
- "native ASCON backend enabled"
- "optimization roadmap in progress"

This framing is technically accurate and defensible in front of an academic panel.
