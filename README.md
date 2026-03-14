# Lightweight Secure Communication Protocol for IoT using ASCON and Optimized ECC

A research-oriented Python prototype of a lightweight secure channel between an IoT device and a gateway.

This project implements and evaluates:
- ECDH key exchange on `secp256r1`
- ASCON-128 authenticated encryption
- Sponge-based lightweight key derivation (absorb -> permute -> squeeze)
- DTLS connection identifier inspired session resumption
- Comparative experiments against an AES-GCM baseline

---

## 1) What This Project Provides

The repository includes two full protocol stacks for controlled research comparison.

- Proposed protocol:
  - ECC + ASCON + sponge-KDF + CID-based session resumption
- Baseline protocol:
  - ECC + HKDF-SHA256 + AES-GCM

You can:
- run an end-to-end secure communication demo
- run automated experiments (100, 500, 1000 messages)
- generate plots and result tables
- auto-generate a research paper draft from measured results

---

## 2) Repository Layout

```text
lightweight_secure_channel/
  crypto/
    ecc.py
    ascon_cipher.py
    kdf.py
    nonce_manager.py
  protocol/
    handshake.py
    packet.py
    secure_channel.py
    session_manager.py
  network/
    client.py
    server.py

demo/
  main_demo.py

experiments/
  baseline_protocol.py
  run_evaluation.py
  generate_paper.py

tests/
  test_ecc.py
  test_ascon.py
  test_kdf.py
  test_protocol.py

results/
  graphs/
  tables/
  paper_draft.md

requirements.txt
README.md
main_demo.py
```

Notes:
- `main_demo.py` at repository root is a compatibility entrypoint that forwards to `demo/main_demo.py`.
- `results/` is generated and updated when you run experiments.

---

## 3) Protocol Architecture (High-Level)

### Endpoints
- IoT Device (client)
- Gateway (server)

### Cryptographic pipeline
1. ECDH shared secret (`secp256r1`)
2. KDF
   - Proposed: sponge-based derivation
   - Baseline: HKDF-SHA256
3. AEAD channel
   - Proposed: ASCON-128
   - Baseline: AES-GCM
4. Session cache and resumption
   - Proposed: connection ID (CID) for reconnect continuity

### Proposed packet structure
```text
{
  protocol_version,
  session_id,
  sequence_number,
  nonce,
  ciphertext,
  authentication_tag
}
```

### Handshake model (proposed)
- `ClientHello`
- `ServerHello`
- key schedule + transcript verification (`ClientFinished` / `ServerFinished`)
- optional resumed handshake path via cached `connection_id`

---

## 4) Security Mechanisms Implemented

- authenticated encryption for confidentiality + integrity
- transcript-bound handshake verification
- deterministic per-message nonce derivation from session nonce seed + sequence number
- replay protection via monotonic sequence checks
- session timeout and cache cleanup
- persistent session continuity using CID-inspired session mapping

---

## 5) Environment Requirements

- Python 3.10+
- OS: Windows, Linux, or macOS
- Recommended: virtual environment (`venv`)

Dependencies (from `requirements.txt`):
- `cryptography`
- `matplotlib`
- `psutil`

---

## 6) Setup Guide (Fresh Machine)

### Step A: Get the project
- Clone or download this repository.
- Open terminal in the project root (the folder containing `README.md`).

### Step B: Create and activate a virtual environment

#### Windows PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### Linux/macOS (bash/zsh)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step C: Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step D: Validate installation
```bash
python -m unittest discover -s tests -v
```
Expected: all tests pass.

---

## 7) Run the Demo (Secure Channel + Resumption)

Run:
```bash
python demo/main_demo.py
```

Alternative entrypoint:
```bash
python main_demo.py
```

Demo includes:
1. initial handshake
2. encrypted message exchange
3. packet encrypt/decrypt check
4. reconnect with session resumption

Typical output pattern:
- `Handshake complete: resumed=False, latency=... ms`
- sensor payload ACK responses
- `Packet demo plaintext recovered: ...`
- `Resumed handshake: resumed=True, latency=... ms`

---

## 8) Run Comparative Experiments

Run:
```bash
python experiments/run_evaluation.py
```

This executes baseline vs proposed protocols for:
- 100 messages
- 500 messages
- 1000 messages

Metrics measured:
- handshake latency
- encryption latency
- memory usage delta
- CPU utilization
- throughput

Outputs generated:
- Graphs in `results/graphs/`
  - `handshake_latency_comparison.png`
  - `encryption_latency_comparison.png`
  - `memory_usage_comparison.png`
  - `throughput_comparison.png`
- Tables in `results/tables/`
  - `metrics_detailed.csv`
  - `metrics_summary.csv`
  - `metrics_summary.md`
- Paper draft
  - `results/paper_draft.md`

---

## 9) Research Paper Draft Generation

The paper draft is generated automatically by the evaluation pipeline.

To regenerate only the draft from existing summary data:
```bash
python experiments/generate_paper.py
```

Required source file for draft generation:
- `results/tables/metrics_summary.csv`

---

## 10) How to Read the Results Correctly

In this implementation, performance is strongly affected by backend choice:
- AES-GCM uses optimized native crypto backend via `cryptography`.
- ASCON path is implemented in pure Python for research transparency.

Implication:
- baseline often appears faster on desktop-class CPUs.
- this does not invalidate the protocol design; it reflects implementation maturity and hardware acceleration differences.

For fairer ASCON performance conclusions:
- use an optimized/native ASCON backend
- evaluate on target IoT hardware
- include energy and memory footprint per device class

---

## 11) Module Guide

### `lightweight_secure_channel/crypto`
- `ecc.py`
  - `generate_keypair()`
  - `serialize_public_key()`
  - `deserialize_public_key()`
  - `compute_shared_secret()`
- `ascon_cipher.py`
  - `encrypt(key, nonce, plaintext, associated_data)`
  - `decrypt(key, nonce, ciphertext, associated_data, authentication_tag=None)`
- `kdf.py`
  - `absorb(shared_secret, context_info)`
  - `permute(state)`
  - `squeeze(state, output_length)`
  - `derive_keys(shared_secret, context_info)`
- `nonce_manager.py`
  - deterministic nonce sequencing for unique per-packet nonces

### `lightweight_secure_channel/protocol`
- `handshake.py`
  - full handshake + resumed handshake
  - precomputed ephemeral key pool
- `packet.py`
  - packet schema and serialization helpers
- `secure_channel.py`
  - encrypt/decrypt packet operations
  - replay protection checks
- `session_manager.py`
  - session cache, timeout, cleanup, resumption

### `lightweight_secure_channel/network`
- `client.py`
  - connect, handshake, resume, send messages
- `server.py`
  - listen, handshake, receive encrypted packets

### `experiments`
- `baseline_protocol.py`
  - baseline implementation used for comparison
- `run_evaluation.py`
  - full benchmark orchestration
- `generate_paper.py`
  - result-driven draft generation

---

## 12) Reproducibility and Experiment Tuning

Edit `experiments/run_evaluation.py` to tune:
- `MESSAGE_COUNTS` (default `[100, 500, 1000]`)
- `REPEATS` (default `3`)
- `PAYLOAD_SIZE` (default `128` bytes)

Recommendation:
- increase `REPEATS` for more stable statistics
- keep environment consistent across runs
- avoid heavy background load during benchmarking

---

## 13) Troubleshooting

### `ModuleNotFoundError` when running demo
Use project root as working directory:
```bash
python demo/main_demo.py
```
Do not run from inside `demo/` unless Python path is configured.

### Port already in use
Default demo server port is `9010`.
- stop conflicting process
- or change host/port in demo and client/server constructors

### Matplotlib/plot generation issues
Ensure dependencies are installed from `requirements.txt`.
The evaluation script uses non-GUI backend (`Agg`) and should work headless.

### Tests fail after partial edits
Run full tests:
```bash
python -m unittest discover -s tests -v
```
Then re-run evaluation.

---

## 14) Ethical and Practical Scope

This is a research prototype for evaluation and learning.
It is not production-hardened.

Before production deployment, add:
- formal protocol verification
- hardened key storage strategy
- stronger anti-DoS controls
- secure provisioning and device identity lifecycle
- side-channel and fault-injection resilience analysis

---

## 15) Quick Command Reference

Setup:
```bash
pip install -r requirements.txt
```

Tests:
```bash
python -m unittest discover -s tests -v
```

Demo:
```bash
python demo/main_demo.py
```

Experiments + plots + paper draft:
```bash
python experiments/run_evaluation.py
```

Regenerate paper from summary table:
```bash
python experiments/generate_paper.py
```
