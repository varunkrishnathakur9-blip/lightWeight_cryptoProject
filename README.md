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

Native ASCON backend (mandatory):
- Install at least one: `pyascon` or `ascon`

---

## 5A) Phone Quickstart (Phase 1)

Use this if you want the fastest path to run phone-based experiments.

### On PC (gateway)
From project root:
```bash
python experiments/phase1_run_gateway.py --host 0.0.0.0 --port 9010
```
Copy the printed `LAN IP hint` (example: `192.168.1.15:9010`).

### On phone (Termux recommended)
```bash
pkg update
pkg install -y git python
git clone <YOUR_REPO_URL>
cd lightWeight_cryptoProject
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyascon  # or: pip install ascon
```

Run workload (replace `<PC_LAN_IP>`):
```bash
python experiments/phase1_phone_client.py \
  --host <PC_LAN_IP> \
  --port 9010 \
  --device-id phone-1 \
  --scenario stable_wifi \
  --cycles 3 \
  --messages 100 \
  --payload-size 128
```

### Analyze results
On PC (or phone in same repo):
```bash
python experiments/phase1_analyze.py
```
Outputs:
- `results/tables/phase1_phone_metrics.csv`
- `results/tables/phase1_phone_summary.csv`
- `results/tables/phase1_phone_summary.md`
- `results/graphs/phase1_handshake_latency.png`
- `results/graphs/phase1_roundtrip_latency.png`
- `results/graphs/phase1_throughput.png`
- `results/graphs/phase1_resume_hit_rate.png`

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
pip install pyascon  # or: pip install ascon
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
- ASCON AEAD plus sponge/hash/KDF paths require a native backend (`pyascon` or `ascon`).
- Results should be interpreted after confirming active native backend via `active_backend()`.

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
pip install pyascon  # or: pip install ascon
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

---

## 16) Phase 1 Real-Environment Run (Phone as IoT Device)

This phase runs the gateway on your system and uses your phone as the IoT client.
It now supports both protocols for fair comparison:
- Proposed: ECC + ASCON + sponge-KDF + session resumption
- Baseline: ECC + HKDF-SHA256 + AES-GCM

### A) Start gateway on system (PC/laptop)

#### Proposed gateway (default Phase 1)
```bash
python experiments/phase1_run_gateway.py --host 0.0.0.0 --port 9010
```

#### Baseline gateway
```bash
python experiments/phase1_run_baseline_gateway.py --host 0.0.0.0 --port 9020
```

Each command prints a `LAN IP hint` (example: `192.168.x.x:9010`).
Use that IP in phone client commands.

### B) Run phone client workload (on phone)

#### B1) Best option: use Termux
Termux is recommended for reproducible CLI-based experiments.

Install Termux, then run:
```bash
pkg update
pkg install -y git python
```

#### B2) Copy project to phone
Choose one method:

1. Git clone directly on phone (recommended):
```bash
git clone <YOUR_REPO_URL>
cd lightWeight_cryptoProject
```

2. ZIP transfer from PC:
- Zip the project folder on PC.
- Transfer via USB/Drive/LocalSend.
- Extract on phone.
- `cd` into extracted `lightWeight_cryptoProject` directory in Termux.

#### B3) Install dependencies on phone
From project root on phone:
```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install pyascon  # or: pip install ascon
```

#### B4) Run proposed protocol workload command
Use your PC LAN IP from gateway output (`LAN IP hint`), not `127.0.0.1`.

```bash
python experiments/phase1_phone_client.py \
  --host <PC_LAN_IP> \
  --port 9010 \
  --device-id phone-1 \
  --device-class phone_midrange \
  --scenario stable_wifi \
  --cycles 3 \
  --messages 100 \
  --payload-size 128
```

#### B5) Run baseline protocol workload command (for fair comparison)
```bash
python experiments/phase1_phone_baseline_client.py \
  --host <PC_LAN_IP> \
  --port 9020 \
  --device-id phone-1 \
  --device-class phone_midrange \
  --scenario stable_wifi \
  --cycles 3 \
  --messages 100 \
  --payload-size 128
```

#### B6) Scenario list
Run same command for each scenario by changing `--scenario`:
- `stable_wifi`
- `wifi_to_mobile`
- `airplane_toggle`
- `app_restart`

For stronger results, execute each scenario multiple times.

#### B7) Device class and energy estimation
New fields are logged per cycle for energy/memory footprint by device class.

Key flags:
- `--device-class` (label in logs):
  - `phone_midrange`
  - `phone_flagship`
  - `iot_mcu_wifi`
  - `iot_mcu_ble`
  - any custom label
- `--power-w` (optional): override assumed average power in Watts for energy estimation

If `--power-w` is omitted, a default profile is used based on `--device-class`.

#### B8) If you prefer Pydroid (optional)
- Open extracted project folder in Pydroid.
- Install dependencies from terminal in app: `pip install -r requirements.txt` and `pip install pyascon` (or `pip install ascon`).
- Run same client commands (single-line form if needed).

### C) Analyze Phase 1 logs (on system or phone)
```bash
python experiments/phase1_analyze.py
```

Generated outputs:
- `results/tables/phase1_phone_metrics.csv`
- `results/tables/phase1_phone_summary.csv`
- `results/tables/phase1_phone_summary.md`
- `results/graphs/phase1_handshake_latency.png`
- `results/graphs/phase1_roundtrip_latency.png`
- `results/graphs/phase1_throughput.png`
- `results/graphs/phase1_resume_hit_rate.png`
- `results/graphs/phase1_deviceclass_memory.png`
- `results/graphs/phase1_deviceclass_energy_per_message.png`

### D) Firewall/network checklist
- PC and phone must be on reachable network.
- Allow inbound TCP on selected ports (`9010`, `9020`) on system firewall.
- Use system LAN IP, not `127.0.0.1`, from phone.


---

## 17) Native ASCON Backend (Mandatory)

ASCON operations in this project now **require** a native backend.
There is no pure-Python fallback for AEAD, sponge hash, or KDF.

Install at least one backend in your active environment:

```bash
python -m pip install pyascon
# or
python -m pip install ascon
```

Verify backend resolution:
```bash
python -c "from lightweight_secure_channel.crypto.ascon_cipher import active_backend; print(active_backend())"
```

Expected output example:
- `native:pyascon`
- or `native:ascon`

If backend is missing, imports will fail intentionally with:
- `RuntimeError: Native ASCON backend is mandatory but not found. Install pyascon or ascon.`

Recommended pre-test check:
```bash
python -m pip show pyascon
python -m pip show ascon
python -m unittest discover -s tests -v
```


