# Lightweight Secure Communication Protocol for IoT Using ASCON and Optimized ECC

## Project Overview
This repository contains a research-grade Python prototype of a lightweight secure channel for IoT communication.
It combines:

- ECDH key exchange on `secp256r1`
- ASCON-128 authenticated encryption (pure Python)
- Lightweight key derivation (ASCON sponge KDF) and baseline HKDF-SHA256
- Session resumption with token validation and expiration
- Benchmarking against AES-GCM with plot generation

## Architecture
Protocol model:

1. `ClientHello`
2. `ServerHello`
3. `KeyExchange` (ECC public key delivery)
4. `SessionKeyDerivation` (derived key hash confirmation)
5. `HandshakeComplete`

Data channel:

- Encrypted packets with ASCON AEAD
- Associated data includes `session_id`, `sequence_number`, and protocol version
- Replay prevention via monotonic sequence number checks
- Deterministic per-message nonce generation from session `nonce_seed`

Session resumption:

- Session token format:
  - `session_id`
  - `derived_key_hash`
  - `timestamp`
  - `nonce_seed`
- Default timeout: 5 minutes (`300` seconds)

## Project Structure
```text
lightweight_secure_channel/
  crypto/
    ecc.py
    ascon_cipher.py
    kdf.py
  protocol/
    handshake.py
    secure_channel.py
    session_manager.py
  network/
    client.py
    server.py
  utils/
    benchmark.py
    metrics.py
    logger.py
tests/
  test_handshake.py
  test_encryption.py
  test_session_resumption.py
main_demo.py
README.md
```

## Setup
Python 3.10+ is required.

Install dependencies:

```bash
pip install cryptography psutil matplotlib
```

## Run Demo
```bash
python main_demo.py
```

Demo flow:

1. Starts gateway server
2. Starts IoT client and performs full handshake
3. Sends encrypted messages
4. Reconnects and performs session resumption
5. Runs benchmark (100 encrypted messages, ASCON vs AES-GCM)

Example output:

```text
Handshake time: 45.12 ms
Session resumed: False
Resumed handshake time: 8.43 ms
Session resumed: True
Encryption time (ASCON mean): 2.04 ms
```

## Run Tests
```bash
python -m unittest discover -s tests -v
```

## Benchmarking
The benchmark module reports:

- Full handshake latency
- Resumed handshake latency
- ASCON encryption/decryption latency
- AES-GCM encryption/decryption latency
- Throughput comparison
- Memory delta and process CPU utilization

Generated plots are saved to `benchmark_results/`:

- `encryption_latency.png`
- `handshake_latency.png`
- `memory_usage.png`
- `throughput.png`

## Security Notes
This prototype demonstrates core protocol mechanisms for research and evaluation.
Before production usage:

- Add secure key storage (HSM/TPM/secure element where possible)
- Introduce robust anti-replay windows for out-of-order delivery scenarios
- Harden token protection and transport-level endpoint authentication
- Add formal verification and extended interoperability testing

