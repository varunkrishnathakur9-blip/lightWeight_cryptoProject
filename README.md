# Lightweight Secure Communication Protocol for IoT using ASCON and Optimized ECC

This repository contains a research-quality Python prototype implementing a lightweight secure channel for IoT device-to-gateway communication.

## Implemented Design Goals

- ECC key exchange using ECDH on `secp256r1`
- ASCON-128 authenticated encryption
- Sponge-based lightweight KDF (absorb -> permute -> squeeze)
- DTLS-CID-inspired lightweight session resumption
- TCP client/server simulation

## Repository Structure

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
```

## Cryptographic Modules

### ECC (`crypto/ecc.py`)
- `generate_keypair()`
- `serialize_public_key()`
- `deserialize_public_key()`
- `compute_shared_secret()`

### ASCON AEAD (`crypto/ascon_cipher.py`)
- `encrypt(key, nonce, plaintext, associated_data)`
- `decrypt(key, nonce, ciphertext, associated_data)`

`decrypt` also supports detached tags by passing optional `authentication_tag`.

### Sponge KDF (`crypto/kdf.py`)
- `absorb(shared_secret, context_info)`
- `permute(state)`
- `squeeze(state, output_length)`
- `derive_keys(shared_secret, context_info)` -> `(session_key, auth_key, nonce_seed)`

### Nonce Manager (`crypto/nonce_manager.py`)
Deterministic nonce generation from `nonce_seed + sequence_number` for unique nonces per packet.

## Protocol and Session Model

### Handshake (`protocol/handshake.py`)
- Optimized ECC handshake using precomputed ephemeral key pools
- Reduced message rounds via combined server response
- Finished-message transcript verification
- Session resumption using persistent connection IDs

### Session Manager (`protocol/session_manager.py`)
Session state stores:
- `session_id`
- `session_key`
- `timestamp`
- `nonce_counter`

plus `auth_key`, `nonce_seed`, and `connection_id` for resumed secure channels.

### Packet Format (`protocol/packet.py`)
Each encrypted packet includes:
- `protocol_version`
- `session_id`
- `sequence_number`
- `nonce`
- `ciphertext`
- `authentication_tag`

## Network Layer

### Server (`network/server.py`)
- `listen()`
- `perform_handshake()`
- `receive_encrypted_packets()`

### Client (`network/client.py`)
- `connect()`
- `perform_handshake()`
- `resume_session_if_available()`
- `send_encrypted_messages()`

## Demo

Run:

```bash
python demo/main_demo.py
```

The demo shows:
1. Handshake
2. Encrypted communication
3. Session resumption
4. Packet encryption/decryption

## Experimental Evaluation

Run:

```bash
python experiments/run_evaluation.py
```

Outputs:
- `results/graphs/`:
  - `handshake_latency_comparison.png`
  - `encryption_latency_comparison.png`
  - `memory_usage_comparison.png`
  - `throughput_comparison.png`
- `results/tables/`:
  - `metrics_detailed.csv`
  - `metrics_summary.csv`
  - `metrics_summary.md`
- `results/paper_draft.md`

## Tests

Run:

```bash
python -m unittest discover -s tests -v
```

Test suite covers:
- ECC correctness
- ASCON encrypt/decrypt and tag verification
- Sponge KDF behavior
- End-to-end protocol with session resumption
