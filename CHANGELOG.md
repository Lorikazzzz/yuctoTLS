# Changelog

## Hardening, correctness & performance pass

A broad pass over the original AI-generated codebase: fixed security/correctness
bugs, replaced the broken post-quantum implementation with an audited one, added
TLS 1.3 session resumption, and hardware-accelerated the bulk ciphers. Every
crypto change is verified against a reference (NIST vectors / Python differential
tests) before being enabled.

### Security & correctness fixes

- **AEAD authentication bypass** — `tls_core_recv` ignored the AES-GCM /
  ChaCha20-Poly1305 decrypt return value, so a forged record was accepted as
  plaintext. All decrypt results are now checked (TLS 1.2, TLS 1.3, and H2 paths).
- **Wrong SHA-384 empty-hash constant** — broke every TLS_AES_256_GCM_SHA384
  (cipher `0x1302`) handshake. Corrected; Akamai & co. now work.
- **Hybrid key-share order** — X25519MLKEM768 shared secret was concatenated in
  the wrong order (`ML-KEM‖X25519` instead of `X25519‖ML-KEM`).
- **NewSessionTicket handling** — post-handshake handshake records (inner type
  `0x16`) were returned to the caller as application data, corrupting the first
  `recv()` on the HTTP/1.1 path. Now skipped/parsed correctly.
- **Unchecked `malloc` / `write`** — added null checks and a `write_full()` helper;
  TLS record sends no longer silently truncate.
- **HTTP/1.1 request builder** — replaced unchecked `sprintf` with bounds-checked
  `snprintf`.
- **PRNG** — replaced `rand()` fallback with `getrandom()`; removed weak
  non-cryptographic entropy paths.
- **Obfuscated `"finished"` label** — removed pointless XOR obfuscation.
- Misc: self-include in `nanotls.h`, `bind()` before `socket()` check in QUIC,
  X25519 double-clamping, `quic_skip_frame` wrong length argument.

### Thread safety

- Removed the single `static nanotls_conn global_conn` — connections are now
  heap-allocated per call and freed by `tls_core_close`.
- Removed a `static` scratch buffer in the QUIC handshake.
- Stopped storing a pointer to `__thread` storage in the connection struct
  (ALPN string is copied into the struct).
- PRNG no longer keeps mutable static state.
- Validated under concurrent load: per-thread checksums + verified decrypts, no
  corruption or crashes.

### Post-quantum (ML-KEM-768)

- The hand-rolled ML-KEM had NTT-domain bugs throughout and produced wrong shared
  secrets. **Replaced with the PQClean clean reference implementation** (FIPS 203),
  vendored under `pqclean_mlkem/` and compiled as a single amalgamation
  (`mlkem768.c`) with a compact in-tree Keccak (`keccak.c`) replacing PQClean's
  bulky fips202.c. Round-trip verified against the Python `kyber-py` reference.
- X25519MLKEM768 key share re-enabled now that decaps is correct.

### TLS 1.3 session resumption (PSK)

- Full RFC 8446 resumption: derive `resumption_master_secret`, capture
  `NewSessionTicket`, cache the PSK per host, and on the next connection emit the
  `pre_shared_key` extension with a correct binder (HMAC over the truncated
  ClientHello). Handles server PSK acceptance (PSK-based early secret) and
  rejection (full handshake) transparently.
- Net effect: on a resumed connection the TLS fingerprint (JA3/JA4) matches a real
  Chrome resumption handshake, including extension `0x0029`.

### Fingerprint accuracy

- Full Chrome cipher list (15 suites) and the `application_settings` (ALPS,
  `0x44cd`) extension added — JA4 cipher hash now matches Chrome exactly.

### Performance — hardware-accelerated bulk crypto (x86-64, runtime-detected)

All paths fall back to portable C when the CPU feature is absent.

| Cipher | Before | After | Speedup |
|---|---|---|---|
| AES-128-GCM | 9.3 MB/s | ~1050 MB/s (8.2 Gbit/s) | ~113× |
| AES-256-GCM | 8.8 MB/s | ~1000 MB/s (7.8 Gbit/s) | ~113× |
| ChaCha20-Poly1305 | 230 MB/s | ~525 MB/s (4.1 Gbit/s) | ~2.3× |

- **AES-GCM**: AES-NI block cipher with 8-way pipelined CTR + PCLMULQDQ
  carryless-multiply GHASH (Intel-whitepaper reduction).
- **ChaCha20**: 4-way SSE2 SIMD (4 blocks in parallel).
- **Poly1305**: zero-copy incremental MAC (also fixed a latent build break).
- Verified: NIST AES-GCM vector + thousands of differential cases vs Python for
  both AES-GCM and ChaCha20-Poly1305.
- A SHA-NI SHA-256 and a software-fallback note are present but **disabled** until
  bit-exact (SHA is handshake-path only, not bulk).

### Tooling

- `testcodes/stress.c` — benchmark + concurrency stress harness (bulk AEAD,
  handshake primitives, multi-threaded scaling).
- `testcodes/test_tcp.c` — exercises HTTP/2 and HTTP/1.1 over TLS 1.2/1.3.
