# pp-cpp-crypto

Shared C++ crypto for People Post apps (`namespace pp`).

## Contents

- Vendored **libsodium** (CMake target `sodium`), built with its SIMD implementations (picked by the CPU at run time)
- Vendored lean **BoringSSL** (CMake targets `crypto` / `ssl`, headers in `PP_CRYPTO_BORINGSSL_INCLUDE_DIR`): the AEAD
  engine, and TLS for consumers that want it. Windows x86 builds need NASM for its assembly
- Lean **mlkem-native** (ML-KEM-768) and **mldsa-native** (ML-DSA-65) — CMake targets `mlkem_native` / `mldsa_native`
- Thin C++ wrappers: `pp::MlDsa`, `pp::MlKem`, `pp::XChaCha20Poly1305` (AEAD over BoringSSL, libsodium-compatible bytes; `SealInto` / `OpenInto` for
  allocation-free packets), `pp::EnsureSodiumInit`, hex / base64 /
  base64url helpers, `pp::Blake2b256`
- `pp::HmacSha256`: HMAC-SHA256 under one key with its pads hashed once (BoringSSL; libsodium-compatible tags)
- `pp::ReplayWindow`: replay protection for out-of-order sequence numbers
- `pp::PeerIdFromMlDsaPublicKey`: the mesh PeerId of an ML-DSA-65 key (byte layout and golden vectors in `crypto/PeerId.h`)
- `crypto/AlgId.h`: the algorithm registry (ids per kind: signature `ml-dsa-65` 1, KEM `ml-kem-768` 1, AEAD
  `xchacha20-poly1305` 1, hash `blake2b-256` 1 / `sha2-256` 2, KDF `hkdf-sha256` 1; 0 is invalid) with each id's sizes, and
  typed blobs (`u8 id ‖ body`: `EncodeTypedBlob` / `DecodeTypedBlob`, an unknown id told apart from a malformed blob)

## Frozen vectors

Read by the tests; other implementations copy them byte for byte.

- `tests/data/alg_id_vectors.json`: the registry and typed blobs of every kind (accepted, unknown id, malformed), read
  by pp-browser and the relay. Deterministic: the test rebuilds it and compares; `PP_WRITE_ALG_ID_VECTORS=<path>`
  writes it (a new id only — ids never change).
- `tests/data/seeded_keygen_vectors.json`: seeded ML-DSA-65 / ML-KEM-768 keygen goldens (key hashes and PeerIds from
  fixed seeds, a frozen signature that must verify, a frozen ciphertext that must decapsulate). They guard identity
  recovery across library updates; a key row never changes. `PP_WRITE_SEEDED_KEYGEN_VECTORS=<path>` writes a fresh
  file (new signature and ciphertext, the same keys) for a new row.

Public headers live under `include/crypto/`.

Product wire formats (e.g. `account:` IDs, `key_init` base64) stay in consuming apps.

## Build

```bash
cmake -S . -B build -DPP_CRYPTO_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

CI builds and tests on Ubuntu 24.04, Windows 2022, and macOS 14 for every PR to `main`.

## Consume (FetchContent)

Pin a **release tag cut from `main`** (do not track floating branch tips such as `main`):

```cmake
include(FetchContent)
FetchContent_Declare(
  pp_cpp_crypto
  GIT_REPOSITORY https://github.com/people-post/pp-cpp-crypto.git
  GIT_TAG v1.0.0
)
FetchContent_MakeAvailable(pp_cpp_crypto)
target_link_libraries(your_target PUBLIC pp_crypto)
# C APIs / targets also available: sodium, mldsa_native, mlkem_native
```

For a local sibling checkout (e.g. `../pp-cpp-crypto`), pass `-DPP_CPP_CRYPTO_SOURCE_DIR=...` from the consumer.

Release flow: land on `main` (the only branch; there is no `develop`) → tag `vX.Y.Z` on `main`.

## Re-import vendors

```bash
./scripts/vendor_import.sh
```

## Formatting

Every first-party C/C++ source is formatted with [`.clang-format`](.clang-format) by exactly clang-format 23.1.5 (`pip install clang-format==23.1.5`; other versions format differently). Run `./scripts/check_format.sh --fix` before committing; CI fails on an unformatted file. Vendored code is left as it came.
