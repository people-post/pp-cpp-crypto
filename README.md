# pp-cpp-crypto

Shared C++ crypto for People Post apps (`namespace pp`).

## Contents

- Vendored **libsodium** (CMake target `sodium`)
- Lean **mlkem-native** (ML-KEM-768) and **mldsa-native** (ML-DSA-65) — CMake targets `mlkem_native` / `mldsa_native`
- Thin C++ wrappers: `pp::MlDsa`, `pp::MlKem`, `pp::EnsureSodiumInit`, hex/base64 helpers

Public headers live under `include/crypto/`.

Product wire formats (e.g. `account:` IDs, `key_init` base64) stay in consuming apps.

## Build

```bash
cmake -S . -B build -DPP_CRYPTO_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

CI builds and tests on Ubuntu 24.04, Windows 2022, and macOS 14 for every PR to `develop` / `main`.

## Consume (FetchContent)

Pin a **release tag cut from `main`** (do not track `develop` or floating branch tips):

```cmake
include(FetchContent)
FetchContent_Declare(
  pp_cpp_crypto
  GIT_REPOSITORY https://github.com/people-post/pp-cpp-crypto.git
  GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(pp_cpp_crypto)
target_link_libraries(your_target PUBLIC pp_crypto)
# C APIs / targets also available: sodium, mldsa_native, mlkem_native
```

For a local sibling checkout (e.g. `../pp-cpp-crypto`), pass `-DPP_CPP_CRYPTO_SOURCE_DIR=...` from the consumer.

Release flow: land on `develop` → merge to `main` → tag `vX.Y.Z` on `main`.

## Re-import vendors

```bash
./scripts/vendor_import.sh
```
