# BoringSSL (vendored)

Upstream: [google/boringssl](https://github.com/google/boringssl) tag **0.20261105.0** (commit in `UPSTREAM_COMMIT`).

A lean tree: the files `gen/sources.json` lists for the library targets (`bcm`, `crypto`, `ssl`, `decrepit`,
`pki`, `bssl`), plus `include/`, `cmake/` and the top-level `CMakeLists.txt`. Tests, fuzzers, Rust bindings and
test vectors are left upstream, so the tree only configures with `BUILD_TESTING` off — `pp_crypto_add_boringssl()`
in the top-level `CMakeLists.txt` sets that for this directory alone.

pp-cpp-crypto uses it for `pp::XChaCha20Poly1305`: the fused ChaCha20-Poly1305 assembly seals about 2.6× faster
than libsodium on x86-64. Consumers also get the `crypto` and `ssl` targets for TLS (pp-browser's curl).

Windows x86 needs NASM for the assembly; without it the build falls back to `OPENSSL_NO_ASM` (portable C) and says
so. One source edit, made by the import: `set(INSTALL_ENABLED 1)` becomes a default the caller may override, and
`pp_crypto_add_boringssl()` sets it to 0 — the libraries are linked statically, so nothing of BoringSSL belongs in a
consumer's install (and its rule for the `bssl` tool fails on iOS). Re-import with
`scripts/vendor_import.sh boringssl` when bumping.
