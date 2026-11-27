#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace pp {

/**
 * The algorithm registry: one byte names an algorithm, counted per kind (pp-browser SIGNED_FORMATS § 1.3, RC020).
 * A field always holds one kind, so the same id means different algorithms in different kinds; `1` is the value
 * every field already carries. `0` is invalid in every kind. Names are the strings written wherever a name is.
 *
 *   kind       id  name                 sizes (bytes)
 *   signature   1  ml-dsa-65            public key 1952, secret key 4032, signature 3309, seed 32
 *   kem         1  ml-kem-768           public key 1184, private key 2400, ciphertext 1088, shared secret 32, coins 64
 *   aead        1  xchacha20-poly1305   key 32, nonce 24, tag 16
 *   hash        1  blake2b-256          digest 32
 *   hash        2  sha2-256             digest 32
 *   kdf         1  hkdf-sha256          (output length chosen by the caller)
 *
 * Ids are frozen: an id is never reused for another algorithm, and a new algorithm takes the next id of its kind.
 * The registry is pinned by pp-specs' vectors/alg_id_vectors.json (read by every implementation at its pinned tag).
 */
enum class AlgKind : uint8_t {
  kSignature = 1,
  kKem = 2,
  kAead = 3,
  kHash = 4,
  kKdf = 5,
};

/** Invalid in every kind: a typed blob with id 0 is malformed (no writer makes one), not an unknown algorithm. */
inline constexpr uint8_t kAlgIdInvalid = 0;

inline constexpr uint8_t kSignatureAlgMlDsa65 = 1;
inline constexpr uint8_t kKemAlgMlKem768 = 1;
inline constexpr uint8_t kAeadAlgXChaCha20Poly1305 = 1;
inline constexpr uint8_t kHashAlgBlake2b256 = 1;
inline constexpr uint8_t kHashAlgSha2_256 = 2;
inline constexpr uint8_t kKdfAlgHkdfSha256 = 1;

/** One registry entry. A size that does not apply to the kind is 0. */
struct AlgInfo {
  AlgKind kind;
  uint8_t id;
  std::string_view name;
  size_t public_key_bytes = 0;    // signature, kem
  size_t secret_key_bytes = 0;    // signature (secret key), kem (private key)
  size_t signature_bytes = 0;     // signature
  size_t seed_bytes = 0;          // signature: keygen seed; kem: keygen coins
  size_t ciphertext_bytes = 0;    // kem
  size_t shared_secret_bytes = 0; // kem
  size_t key_bytes = 0;           // aead
  size_t nonce_bytes = 0;         // aead
  size_t tag_bytes = 0;           // aead
  size_t digest_bytes = 0;        // hash
};

/** "signature", "kem", "aead", "hash", "kdf". */
std::string_view AlgKindName(AlgKind kind);

/** Every entry, ordered by kind, then id. */
std::span<const AlgInfo> AlgRegistry();

/** The entry for `id` in `kind`; nullptr for 0 or an id this build does not know. */
const AlgInfo* FindAlg(AlgKind kind, uint8_t id);

/** The entry named `name` in `kind`; nullptr when none. */
const AlgInfo* FindAlgByName(AlgKind kind, std::string_view name);

/**
 * Typed blobs: every key, signature, KEM ciphertext and AEAD blob starts with its algorithm id (one byte), then the
 * algorithm's bytes:
 *
 *   typed blob = u8 alg id ‖ body
 *
 *   blob kind              alg kind    body
 *   signature-public-key   signature   public key            (ml-dsa-65: 1952, blob 1953)
 *   signature-secret-key   signature   secret key            (ml-dsa-65: 4032, blob 4033)
 *   signature              signature   signature             (ml-dsa-65: 3309, blob 3310)
 *   kem-public-key         kem         public key            (ml-kem-768: 1184, blob 1185)
 *   kem-private-key        kem         private key           (ml-kem-768: 2400, blob 2401)
 *   kem-ciphertext         kem         ciphertext            (ml-kem-768: 1088, blob 1089)
 *   aead-sealed            aead        nonce ‖ ciphertext ‖ tag, at least nonce + tag   (xchacha20-poly1305: ≥ 40)
 *
 * The AEAD blob is the payload blob and `FileCipher` output unchanged (their first byte was already 1). Hashes and
 * KDFs are never written into blobs: an object's version fixes them. Identities (Account IDs, PeerIds, locker ids)
 * hash the raw key, never the typed blob. In signed bytes a typed blob is `LenBytes(typed blob)`; that framing is the
 * caller's.
 */
enum class BlobKind : uint8_t {
  kSignaturePublicKey = 1,
  kSignatureSecretKey = 2,
  kSignature = 3,
  kKemPublicKey = 4,
  kKemPrivateKey = 5,
  kKemCiphertext = 6,
  kAeadSealed = 7,
};

/** "signature-public-key", "signature-secret-key", "signature", "kem-public-key", … as in the table above. */
std::string_view BlobKindName(BlobKind kind);

/** The algorithm kind whose ids a blob kind carries. */
AlgKind BlobAlgKind(BlobKind kind);

/**
 * Body size for `kind` under `alg` (the minimum for `kAeadSealed`, whose body grows with the plaintext); 0 when
 * `alg` is not of the blob kind's algorithm kind.
 */
size_t TypedBlobBodyBytes(BlobKind kind, const AlgInfo& alg);

/**
 * Error codes of a typed-blob decode, in `Error::code` with `Error::category == kAlgIdErrorCategory`. The split is the
 * receiver's (SIGNED_FORMATS § 1.1): an unknown algorithm is "update needed" (step 3), anything else malformed
 * (step 2) — never a forgery.
 */
inline constexpr int32_t kAlgIdErrorCategory = 0x616c67; // "alg"
enum class TypedBlobError : int32_t {
  /** Empty, id 0 (invalid), or a known id with the wrong body size. */
  kMalformed = 1,
  /** A nonzero id this build does not know for the blob's kind: the caller reports "update needed". */
  kUnknownAlgorithm = 2,
};

/** True when `error` is a typed blob's unknown algorithm (→ "update needed"). */
bool IsUnknownAlgorithm(const Error& error);
/** True when `error` is a typed blob's malformed error. */
bool IsMalformedTypedBlob(const Error& error);

struct TypedBlob {
  /** The registry entry of the blob's id (never null on success). */
  const AlgInfo* alg = nullptr;
  ByteVector body;
};

/**
 * `id ‖ body`. `kMalformed` for id 0; `kUnknownAlgorithm` when a nonzero `id` is not in the registry for the blob
 * kind's algorithm kind; `kMalformed` when `body` is not the algorithm's size (shorter than nonce + tag for
 * `kAeadSealed`).
 */
Roe<ByteVector> EncodeTypedBlob(BlobKind kind, uint8_t id, std::span<const uint8_t> body);

/**
 * Read a typed blob of `kind`. Checked in order: empty → `kMalformed`; id 0 → `kMalformed` (invalid, like ExtArea's
 * type 0x0000); a nonzero id not known for the kind → `kUnknownAlgorithm`, whatever follows (a later algorithm's sizes
 * are unknown here); a known id with a body of the wrong size → `kMalformed`.
 */
Roe<TypedBlob> DecodeTypedBlob(BlobKind kind, std::span<const uint8_t> blob);

} // namespace pp
