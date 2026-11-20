#include "crypto/AlgId.h"

#include "crypto/Aead.h"
#include "crypto/MlDsa.h"
#include "crypto/MlKem.h"

#include <algorithm>
#include <array>
#include <string>

namespace pp {
namespace {

constexpr size_t kBlake2b256DigestBytes = 32;
constexpr size_t kSha2_256DigestBytes = 32;

constexpr std::array<AlgInfo, 6> kRegistry = {{
    {.kind = AlgKind::kSignature,
     .id = kSignatureAlgMlDsa65,
     .name = "ml-dsa-65",
     .public_key_bytes = kMlDsa65PublicKeyBytes,
     .secret_key_bytes = kMlDsa65SecretKeyBytes,
     .signature_bytes = kMlDsa65SignatureBytes,
     .seed_bytes = kMlDsa65SeedBytes},
    {.kind = AlgKind::kKem,
     .id = kKemAlgMlKem768,
     .name = "ml-kem-768",
     .public_key_bytes = kMlKem768PublicKeyBytes,
     .secret_key_bytes = kMlKem768PrivateKeyBytes,
     .seed_bytes = kMlKem768KeygenCoinsBytes,
     .ciphertext_bytes = kMlKem768CiphertextBytes,
     .shared_secret_bytes = kMlKem768SharedSecretBytes},
    {.kind = AlgKind::kAead,
     .id = kAeadAlgXChaCha20Poly1305,
     .name = "xchacha20-poly1305",
     .key_bytes = XChaCha20Poly1305::kKeyBytes,
     .nonce_bytes = XChaCha20Poly1305::kNonceBytes,
     .tag_bytes = XChaCha20Poly1305::kTagBytes},
    {.kind = AlgKind::kHash, .id = kHashAlgBlake2b256, .name = "blake2b-256", .digest_bytes = kBlake2b256DigestBytes},
    {.kind = AlgKind::kHash, .id = kHashAlgSha2_256, .name = "sha2-256", .digest_bytes = kSha2_256DigestBytes},
    {.kind = AlgKind::kKdf, .id = kKdfAlgHkdfSha256, .name = "hkdf-sha256"},
}};

Error AlgError(TypedBlobError code, std::string message) {
  return Error::Make(kAlgIdErrorCategory, static_cast<int32_t>(code), message);
}

Error InvalidId(BlobKind kind) {
  return AlgError(TypedBlobError::kMalformed, std::string(BlobKindName(kind)) + ": algorithm id 0 is invalid");
}

Error UnknownAlgorithm(BlobKind kind, uint8_t id) {
  return AlgError(TypedBlobError::kUnknownAlgorithm, std::string(BlobKindName(kind)) + ": unknown " +
                                                         std::string(AlgKindName(BlobAlgKind(kind))) +
                                                         " algorithm id " + std::to_string(id));
}

Roe<void> CheckBodySize(BlobKind kind, const AlgInfo& alg, size_t size) {
  const size_t want = TypedBlobBodyBytes(kind, alg);
  const bool ok = kind == BlobKind::kAeadSealed ? size >= want : size == want;
  if (!ok) {
    return AlgError(TypedBlobError::kMalformed, std::string(BlobKindName(kind)) + " (" + std::string(alg.name) +
                                                    "): body is " + std::to_string(size) + " bytes, want " +
                                                    (kind == BlobKind::kAeadSealed ? "at least " : "") +
                                                    std::to_string(want));
  }
  return {};
}

} // namespace

std::string_view AlgKindName(const AlgKind kind) {
  switch (kind) {
    case AlgKind::kSignature:
      return "signature";
    case AlgKind::kKem:
      return "kem";
    case AlgKind::kAead:
      return "aead";
    case AlgKind::kHash:
      return "hash";
    case AlgKind::kKdf:
      return "kdf";
  }
  return "unknown";
}

std::span<const AlgInfo> AlgRegistry() {
  return kRegistry;
}

const AlgInfo* FindAlg(const AlgKind kind, const uint8_t id) {
  for (const AlgInfo& alg : kRegistry) {
    if (alg.kind == kind && alg.id == id && id != kAlgIdInvalid) {
      return &alg;
    }
  }
  return nullptr;
}

const AlgInfo* FindAlgByName(const AlgKind kind, const std::string_view name) {
  for (const AlgInfo& alg : kRegistry) {
    if (alg.kind == kind && alg.name == name) {
      return &alg;
    }
  }
  return nullptr;
}

std::string_view BlobKindName(const BlobKind kind) {
  switch (kind) {
    case BlobKind::kSignaturePublicKey:
      return "signature-public-key";
    case BlobKind::kSignatureSecretKey:
      return "signature-secret-key";
    case BlobKind::kSignature:
      return "signature";
    case BlobKind::kKemPublicKey:
      return "kem-public-key";
    case BlobKind::kKemPrivateKey:
      return "kem-private-key";
    case BlobKind::kKemCiphertext:
      return "kem-ciphertext";
    case BlobKind::kAeadSealed:
      return "aead-sealed";
  }
  return "unknown";
}

AlgKind BlobAlgKind(const BlobKind kind) {
  switch (kind) {
    case BlobKind::kSignaturePublicKey:
    case BlobKind::kSignatureSecretKey:
    case BlobKind::kSignature:
      return AlgKind::kSignature;
    case BlobKind::kKemPublicKey:
    case BlobKind::kKemPrivateKey:
    case BlobKind::kKemCiphertext:
      return AlgKind::kKem;
    case BlobKind::kAeadSealed:
      return AlgKind::kAead;
  }
  return AlgKind::kSignature;
}

size_t TypedBlobBodyBytes(const BlobKind kind, const AlgInfo& alg) {
  if (alg.kind != BlobAlgKind(kind)) {
    return 0;
  }
  switch (kind) {
    case BlobKind::kSignaturePublicKey:
    case BlobKind::kKemPublicKey:
      return alg.public_key_bytes;
    case BlobKind::kSignatureSecretKey:
    case BlobKind::kKemPrivateKey:
      return alg.secret_key_bytes;
    case BlobKind::kSignature:
      return alg.signature_bytes;
    case BlobKind::kKemCiphertext:
      return alg.ciphertext_bytes;
    case BlobKind::kAeadSealed:
      return alg.nonce_bytes + alg.tag_bytes;
  }
  return 0;
}

bool IsUnknownAlgorithm(const Error& error) {
  return error.category == kAlgIdErrorCategory && error.code == static_cast<int32_t>(TypedBlobError::kUnknownAlgorithm);
}

bool IsMalformedTypedBlob(const Error& error) {
  return error.category == kAlgIdErrorCategory && error.code == static_cast<int32_t>(TypedBlobError::kMalformed);
}

Roe<ByteVector> EncodeTypedBlob(const BlobKind kind, const uint8_t id, const std::span<const uint8_t> body) {
  if (id == kAlgIdInvalid) {
    return InvalidId(kind);
  }
  const AlgInfo* alg = FindAlg(BlobAlgKind(kind), id);
  if (alg == nullptr) {
    return UnknownAlgorithm(kind, id);
  }
  if (auto size = CheckBodySize(kind, *alg, body.size()); !size) {
    return size.error();
  }
  ByteVector out(1 + body.size());
  out[0] = id;
  std::copy(body.begin(), body.end(), out.begin() + 1);
  return out;
}

Roe<TypedBlob> DecodeTypedBlob(const BlobKind kind, const std::span<const uint8_t> blob) {
  if (blob.empty()) {
    return AlgError(TypedBlobError::kMalformed, std::string(BlobKindName(kind)) + ": empty, no algorithm id");
  }
  if (blob[0] == kAlgIdInvalid) {
    return InvalidId(kind);
  }
  const AlgInfo* alg = FindAlg(BlobAlgKind(kind), blob[0]);
  if (alg == nullptr) {
    return UnknownAlgorithm(kind, blob[0]);
  }
  if (auto size = CheckBodySize(kind, *alg, blob.size() - 1); !size) {
    return size.error();
  }
  TypedBlob out;
  out.alg = alg;
  out.body.assign(blob.begin() + 1, blob.end());
  return out;
}

} // namespace pp
