// Seeded-keygen goldens (pp-browser INVENTORY F3, SIGNED_FORMATS § 6 "Seeded keygen"): fixed seeds give fixed keys.
// pp-browser derives its account, device and locker keys from seeds (the recovery phrase, PP_NODE_IDENTITY_SEED) and
// the relay its operator, transport and signing keys, so a library update that changed seeded keygen would silently
// re-key every recovered identity: a new Account ID and PeerId for the same phrase. Frozen here, in
// pp-specs' vectors/seeded_keygen_vectors.json:
//
//  - ML-DSA-65 and ML-KEM-768 keys from fixed seeds: SHA-256 of the public key and of the secret key, and the PeerId;
//  - a frozen ML-DSA-65 signature (signing is hedged, so it is frozen whole) that must verify under its seeded key;
//  - a frozen ML-KEM-768 ciphertext that must decapsulate, under its seeded key, to the frozen shared secret.
//
// The seeds are fixed test seeds (the HKDF from a phrase to them is pp-browser's): operators 0x01…, 0x02…, 0x03… as
// relay_certificate_vectors.json; relays a and b 0x07…, 0x08…, account 0x09… (KEM 0x0a…) and device 0x0b… (KEM
// 0x0c…) as pp-browser's relay_sign_vectors.json; locker 0x0d… and the relay's signing key 0x0e… (new); and one
// counting seed (00 01 02 …) per algorithm, which a byte-order change would move.
//
// The key rows must never change. PP_WRITE_SEEDED_KEYGEN_VECTORS=<path> writes a fresh file (a new signature and
// ciphertext, the same keys): only for a new row, never to make a changed key pass.

#include "crypto/MlDsa.h"
#include "crypto/MlKem.h"
#include "crypto/PeerId.h"
#include "crypto/SodiumUtil.h"

#include "common/ValueJson.h"

#include <sodium.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace pp {
namespace {

using common::ArrayValue;
using common::Object;
using common::ObjectValue;
using common::Value;

constexpr uint8_t kCounting = 0xff; // not a fill: the seed 00 01 02 …

struct Role {
  const char* role;
  uint8_t fill;
};

constexpr Role kMlDsaRoles[] = {
    {"operator-1", 0x01},        {"operator-2", 0x02},    {"operator-3", 0x03}, {"relay-a-transport", 0x07},
    {"relay-b-transport", 0x08}, {"account", 0x09},       {"device", 0x0b},     {"locker", 0x0d},
    {"relay-signing", 0x0e},     {"counting", kCounting},
};
constexpr Role kMlKemRoles[] = {{"account-kem", 0x0a}, {"device-kem", 0x0c}, {"counting", kCounting}};

constexpr char kSignatureRole[] = "account";
constexpr char kSignedMessage[] = "pp-cpp-crypto F3: a frozen ML-DSA-65 signature";
constexpr char kDecapsulationRole[] = "account-kem";

ByteVector Seed(const uint8_t fill, const size_t size) {
  ByteVector seed(size, fill);
  if (fill == kCounting) {
    for (size_t i = 0; i < size; ++i) {
      seed[i] = static_cast<uint8_t>(i);
    }
  }
  return seed;
}

std::string Sha256Hex(const ByteVector& data) {
  EnsureSodiumInit();
  ByteVector digest(crypto_hash_sha256_BYTES);
  crypto_hash_sha256(digest.data(), data.data(), data.size());
  return BytesToHex(digest);
}

uint8_t FillOf(const Role* begin, const Role* end, const std::string& role) {
  for (const Role* r = begin; r != end; ++r) {
    if (role == r->role) {
      return r->fill;
    }
  }
  ADD_FAILURE() << "no role " << role;
  return 0;
}

MlDsaKeyPair MlDsaKeysOf(const std::string& role) {
  return MlDsa::GenerateKeyPairFromSeed(
             Seed(FillOf(std::begin(kMlDsaRoles), std::end(kMlDsaRoles), role), kMlDsa65SeedBytes))
      .value();
}

MlKemKeyPair MlKemKeysOf(const std::string& role) {
  return MlKem::GenerateKeyPairFromSeed(
             Seed(FillOf(std::begin(kMlKemRoles), std::end(kMlKemRoles), role), kMlKem768KeygenCoinsBytes))
      .value();
}

/** The deterministic rows: what the seeds give. */
std::vector<Value> MlDsaRows() {
  std::vector<Value> rows;
  for (const Role& r : kMlDsaRoles) {
    const ByteVector seed = Seed(r.fill, kMlDsa65SeedBytes);
    const auto keys = MlDsa::GenerateKeyPairFromSeed(seed).value();
    Object row;
    row.set("role", std::string(r.role));
    row.set("seed_hex", BytesToHex(seed));
    row.set("public_key_sha256_hex", Sha256Hex(keys.public_key));
    row.set("secret_key_sha256_hex", Sha256Hex(keys.secret_key));
    row.set("peer_id", PeerIdFromMlDsaPublicKey(keys.public_key).value());
    rows.push_back(ObjectValue(std::move(row)));
  }
  return rows;
}

std::vector<Value> MlKemRows() {
  std::vector<Value> rows;
  for (const Role& r : kMlKemRoles) {
    const ByteVector coins = Seed(r.fill, kMlKem768KeygenCoinsBytes);
    const auto keys = MlKem::GenerateKeyPairFromSeed(coins).value();
    Object row;
    row.set("role", std::string(r.role));
    row.set("coins_hex", BytesToHex(coins));
    row.set("public_key_sha256_hex", Sha256Hex(keys.public_key));
    row.set("private_key_sha256_hex", Sha256Hex(keys.private_key));
    rows.push_back(ObjectValue(std::move(row)));
  }
  return rows;
}

Object BuildVectors() {
  const ByteVector message(kSignedMessage, kSignedMessage + sizeof(kSignedMessage) - 1);
  Object signature;
  signature.set("role", std::string(kSignatureRole));
  signature.set("message_hex", BytesToHex(message));
  signature.set("signature_hex", BytesToHex(MlDsa::Sign(MlDsaKeysOf(kSignatureRole).secret_key, message).value()));

  const auto encap = MlKem::Encapsulate(MlKemKeysOf(kDecapsulationRole).public_key).value();
  Object decapsulation;
  decapsulation.set("role", std::string(kDecapsulationRole));
  decapsulation.set("ciphertext_hex", BytesToHex(encap.ciphertext));
  decapsulation.set("shared_secret_hex", BytesToHex(encap.shared_secret));

  Object root;
  root.set("format", std::string("pp-cpp-crypto seeded keygen vectors v1"));
  root.set("about", std::string("INVENTORY F3: fixed seeds, fixed keys. ML-DSA-65 KeyGen_internal(seed), ML-KEM-768 "
                                "KeyGen_internal(coins); hashes are SHA-256 of the raw key. The signature (empty "
                                "context) and the ciphertext are frozen whole. Key rows never change."));
  root.set("ml_dsa_65", ArrayValue(MlDsaRows()));
  root.set("ml_kem_768", ArrayValue(MlKemRows()));
  root.set("ml_dsa_65_signature", ObjectValue(std::move(signature)));
  root.set("ml_kem_768_decapsulation", ObjectValue(std::move(decapsulation)));
  return root;
}

Object ReadVectors() {
  std::ifstream file(PP_SEEDED_KEYGEN_VECTORS_PATH, std::ios::binary);
  std::stringstream text;
  text << file.rdbuf();
  auto root = common::TryParseObject(text.str());
  EXPECT_TRUE(root) << PP_SEEDED_KEYGEN_VECTORS_PATH;
  return root.value_or(Object{});
}

ByteVector HexField(const Object& object, const char* field) {
  auto bytes = HexToBytes(object.getString(field).value_or("x"));
  EXPECT_TRUE(static_cast<bool>(bytes)) << field;
  return bytes ? *bytes : ByteVector{};
}

// The golden: the committed key rows are what the seeds give today (keys, secret keys, PeerIds).
TEST(SeededKeygenTest, FixedSeedsGiveTheFrozenKeys) {
  if (const char* out = std::getenv("PP_WRITE_SEEDED_KEYGEN_VECTORS"); out && *out) {
    std::ofstream file(out, std::ios::binary);
    file << common::DumpJson(BuildVectors(), 2) << "\n";
    ASSERT_TRUE(file.good()) << out;
    GTEST_SKIP() << "wrote " << out;
  }
  const Object root = ReadVectors();
  const common::Array* dsa = root.getArray("ml_dsa_65");
  const common::Array* kem = root.getArray("ml_kem_768");
  ASSERT_NE(dsa, nullptr);
  ASSERT_NE(kem, nullptr);
  const std::vector<Value> dsa_now = MlDsaRows();
  const std::vector<Value> kem_now = MlKemRows();
  ASSERT_EQ(dsa->elements.size(), dsa_now.size());
  ASSERT_EQ(kem->elements.size(), kem_now.size());
  for (size_t i = 0; i < dsa_now.size(); ++i) {
    EXPECT_EQ(common::DumpJson(dsa->elements[i]), common::DumpJson(dsa_now[i]))
        << "ML-DSA-65 seeded keygen changed: every identity recovered from its seed would be re-keyed";
  }
  for (size_t i = 0; i < kem_now.size(); ++i) {
    EXPECT_EQ(common::DumpJson(kem->elements[i]), common::DumpJson(kem_now[i]))
        << "ML-KEM-768 seeded keygen changed: every KEM key recovered from its seed would change";
  }
}

// Each row on its own, from its own seed: the hashes are the ones written.
TEST(SeededKeygenTest, EachCommittedRowRederives) {
  const Object root = ReadVectors();
  const common::Array* dsa = root.getArray("ml_dsa_65");
  ASSERT_NE(dsa, nullptr);
  for (const Value& item : dsa->elements) {
    const Object* row = common::asObject(item);
    ASSERT_NE(row, nullptr);
    auto keys = MlDsa::GenerateKeyPairFromSeed(HexField(*row, "seed_hex"));
    ASSERT_TRUE(static_cast<bool>(keys));
    EXPECT_EQ(Sha256Hex(keys->public_key), row->getString("public_key_sha256_hex").value_or(""));
    EXPECT_EQ(Sha256Hex(keys->secret_key), row->getString("secret_key_sha256_hex").value_or(""));
    EXPECT_EQ(*PeerIdFromMlDsaPublicKey(keys->public_key), row->getString("peer_id").value_or(""));
  }
  const common::Array* kem = root.getArray("ml_kem_768");
  ASSERT_NE(kem, nullptr);
  for (const Value& item : kem->elements) {
    const Object* row = common::asObject(item);
    ASSERT_NE(row, nullptr);
    auto keys = MlKem::GenerateKeyPairFromSeed(HexField(*row, "coins_hex"));
    ASSERT_TRUE(static_cast<bool>(keys));
    EXPECT_EQ(Sha256Hex(keys->public_key), row->getString("public_key_sha256_hex").value_or(""));
    EXPECT_EQ(Sha256Hex(keys->private_key), row->getString("private_key_sha256_hex").value_or(""));
  }
}

TEST(SeededKeygenTest, TheFrozenSignatureVerifies) {
  const Object root = ReadVectors();
  const Object* row = root.getObject("ml_dsa_65_signature");
  ASSERT_NE(row, nullptr);
  ASSERT_EQ(row->getString("role").value_or(""), kSignatureRole);
  const ByteVector message = HexField(*row, "message_hex");
  EXPECT_EQ(std::string(message.begin(), message.end()), kSignedMessage);
  const ByteVector signature = HexField(*row, "signature_hex");
  ASSERT_EQ(signature.size(), kMlDsa65SignatureBytes);
  const MlDsaKeyPair keys = MlDsaKeysOf(kSignatureRole);

  auto ok = MlDsa::Verify(keys.public_key, message, signature);
  ASSERT_TRUE(static_cast<bool>(ok));
  EXPECT_TRUE(*ok) << "a signature made by the seeded key no longer verifies";

  ByteVector other = message;
  other.back() ^= 0x01;
  EXPECT_FALSE(*MlDsa::Verify(keys.public_key, other, signature));
  EXPECT_FALSE(*MlDsa::Verify(MlDsaKeysOf("device").public_key, message, signature));
  // The seeded secret key still signs for its public key.
  EXPECT_TRUE(*MlDsa::Verify(keys.public_key, message, MlDsa::Sign(keys.secret_key, message).value()));
}

TEST(SeededKeygenTest, TheFrozenCiphertextDecapsulates) {
  const Object root = ReadVectors();
  const Object* row = root.getObject("ml_kem_768_decapsulation");
  ASSERT_NE(row, nullptr);
  ASSERT_EQ(row->getString("role").value_or(""), kDecapsulationRole);
  const ByteVector ciphertext = HexField(*row, "ciphertext_hex");
  ASSERT_EQ(ciphertext.size(), kMlKem768CiphertextBytes);
  const MlKemKeyPair keys = MlKemKeysOf(kDecapsulationRole);

  auto secret = MlKem::Decapsulate(keys.private_key, ciphertext);
  ASSERT_TRUE(static_cast<bool>(secret));
  EXPECT_EQ(BytesToHex(*secret), row->getString("shared_secret_hex").value_or(""))
      << "the seeded KEM key no longer opens what was sealed to it";
  // Another key's decapsulation gives another (implicit-rejection) secret.
  EXPECT_NE(BytesToHex(*MlKem::Decapsulate(MlKemKeysOf("device-kem").private_key, ciphertext)),
            row->getString("shared_secret_hex").value_or(""));
}

} // namespace
} // namespace pp
