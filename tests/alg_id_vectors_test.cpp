// Frozen typed-blob vectors (pp-browser SIGNED_FORMATS § 6, "Typed blobs"): the algorithm registry with each id's
// sizes, and typed blobs of every blob kind — accepted, unknown algorithm (unassigned ids) and malformed (id 0 too). The
// file is read here and copied byte for byte into pp-browser and the relay (`crypto/alg-id.ts`), which read it alike.
// Everything in it is deterministic, so the committed file must equal what this test builds;
// PP_WRITE_ALG_ID_VECTORS=<path> writes it (only with a registry change, which is a new id, never a changed one).

#include "crypto/AlgId.h"
#include "crypto/SodiumUtil.h"

#include "common/ValueJson.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace pp {
namespace {

using common::ArrayValue;
using common::Object;
using common::ObjectValue;
using common::Value;

constexpr AlgKind kAllAlgKinds[] = {AlgKind::kSignature, AlgKind::kKem, AlgKind::kAead, AlgKind::kHash, AlgKind::kKdf};
constexpr BlobKind kAllBlobKinds[] = {
    BlobKind::kSignaturePublicKey, BlobKind::kSignatureSecretKey, BlobKind::kSignature, BlobKind::kKemPublicKey,
    BlobKind::kKemPrivateKey,      BlobKind::kKemCiphertext,      BlobKind::kAeadSealed};

std::optional<AlgKind> AlgKindOfName(const std::string& name) {
  for (const AlgKind kind : kAllAlgKinds) {
    if (AlgKindName(kind) == name) {
      return kind;
    }
  }
  return std::nullopt;
}

std::optional<BlobKind> BlobKindOfName(const std::string& name) {
  for (const BlobKind kind : kAllBlobKinds) {
    if (BlobKindName(kind) == name) {
      return kind;
    }
  }
  return std::nullopt;
}

/** The sizes that apply to the kind, by AlgInfo field name. */
std::vector<std::pair<std::string, size_t>> SizesOf(const AlgInfo& alg) {
  switch (alg.kind) {
    case AlgKind::kSignature:
      return {{"public_key_bytes", alg.public_key_bytes},
              {"secret_key_bytes", alg.secret_key_bytes},
              {"signature_bytes", alg.signature_bytes},
              {"seed_bytes", alg.seed_bytes}};
    case AlgKind::kKem:
      return {{"public_key_bytes", alg.public_key_bytes},
              {"secret_key_bytes", alg.secret_key_bytes},
              {"ciphertext_bytes", alg.ciphertext_bytes},
              {"shared_secret_bytes", alg.shared_secret_bytes},
              {"seed_bytes", alg.seed_bytes}};
    case AlgKind::kAead:
      return {{"key_bytes", alg.key_bytes}, {"nonce_bytes", alg.nonce_bytes}, {"tag_bytes", alg.tag_bytes}};
    case AlgKind::kHash:
      return {{"digest_bytes", alg.digest_bytes}};
    case AlgKind::kKdf:
      return {};
  }
  return {};
}

/** The next id of `kind`: not assigned yet. */
uint8_t NextId(const AlgKind kind) {
  uint8_t next = 1;
  while (FindAlg(kind, next) != nullptr) {
    ++next;
  }
  return next;
}

ByteVector Blob(const uint8_t id, const size_t body_bytes) {
  ByteVector out(1 + body_bytes);
  out[0] = id;
  for (size_t i = 0; i < body_bytes; ++i) {
    out[1 + i] = static_cast<uint8_t>(i);
  }
  return out;
}

Object BuildVectors() {
  std::vector<Value> registry;
  for (const AlgInfo& alg : AlgRegistry()) {
    Object row;
    row.set("kind", std::string(AlgKindName(alg.kind)));
    row.set("id", int64_t{alg.id});
    row.set("name", std::string(alg.name));
    for (const auto& [field, size] : SizesOf(alg)) {
      row.set(field, static_cast<int64_t>(size));
    }
    registry.push_back(ObjectValue(std::move(row)));
  }

  std::vector<Value> unknown_ids;
  for (const AlgKind kind : kAllAlgKinds) {
    for (const uint8_t id : {kAlgIdInvalid, NextId(kind), uint8_t{0xff}}) {
      Object row;
      row.set("kind", std::string(AlgKindName(kind)));
      row.set("id", int64_t{id});
      unknown_ids.push_back(ObjectValue(std::move(row)));
    }
  }

  std::vector<Value> blob_kinds;
  std::vector<Value> blobs;
  auto add = [&](const BlobKind kind, const ByteVector& blob, const char* result, const std::string& note) {
    Object row;
    row.set("note", note);
    row.set("blob_kind", std::string(BlobKindName(kind)));
    row.set("result", std::string(result));
    if (std::string(result) == "ok") {
      row.set("id", int64_t{blob[0]});
      row.set("body_bytes", static_cast<int64_t>(blob.size() - 1));
    }
    row.set("blob_hex", BytesToHex(blob));
    blobs.push_back(ObjectValue(std::move(row)));
  };
  for (const BlobKind kind : kAllBlobKinds) {
    Object row;
    row.set("blob_kind", std::string(BlobKindName(kind)));
    row.set("alg_kind", std::string(AlgKindName(BlobAlgKind(kind))));
    row.set("body", std::string(kind == BlobKind::kAeadSealed ? "nonce, ciphertext, tag: at least nonce + tag bytes"
                                                              : "exactly the algorithm's size"));
    blob_kinds.push_back(ObjectValue(std::move(row)));

    for (const AlgInfo& alg : AlgRegistry()) {
      if (alg.kind != BlobAlgKind(kind)) {
        continue;
      }
      const size_t size = TypedBlobBodyBytes(kind, alg);
      const std::string name(alg.name);
      const std::string sz = std::to_string(size);
      if (kind == BlobKind::kAeadSealed) {
        add(kind, Blob(alg.id, size), "ok", name + ", nonce and tag, empty plaintext (" + sz + " bytes)");
        add(kind, Blob(alg.id, size + 5), "ok", name + ", a 5-byte plaintext");
        add(kind, Blob(alg.id, size - 1), "malformed", name + ", one byte under nonce and tag");
      } else {
        add(kind, Blob(alg.id, size), "ok", name + ", " + sz + " bytes");
        add(kind, Blob(alg.id, size - 1), "malformed", name + ", one byte short");
        add(kind, Blob(alg.id, size + 1), "malformed", name + ", one byte long");
      }
    }
    add(kind, ByteVector{}, "malformed", "empty: no algorithm id");
    add(kind, Blob(kAlgIdInvalid, 3), "malformed", "id 0 is invalid");
    const uint8_t next = NextId(BlobAlgKind(kind));
    add(kind, Blob(next, 3), "unknown_algorithm",
        "id " + std::to_string(next) + ", the next of its kind, is not assigned");
    add(kind, Blob(0xff, 0), "unknown_algorithm", "id 255, no body: the id is read before the size");
  }
  // An unknown id is unknown even with a body of a known algorithm's size.
  add(BlobKind::kSignaturePublicKey,
      Blob(NextId(AlgKind::kSignature), TypedBlobBodyBytes(BlobKind::kSignaturePublicKey, AlgRegistry()[0])),
      "unknown_algorithm", "an unassigned id with ml-dsa-65's size: the size does not make it known");

  Object root;
  root.set("format", std::string("pp-cpp-crypto alg-id vectors v1"));
  root.set("about",
           std::string("SIGNED_FORMATS 1.3: ids count per kind, 0 is invalid; typed blob = u8 id || body. "
                       "result: ok | unknown_algorithm (update needed) | malformed. Body bytes are i mod 256."));
  std::vector<Value> kinds;
  for (const AlgKind kind : kAllAlgKinds) {
    kinds.emplace_back(std::string(AlgKindName(kind)));
  }
  root.set("alg_kinds", ArrayValue(std::move(kinds)));
  root.set("registry", ArrayValue(std::move(registry)));
  root.set("unknown_ids", ArrayValue(std::move(unknown_ids)));
  root.set("blob_kinds", ArrayValue(std::move(blob_kinds)));
  root.set("blobs", ArrayValue(std::move(blobs)));
  return root;
}

std::string VectorsText() {
  return common::DumpJson(BuildVectors(), 2) + "\n";
}

std::string ReadFile(const char* path) {
  std::ifstream file(path, std::ios::binary);
  std::stringstream text;
  text << file.rdbuf();
  return text.str();
}

TEST(AlgIdVectorsTest, TheCommittedFileIsTheRegistry) {
  if (const char* out = std::getenv("PP_WRITE_ALG_ID_VECTORS"); out && *out) {
    std::ofstream file(out, std::ios::binary);
    file << VectorsText();
    ASSERT_TRUE(file.good()) << out;
    GTEST_SKIP() << "wrote " << out;
  }
  const std::string text = ReadFile(PP_ALG_ID_VECTORS_PATH);
  ASSERT_FALSE(text.empty()) << PP_ALG_ID_VECTORS_PATH;
  EXPECT_EQ(text, VectorsText()) << "the registry or the typed-blob rules changed; ids are frozen";
}

TEST(AlgIdVectorsTest, TheCommittedRegistryRowsAreKnown) {
  auto root = common::TryParseObject(ReadFile(PP_ALG_ID_VECTORS_PATH));
  ASSERT_TRUE(root);
  const common::Array* registry = root->getArray("registry");
  ASSERT_NE(registry, nullptr);
  ASSERT_EQ(registry->elements.size(), AlgRegistry().size());
  for (const Value& item : registry->elements) {
    const Object* row = common::asObject(item);
    ASSERT_NE(row, nullptr);
    const auto kind = AlgKindOfName(row->getString("kind").value_or(""));
    ASSERT_TRUE(kind);
    const AlgInfo* alg = FindAlg(*kind, static_cast<uint8_t>(row->getNonNegInt("id").value_or(0)));
    ASSERT_NE(alg, nullptr);
    EXPECT_EQ(alg->name, row->getString("name").value_or(""));
    for (const auto& [field, size] : SizesOf(*alg)) {
      EXPECT_EQ(row->getNonNegInt(field), std::optional<uint64_t>(size)) << alg->name << " " << field;
    }
  }
  const common::Array* unknown = root->getArray("unknown_ids");
  ASSERT_NE(unknown, nullptr);
  ASSERT_EQ(unknown->elements.size(), 3 * std::size(kAllAlgKinds));
  for (const Value& item : unknown->elements) {
    const Object* row = common::asObject(item);
    ASSERT_NE(row, nullptr);
    const auto kind = AlgKindOfName(row->getString("kind").value_or(""));
    ASSERT_TRUE(kind);
    const auto id = row->getNonNegInt("id");
    ASSERT_TRUE(id);
    EXPECT_EQ(FindAlg(*kind, static_cast<uint8_t>(*id)), nullptr) << AlgKindName(*kind) << " " << *id;
  }
}

TEST(AlgIdVectorsTest, TheCommittedBlobsDecodeAsStated) {
  auto root = common::TryParseObject(ReadFile(PP_ALG_ID_VECTORS_PATH));
  ASSERT_TRUE(root);
  const common::Array* blobs = root->getArray("blobs");
  ASSERT_NE(blobs, nullptr);
  size_t ok = 0, unknown = 0, malformed = 0;
  for (const Value& item : blobs->elements) {
    const Object* row = common::asObject(item);
    ASSERT_NE(row, nullptr);
    const std::string note = row->getString("note").value_or("");
    const auto kind = BlobKindOfName(row->getString("blob_kind").value_or(""));
    ASSERT_TRUE(kind) << note;
    const auto bytes = HexToBytes(row->getString("blob_hex").value_or("x"));
    ASSERT_TRUE(static_cast<bool>(bytes)) << note;
    const std::string result = row->getString("result").value_or("");
    auto decoded = DecodeTypedBlob(*kind, *bytes);
    if (result == "ok") {
      ++ok;
      ASSERT_TRUE(static_cast<bool>(decoded)) << note << ": " << decoded.error().message;
      EXPECT_EQ(decoded->alg->id, row->getNonNegInt("id").value_or(0)) << note;
      EXPECT_EQ(decoded->body.size(), row->getNonNegInt("body_bytes").value_or(0)) << note;
      EXPECT_EQ(*EncodeTypedBlob(*kind, decoded->alg->id, decoded->body), *bytes) << note;
    } else if (result == "unknown_algorithm") {
      ++unknown;
      ASSERT_FALSE(static_cast<bool>(decoded)) << note;
      EXPECT_TRUE(IsUnknownAlgorithm(decoded.error())) << note << ": " << decoded.error().message;
    } else {
      ASSERT_EQ(result, "malformed") << note;
      ++malformed;
      ASSERT_FALSE(static_cast<bool>(decoded)) << note;
      EXPECT_TRUE(IsMalformedTypedBlob(decoded.error())) << note << ": " << decoded.error().message;
    }
  }
  // Every blob kind: accepted, refused as unknown (unassigned, 255) and malformed (empty, id 0, wrong sizes).
  EXPECT_EQ(ok, std::size(kAllBlobKinds) + 1);
  EXPECT_EQ(unknown, 2 * std::size(kAllBlobKinds) + 1);
  EXPECT_EQ(malformed, 4 * std::size(kAllBlobKinds) - 1);
}

} // namespace
} // namespace pp
