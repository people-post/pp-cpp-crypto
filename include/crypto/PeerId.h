#pragma once

#include "crypto/Types.h"

#include "common/Error.h"

#include <string>

namespace pp {

/**
 * The mesh PeerId of an ML-DSA-65 public key (1952 bytes) — the one derivation for pp-cpp-amp's links,
 * pp-browser and pp-ledger. libp2p's shape, frozen: PeerIds are on the wire and stored everywhere, so
 * any change renames every node.
 *
 * 1. The key in libp2p's `PublicKey { KeyType Type = 1; bytes Data = 2; }`, encoded by hand:
 *      08 04        field 1 (varint): key type 4 — ML-DSA-65 (our assignment; libp2p defines 0–3)
 *      12 A0 0F     field 2 (bytes): length 1952 as a varint
 *      <1952 bytes> the key                                          (1957 bytes in all)
 * 2. Multihash: an encoding over 42 bytes is hashed (libp2p inlines shorter ones):
 *      12 20 ‖ SHA-256(encoding)                                     (34 bytes)
 * 3. Base58btc of the multihash, no multibase prefix — `Qm…` for every ML-DSA key.
 *
 * Golden: 1952 × 0x42 → QmTWkSQAcGsETogTFKrPJ3GzdHG3vP9UwXVyp2HeK9YBvP;
 *         1952 × 0x01 → QmeKYz9h9AozszFqAkRzwxx4xGheEMYRVrLHuh7EMG7Bie.
 */
Roe<std::string> PeerIdFromMlDsaPublicKey(const ByteVector& public_key);

} // namespace pp
