#!/usr/bin/env bash
# Populate third_party/ from upstream git tags. Safe to re-run when bumping versions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY="${ROOT}/third_party"
TMP="${ROOT}/.vendor_import_tmp"

declare -A REPOS=(
  [libsodium]="https://github.com/jedisct1/libsodium.git|1.0.20-RELEASE"
  [mlkem-native]="https://github.com/pq-code-package/mlkem-native.git|v2.0.0"
  [mldsa-native]="https://github.com/pq-code-package/mldsa-native.git|v2.0.0"
)

DEFAULT_ORDER=(libsodium mlkem-native mldsa-native)

preserve_pp_cmake() {
  local name="$1"
  local dest="${THIRD_PARTY}/${name}"
  local backup="${TMP}/${name}_CMakeLists.txt"
  mkdir -p "${TMP}"
  if [[ -f "${dest}/CMakeLists.txt" ]]; then
    cp "${dest}/CMakeLists.txt" "${backup}"
  fi
}

restore_pp_cmake() {
  local name="$1"
  local dest="${THIRD_PARTY}/${name}"
  local backup="${TMP}/${name}_CMakeLists.txt"
  if [[ -f "${backup}" ]]; then
    cp "${backup}" "${dest}/CMakeLists.txt"
  fi
}

import_pqcp_lean() {
  local name="$1"
  local url="$2"
  local tag="$3"
  local dest="${THIRD_PARTY}/${name}"
  local clone_dir="${TMP}/${name}"
  local subdir
  if [[ "${name}" == "mlkem-native" ]]; then
    subdir="mlkem"
  else
    subdir="mldsa"
  fi

  echo "==> ${name} @ ${tag} (lean ${subdir}/)"
  preserve_pp_cmake "${name}"
  local readme_backup="${TMP}/${name}_README.pp-cpp-crypto.md"
  if [[ -f "${dest}/README.pp-cpp-crypto.md" ]]; then
    cp "${dest}/README.pp-cpp-crypto.md" "${readme_backup}"
  fi

  git clone --depth 1 --branch "${tag}" "${url}" "${clone_dir}"
  local commit
  commit="$(git -C "${clone_dir}" rev-parse HEAD)"

  rm -rf "${dest}"
  mkdir -p "${dest}"
  cp -a "${clone_dir}/${subdir}" "${dest}/${subdir}"
  cp "${clone_dir}/LICENSE" "${dest}/LICENSE"
  echo "${commit}" > "${dest}/UPSTREAM_COMMIT"
  find "${dest}" -name '.git' -exec rm -rf {} + 2>/dev/null || true
  restore_pp_cmake "${name}"
  if [[ -f "${readme_backup}" ]]; then
    cp "${readme_backup}" "${dest}/README.pp-cpp-crypto.md"
  fi

  python3 - "${dest}" "${name}" <<'PY'
import sys
from pathlib import Path
dest, name = Path(sys.argv[1]), sys.argv[2]
mlkem_rng = '''#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include <sodium.h>
#include "src/sys.h"
static MLK_INLINE int mlk_randombytes(uint8_t *ptr, size_t len)
{
  if (ptr == NULL && len != 0) {
    return -1;
  }
  if (sodium_init() < 0) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }
  randombytes_buf(ptr, len);
  return 0;
}
#endif'''
mldsa_rng = '''#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include <sodium.h>
#include "src/sys.h"
static MLD_INLINE int mld_randombytes(uint8_t *ptr, size_t len)
{
  if (ptr == NULL && len != 0) {
    return -1;
  }
  if (sodium_init() < 0) {
    return -1;
  }
  if (len == 0) {
    return 0;
  }
  randombytes_buf(ptr, len);
  return 0;
}
#endif'''
mlkem_rng_old = '''/* #define MLK_CONFIG_CUSTOM_RANDOMBYTES
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/sys.h"
   static MLK_INLINE int mlk_randombytes(uint8_t *ptr, size_t len)
   {
       ... your implementation ...
       return 0;
   }
   #endif
*/'''
mldsa_rng_old = '''/* #define MLD_CONFIG_CUSTOM_RANDOMBYTES
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "src/src.h"
   static MLD_INLINE int mld_randombytes(uint8_t *ptr, size_t len)
   {
       ... your implementation ...
       return 0;
   }
   #endif
*/'''
if name == "mlkem-native":
    p = dest / "mlkem" / "mlkem_native_config.h"
    text = p.read_text()
    text = text.replace(
        "#define MLK_CONFIG_PARAMETER_SET \\\n  768 /* Change this for different security strengths */",
        "#define MLK_CONFIG_PARAMETER_SET \\\n  768 /* pp-cpp-crypto: ML-KEM-768 */",
    )
    text = text.replace(
        "#if !defined(MLK_CONFIG_NAMESPACE_PREFIX)\n#define MLK_CONFIG_NAMESPACE_PREFIX MLK_DEFAULT_NAMESPACE_PREFIX\n#endif",
        "#if !defined(MLK_CONFIG_NAMESPACE_PREFIX)\n#define MLK_CONFIG_NAMESPACE_PREFIX mlkem\n#endif",
    )
    text = text.replace(
        "/* #define MLK_CONFIG_INTERNAL_API_QUALIFIER */",
        "#define MLK_CONFIG_INTERNAL_API_QUALIFIER static",
        1,
    )
    if mlkem_rng_old not in text:
        raise SystemExit("mlkem CUSTOM_RANDOMBYTES template not found")
    text = text.replace(mlkem_rng_old, mlkem_rng, 1)
    p.write_text(text)
else:
    p = dest / "mldsa" / "mldsa_native_config.h"
    text = p.read_text()
    text = text.replace(
        "#define MLD_CONFIG_PARAMETER_SET \\\n  44 /* Change this for different security strengths */",
        "#define MLD_CONFIG_PARAMETER_SET \\\n  65 /* pp-cpp-crypto: ML-DSA-65 */",
    )
    text = text.replace(
        "#if !defined(MLD_CONFIG_NAMESPACE_PREFIX)\n#define MLD_CONFIG_NAMESPACE_PREFIX MLD_DEFAULT_NAMESPACE_PREFIX\n#endif",
        "#if !defined(MLD_CONFIG_NAMESPACE_PREFIX)\n#define MLD_CONFIG_NAMESPACE_PREFIX mldsa\n#endif",
    )
    text = text.replace(
        "/* #define MLD_CONFIG_INTERNAL_API_QUALIFIER */",
        "#define MLD_CONFIG_INTERNAL_API_QUALIFIER static",
        1,
    )
    if mldsa_rng_old not in text:
        raise SystemExit("mldsa CUSTOM_RANDOMBYTES template not found")
    text = text.replace(mldsa_rng_old, mldsa_rng, 1)
    p.write_text(text)
print(f"patched {name} config")
PY

  python3 - "${PATCH_JSON}" "${name}" "${url}" "${tag}" "${commit}" <<'PY'
import json, sys
from pathlib import Path
path, name, url, tag, commit = sys.argv[1:6]
data = json.loads(Path(path).read_text())
data[name] = {
    "repository": url,
    "tag": tag,
    "commit": commit,
    "notes": f"Vendored lean tree; see README.pp-cpp-crypto.md",
}
Path(path).write_text(json.dumps(data))
PY
}

mkdir -p "${THIRD_PARTY}"
rm -rf "${TMP}"
mkdir -p "${TMP}"

PATCH_JSON="${TMP}/upstream_patch.json"
echo "{}" > "${PATCH_JSON}"

if [[ $# -gt 0 ]]; then
  ORDER=("$@")
else
  ORDER=("${DEFAULT_ORDER[@]}")
fi

for name in "${ORDER[@]}"; do
  if [[ -z "${REPOS[$name]+x}" ]]; then
    echo "error: unknown vendored dependency '${name}'" >&2
    exit 1
  fi
  IFS='|' read -r url tag <<< "${REPOS[$name]}"

  if [[ "${name}" == "mlkem-native" || "${name}" == "mldsa-native" ]]; then
    import_pqcp_lean "${name}" "${url}" "${tag}"
    continue
  fi

  dest="${THIRD_PARTY}/${name}"
  clone_dir="${TMP}/${name}"
  echo "==> ${name} @ ${tag}"
  preserve_pp_cmake "${name}"
  git clone --depth 1 --branch "${tag}" "${url}" "${clone_dir}"
  commit="$(git -C "${clone_dir}" rev-parse HEAD)"
  rm -rf "${dest}"
  mkdir -p "${dest}"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude='.git' "${clone_dir}/" "${dest}/"
  else
    cp -a "${clone_dir}/." "${dest}/"
    find "${dest}" -name '.git' -exec rm -rf {} + 2>/dev/null || true
  fi
  find "${dest}" -name '.git' -exec rm -rf {} + 2>/dev/null || true
  restore_pp_cmake "${name}"
  if [[ "${name}" == "libsodium" ]]; then
    python3 "${ROOT}/scripts/generate_libsodium_cmake.py" "${dest}"
  fi
  python3 - "${PATCH_JSON}" "${name}" "${url}" "${tag}" "${commit}" <<'PY'
import json, sys
from pathlib import Path
path, name, url, tag, commit = sys.argv[1:6]
data = json.loads(Path(path).read_text())
data[name] = {"repository": url, "tag": tag, "commit": commit}
Path(path).write_text(json.dumps(data))
PY
done

UPSTREAM="${THIRD_PARTY}/UPSTREAM.json"
python3 - "${UPSTREAM}" "${PATCH_JSON}" <<'PY'
import json, sys
from pathlib import Path
upstream_path = Path(sys.argv[1])
patch_path = Path(sys.argv[2])
data = {}
if upstream_path.exists():
    data = json.loads(upstream_path.read_text())
data.update(json.loads(patch_path.read_text()))
upstream_path.write_text(json.dumps(data, indent=2) + "\n")
print(f"Updated {upstream_path}")
PY

rm -rf "${TMP}"
echo "Done."
