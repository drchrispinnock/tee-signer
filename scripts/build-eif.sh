#!/usr/bin/env bash
# Reproducibly build the Nitro signer EIF and print its measurements.
#
#   scripts/build-eif.sh [arm64|amd64]        (default: arm64)
#
# Output: dist/nitro-signer-<arch>.eif and dist/nitro-signer-<arch>.measurements.json
#
# Two builds of the same commit produce the same PCR0/PCR1/PCR2:
#  - base images are pinned by digest and nitro-cli by version,
#  - cargo builds with --locked against the pinned toolchain,
#  - BuildKit rewrites every file timestamp to SOURCE_DATE_EPOCH (the commit time).
# The .eif file's own SHA-256 still differs (its metadata section records the build
# time), but that section is not measured. Compare PCRs, not file hashes.
set -euo pipefail

ARCH="${1:-arm64}"
case "$ARCH" in arm64|amd64) ;; *) echo "arch must be arm64 or amd64" >&2; exit 2 ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "warning: working tree is dirty; measurements will not match a clean checkout" >&2
fi

export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
COMMIT="$(git rev-parse HEAD)"
IMAGE="tee-signer-nitro:${COMMIT:0:12}-${ARCH}"
BUILDER="tee-signer-eif-builder:${ARCH}"
mkdir -p dist

docker buildx build --no-cache --platform "linux/${ARCH}" \
  -f docker/nitro_signer.Dockerfile \
  --build-arg RELEASE=1 \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --output "type=docker,name=${IMAGE},rewrite-timestamp=true" \
  .

docker buildx build --platform "linux/${ARCH}" -f docker/eif_builder.Dockerfile \
  --output "type=docker,name=${BUILDER}" docker

docker run --rm --platform "linux/${ARCH}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$ROOT/dist:/out" \
  "$BUILDER" build-enclave --docker-uri "$IMAGE" --output-file "/out/nitro-signer-${ARCH}.eif" \
  > "dist/nitro-signer-${ARCH}.build.json"

python3 - "$ARCH" "$COMMIT" "$SOURCE_DATE_EPOCH" <<'PY'
import json, sys
arch, commit, epoch = sys.argv[1:]
raw = open(f"dist/nitro-signer-{arch}.build.json").read()
m = json.loads(raw[raw.index("{"):])["Measurements"]
out = {"arch": arch, "commit": commit, "source_date_epoch": int(epoch),
       "pcr0": m["PCR0"], "pcr1": m["PCR1"], "pcr2": m["PCR2"]}
json.dump(out, open(f"dist/nitro-signer-{arch}.measurements.json", "w"), indent=2)
print(json.dumps(out, indent=2))
PY
