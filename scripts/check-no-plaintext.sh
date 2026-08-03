#!/usr/bin/env bash
# Fails if a stripped release librootect.so leaks a string the native layer hides.
#
# Greps the raw binary, so it needs no strings(1) — portable to CI and Git Bash. Detector
# paths are XOR-hidden at compile time (obfuscate.h); this is the gate that proves the
# plaintext actually stayed out of the shipped .so.
#
# Usage: scripts/check-no-plaintext.sh   (build release first: ./gradlew :rootect-core:assembleRelease)

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

mapfile -t sos < <(find rootect-core/build -path '*stripped_native_libs/release*' -name librootect.so 2>/dev/null)
if [ "${#sos[@]}" -eq 0 ]; then
  echo "no release .so found — run: ./gradlew :rootect-core:assembleRelease"
  exit 2
fi

# Specific enough that random binary noise won't false-positive. Short tokens like bare
# "su" are deliberately excluded — they'd match constantly. Detectors hide full paths.
needles=(
  magisk magiskhide superuser supersu busybox zygisk
  "/data/adb" "/sbin/su" "/system/bin/su" "/system/xbin/su"
  frida frida-gum lsposed xposed
  # Partial forms matter: an optimiser can leak a 16-byte fragment of a longer literal,
  # so watch for the distinctive prefix, not just the full path.
  "/proc/self" "/proc/1/" "/system/"
)

status=0
for so in "${sos[@]}"; do
  abi=$(basename "$(dirname "$so")")
  for n in "${needles[@]}"; do
    if grep -aqF -- "$n" "$so"; then
      printf '  !! %-14s leaks "%s"\n' "$abi" "$n"
      status=1
    fi
  done
done

if [ "$status" -eq 0 ]; then
  echo "check-no-plaintext: clean (${#sos[@]} .so)"
else
  echo "check-no-plaintext: FAILED — a hidden string is present in the binary"
fi
exit "$status"
