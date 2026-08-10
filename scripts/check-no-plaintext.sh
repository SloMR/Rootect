#!/usr/bin/env bash
# Fails if a stripped release librootect.so leaks a string the native layer hides.
#
# Greps the raw binary, so it needs no strings(1) — portable to CI and Git Bash. Detector
# paths are XOR-hidden at compile time (obfuscate.h); this is the gate that proves the
# plaintext actually stayed out of the shipped .so.
#
# Needles are derived from the sources, not kept by hand: a hand-written list stops covering
# new literals the moment a detector adds one, and the gate keeps passing while proving less.
#
# Usage: scripts/check-no-plaintext.sh   (build release first: ./gradlew :rootect-core:assembleRelease)

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

mapfile -t sos < <(find rootect-core/build -path '*stripped_native_libs/release*' -name librootect.so 2>/dev/null)
if [ "${#sos[@]}" -eq 0 ]; then
  echo "no release .so found — run: ./gradlew :rootect-core:assembleRelease"
  exit 2
fi

# Every hidden literal, straight from the source. Short ones are dropped: "0", "1" and the
# like occur in any binary as noise and would fail the gate constantly.
mapfile -t derived < <(
  grep -rhoE 'ROOTECT_HIDE\("[^"]*"\)' rootect-core/src/main/cpp |
    sed -e 's/^ROOTECT_HIDE("//' -e 's/")$//' |
    awk 'length($0) >= 5' |
    sort -u
)

# None found means the sources moved. A gate that checks nothing still reports success.
if [ "${#derived[@]}" -eq 0 ]; then
  echo "no ROOTECT_HIDE literals found in rootect-core/src/main/cpp — the gate would prove nothing"
  exit 2
fi

# Names that must never appear however they arrive, including from a literal someone forgot
# to wrap. These are the tokens an attacker greps for first.
extra=(
  magisk magiskhide superuser supersu busybox zygisk
  "/data/adb" "/sbin/su" "/system/bin/su" "/system/xbin/su"
  frida frida-gum frida-agent lsposed xposed riru
  "/proc/self" "/proc/1/" "/system/"
)

mapfile -t needles < <(printf '%s\n' "${derived[@]}" "${extra[@]}" | sort -u)
echo "check-no-plaintext: ${#needles[@]} needles (${#derived[@]} derived from source)"

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
