#!/usr/bin/env bash
#
# mayhem/build.sh — build youtubeUnblock's fuzz harnesses and its Unity test suite.
#
# Upstream's autotools (libmnl/libnfnetlink/libnetfilter_queue) are only needed by the NFQUEUE daemon
# (src/youtubeUnblock.c). The packet-processing code (src/*.c minus the daemon) needs just the
# vendored libnetfilter_queue "extra" helpers and cyclone, so those sources are compiled directly,
# out of tree, into build/ (already gitignored). Nothing is fetched; the build is offline.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The parsers read big-endian protocol fields through casts such as *(uint16_t *)ptr (tls.c, quic.c, ...),
# which UBSan's alignment check flags on nearly every packet. The loads are benign on every supported
# target, so only that one check is relaxed (-fno-sanitize=alignment); ASan and the rest of UBSan halt.
RELAX="-fno-sanitize=alignment"
# Vendored cyclone's HMAC calls hash init/update functions through a differently-typed function pointer
# (hmac.c:185) and shifts a byte into the int sign bit (aes.c:299); UBSan halts on both for every HKDF/AES
# call, so function and shift-base are relaxed for cyclone only.
CYC_RELAX_FUZZ="-fno-sanitize=function,shift-base"

CORE="args dpi getopt inet_ntop mangle quic quic_crypto tls trie utils"
NFQ_INC="-Ideps/libnetfilter_queue/include -Ideps/libmnl/include -Ideps/libnfnetlink/include"
BUILD="$SRC/build"
HARNESSES="fuzz_process_packet fuzz_tcp_payload fuzz_quic_udp_payload fuzz_quic_frames fuzz_tls_message fuzz_args"

# The vendored libnetfilter_queue extras include an autotools-generated "config.h" that is absent
# from a clean tree; an empty one on their private include path is all they need.
mkdir -p "$BUILD/inc"
: > "$BUILD/inc/config.h"

# compile_all <outdir> <flags...>: compile every library source into <outdir>/*.o
compile_all() {
  local out="$1"; shift
  mkdir -p "$out"
  local pids=() f
  for f in $CORE; do
    "$CC" "$@" -DPKG_VERSION='"mayhem"' -std=gnu99 -Wno-unused-variable -Isrc -Ideps/cyclone/include $NFQ_INC \
      -c "src/$f.c" -o "$out/$f.o" &
    pids+=($!)
    [ "${#pids[@]}" -lt "$MAYHEM_JOBS" ] || { wait "${pids[0]}"; pids=("${pids[@]:1}"); }
  done
  for f in deps/libnetfilter_queue/src/extra/*.c; do
    "$CC" "$@" -w -I"$BUILD/inc" -Ideps/libnetfilter_queue/src $NFQ_INC -c "$f" -o "$out/nfq_$(basename "$f" .c).o" &
    pids+=($!)
    [ "${#pids[@]}" -lt "$MAYHEM_JOBS" ] || { wait "${pids[0]}"; pids=("${pids[@]:1}"); }
  done
  for f in deps/cyclone/*.c; do
    "$CC" "$@" ${CYC_RELAX:-} -w -Isrc -Ideps/cyclone/include -c "$f" -o "$out/cyc_$(basename "$f" .c).o" &
    pids+=($!)
    [ "${#pids[@]}" -lt "$MAYHEM_JOBS" ] || { wait "${pids[0]}"; pids=("${pids[@]:1}"); }
  done
  local p; for p in "${pids[@]}"; do wait "$p"; done
}

# 1) Sanitized library (fuzz flags). fuzzer-no-link puts SanCov on the fuzzed code, unconditionally.
rm -rf "$BUILD/fuzz"
CYC_RELAX="$CYC_RELAX_FUZZ" compile_all "$BUILD/fuzz" -O1 $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link
rm -f "$BUILD/libyu_fuzz.a"
ar rcs "$BUILD/libyu_fuzz.a" "$BUILD"/fuzz/*.o

# 2) Harnesses: libFuzzer binary + standalone reproducer, each linked with the LSan-off hook.
"$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$BUILD/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"
for h in $HARNESSES; do
  "$CC" -O1 $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link -std=gnu99 -Isrc -Ideps/cyclone/include $NFQ_INC \
    -Imayhem -c "mayhem/$h.c" -o "$BUILD/$h.o"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD/$h.o" "$BUILD/lsan_off.o" \
    "$BUILD/libyu_fuzz.a" -o "/mayhem/$h"
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS "$BUILD/standalone_main.o" "$BUILD/$h.o" "$BUILD/lsan_off.o" \
    "$BUILD/libyu_fuzz.a" -o "/mayhem/$h-standalone"
done

# 3) Upstream's Unity suite with NORMAL flags, a separate clean build; mayhem/test.sh only runs it.
rm -rf "$BUILD/test"
compile_all "$BUILD/test/lib" -O2 $COVERAGE_FLAGS
mkdir -p "$BUILD/test/t"
for f in test/*.c test/unity/*.c; do
  "$CC" -O2 $COVERAGE_FLAGS -std=gnu99 -w -Isrc -Ideps/cyclone/include $NFQ_INC -Itest/unity -Itest \
    -c "$f" -o "$BUILD/test/t/$(echo "$f" | tr / _ | sed 's/\.c$//').o"
done
"$CC" $COVERAGE_FLAGS "$BUILD"/test/lib/*.o "$BUILD"/test/t/*.o -o "$BUILD/testYoutubeUnblock" -lm
