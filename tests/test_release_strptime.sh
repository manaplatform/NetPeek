#!/bin/sh
# Regression guard for the Release build failure caused by feature-test
# macros defined AFTER system headers were already included:
#   src/npe_lib/npe_lib_time.c: error: implicit declaration of function
#   'strptime' (and the resulting int-to-pointer conversion error).
#
# npe_lib_time.h includes <time.h>; under strict C11 glibc only declares
# strptime() when _XOPEN_SOURCE >= 500 was defined BEFORE the first header.
# Defining it later in the file is a no-op. This test locks in the ordering
# on every platform and additionally compiles the real translation unit
# with -Werror=implicit-function-declaration (which rejects the broken
# shape on glibc, where the release job runs).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cc_bin=${CC:-cc}
lua_inc=${1:-}
src="$root/src/npe_lib/npe_lib_time.c"

# Ordering guard (platform independent): the first _XOPEN_SOURCE definition
# must precede the first #include, otherwise <time.h> has already been read
# without it and strptime stays undeclared under strict C11.
awk '
    /^[[:space:]]*#[[:space:]]*include/ { if (!inc) inc = NR }
    /^[[:space:]]*#[[:space:]]*define[[:space:]]+_XOPEN_SOURCE/ {
        if (!xopen) xopen = NR
    }
    END {
        if (!xopen) { print "missing _XOPEN_SOURCE definition" > "/dev/stderr"; exit 1 }
        if (inc && xopen > inc) {
            print "_XOPEN_SOURCE defined after first #include" > "/dev/stderr"
            exit 1
        }
    }
' "$src"

# Compile the real file under strict C11 with the same feature macros the
# build uses; implicit declarations must be hard errors.
lua_flags=""
if [ -n "$lua_inc" ]; then
    lua_flags="-I$lua_inc"
fi

"$cc_bin" -std=c11 -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE \
    -Werror=implicit-function-declaration \
    -I"$root/include" -I"$root/include/npe_lib" $lua_flags \
    -c "$src" -o "$tmp/npe_lib_time.o"

printf '%s\n' "release strptime declaration guard OK"
