#!/bin/sh
# Regression guard for the Release build failure caused by discarding `const`
# through pointer assignment (lua_tolstring(), X509_get_subject_name() and the
# const-qualified port spec all hand back const pointers).
#
# Modern GCC treats these as hard errors while other toolchains only warn, so a
# build that passes locally can still fail the release job. This test finds a
# warning flag that actually rejects the broken shape, confirms the fixed shape
# compiles, and locks in the declarations that broke the release build.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cc_bin=${CC:-cc}

# The shape that broke the build: assigning a const pointer to a non-const one.
printf '%s\n' \
  'struct req { char *body; };' \
  'const char *lua_like(void);' \
  'void fill(struct req *r) { r->body = lua_like(); }' \
  > "$tmp/bad.c"

# The shape we replaced it with.
printf '%s\n' \
  'struct req { const char *body; };' \
  'const char *lua_like(void);' \
  'void fill(struct req *r) { r->body = lua_like(); }' \
  > "$tmp/good.c"

# Self-calibrate: pick the first flag that rejects bad.c yet still accepts
# good.c. Clang uses the long spelling; GCC spells it -Wdiscarded-qualifiers.
# An unknown -Werror= name makes both fail, so it is correctly skipped.
qual_err=""
for cand in \
  -Werror=incompatible-pointer-types-discards-qualifiers \
  -Werror=discarded-qualifiers \
  -Werror
do
  if "$cc_bin" -std=c11 "$cand" -c "$tmp/bad.c" -o "$tmp/bad.o" 2>/dev/null; then
    continue
  fi
  if "$cc_bin" -std=c11 "$cand" -c "$tmp/good.c" -o "$tmp/good.o" 2>/dev/null; then
    qual_err=$cand
    break
  fi
done

if [ -z "$qual_err" ]; then
  echo "no available compiler flag detects const-to-non-const assignment" >&2
  exit 1
fi

# The fixed shape must compile cleanly under the detecting flag.
"$cc_bin" -std=c11 "$qual_err" -c "$tmp/good.c" -o "$tmp/good.o"

# Lock in the declarations that broke the release build.
grep -q 'const char \*body;' \
    "$root/include/npe_lib/npe_lib_http.h"
grep -q 'const char \*cookie_header;' \
    "$root/include/npe_lib/npe_lib_http.h"
grep -q 'const X509_NAME \*subject = X509_get_subject_name' \
    "$root/src/npe_lib/npe_lib_ssl.c"
grep -q 'const X509_NAME \*issuer = X509_get_issuer_name' \
    "$root/src/npe_lib/npe_lib_ssl.c"
grep -q 'const X509_NAME \*subj = X509_get_subject_name' \
    "$root/src/recon/submodules/scanner/tls_probe.c"
grep -q 'const np_port_range_t \*r = &spec->ranges' \
    "$root/src/ports.c"

printf '%s\n' "release const-correctness guard OK ($qual_err)"
