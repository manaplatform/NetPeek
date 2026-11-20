#!/bin/sh
# Fail-closed extraction of project(VERSION) from CMakeLists.txt.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ver=$(make -C "$root" -s version)
test -n "$ver"

printf '%s\n' \
  'cmake_minimum_required(VERSION 3.16)' \
  'project(netpeek LANGUAGES C)' \
  > "$tmp/noversion.cmake"
if make -C "$root" -s version CMAKE_LISTS="$tmp/noversion.cmake" >/dev/null 2>&1; then
  echo "expected missing project VERSION to fail" >&2
  exit 1
fi

printf '%s\n' 'project(netpeek VERSION 9.8.7 LANGUAGES C)' > "$tmp/ok.cmake"
got=$(make -C "$root" -s version CMAKE_LISTS="$tmp/ok.cmake")
test "$got" = "9.8.7"

printf '%s\n' \
  'project(netpeek' \
  '    VERSION 4.5.6' \
  '    LANGUAGES C)' \
  > "$tmp/multiline.cmake"
got=$(make -C "$root" -s version CMAKE_LISTS="$tmp/multiline.cmake")
test "$got" = "4.5.6"
