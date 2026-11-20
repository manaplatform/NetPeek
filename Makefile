BUILD_DIR ?= build
BUILD_TYPE ?= Debug
NPROC := $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4))

CMAKE_LISTS ?= CMakeLists.txt
DIST_DIR ?= dist

.PHONY: all configure build clean test debug release relwithdebinfo wordlist_builtin install version package

all: build

configure:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: wordlist_builtin configure
	cmake --build $(BUILD_DIR) -j$(NPROC)

wordlist_builtin:
	@mkdir -p data
	@if [ -f data/wordlists/subdomains-top5000.txt ] && command -v xxd >/dev/null 2>&1; then \
		xxd -i data/wordlists/subdomains-top5000.txt > data/wordlist_builtin.h; \
	fi

debug:
	$(MAKE) BUILD_TYPE=Debug build

release:
	$(MAKE) BUILD_TYPE=Release build

relwithdebinfo:
	$(MAKE) BUILD_TYPE=RelWithDebInfo build

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR)

install: build
	cmake --install $(BUILD_DIR)

# Print project(VERSION) from CMakeLists.txt. Fail closed when it is absent.
# cmake_minimum_required(VERSION ...) is not a project version.
version:
	@awk 'BEGIN { found = 0; in_project = 0; buf = "" } \
	{ \
	  if (!in_project && $$0 ~ /^[[:space:]]*project[[:space:]]*\(/) { \
	    in_project = 1; \
	    buf = $$0; \
	  } else if (in_project) { \
	    buf = buf " " $$0; \
	  } \
	  if (in_project && buf ~ /\)/) { \
	    if (match(buf, /VERSION[[:space:]]+[0-9]+([.][0-9]+)*/)) { \
	      s = substr(buf, RSTART, RLENGTH); \
	      sub(/^VERSION[[:space:]]+/, "", s); \
	      print s; \
	      found = 1; \
	      exit 0; \
	    } \
	    exit 1; \
	  } \
	} \
	END { \
	  if (!found) { \
	    print "error: CMakeLists.txt has no project VERSION" > "/dev/stderr"; \
	    exit 1; \
	  } \
	}' $(CMAKE_LISTS)

# Release build plus a dist/ archive. Never stages or commits artifacts.
package: release
	@set -eu; \
	ver="$$($(MAKE) -s version)"; \
	test -n "$$ver"; \
	test -x "$(BUILD_DIR)/bin/netpeek"; \
	mkdir -p "$(DIST_DIR)"; \
	os="$$(uname -s | tr '[:upper:]' '[:lower:]')"; \
	arch="$$(uname -m)"; \
	name="netpeek-$$ver-$$os-$$arch"; \
	cp "$(BUILD_DIR)/bin/netpeek" "$(DIST_DIR)/$$name"; \
	chmod 755 "$(DIST_DIR)/$$name"; \
	tar -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$$name.tar.gz" "$$name"; \
	printf '%s\n' "$(DIST_DIR)/$$name.tar.gz"

