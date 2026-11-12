BUILD_DIR ?= build
BUILD_TYPE ?= Debug
NPROC := $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4))

.PHONY: all configure build clean test debug release relwithdebinfo wordlist_builtin install

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
	rm -rf $(BUILD_DIR)

install: build
	cmake --install $(BUILD_DIR)

