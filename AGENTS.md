# AGENTS.md — NetPeek

> Instructions for AI coding agents working on the NetPeek repository.
> Read this file before making changes. Prefer evidence from the current tree over assumptions.

## Project overview

**NetPeek** is a high-performance, modular network scanner written in C (C11).  
It supports TCP connect / SYN / UDP and other scan techniques, service/version probing, OS fingerprinting, multi-threaded and multi-worker execution, proxy support, and an extensible Lua-based scripting engine called **NPE (NetPeek Probe Engine)**.

Primary goals:
- Speed and clean architecture
- Practical scanning tool + research/learning codebase for network reconnaissance
- Clear separation of CLI, runtime, scanner engines, recon output, and NPE

License: MIT

## Repository layout

```
.
├── include/          # Public + internal headers (by subsystem)
│   ├── evasion/
│   ├── npe/          # NPE scripting engine
│   ├── npe_lib/
│   ├── npe_proto/
│   ├── os_detect/
│   ├── packet/
│   ├── recon/
│   ├── runtime/      # Threading, workers, queues
│   ├── scanner/
│   └── ui/
├── src/              # Implementation (mirrors include/ structure)
│   ├── cli/
│   ├── evasion/
│   ├── npe/
│   ├── npe_lib/
│   ├── npe_proto/
│   ├── os_detect/
│   ├── recon/
│   ├── runtime/
│   └── scanner/
├── scripts/          # NPE Lua scripts
│   ├── auth/
│   ├── default/
│   ├── discovery/
│   ├── intrusive/
│   ├── safe/
│   └── vuln/
├── utils/            # Shared helpers
├── data/             # Wordlists and generated headers (e.g. wordlist_builtin.h)
├── docs/
├── tests/
├── CMakeLists.txt
├── Makefile          # Convenience wrapper around CMake
└── README.md
```

Binary output location: `build/bin/netpeek`

## Build & commands

### Dependencies
- C compiler: GCC or Clang (C11)
- libpcap
- Lua ≥ 5.4 (system-installed)
- OpenSSL
- PCRE2
- libssh2
- pthread
- SQLite3
- (optional on Linux) liburing

On macOS, Homebrew paths are supported. On Linux, standard system packages.

### Commands

```bash
# Configure + build (default: Debug)
make

# Explicit targets
make configure
make build
make clean
make rebuild          # clean + build
make debug            # BUILD_TYPE=Debug
make release          # BUILD_TYPE=Release
make relwithdebinfo

# Run tests (after build)
make test
# or
ctest --test-dir build --output-on-failure
```

CMake is the real build system. The Makefile is a thin wrapper that sets `BUILD_DIR=build` and `BUILD_TYPE` (default Debug), runs a wordlist embedding step when needed, then invokes CMake.

Debug builds enable AddressSanitizer + UndefinedBehaviorSanitizer.  
Release builds use `-O2 -march=native -flto`.

### Running the binary

```bash
./build/bin/netpeek
./build/bin/netpeek help
./build/bin/netpeek scan <target> [options]
```

Many advanced scan modes (SYN, null/fin/xmas, OS detection, etc.) require root privileges. The code checks effective UID.

## Architecture notes for agents

- Keep the existing layered separation: CLI → runtime/workers → scanner engines → recon output / NPE.
- Prefer extending existing subsystems over introducing new top-level modules.
- NPE is Lua-based. Scripts live under `scripts/`. Engine and protocol helpers are under `include/npe*` and `src/npe*`.
- Raw packet construction and parsing live under `packet/`.
- OS fingerprinting is a distinct subsystem (`os_detect/`).
- Recon output supports multiple formats (text, JSON, CSV, XML, HTML, SARIF, etc.) and style presets.

When adding features:
1. Place headers in the matching `include/<subsystem>/` directory.
2. Place implementation in the matching `src/<subsystem>/` directory.
3. Update CMake source collection only if the existing `GLOB_RECURSE` does not already pick up the new files (it currently globs `src/*.c` and `utils/*.c`).
4. Prefer small, focused changes. Avoid drive-by refactors of unrelated modules.

## Code style & conventions

- C11, no C++.
- Prefer clear, explicit naming over clever macros.
- Match the style of the surrounding file (indentation, brace style, comment density).
- Keep privilege-sensitive paths (raw sockets, root checks) explicit and well-guarded.
- Do not introduce new external dependencies without a strong reason and clear CMake detection.
- Generated / build artifacts belong under `build/`. Do not commit them.
- Wordlist embedding uses `xxd` → `data/wordlist_builtin.h` when the source wordlist is present.

## Testing

- Tests live under `tests/` and are wired via CMake `add_subdirectory(tests)` when `BUILD_TESTING` is on.
- Prefer running the relevant unit/integration tests after changes to scanners, runtime, or NPE.
- For network-related tests, be careful about privileges, interfaces, and side effects on the host.

## Security & safety boundaries

- This is a network reconnaissance tool. Agents must not:
  - Expand scope into weaponization, exploit delivery, or unauthorized scanning of external networks.
  - Remove or weaken root/privilege checks.
  - Add default behavior that scans remote hosts without explicit user configuration.
- Treat raw packet and privilege code as high-risk. Changes there need careful review.
- Do not hard-code credentials, private keys, or live target lists into the repository.
- Keep secrets and any future configuration out of source control.

## Git & PR hygiene

- Prefer small, focused commits/PRs that do one thing.
- Do not reformat large unrelated sections.
- Update README.md only when user-facing behavior or build instructions actually change.
- Generated files (`build/`, certain `data/*.h`) should stay out of commits.

## What to do first on a new task

1. Read the relevant headers and source under `include/` + `src/` for the subsystem you will touch.
2. Check existing tests and NPE scripts if the change involves scanning, probing, or scripting.
3. Build with `make` (or the appropriate `BUILD_TYPE`) and run `make test` when feasible.
4. Keep changes minimal and reviewable.

## Common pitfalls

- Forgetting that many scan techniques require root.
- Breaking the include path layout (headers are discovered recursively under `include/`).
- Adding sources outside the current `GLOB_RECURSE` without updating CMake.
- Treating the Makefile as the source of truth instead of CMakeLists.txt.
- Committing build artifacts or large generated headers.

---

When in doubt: match existing patterns in the nearest subsystem, keep privilege boundaries intact, and prefer the smallest change that correctly solves the requested problem.
```