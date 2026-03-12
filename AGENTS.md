# AGENTS.md

Repository guide for agentic coding tools working in `amneziawg-linux-kernel-module`.

## Scope And Layout

- Kernel module sources live in `src/`.
- Primary module objects are declared in `src/Kbuild` as `amneziawg-y := ...`.
- Compatibility shims for older kernels live in `src/compat/`.
- Integration tests live in `src/tests/`:
  - `src/tests/netns.sh` (network namespace integration suite).
  - `src/tests/qemu/Makefile` (QEMU-based cross-arch integration run).

## Environment Assumptions

- Most commands are expected to run from `src/` unless noted.
- Building requires kernel headers or full kernel tree (see `README.md`).
- Many tests require root privileges and kernel networking capabilities.
- QEMU tests download/build distfiles and can take significant time/disk.

## Build Commands

- Build module:
  - `make -C src`
- Build with verbose debug flags:
  - `make -C src debug`
- Clean module artifacts:
  - `make -C src clean`
- Install module into current kernel modules path:
  - `sudo make -C src install`
- Install DKMS source payload:
  - `make -C src dkms-install`

## Lint / Static Analysis Commands

- Kernel style check (checkpatch):
  - `make -C src style`
- Sparse/scan-build style static checking:
  - `make -C src check`
- Coccinelle report mode:
  - `make -C src coccicheck`

## Test Commands

- Main integration test (network namespaces):
  - `sudo make -C src test`
  - Equivalent direct script: `sudo src/tests/netns.sh`
- QEMU integration test:
  - `make -C src test-qemu`
- QEMU test for one architecture (closest equivalent to single-target run):
  - `make -C src/tests/qemu ARCH=x86_64 qemu`
  - Swap `ARCH` for supported values: `x86_64`, `i686`, `arm`, `armeb`, `aarch64`, `aarch64_be`, `mips`, `mipsel`, `mips64`, `mips64el`, `powerpc64le`, `powerpc`, `m68k`.

## Running A Single Test

There is no unit-test framework with per-test selectors in this repository.

- `src/tests/netns.sh` runs as one large integration scenario (no `--filter` equivalent).
- `src/tests/qemu/Makefile` runs one integration scenario per QEMU invocation.
- Practical "single test" options:
  - Run only one test family: `sudo make -C src test` or `make -C src test-qemu`.
  - Run one QEMU arch target: `make -C src/tests/qemu ARCH=x86_64 qemu`.
  - For style checks on one file, run checkpatch script directly from kernel tree:
    - `"$KERNELDIR"/scripts/checkpatch.pl -f src/noise.c`

## Developer Workflow (Recommended)

1. `make -C src clean`
2. `make -C src` (or `make -C src debug`)
3. `make -C src style`
4. `make -C src check` (when touching tricky logic or concurrency)
5. `sudo make -C src test` for integration validation

## Code Style Guidelines

These are derived from existing code and Linux kernel conventions used in `src/*.c` and `src/*.h`.

### Language And Tooling

- Use C for kernel code; avoid introducing C++ or userspace-only patterns.
- Keep code compatible with the existing kernel compatibility layer in `src/compat/`.
- Do not add dependencies on userspace package managers.

### Includes / Imports

- Include local project headers first (e.g., `"device.h"`, `"noise.h"`).
- Include kernel/system headers after local headers.
- Keep include groups stable and minimal; remove unused includes.
- Prefer module-local headers over deep includes when an abstraction exists.

### Formatting

- Follow Linux kernel formatting style:
  - Tabs for indentation.
  - Braces on their own lines for functions and control blocks.
  - Keep wrapping consistent with nearby code.
- Keep lines readable; do not optimize for extreme compactness.
- Use existing SPDX header style for new source files.

### Naming Conventions

- Public module symbols use `wg_` prefix (e.g., `wg_noise_init`).
- Use descriptive snake_case for variables and function names.
- Constants/macros use upper snake case.
- Keep names aligned with existing subsystem terms (`peer`, `handshake`, `keypair`, `endpoint`).

### Types And Data Handling

- Use kernel fixed-width types (`u8`, `u32`, `u64`, etc.) where appropriate.
- Use `bool` for boolean state.
- Respect endianness conversions (`cpu_to_le32`, `cpu_to_be64`, etc.).
- Prefer explicit structure ownership/lifetime patterns already used (kref, RCU, locks).

### Error Handling

- Use kernel-style negative error codes (`-ENOMEM`, `-EINVAL`, etc.).
- Check return values from allocations, crypto ops, and kernel APIs.
- Use early returns and `goto` unwind labels for structured cleanup.
- Keep cleanup labels ordered from most-specific failure to shared teardown.

### Concurrency / Memory Safety

- Preserve existing locking discipline (`spin_lock_bh`, `down_read`, `down_write`, RCU helpers).
- Do not change lock ordering without strong justification.
- Zero sensitive material with `memzero_explicit` / `kfree_sensitive` where applicable.
- Use `READ_ONCE` / `WRITE_ONCE` patterns consistently with surrounding code.

### Logging And Diagnostics

- Use kernel logging macros (`pr_info`, `net_dbg_ratelimited`, etc.) already used in subsystem.
- Keep logs concise and useful; avoid excessive noisy logs in hot paths.
- Debug-only behavior should remain guarded by existing debug config paths.

### Kbuild / Compatibility Updates

- If adding/removing source files, update `src/Kbuild` object lists.
- If kernel-version compatibility is affected, update `src/compat/Kbuild.include` and related compat headers/sources.
- Do not break support assumptions for older kernels without explicit requirement.

### Test Script Edits

- `src/tests/netns.sh` is a strict `set -e` integration script; keep commands deterministic.
- Keep privileged/network-mutating steps paired with cleanup logic.
- For `src/tests/qemu/Makefile`, preserve cross-arch conditionals and existing variable conventions.

## Repository-Specific Policy Files

- Cursor rules:
  - No `.cursor/rules/` directory found.
  - No `.cursorrules` file found.
- Copilot rules:
  - No `.github/copilot-instructions.md` found.

If these files are added later, update this document to reflect and enforce them.
