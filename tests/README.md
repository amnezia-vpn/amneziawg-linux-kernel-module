# Obfuscation hardening regressions

The tests exercise the CPS parser and the module's actual netlink and UDP paths.
No production keys or configurations are required.

## Fast parser checks

Python 3 and a C compiler with AddressSanitizer/UndefinedBehaviorSanitizer:

```sh
CC=clang python3 tests/cps-parser.py
```

This compiles the actual `src/junk.c` with userspace allocation/list shims.
It checks negative and oversized lengths, aggregate size limits, valid tags,
empty CPS, preservation after invalid updates, and each allocation failure.
It does not model kernel locking or scheduling.

To demonstrate a regression against an older source directory:

```sh
CC=clang python3 tests/cps-parser.py --source /path/to/old/src --case rollback
```

## Disposable debug-kernel VM

**The baseline module can panic in these tests. Never run the native test on a
production host.** The VM has no network device; all traffic stays inside it.

Tested with Ubuntu 24.04 x86-64 userspace, QEMU TCG, and Linux 6.6.87. Install
`qemu-system-x86`, `busybox-static`, `iproute2`, Python 3, `cpio`, `gzip`, the C
build toolchain, `flex`, `bison`, and `libelf-dev`. The host kernel is not changed.
Use a separate Linux source tree: the helper replaces its kernel configuration.

```sh
KERNEL_TREE=/path/to/linux-6.6.87
sh tests/build-hardening-kernel.sh "$KERNEL_TREE"
make -C "$KERNEL_TREE" M="$PWD/src" -j8 modules
python3 tests/hardening-vm.py \
  --kernel-tree "$KERNEL_TREE" \
  --module "$PWD/src/amneziawg.ko" \
  --output /tmp/awg-hardening-fixed
```

Use a fresh output directory per run. The packager includes the host's Python
standard library, `ip`, BusyBox and their runtime libraries. The resulting
initramfs is a test artifact, not a distributable operating system image.

The kernel enables KASAN, lockdep, DEBUG_ATOMIC_SLEEP, FAILSLAB and stack-filtered
fault injection. Six native tests cover:

1. Rejection of negative and oversized CPS via direct netlink.
2. Reversed ranges, invalid partial Jmin/Jmax updates, valid zero/ranged timers,
   and rejecting invalid keepalive before inserting a peer.
3. A failed CPS update preserving both the exported description and actual
   emitted CPS packet.
4. UDP reception with HPK while the same HPK is concurrently updated.
5. Bidirectional ICMP through two network namespaces in ordinary WireGuard,
   legacy AWG without HPK, and AWG 3.1 modes.
6. A targeted failure of the junk-buffer allocation in the AmneziaWG handshake
   worker. The module must automatically retry with the full configured junk
   sequence and then send the handshake, without a NULL dereference.

The stack filter selects the `[amneziawg]` symbol, not a same-named function in
the built-in WireGuard driver. It proves the injection was consumed and that
the fault trace contains the intended handshake path.

For a single native case, pass e.g.
`--case Hardening.test_04_header_protection_softirq_and_updates` to the VM helper.
The console and fault-injection traces are saved to `OUTPUT/console.log`.
The helper requires successful completion and rejects BUG, KASAN, Oops or RCU
warning diagnostics. Expected fault-injection notices are allowed.

The native script also accepts the normal `unittest` case arguments when run
inside another disposable VM:

```sh
AWG_DISPOSABLE_LAB=1 python3 tests/kernel-hardening.py
```

These checks do not measure throughput, reproduce mobile-network filtering, or
prove the cause of any historical client stall. The patch leaves the packet
format and valid obfuscation settings unchanged.
