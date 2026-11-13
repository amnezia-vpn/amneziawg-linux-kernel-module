# SPDX-License-Identifier: GPL-2.0
"""Compile the actual session-derived callback with a deterministic timer/RNG shim.

No root, loaded module, or network is needed. Kernel scheduling/concurrency is
not modeled: this checks the deadline selected by the real callback and helpers.
"""

import argparse
import os
import pathlib
import re
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

C = r"""
#include <stdio.h>
static int choose_high;
#include "type.h"
#define READ_ONCE(value) (value)
#define HZ 1000UL
#define REJECT_AFTER_TIME @DEFAULT@
static unsigned long jiffies = 123456;
struct wg_device { u16_range_t reject_after_time; };
struct wg_peer {
    struct wg_device *device;
    unsigned long timer_zero_key_material;
};
static void mod_peer_timer(struct wg_peer *peer, unsigned long *timer,
                           unsigned long expires)
{
    (void)peer;
    *timer = expires;
}
@CALLBACK@
int main(void)
{
    const struct { u16 lo, hi; unsigned long expected; } cases[] = {
        {0, 0, REJECT_AFTER_TIME * 3UL}, {4, 4, 12},
        {1, 210, 630}, {2, 65535, 196605}
    };
    struct wg_device device = {0};
    struct wg_peer peer = {.device = &device};
    int failed = 0;
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        u16_range_init(&device.reject_after_time, cases[i].lo, cases[i].hi);
        for (choose_high = 0; choose_high <= 1; ++choose_high) {
            wg_timers_session_derived(&peer);
            unsigned long actual =
                (peer.timer_zero_key_material - jiffies) / HZ;
            if (actual != cases[i].expected) {
                fprintf(stderr, "%u-%u RNG=%s: cleanup=%lu, expected=%lu seconds\n",
                        cases[i].lo, cases[i].hi, choose_high ? "hi" : "lo",
                        actual, cases[i].expected);
                failed = 1;
            }
        }
    }
    if (!failed) puts("PASS: 8 cleanup deadline cases (including lowest RNG output)");
    return failed;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, default=ROOT / "src/timers.c")
    args = parser.parse_args()
    text = args.source.read_text()
    callback = re.search(
        r"void wg_timers_session_derived\(struct wg_peer \*peer\)\n\{.*?^\}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert callback, "Cannot find the session-derived callback"
    default = re.search(
        r"REJECT_AFTER_TIME\s*=\s*([0-9]+)", (ROOT / "src/messages.h").read_text()
    )
    assert default, "Cannot find the default key lifetime"
    source = C.replace("@CALLBACK@", callback.group()).replace("@DEFAULT@", default[1])
    with tempfile.TemporaryDirectory(prefix="awg-key-cleanup-") as directory:
        tmp = pathlib.Path(directory)
        (tmp / "linux").mkdir()
        (tmp / "linux/types.h").write_text(
            "#include <stdint.h>\n#include <stdbool.h>\n"
            "typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;\n"
        )
        (tmp / "linux/random.h").write_text(
            "static inline u32 get_random_u32_inclusive(u32 lo, u32 hi) {\n"
            "return choose_high ? hi : lo;\n}\n"
        )
        (tmp / "test.c").write_text(source)
        binary = tmp / "key-cleanup"
        subprocess.run(
            shlex.split(os.environ.get("CC", "cc"))
            + [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(tmp),
                "-I",
                str(ROOT / "src"),
                str(tmp / "test.c"),
                "-o",
                str(binary),
            ],
            check=True,
        )
        return subprocess.run([str(binary)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
