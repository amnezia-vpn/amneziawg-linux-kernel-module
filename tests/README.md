# Key lifetime regression

`key-cleanup.py` compiles the actual session-derived timer callback and range
helpers with a small timer/RNG shim. It forces both range endpoints rather than
waiting for a random premature cleanup. It needs Python 3 and a C compiler (`CC`
defaults to `cc`); it does not need root, a module, or a network namespace.

```sh
python3 tests/key-cleanup.py
# Optional: demonstrate failure with an older src/timers.c.
python3 tests/key-cleanup.py --source /path/to/old/timers.c
```

For `RejectAfterTime = 1-210`, the old callback can schedule cleanup after
3 seconds, while a key remains valid until 210 seconds. The corrected callback
always schedules cleanup after 630 seconds. The test also covers the zero/default
case, a fixed value, and a range up to 65535. This is a callback calculation test;
it does not model kernel scheduling or concurrency.

## Native integration

`key-lifetime.py` exercises the installed AmneziaWG kernel module over loopback
inside a temporary network namespace. It generates fresh server/client keys and
a PSK, completes Noise IKpsk2, verifies the response MAC1 and AEAD, and tests ICMP
traffic in both directions. The client deliberately does not answer subsequent
handshake initiations: rekeying cannot hide an incorrect expiration boundary.

Requirements: Linux, root, Python 3 with `cryptography`, iproute2, `awg`, and a
loaded AmneziaWG module. The test does not require Internet connectivity. It
creates namespace `awg-rat-regression` and interface `rat0`; an existing namespace
with that name causes an error before any modification. Cleanup runs on normal
completion, test errors, timeouts, and Ctrl-C. It does not change host routes,
firewall rules, or existing peers.

```sh
# Fast reproduction on an affected module (about 7 seconds).
sudo python3 tests/key-lifetime.py --expect broken

# Validate a fixed module: fixed deadline and a short range (about 18 seconds).
sudo python3 tests/key-lifetime.py --expect fixed

# Also exercise a wide range crossing the 180-second default (about 4 minutes).
sudo python3 tests/key-lifetime.py --expect fixed --long
```

The fixed native modes require the data-path fixes proposed in #240 as well as
the cleanup correction. This PR's timer change alone does not make the complete
native lifetime suite pass on the current master branch.

The affected module ignores `RejectAfterTime = 4` in its data paths: the same
session still receives and sends data after six seconds. On a fixed module,
those probes must fail while the initial RX/TX probes pass.

The long case uses `RejectAfterTime = 1-210`. It requires the same session to
receive and send at age 185 seconds and to expire after 210 seconds. This checks
both premature data-path expiration at 180 seconds and premature key-material
cleanup if a randomly selected cleanup timeout falls before that probe. A
single wide-range run does not exhaust every possible random timeout.
The expected expiration boundary is the range's upper bound, matching
`amneziawg-go`'s `keychainExpireTime()`.

These tests reproduce the data-path lifetime problem in issue #227 and PR #240.
They complement the timer fixes in PRs #238 and #239; they do not directly test
exhausted handshake retries or the refresh-timeout clamp.
A failed before-deadline probe exits nonzero;
an unavailable module or failed initial handshake is an error, not a successful
expiration test.
