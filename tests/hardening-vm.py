# SPDX-License-Identifier: GPL-2.0
"""Package host Python/ip in an initramfs and run an offline x86-64 debug VM."""
import argparse
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-tree', type=pathlib.Path, required=True)
    parser.add_argument('--module', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--case', action='append', default=[])
    args = parser.parse_args()
    kernel = args.kernel_tree.resolve()
    output = args.output.resolve()
    config = (kernel / '.config').read_text()
    for option in ['KASAN', 'PROVE_LOCKING', 'DEBUG_ATOMIC_SLEEP', 'FAILSLAB',
                   'FAULT_INJECTION_STACKTRACE_FILTER']:
        assert 'CONFIG_' + option + '=y\n' in config, 'Enable ' + option
    output.mkdir(parents=True, exist_ok=True)
    root = output / 'root'
    for name in ['bin', 'sbin', 'usr/bin', 'lib', 'lib64', 'proc', 'sys', 'dev',
                 'run/netns', 'tmp', 'lab', 'etc']:
        (root / name).mkdir(parents=True, exist_ok=True)

    def copy(path):
        p = pathlib.Path(path)
        dest = root / str(p).lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            dest.unlink()
        if not dest.exists():
            shutil.copy2(p.resolve(), dest)

    executables = [shutil.which('busybox'), sys.executable, shutil.which('ip')]
    assert all(executables), 'Install busybox-static, iproute2 and Python 3'
    for path in executables:
        copy(path)
    stdlib = pathlib.Path(sysconfig.get_path('stdlib'))
    for p in stdlib.rglob('*'):
        if (p.is_file() and '__pycache__' not in str(p) and '/test/' not in str(p)
                and not {'site-packages', 'dist-packages'} & set(p.relative_to(stdlib).parts)):
            copy(p)
    for path in executables + [str(p) for p in (stdlib / 'lib-dynload').glob('*.so')]:
        result = subprocess.run(['ldd', path], capture_output=True, text=True)
        for dependency in re.findall(r'(/[^\s()]+)', result.stdout):
            copy(dependency)
    for applet in ['sh', 'mount', 'ping', 'insmod', 'dmesg', 'reboot', 'mkdir']:
        p = root / 'bin' / applet
        if not p.exists():
            p.symlink_to(executables[0])
    shutil.copy2(args.module, root / 'lab/amneziawg.ko')
    shutil.copy2(pathlib.Path(__file__).with_name('kernel-hardening.py'), root / 'lab/kernel-hardening.py')
    python = shlex.quote(sys.executable)
    cases = shlex.join(args.case)
    (root / 'init').write_text('''#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/kernel/debug
mount -t debugfs debugfs /sys/kernel/debug
ip link set lo up
insmod /lab/amneziawg.ko || { echo LAB_INSMOD_FAILED; reboot -f; }
export AWG_DISPOSABLE_LAB=1
''' + python + ' /lab/kernel-hardening.py ' + cases + '''
result=$?
echo LAB_RESULT=$result
dmesg
reboot -f
''')
    (root / 'init').chmod(0o755)
    with (output / 'initramfs.cpio.gz').open('wb') as archive:
        subprocess.run(['sh', '-c', 'find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1'],
                       cwd=root, stdout=archive, check=True)
    command = ['qemu-system-x86_64', '-accel', 'tcg,thread=multi', '-smp', '2',
               '-m', '1536', '-nic', 'none', '-nographic', '-no-reboot',
               '-kernel', str(kernel / 'arch/x86/boot/bzImage'),
               '-initrd', str(output / 'initramfs.cpio.gz'),
               '-append', 'console=ttyS0 panic=1 oops=panic nokaslr']
    with (output / 'console.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=240, check=True)
    text = (output / 'console.log').read_text(errors='replace')
    if 'LAB_RESULT=0' not in text or any(marker in text for marker in
        ['BUG:', 'KASAN:', 'Oops:', 'WARNING: suspicious RCU usage']):
        raise SystemExit('FAIL: see ' + str(output / 'console.log'))
    print('PASS: offline debug-kernel VM; log: ' + str(output / 'console.log'))


if __name__ == '__main__':
    main()
