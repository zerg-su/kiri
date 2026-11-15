#!/usr/bin/env python3
"""Build guest unit tests on macOS and run only DNS/profile tests in Linux.

Uses an explicit engine socket and mounts only its own static test executable,
read-only. Safe for a copied source tree as well as the normal checkout.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--socket', required=True)
parser.add_argument('--docker', default='docker')
args = parser.parse_args()
env = dict(os.environ)
for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'CARGO_TARGET_DIR'):
    env.pop(key, None)
build = subprocess.run(['cargo', 'test', '-p', 'kiri-init', '--target', 'aarch64-unknown-linux-musl',
                        '--no-run', '--message-format=json'], env=env, text=True, stdout=subprocess.PIPE, timeout=300)
build.check_returncode()
executables = []
for line in build.stdout.splitlines():
    event = json.loads(line)
    if event.get('reason') == 'compiler-artifact' and event.get('executable') and event['profile']['test']:
        executables.append(Path(event['executable']).resolve())
assert len(executables) == 1, executables
command = [args.docker, '--host', 'unix://' + args.socket]
image = 'alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f'
for selector in ('linux::dns::tests', 'linux::seccomp_profile::tests'):
    name = 'kiri-unit-' + uuid.uuid4().hex[:12]
    try:
        subprocess.run([*command, 'run', '--name', name, '--network', 'none', '--mount',
                        f'type=bind,source={executables[0]},target=/test,readonly', image,
                        '/test', selector, '--test-threads=1'], env=env, check=True, timeout=30)
    finally:
        for action in (['stop', '-t', '1', name], ['rm', name]):
            subprocess.run([*command, *action], env=env, capture_output=True, timeout=15)
