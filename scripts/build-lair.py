#!/usr/bin/env python3
"""Build and verify one pinned Kiri checkout on Apple silicon, without Docker.

Requires macOS 14+, Python 3 and Xcode Command Line Tools. Rust and the donor
guest artifacts are downloaded into a private cache and checked against pins.
Nothing is installed into Applications, shell profiles or the default context.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FILES = ('Contents/MacOS/kiri', 'Contents/Resources/guest/Image',
         'Contents/Resources/guest/initramfs.cpio', 'Contents/Resources/guest/data.img.tgz',
         'Contents/Resources/bin/docker', 'Contents/Resources/bin/cli-plugins/docker-compose',
         'Contents/Resources/bin/cli-plugins/docker-buildx')


def digest(path):
    with Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else _digest(file)


def _digest(file):
    value = hashlib.sha256()
    for chunk in iter(lambda: file.read(1024 * 1024), b''):
        value.update(chunk)
    return value.hexdigest()


def checked_hash(path, expected):
    if not re.fullmatch('[0-9a-f]{64}', expected) or Path(path).is_symlink() or digest(path) != expected:
        raise ValueError('SHA-256 mismatch: ' + str(path))


def run(argv, *, env=None, capture=False, timeout=1800, cwd=ROOT):
    print('+ ' + ' '.join(map(str, argv)), flush=True)
    result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True,
                            text=True, stdout=subprocess.PIPE if capture else None, timeout=timeout)
    return result.stdout.strip() if capture else None


def validate_source(root, expected):
    if not re.fullmatch('[0-9a-f]{40}', expected):
        raise ValueError('expected-commit must be a full Git commit')
    actual = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != expected:
        raise ValueError('checkout commit does not match expected-commit')
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=all'], text=True)
    if dirty:
        raise ValueError('checkout is dirty; use a clean detached checkout')


def download(cache, name, url, expected, env):
    if not url.startswith('https://'):
        raise ValueError('download must use HTTPS')
    dest = cache / name
    if dest.exists():
        checked_hash(dest, expected)
        return dest
    temporary = cache / (name + '.part-' + uuid.uuid4().hex)
    try:
        run(['curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
             '--proto-redir', '=https', '--retry', '2', '--max-time', '900', '-o', temporary, url], env=env)
        checked_hash(temporary, expected)
        temporary.replace(dest)
    finally:
        temporary.unlink(missing_ok=True)
    return dest


def validate_tests(report):
    if (report.get('successful') is not True or type(report.get('tests_run')) is not int or
            report['tests_run'] < 11 or any(report.get(k) != 0 for k in ('failures', 'errors', 'skipped'))):
        raise ValueError('isolation checks failed, skipped or incomplete')


def verify_files(app, files):
    for name, expected in files.items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('unsafe receipt path')
        checked_hash(app / path, expected)


def seal(app, provenance, env):
    # Signing a bundle changes its main Mach-O signature. Its own raw hash
    # cannot live inside the sealed Resources without a circular dependency.
    (app / 'Contents/Resources/lair-build.json').write_text(json.dumps(provenance, indent=2) + '\n')
    run(['codesign', '--force', '--sign', '-', '--entitlements', ROOT / 'crates/kiri/kiri.entitlements', app], env=env)
    run(['codesign', '--verify', '--deep', '--strict', app], env=env)
    receipt = {**provenance, 'files': {name: digest(app / name) for name in FILES}}
    verify_files(app, receipt['files'])
    Path(str(app) + '.build.json').write_text(json.dumps(receipt, indent=2) + '\n')


def build_env(cache, version):
    # Do not inherit Cargo wrappers, flags, credentials or SSH-agent access.
    env = {k: os.environ[k] for k in ('HOME', 'TMPDIR', 'DEVELOPER_DIR', 'SDKROOT', 'LANG') if k in os.environ}
    env.update(PATH=str(cache / 'cargo/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
               CARGO_HOME=str(cache / 'cargo'), RUSTUP_HOME=str(cache / 'rustup'),
               RUSTUP_DIST_SERVER='https://static.rust-lang.org',
               RUSTUP_UPDATE_ROOT='https://static.rust-lang.org/rustup',
               RUSTUP_TOOLCHAIN=version, KIRI_SIGN_IDENTITY='-', PYTHONDONTWRITEBYTECODE='1')
    return env


def toolchain(cache, pins, env):
    download(cache, 'rust-' + pins['rust'] + '.toml',
             'https://static.rust-lang.org/dist/channel-rust-' + pins['rust'] + '.toml',
             pins['rust_manifest_sha256'], env)
    rustup = cache / 'cargo/bin/rustup'
    if not rustup.exists():
        pin = pins['rustup']
        installer = download(cache, 'rustup-init-' + pin['version'], pin['url'], pin['sha256'], env)
        installer.chmod(0o700)
        run([installer, '-y', '--no-modify-path', '--profile', 'minimal',
             '--default-toolchain', pins['rust'], '--target', 'aarch64-unknown-linux-musl'], env=env)
    run([rustup, 'toolchain', 'install', pins['rust'], '--profile', 'minimal',
         '--target', 'aarch64-unknown-linux-musl', '--no-self-update'], env=env)
    version = run([cache / 'cargo/bin/rustc', '--version'], env=env, capture=True)
    if not version.startswith('rustc ' + pins['rust'] + ' '):
        raise ValueError('unexpected Rust version')
    return version


def guest_artifacts(cache, pins, env):
    pin = pins['guest_base']
    archive = download(cache, 'Kiri-' + pin['version'] + '-arm64.tar.gz', pin['url'], pin['sha256'], env)
    with tempfile.TemporaryDirectory(prefix='donor-', dir=cache) as folder:
        run(['tar', '-xzf', archive, '-C', folder], env=env)
        app = Path(folder) / 'Kiri.app'
        requirement = '=identifier "dev.kiri.app" and anchor apple generic and certificate leaf[subject.OU] = "' + pin['team_id'] + '"'
        run(['codesign', '--verify', '--deep', '--strict', '-R', requirement, app], env=env)
        run(['spctl', '--assess', '--type', 'execute', app], env=env)
        out = ROOT / 'guest/out'; out.mkdir(parents=True, exist_ok=True)
        shutil.copy2(app / 'Contents/Resources/guest/Image', out / 'Image')
        run(['tar', '-xzf', app / 'Contents/Resources/guest/data.img.tgz', '-C', out], env=env)


def isolation(app, profile, env):
    # A distinct development flavor isolates its HOME-owned state too.
    feature = 'lairverify' + uuid.uuid4().hex[:12]
    state = Path.home() / ('.kiri-' + feature)
    if state.exists():
        raise ValueError('verification state already exists')
    with tempfile.TemporaryDirectory(prefix='kiri-verify-') as folder:
        work = Path(folder)
        verify_app = work / 'Kiri Verify.app'
        shutil.copytree(app, verify_app)
        plist_path = verify_app / 'Contents/Info.plist'
        plist = plistlib.loads(plist_path.read_bytes())
        plist.update(CFBundleIdentifier='dev.kiri.app.' + feature, CFBundleName='Kiri Verify', CFBundleDisplayName='Kiri Verify')
        plist_path.write_bytes(plistlib.dumps(plist))
        run(['codesign', '--force', '--sign', '-', '--entitlements', ROOT / 'crates/kiri/kiri.entitlements', verify_app], env=env)
        sock = work / 'docker.sock'
        test_env = {**env, 'KIRI_SOCKET': str(sock), 'KIRI_DATA_DIR': str(work / 'data'),
                    'KIRI_NO_FINDER': '1', 'KIRI_MEMORY_MIB': '2048', 'KIRI_CPUS': '2'}
        docker = verify_app / 'Contents/Resources/bin/docker'
        proc = None
        try:
            with (work / 'daemon.log').open('w') as log:
                proc = subprocess.Popen([str(verify_app / 'Contents/MacOS/kiri'), 'daemon'], env=test_env,
                                        stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 90
                while not sock.exists():
                    if proc.poll() is not None or time.monotonic() >= deadline:
                        raise ValueError('verification engine did not start: ' + (work / 'daemon.log').read_text())
                    time.sleep(0.2)
                report = work / 'isolation.json'
                run([sys.executable, ROOT / 'tests/lair-isolation.py', '--socket', sock,
                     '--docker', docker, '--probe', ROOT / 'target/isolation-probe',
                     '--lair-profile', profile, '--report', report, '-v'], env=test_env, timeout=900)
                result = json.loads(report.read_text())
                validate_tests(result)
                return result
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=10)
            if state.exists():
                shutil.rmtree(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--lair-profile', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path.home() / 'Library/Caches/Lair/Kiri')
    args = parser.parse_args()
    validate_source(ROOT, args.expected_commit)
    if sys.platform != 'darwin' or os.geteuid() == 0:
        raise ValueError('requires macOS, run as a normal user')
    if subprocess.check_output(['sysctl', '-n', 'hw.optional.arm64'], text=True).strip() != '1':
        raise ValueError('this verified build currently supports Apple silicon only')
    major = int(subprocess.check_output(['sw_vers', '-productVersion'], text=True).split('.')[0])
    if major < 14:
        raise ValueError('requires macOS 14 or later')
    run(['xcode-select', '-p'], timeout=15)
    profile = args.lair_profile.resolve(strict=True)
    json.loads(profile.read_text())
    os.umask(0o077)
    cache = args.cache.resolve()
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    if cache.stat().st_uid != os.getuid() or cache.stat().st_mode & 0o022:
        raise ValueError('cache must be private and owned by this user')
    pins_path = ROOT / 'scripts/lair-build-pins.json'
    pins = json.loads(pins_path.read_text())
    env = build_env(cache, pins['rust'])
    rust = toolchain(cache, pins, env)
    guest_artifacts(cache, pins, env)
    cargo = cache / 'cargo/bin/cargo'
    for task in (['guest'], ['app-dev', 'lair']):
        run([cargo, 'run', '--locked', '-q', '--package', 'xtask', '--', *task], env=env)
    app = ROOT / 'target/dev/Kiri Lair.app'
    run([cache / 'cargo/bin/rustc', '--edition', '2024', '--target', 'aarch64-unknown-linux-musl',
         '-C', 'linker=rust-lld', ROOT / 'tests/isolation-probe.rs', '-o', ROOT / 'target/isolation-probe'], env=env)
    result = isolation(app, profile, env)
    validate_source(ROOT, args.expected_commit)
    receipt = {'schema': 1, 'source_commit': args.expected_commit, 'architecture': 'arm64',
               'build_pins_sha256': digest(pins_path), 'rust': rust,
               'lair_profile_sha256': digest(profile), 'capabilities': pins['capabilities'],
               'isolation': result}
    seal(app, receipt, env)
    print('Verified experimental build: ' + str(app), flush=True)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print('Build cancelled.', file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('Build refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
