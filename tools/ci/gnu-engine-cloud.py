"""GNU ARM64 release stages for a disposable native GitHub-hosted Linux VM.

No Android tools, device, credentials or APK signing inputs are used. Cached
downloads and source/build receipts remain subject to the maintained builder.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'work/ci/gnu'
CACHE = ROOT / 'work/ci/cache'
EVIDENCE = ROOT / 'work/ci/evidence/gnu-cloud'
RUST = '1.95.0'
TARGET = 'aarch64-unknown-linux-gnu'
MIN_DISK = 20 * 1024 ** 3
MIN_MEMORY = 12 * 1024 ** 3


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def builder():
    return module('gnu_release_builder', ROOT / 'tools/executor/build-gnu-engine.py')


def require_vm(*, root=False):
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or Path(os.environ.get('GITHUB_WORKSPACE', '/missing')).resolve() != ROOT
            or platform.system() != 'Linux' or platform.machine().lower() not in ('aarch64', 'arm64')
            or (os.geteuid() == 0) != root):
        raise RuntimeError('Use a disposable native ARM64 GitHub-hosted VM; root is limited to the Debian library stage')
    status = Path('/proc/self/status').read_text()
    if any(line.startswith('TracerPid:') and line.split()[1] != '0' for line in status.splitlines()):
        raise RuntimeError('PRoot/ptrace is not an admitted cloud build environment')


def resources():
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemTotal:'))) * 1024
    return {'memoryBytes': memory, 'disk': shutil.disk_usage(ROOT)._asdict()}


def preflight():
    require_vm()
    report = {'schema': 'codex.gnu-cloud-host.v1', 'machine': platform.machine(),
        'platform': platform.platform(), 'resources': resources(),
        'repository': os.environ.get('GITHUB_REPOSITORY'), 'commit': os.environ.get('GITHUB_SHA'),
        'runId': os.environ.get('GITHUB_RUN_ID'), 'rust': RUST, 'target': TARGET,
        'androidExecuted': False, 'secretsRequired': False}
    save(EVIDENCE / 'host.json', report)
    if report['resources']['memoryBytes'] < MIN_MEMORY:
        raise RuntimeError('At least 12 GiB RAM is required; the public ARM64 VM has 16 GB, private 8 GB VMs are insufficient')
    if report['resources']['disk']['free'] < MIN_DISK:
        raise RuntimeError('At least 20 GiB free disk is required after unused SDK cleanup; choose a roomier runner if unavailable')


def run(name, command, *, cwd=ROOT):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    command = list(map(str, command))
    started = time.monotonic()
    print('RUN ' + name + ': ' + ' '.join(command), flush=True)
    with (EVIDENCE / (name + '.log')).open('w') as log:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors='replace', bufsize=1)
        for line in process.stdout:
            log.write(line)
            log.flush()
            print(line, end='', flush=True)
        code = process.wait()
    save(EVIDENCE / (name + '.result.json'), {'command': command, 'cwd': str(cwd),
        'exitCode': code, 'seconds': round(time.monotonic() - started, 3), 'resources': resources()})
    if code:
        raise RuntimeError(name + ' failed with exit code ' + str(code))


def prepare():
    require_vm()
    WORK.mkdir(parents=True, exist_ok=True)
    build = builder()
    recovery = json.loads((ROOT / 'recovery/engine/manifest.json').read_bytes())
    if recovery['base'] != build.BASE or build.sha(ROOT / 'recovery/engine' / recovery['patch']) != recovery['sha256']:
        raise ValueError('Recovery source pins differ')
    # The linked source path is stable across VM runs. Its complete content is
    # compared with a fresh recovery snapshot by --verified-checkout, so a cache
    # never becomes a source admission shortcut.
    repository, source = WORK / 'upstream', WORK / 'engine'
    run('restore-engine', [sys.executable, '-B', ROOT / 'tools/recovery/restore-engine.py', '--destination', repository])
    run('stable-source-worktree', ['git', '-C', repository, 'worktree', 'add', '--detach', source, recovery['base']])
    run('worktree-patch-check', ['git', '-C', source, 'apply', '--index', '--check', ROOT / 'recovery/engine' / recovery['patch']])
    run('worktree-patch', ['git', '-C', source, 'apply', '--index', ROOT / 'recovery/engine' / recovery['patch']])
    channel = tomllib.loads((source / 'codex-rs/rust-toolchain.toml').read_text())['toolchain']['channel']
    if channel != RUST:
        raise ValueError('Recovered engine Rust toolchain differs from the CI pin')
    inputs = CACHE / 'gnu-inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    archive = inputs / ('openssl-' + build.OPENSSL_VERSION + '.tar.gz')
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        with urllib.request.urlopen(build.OPENSSL_SOURCE_URL, timeout=180) as response, temporary.open('wb') as output:
            shutil.copyfileobj(response, output)
        if build.sha(temporary) != build.OPENSSL_SOURCE_SHA256:
            raise ValueError('OpenSSL download digest differs')
        temporary.rename(archive)
    if build.sha(archive) != build.OPENSSL_SOURCE_SHA256:
        raise ValueError('Cached OpenSSL source digest differs')
    openssl_source = WORK / 'openssl-source'
    openssl_source.mkdir()
    with tarfile.open(archive) as stream:
        stream.extractall(openssl_source, filter='data')
    tree = openssl_source / ('openssl-' + build.OPENSSL_VERSION)
    deps, prefix = WORK / 'deps', WORK / 'deps/openssl'
    run('openssl-configure', ['perl', './Configure', 'linux-aarch64', '--cross-compile-prefix=aarch64-linux-gnu-',
        'no-shared', '--libdir=lib', '--prefix=' + str(prefix), '--openssldir=/usr/lib/ssl'], cwd=tree)
    run('openssl-build', ['make', '-j2', 'build_sw'], cwd=tree)
    run('openssl-install', ['make', 'install_sw'], cwd=tree)
    dependency_manifest = WORK / 'dependency-inputs.json'
    save(dependency_manifest, {'schema': 'codex.gnu-engine-dependencies.v1', 'target': TARGET,
        'openssl': {'version': build.OPENSSL_VERSION, 'source': {'url': build.OPENSSL_SOURCE_URL,
            'archive': str(archive), 'sha256': build.sha(archive)}, 'configureTarget': 'linux-aarch64',
            'compilerTarget': 'aarch64-linux-gnu',
            'archives': {name: build.sha(prefix / 'lib' / name) for name in build.OPENSSL_ARCHIVES}}})
    run('prepare-release', [sys.executable, '-B', ROOT / 'tools/executor/build-gnu-engine.py', 'prepare',
        '--verified-checkout', '--engine', source, '--build-root', WORK / 'builds',
        '--target-dir', CACHE / 'gnu-arm64-target', '--dependencies', deps,
        '--dependency-manifest', dependency_manifest, '--cargo-home', os.environ['CARGO_HOME'],
        '--rustup-home', os.environ['RUSTUP_HOME']])
    state = Path((EVIDENCE / 'prepare-release.log').read_text().strip().splitlines()[-1])
    if not state.is_file() or state.name != 'build-state.json' or not state.resolve().is_relative_to(ROOT / 'downloads/engine-gnu-arm64'):
        raise ValueError('Builder did not emit an actual build-state receipt')
    (WORK / 'engine-state.txt').write_text(str(state) + '\n')


def state_path():
    path = Path((WORK / 'engine-state.txt').read_text().strip())
    if not path.resolve(strict=True).is_relative_to(ROOT / 'downloads/engine-gnu-arm64'):
        raise ValueError('State pointer leaves the release evidence directory')
    return path


def compile_engine(jobs):
    require_vm()
    run('build-release', [sys.executable, '-B', ROOT / 'tools/executor/build-gnu-engine.py',
        'build', '--state', state_path(), '--jobs', str(jobs)])


def debian_runtime():
    require_vm(root=True)
    # This is only a small authenticated Debian 13 library baseline. It is NOT
    # a desktop image, installed phone runtime or historical device collection.
    rootfs_builder = module('ci_debian_builder', ROOT / 'tools/install/build_rootfs.py')
    runtime = WORK / 'debian-runtime'
    runtime.mkdir(mode=0o755)
    key = rootfs_builder.bootstrap_keyring(runtime)
    root = runtime / 'rootfs'
    run('debian-library-root', ['mmdebstrap', '--mode=root', '--variant=minbase',
        '--format=directory', '--architectures=arm64', '--keyring=' + str(key),
        '--include=libgcc-s1,libstdc++6,zlib1g,libdbus-1-3,libcap2,libzstd1',
        '--aptopt=Acquire::Languages none', '--aptopt=Acquire::AllowInsecureRepositories false',
        '--aptopt=APT::Get::AllowUnauthenticated false', 'trixie', root,
        'deb https://deb.debian.org/debian trixie main'])
    release = (root / 'etc/os-release').resolve(strict=True).read_text()
    if 'ID=debian' not in release or 'VERSION_ID="13"' not in release:
        raise ValueError('Library baseline is not actual Debian 13')
    archive = runtime / 'debian-13-arm64-libraries.tar.gz'
    run('debian-library-archive', ['tar', '--sort=name', '--hard-dereference', '--numeric-owner',
        '-C', root, '-czf', archive, '.'])
    archive.chmod(0o644)
    run('debian-installed-versions', ['dpkg-query', '--admindir=' + str(root / 'var/lib/dpkg'),
        '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n'])
    build = builder()
    save(EVIDENCE / 'debian-library-baseline.json', {'schema': 'codex.gnu-ci-debian-runtime.v1',
        'scope': 'Authenticated minimal Debian library baseline only, not a first-install image',
        'archiveSha256': build.sha(archive), 'keyringSha256': build.sha(key), 'androidCollected': False})


def package():
    require_vm()
    build = builder()
    path = state_path()
    state = json.loads(path.read_bytes())
    if not state.get('buildCompleted') or state.get('buildExitCode') != 0:
        raise ValueError('No completed GNU source build to package')
    runtime = WORK / 'debian-runtime/debian-13-arm64-libraries.tar.gz'
    run('collect-debian-libraries', [sys.executable, '-B', ROOT / 'tools/executor/collect-gnu-rootfs-libraries.py',
        '--rootfs-archive', runtime, '--rootfs-sha256', build.sha(runtime),
        '--binaries', Path(state['build']) / 'unstripped', '--output', WORK / 'gnu-libraries'])
    run('package-release', [sys.executable, '-B', ROOT / 'tools/executor/build-gnu-engine.py',
        'package', '--state', path, '--libraries', WORK / 'gnu-libraries'])
    output = WORK / 'output'
    output.mkdir()
    run('stage-apk-assets', [sys.executable, '-B', ROOT / 'tools/executor/stage-gnu-engine-assets.py',
        '--state', path, '--output', output / 'apk-assets'])
    state = json.loads(path.read_bytes())
    for name in ('codex-gnu-engine-aarch64.tar.gz', 'codex-gnu-engine-aarch64-symbols.tar.gz', 'SHA256SUMS'):
        shutil.copy2(Path(state['evidence']) / name, output / name)
    shutil.copy2(path, output / 'original-cloud-build-state.json')
    shutil.copy2(Path(state['source']) / 'codex-rs/Cargo.toml', output / 'engine-Cargo.toml')
    receipt = {'schema': 'codex.gnu-cloud-output.v1', 'repository': os.environ['GITHUB_REPOSITORY'],
        'commit': os.environ['GITHUB_SHA'], 'runId': os.environ['GITHUB_RUN_ID'],
        'runUrl': 'https://github.com/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
        'sourceBase': state['sourceBase'], 'patchSha256': state['patchSha256'], 'rust': RUST,
        'target': TARGET, 'androidExecuted': False, 'qualifiedCandidate': False,
        'files': build.files(output),
        'limits': ['Original cloud state contains VM-local paths; it is retained as evidence, not a local resumable build',
                   'APK assets contain only the GNU matched pair, not Android executors or the desktop image',
                   'Android desktop/backend/local-command validation remains required']}
    save(output / 'cloud-build.json', receipt)
    print(json.dumps({'output': str(output), 'packageSha256': state['packageSha256'], 'androidExecuted': False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('plan', 'preflight', 'prepare', 'build', 'debian-runtime', 'package'))
    parser.add_argument('--jobs', type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    if args.stage == 'plan':
        print(json.dumps({'runner': 'ubuntu-24.04-arm', 'rust': RUST, 'target': TARGET,
            'minimumFreeDiskBytes': MIN_DISK, 'minimumMemoryBytes': MIN_MEMORY,
            'deviceRequired': False, 'secretsRequired': False, 'nativeStages':
            ['preflight', 'prepare', 'build', 'debian-runtime (root)', 'package']}, indent=2))
    elif args.stage == 'build':
        compile_engine(args.jobs)
    else:
        globals()[args.stage.replace('-', '_')]()


if __name__ == '__main__':
    main()
