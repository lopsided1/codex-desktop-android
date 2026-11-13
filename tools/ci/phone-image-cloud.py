"""Build a pristine first-install image on native ARM64 Linux, reusing GNU/GPU inputs.

No phone, APK installation, account, project, signing key or Android qualification
is involved. Root is admitted only for disposable Debian/image/export stages.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'work/ci/phone'
EVIDENCE = ROOT / 'work/ci/evidence/phone-cloud'
TRANSFER = ROOT / 'work/ci/phone-transfer'
CONFIG = ROOT / '.ci-inputs/phone-rootfs/inputs.json'
IMAGE = ROOT / 'downloads/phone-image-cloud'
PART_BYTES = 384 * 1024 ** 2


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def require_vm(*, root=False):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or Path(os.environ.get('GITHUB_WORKSPACE', '/missing')).resolve() != ROOT
            or platform.system() != 'Linux' or platform.machine().lower() not in ('aarch64', 'arm64')
            or (os.geteuid() == 0) != root or Path('/system/build.prop').exists()):
        raise RuntimeError('Use the disposable native ARM64 hosted VM; never a phone/PRoot')
    if any(line.startswith('TracerPid:') and line.split()[1] != '0'
           for line in Path('/proc/self/status').read_text().splitlines()):
        raise RuntimeError('Ptrace/PRoot is not admitted for cloud image production')


def resources():
    return {'disk': shutil.disk_usage(ROOT)._asdict(), 'load': os.getloadavg(),
            'memory': [line for line in Path('/proc/meminfo').read_text().splitlines()
                       if line.startswith(('MemTotal:', 'MemAvailable:', 'SwapFree:'))]}


def preflight():
    require_vm()
    save(EVIDENCE / 'host.json', {'machine': platform.machine(), 'platform': platform.platform(),
         'repository': os.environ['GITHUB_REPOSITORY'], 'commit': os.environ['GITHUB_SHA'],
         'resources': resources(), 'androidExecuted': False, 'userDataIncluded': False})
    if shutil.disk_usage(ROOT).free < 20 * 1024 ** 3:
        raise RuntimeError('Need 20 GiB free VM space after guarded hosted SDK cleanup')


def run(name, argv, *, timeout=1800):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    argv = list(map(str, argv))
    print('RUN ' + name + ': ' + ' '.join(argv), flush=True)
    start = time.monotonic()
    with (EVIDENCE / (name + '.log')).open('w') as log:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors='replace', bufsize=1, start_new_session=True)
        def output():
            for line in process.stdout:
                log.write(line)
                log.flush()
                print(line, end='', flush=True)
        reader = threading.Thread(target=output, daemon=True)
        reader.start()
        try:
            while process.poll() is None:
                try:
                    process.wait(timeout=min(30, max(1, timeout - (time.monotonic() - start))))
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - start
                    print(json.dumps({'heartbeat': name, 'elapsedSeconds': round(elapsed),
                                      'resources': resources()}), flush=True)
                    apt_log = IMAGE / 'evidence/client-apt.log'
                    if name == 'complete-phone-image' and apt_log.is_file():
                        with apt_log.open('rb') as source:
                            source.seek(max(0, apt_log.stat().st_size - 2000))
                            print(source.read().decode(errors='replace'), flush=True)
                    if elapsed >= timeout:
                        raise TimeoutError(name + ' exceeded its bounded build timeout')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            reader.join(timeout=10)
    save(EVIDENCE / (name + '.result.json'), {'command': argv, 'exitCode': process.returncode,
         'seconds': round(time.monotonic() - start, 3), 'resources': resources()})
    if process.returncode:
        raise RuntimeError(name + ' failed: ' + str(process.returncode))


def prepare():
    require_vm()
    WORK.mkdir(parents=True, exist_ok=True)
    config = read(CONFIG)
    gnu = config['gnu']
    archive = WORK / 'gnu-runtime.zip'
    if sha(archive) != gnu['artifactSha256']:
        raise ValueError('Downloaded GNU transfer ZIP differs from its GitHub artifact digest')
    run('import-verified-gnu', [sys.executable, '-B', ROOT / 'tools/executor/gnu_cloud_import.py',
        '--zip', archive, '--sha256', gnu['artifactSha256'], '--package-sha256', gnu['packageSha256'],
        '--repository', gnu['repository'], '--run-id', gnu['runId'], '--commit', gnu['commit'],
        '--transfer-run-id', gnu['transferRunId'], '--transfer-commit', gnu['transferCommit'],
        '--artifact-id', str(gnu['artifactId']), '--output', WORK / 'gnu-import'])
    gpu = WORK / 'mesa.tar.gz'
    with gpu.open('xb') as output:
        for item in config['gpu']['parts']:
            path = ROOT / item['path']
            if (not str(path).startswith(str(ROOT / '.ci-inputs/phone-rootfs/mesa.part-'))
                    or path.is_symlink() or path.resolve() != path
                    or sha(path) != item['sha256'] or path.stat().st_size != item['bytes']):
                raise ValueError('Mesa input chunk changed')
            with path.open('rb') as source:
                shutil.copyfileobj(source, output)
    if sha(gpu) != config['gpu']['sha256'] or gpu.stat().st_size != config['gpu']['bytes']:
        raise ValueError('Reassembled source-built GPU input differs')
    client = config['client']
    if client['fingerprint'] != '3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4':
        raise ValueError('Client signing identity differs')
    official = WORK / 'official'
    official.mkdir()
    (official / 'repository-key.gpg').write_bytes(base64.b64decode(client['keyBase64'], validate=True))
    save(official / 'authenticated-input.json', client['descriptor'])
    descriptor = client['descriptor']
    cache = ROOT / 'work/ci/cache/phone-inputs'
    cache.mkdir(parents=True, exist_ok=True)
    package = cache / ('chatgpt_' + descriptor['version'] + '_arm64.deb')
    if not package.exists():
        partial = package.with_suffix('.partial')
        print('Downloading exact official client input; credentials are not used', flush=True)
        request = urllib.request.Request(client['url'], headers={'User-Agent': 'Mozilla/5.0',
                                        'Accept': 'application/vnd.debian.binary-package, application/octet-stream, */*'})
        downloaded, heartbeat = 0, time.monotonic()
        with urllib.request.urlopen(request, timeout=180) as response, partial.open('xb') as output:
            while block := response.read(1024 * 1024):
                downloaded += len(block)
                if downloaded > descriptor['bytes']:
                    raise ValueError('Official client exceeds pinned download size')
                output.write(block)
                if time.monotonic() - heartbeat >= 30:
                    print(json.dumps({'heartbeat': 'official-client-download', 'bytes': downloaded,
                                      'expectedBytes': descriptor['bytes']}), flush=True)
                    heartbeat = time.monotonic()
        if sha(partial) != descriptor['sha256'] or partial.stat().st_size != descriptor['bytes']:
            raise ValueError('Official client download differs from exact authenticated input')
        partial.rename(package)
    if sha(package) != descriptor['sha256'] or package.stat().st_size != descriptor['bytes']:
        raise ValueError('Cached official client bytes differ')
    shutil.copyfile(package, official / package.name)
    # Verify the actual origin signature now, before any package script runs.
    sys.path.insert(0, str(ROOT / 'tools/install'))
    spec = importlib.util.spec_from_file_location('phone_client_admission', ROOT / 'tools/install/build-phone-image.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    admission = EVIDENCE / 'client-admission'
    admission.mkdir()
    module.authenticated_client_origin(official, admission)
    save(EVIDENCE / 'prepared-inputs.json', {'gnuPackageSha256': gnu['packageSha256'],
        'gpuSha256': sha(gpu), 'clientSha256': sha(package), 'clientAuthentication': 'actual pinned debsig origin verification',
        'gnuRecompiled': False, 'gpuRecompiled': False, 'androidExecuted': False})


def base():
    require_vm(root=True)
    os.environ['CODEX_APT_FORCE_IPV4'] = '1'
    run('debian-base', [sys.executable, '-B', ROOT / 'tools/install/build_rootfs.py', 'build'], timeout=1500)
    result = json.loads((EVIDENCE / 'debian-base.log').read_text().strip().splitlines()[-1])
    path = Path(result['output']) / 'debian-13-arm64-rootfs.tar.gz'
    if not path.is_relative_to(ROOT / 'downloads/install') or sha(path) != result['sha256']:
        raise ValueError('No matching completed authenticated Debian base')
    save(WORK / 'base-input.json', {'archive': str(path), 'sha256': result['sha256'],
                                  'buildDirectory': result['buildDirectory'], 'output': result['output']})


def image():
    require_vm(root=True)
    baseline = read(WORK / 'base-input.json')
    run('complete-phone-image', [sys.executable, '-B', ROOT / 'tools/install/build-phone-image.py',
        '--base', baseline['archive'], '--base-sha256', baseline['sha256'], '--gpu', WORK / 'mesa.tar.gz',
        '--gpu-sha256', read(CONFIG)['gpu']['sha256'], '--engine-state', WORK / 'gnu-import/cloud-import.json',
        '--official-input', WORK / 'official', '--official-authentication', 'origin-signature',
        '--probe-mode', 'mount', '--output', IMAGE], timeout=1800)


def split_archive(source, directory, *, part_bytes=PART_BYTES):
    directory.mkdir(parents=True, exist_ok=False)
    records = []
    with Path(source).open('rb') as stream:
        index = 0
        while block := stream.read(part_bytes):
            path = directory / ('part-' + str(index).zfill(2))
            path.write_bytes(block)
            records.append({'name': path.name, 'bytes': len(block), 'sha256': hashlib.sha256(block).hexdigest()})
            index += 1
    if not records or len(records) > 8:
        raise ValueError('Archive needs between one and eight bounded transfer parts')
    return records


def export():
    require_vm(root=True)
    release = read(IMAGE / 'assets/phone-runtime/release.json')
    archive = IMAGE / release['archive']
    config, baseline = read(CONFIG), read(WORK / 'base-input.json')
    if (release['enginePackageSha256'] != config['gnu']['packageSha256']
            or release['spec']['sha256'] != sha(archive)
            or release['spec']['compressedBytes'] != archive.stat().st_size
            or release['accountIncluded'] is not False or release['keyringIncluded'] is not False
            or release['androidExecuted'] is not False):
        raise ValueError('No complete pristine image with the expected GNU pair')
    parts = split_archive(archive, TRANSFER / 'parts')
    metadata = TRANSFER / 'metadata'
    shutil.copytree(IMAGE / 'assets', metadata / 'assets')
    phone_evidence = metadata / 'image-evidence'
    phone_evidence.mkdir()
    for path in (IMAGE / 'evidence').iterdir():
        if path.is_file() and path.suffix in ('.json', '.txt', '.log', '.tsv'):
            shutil.copyfile(path, phone_evidence / path.name)
    shutil.copytree(IMAGE / 'evidence/complete-apt-lists', phone_evidence / 'complete-apt-lists')
    base_evidence = Path(baseline['buildDirectory']) / 'evidence'
    target = metadata / 'base-evidence'
    target.mkdir()
    for path in base_evidence.iterdir():
        if path.is_file() and path.suffix in ('.json', '.txt', '.tsv', '.gpg'):
            shutil.copyfile(path, target / path.name)
    shutil.copytree(base_evidence / 'apt-lists', target / 'apt-lists')
    shutil.copyfile(CONFIG, metadata / 'build-inputs.json')
    receipt = {'schema': 'codex.phone-cloud-output.v1', 'repository': os.environ['GITHUB_REPOSITORY'],
        'commit': os.environ['GITHUB_SHA'], 'runId': os.environ['GITHUB_RUN_ID'],
        'runUrl': 'https://github.com/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'],
        'archive': archive.name, 'archiveSha256': sha(archive), 'archiveBytes': archive.stat().st_size,
        'gnuPackageSha256': config['gnu']['packageSha256'], 'baseSha256': baseline['sha256'],
        'gpuSha256': config['gpu']['sha256'], 'parts': parts,
        'files': [{'path': p.relative_to(metadata).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)}
                  for p in sorted(metadata.rglob('*')) if p.is_file()],
        'nativeArm64Build': True, 'androidExecuted': False, 'qualifiedCandidate': False,
        'accountIncluded': False, 'keyringIncluded': False,
        'createdUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'limits': ['Complete first-install input, not an APK or activated device',
                   'No APK signing compatibility, Android desktop/backend/managed-command results claimed']}
    save(metadata / 'phone-cloud.json', receipt)
    save(EVIDENCE / 'export.json', {'archiveSha256': receipt['archiveSha256'], 'parts': len(parts),
         'androidExecuted': False, 'completeImageProduced': True})
    print(json.dumps({'archiveSha256': receipt['archiveSha256'], 'parts': len(parts), 'metadata': str(metadata)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('preflight', 'prepare', 'base', 'image', 'export'))
    args = parser.parse_args()
    globals()[args.stage]()
