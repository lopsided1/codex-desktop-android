"""Import a verified cloud GNU package, never rewrite a local build's state.

The distinct import receipt is a packaging input, not a resumable Cargo state,
Android qualification, signature or proof of device execution.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tomllib
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'codex.gnu-cloud-import.v1'
TARGET = 'aarch64-unknown-linux-gnu'
PACKAGE = 'codex-gnu-engine-aarch64.tar.gz'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def name(value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or '..' in path.parts or '\\' in value
            or path.as_posix() != value or value == '.'):
        raise ValueError('Noncanonical or escaping package path: ' + value)
    return value


def checked(root, record, *, modes=False):
    path = root / name(record['path'])
    if (path.is_symlink() or not path.is_file() or path.resolve() != path
            or path.stat().st_size != record['bytes'] or sha(path) != record['sha256']
            or (modes and stat.S_IMODE(path.stat().st_mode) != record['mode'])):
        raise ValueError('Imported input changed: ' + record['path'])
    return path


def indexed(records):
    result = {}
    for item in records:
        key = name(item['path'])
        if key in result:
            raise ValueError('Duplicate inventory path: ' + key)
        result[key] = item
    return result


def recovery():
    pins = read(ROOT / 'recovery/engine/manifest.json')
    if sha(ROOT / 'recovery/engine' / pins['patch']) != pins['sha256']:
        raise ValueError('Current recovery patch differs from its manifest')
    return pins


def package_members(stream, pins):
    members = stream.getmembers()
    names = [name(item.name) for item in members]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate archive path')
    if len(members) > 100 or sum(item.size for item in members) > 1024 ** 3:
        raise ValueError('Unexpected GNU package expansion')
    if any(not item.isfile() or item.mode & ~0o777 for item in members):
        raise ValueError('GNU package must contain only ordinary files')
    manifest_member = stream.getmember('manifest.json')
    if manifest_member.size > 1024 ** 2:
        raise ValueError('Oversize GNU manifest')
    manifest = json.load(stream.extractfile(manifest_member), object_pairs_hook=unique)
    if (manifest.get('kind') != 'separate-gnu-engine-payload' or manifest.get('target') != TARGET
            or manifest.get('sourceBase') != pins['base'] or manifest.get('patchSha256') != pins['sha256']
            or manifest.get('androidExecution') is not False or manifest.get('liveUiQualified') is not False):
        raise ValueError('GNU package source, target or qualification differs')
    inventory = indexed(manifest['files'])
    if set(names) != set(inventory) | {'manifest.json'}:
        raise ValueError('GNU package inventory is not exact')
    if not {'codex', 'codex-code-mode-host', 'engine.patch', 'recovery-manifest.json',
            'SOURCES.json', 'static-compatibility.json'} <= set(inventory):
        raise ValueError('GNU package is missing matched binaries or provenance')
    for item in members:
        if item.name == 'manifest.json':
            continue
        expected = inventory[item.name]
        if (item.size != expected['bytes'] or item.mode != expected['mode']
                or hashlib.file_digest(stream.extractfile(item), 'sha256').hexdigest() != expected['sha256']):
            raise ValueError('GNU archive content differs: ' + item.name)
    return manifest, members


def check_run(run, repository, run_id, commit):
    if (run.get('id') != int(run_id) or run.get('repository', {}).get('full_name') != repository
            or run.get('head_sha') != commit or run.get('status') != 'completed'
            or run.get('conclusion') != 'success'):
        raise ValueError('GitHub run identity or successful conclusion differs')


def api(repository, resource):
    request = urllib.request.Request('https://api.github.com/repos/' + repository + '/' + resource,
                                    headers={'User-Agent': 'codex-gnu-build-import',
                                             'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response, object_pairs_hook=unique)


def load_import(path):
    path = Path(path).resolve(strict=True)
    receipt, root = read(path), path.parent
    if receipt.get('schema') != SCHEMA or receipt.get('androidExecuted') is not False:
        raise ValueError('Not an unqualified cloud import receipt')
    pins = recovery()
    if receipt.get('sourceBase') != pins['base'] or receipt.get('patchSha256') != pins['sha256']:
        raise ValueError('Imported release differs from current recovery')
    frozen = indexed(receipt['inputFiles'])
    required = {'portable/' + PACKAGE, 'portable/cloud-build.json', 'portable/cloud-transfer.json',
                'portable/original-cloud-build-state.json', 'portable/engine-Cargo.toml',
                'package/manifest.json', 'github-admission.json'}
    if not required <= set(frozen):
        raise ValueError('Cloud import is missing frozen admission evidence')
    for record in frozen.values():
        checked(root, record)
    admission = read(root / 'github-admission.json')
    check_run(admission['original'], receipt['repository'], receipt['runId'], receipt['commit'])
    if (admission['artifact'].get('digest') != 'sha256:' + receipt['transferZipSha256']
            or admission['transfer'].get('status') != 'completed'
            or admission['transfer'].get('conclusion') != 'success'):
        raise ValueError('Frozen transfer admission is not successful or differs')
    original = read(root / 'portable/original-cloud-build-state.json')
    if (not original.get('buildCompleted') or not original.get('packageCompleted')
            or original.get('buildExitCode') != 0 or original.get('packageSha256') != receipt['packageSha256']
            or original.get('sourceBase') != pins['base'] or original.get('patchSha256') != pins['sha256']):
        raise ValueError('Original successful cloud build receipt differs')
    version = tomllib.loads((root / 'portable/engine-Cargo.toml').read_text())['workspace']['package']['version']
    if version != receipt['version']:
        raise ValueError('Imported version metadata changed')
    package = Path(receipt['package'])
    if package != root / 'portable' / PACKAGE or sha(package) != receipt['packageSha256']:
        raise ValueError('Imported GNU release archive changed')
    engine = root / 'package'
    manifest = read(engine / 'manifest.json')
    inventory = indexed(manifest['files'])
    paths = list(engine.rglob('*'))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths):
        raise ValueError('Extracted GNU package contains an alias or special file')
    actual = {p.relative_to(engine).as_posix() for p in paths if p.is_file()}
    if actual != set(inventory) | {'manifest.json'}:
        raise ValueError('Extracted GNU package inventory changed')
    for record in inventory.values():
        checked(engine, record, modes=True)
    # The package manifest itself is frozen separately in inputFiles.
    return receipt, engine


def import_release(args):
    if sha(args.zip) != args.sha256:
        raise ValueError('Transfer ZIP differs from authenticated GitHub artifact digest')
    original = api(args.repository, 'actions/runs/' + args.run_id)
    transfer = api(args.repository, 'actions/runs/' + args.transfer_run_id)
    artifact = api(args.repository, 'actions/artifacts/' + str(args.artifact_id))
    check_run(original, args.repository, args.run_id, args.commit)
    check_run(transfer, args.repository, args.transfer_run_id, args.transfer_commit)
    if (artifact.get('digest') != 'sha256:' + args.sha256 or artifact.get('expired')
            or artifact.get('workflow_run', {}).get('id') != int(args.transfer_run_id)
            or args.zip.stat().st_size != artifact['size_in_bytes']):
        raise ValueError('Transfer artifact identity differs')
    pins = recovery()
    args.output = args.output.resolve()
    args.output.mkdir(exist_ok=False)
    portable = args.output / 'portable'
    portable.mkdir()
    with zipfile.ZipFile(args.zip) as stream:
        rows = stream.infolist()
        names = [name(row.filename) for row in rows]
        if len(names) != len(set(names)) or len(rows) > 200 or sum(p.file_size for p in rows) > 500 * 1024 ** 2:
            raise ValueError('Duplicate or oversize transfer ZIP')
        for row in rows:
            mode = row.external_attr >> 16
            if row.is_dir() or stat.S_ISLNK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                raise ValueError('Transfer ZIP contains a non-regular file')
            target = portable / row.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with stream.open(row) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
    transfer_receipt = read(portable / 'cloud-transfer.json')
    transfer_files = indexed(transfer_receipt['files'])
    if (transfer_receipt.get('schema') != 'codex.gnu-cloud-transfer.v1'
            or {p.relative_to(portable).as_posix() for p in portable.rglob('*') if p.is_file()}
            != set(transfer_files) | {'cloud-transfer.json'}):
        raise ValueError('Transfer inventory is not exact')
    for record in transfer_files.values():
        checked(portable, record)
    if transfer_receipt.get('originalRunId') != args.run_id:
        raise ValueError('Transfer does not identify the requested original run')
    cloud = read(portable / 'cloud-build.json')
    state = read(portable / 'original-cloud-build-state.json')
    if (cloud.get('schema') != 'codex.gnu-cloud-output.v1' or cloud.get('repository') != args.repository
            or cloud.get('commit') != args.commit or cloud.get('runId') != args.run_id
            or cloud.get('sourceBase') != pins['base'] or cloud.get('patchSha256') != pins['sha256']
            or cloud.get('rust') != '1.95.0' or cloud.get('target') != TARGET
            or cloud.get('androidExecuted') is not False or cloud.get('qualifiedCandidate') is not False):
        raise ValueError('Cloud output source/target/provenance differs')
    cloud_files = indexed(cloud['files'])
    for filename in (PACKAGE, 'SHA256SUMS', 'engine-Cargo.toml', 'original-cloud-build-state.json'):
        checked(portable, cloud_files[filename])
    if (state.get('schema') != 'codex.gnu-engine-build.v1' or not state.get('buildCompleted')
            or not state.get('packageCompleted') or state.get('buildExitCode') != 0
            or state.get('packageSha256') != args.package_sha256
            or sha(portable / PACKAGE) != args.package_sha256
            or state.get('sourceBase') != pins['base'] or state.get('patchSha256') != pins['sha256']
            or state.get('target') != TARGET or '--locked' not in state.get('buildCommand', [])):
        raise ValueError('No matching successful locked cloud build/package')
    with tarfile.open(portable / PACKAGE, 'r:gz') as stream:
        manifest, members = package_members(stream, pins)
        engine = args.output / 'package'
        engine.mkdir()
        for member in members:
            target = engine / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with stream.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode)
    if read(engine / 'recovery-manifest.json') != pins or sha(engine / 'engine.patch') != pins['sha256']:
        raise ValueError('Embedded recovery inputs differ')
    for filename, key in (('SOURCES.json', 'sourceManifestSha256'), ('DEPENDENCIES.json', 'dependencyManifestSha256'),
                          ('DEPENDENCY-INPUTS.json', 'dependencyInputsSha256'), ('DEPENDENCY-CHECKS.json', 'dependencyChecksSha256')):
        if sha(engine / filename) != state[key]:
            raise ValueError('Original build provenance differs: ' + filename)
    compatibility = read(engine / 'static-compatibility.json')
    if not compatibility.get('passed') or any(not row['passed'] for row in compatibility['binaries']):
        raise ValueError('Cloud static ELF compatibility did not pass')
    binaries = {row['binary']: row for row in compatibility['binaries']}
    for filename in ('codex', 'codex-code-mode-host'):
        if sha(engine / filename) != binaries[filename]['sha256']:
            raise ValueError('Packaged binary differs from ELF compatibility check')
    version = tomllib.loads((portable / 'engine-Cargo.toml').read_text())['workspace']['package']['version']
    source_files = indexed(read(engine / 'SOURCES.json'))
    if sha(portable / 'engine-Cargo.toml') != source_files['codex-rs/Cargo.toml']['sha256']:
        raise ValueError('Version metadata differs from the frozen recovered source')
    write(args.output / 'github-admission.json', {'original': original, 'transfer': transfer, 'artifact': artifact})
    inputs = [p for p in sorted(portable.rglob('*')) if p.is_file()]
    inputs += [engine / 'manifest.json', args.output / 'github-admission.json']
    receipt = {'schema': SCHEMA, 'repository': args.repository, 'runId': args.run_id, 'commit': args.commit,
        'runUrl': original['html_url'], 'sourceBase': pins['base'], 'patchSha256': pins['sha256'],
        'target': TARGET, 'version': version, 'package': str(portable / PACKAGE),
        'packageSha256': args.package_sha256, 'transferZipSha256': args.sha256,
        'inputFiles': [{'path': p.relative_to(args.output).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in inputs],
        'androidExecuted': False, 'qualifiedCandidate': False, 'resumableCargoState': False,
        'symbols': transfer_receipt['symbols'], 'scope': 'Validated cloud GNU packaging input, not a local compile receipt'}
    path = args.output / 'cloud-import.json'
    write(path, receipt)
    load_import(path)
    print(json.dumps({'receipt': str(path), 'version': version, 'packageSha256': args.package_sha256}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('zip', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    for key in ('sha256', 'package-sha256', 'repository', 'run-id', 'commit', 'transfer-run-id', 'transfer-commit'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--artifact-id', type=int, required=True)
    import_release(parser.parse_args())
