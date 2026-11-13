"""Assemble a new complete first-install image from explicit authenticated inputs.

Run as Linux build-host root. This never reads a phone, user home or login state.
The output descriptor is a release input for the APK, not download metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import re
import stat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'executor'))
from gnu_cloud_import import SCHEMA as CLOUD_IMPORT_SCHEMA, load_import

import guest_bundle
import official_client_package as client
import phone_image as image
import guest_build

ROOT = Path(__file__).resolve().parents[2]
CLIENT_FINGERPRINT = "3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4"
CLIENT_VERSION = "26.1103.31037"


def run(args, **kwargs):
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def authenticated_client(upstream, output):
    """The pinned official signing identity authenticates index and package bytes."""
    verified = subprocess.check_output([
        "gpgv", "--status-fd", "1", "--keyring", str(upstream / "repository-key.gpg"),
        str(upstream / "InRelease")], text=True)
    if f"[GNUPG:] VALIDSIG {CLIENT_FINGERPRINT} " not in verified:
        raise ValueError("Unexpected official repository signer")
    index = (upstream / "Packages.arm64").read_bytes()
    binding = f" {hashlib.sha256(index).hexdigest()} {len(index):16d} main/binary-arm64/Packages"
    # Whitespace is representational; the signed SHA-256 and length are exact.
    signed = (upstream / "InRelease").read_text().split("SHA256:\n", 1)[1].split("SHA512:", 1)[0]
    if not any(line.split() == binding.split() for line in signed.splitlines()):
        raise ValueError("Official ARM64 package index is not bound by the signature")
    records = [client.deb822(record) for record in index.split(b"\n\n") if record.strip()]
    records = [record for record in records if record.get("package") == "chatgpt" and record.get("architecture") == "arm64"]
    if len(records) != 1:
        raise ValueError("Official package index is ambiguous")
    record = records[0]
    source = upstream / Path(record["filename"]).name
    descriptor = client.descriptor({"format": client.FORMAT, "sourceUrl": client.SOURCE_URL,
        "sourceDocument": client.SOURCE_DOCUMENT, "package": "chatgpt", "architecture": "arm64",
        "version": record["version"], "sha256": record["sha256"], "bytes": int(record["size"]),
        "maxTarBytes": 3 * 1024 ** 3, "maxMembers": 100000})
    with source.open("rb") as stream:
        inspected = client.inspect(stream, descriptor)
    (output / "official-client-inspection.json").write_bytes(image.canonical(inspected))
    for name in ("InRelease", "Packages.arm64", "repository-key.gpg"):
        shutil.copy2(upstream / name, output / name)
    return source, descriptor


def authenticated_client_origin(upstream, output):
    """Authenticate the exact client using its independently pinned origin key.

    This separate explicit route does not invent a historical signed APT index
    or trust the caller's policy files. The policy is constructed here and both
    package/control bytes remain subject to the normal package inspector.
    """
    descriptor = client.descriptor(json.loads((upstream / 'authenticated-input.json').read_bytes(),
                                              object_pairs_hook=client.unique_json))
    if descriptor['version'] != CLIENT_VERSION:
        raise ValueError('Origin-signature input is not the matching desktop client version')
    source = upstream / ('chatgpt_' + CLIENT_VERSION + '_arm64.deb')
    key = upstream / 'repository-key.gpg'
    home = output / 'origin-gpg-home'
    home.mkdir(mode=0o700)
    public = subprocess.check_output(['gpg', '--batch', '--homedir', str(home), '--with-colons',
                                      '--show-keys', str(key)], text=True)
    fingerprints = re.findall(r'(?m)^fpr:::::::::([0-9A-F]+):', public)
    if not fingerprints or fingerprints[0] != CLIENT_FINGERPRINT:
        raise ValueError('Client origin signing key fingerprint differs')
    identity = CLIENT_FINGERPRINT[-16:]
    policy = output / 'origin-policies' / identity
    rings = output / 'origin-keyrings' / identity
    policy.mkdir(parents=True)
    rings.mkdir(parents=True)
    shutil.copy2(key, rings / 'pubring.gpg')
    policy_file = policy / 'openai.pol'
    policy_file.write_text('<?xml version="1.0"?>\n'
        '<Policy xmlns="https://www.debian.org/debsig/1.0/">'
        '<Origin Name="OpenAI" id="' + identity + '" Description="Pinned OpenAI signing key"/>'
        '<Selection><Required Type="origin" File="pubring.gpg" id="' + identity + '"/></Selection>'
        '<Verification MinOptional="0"><Required Type="origin" File="pubring.gpg" id="'
        + identity + '"/></Verification></Policy>\n')
    verified = subprocess.check_output(['debsig-verify', '--policies-dir', str(policy.parent),
                                        '--keyrings-dir', str(rings.parent), str(source)],
                                       text=True, stderr=subprocess.STDOUT)
    (output / 'client-origin-verification.txt').write_text(verified)
    with source.open('rb') as stream:
        inspected = client.inspect(stream, descriptor)
    (output / 'official-client-inspection.json').write_bytes(image.canonical(inspected))
    (output / 'client-authentication.json').write_bytes(image.canonical({
        'schema': 'codex.official-client-origin-authentication.v1',
        'fingerprint': CLIENT_FINGERPRINT, 'packageSha256': descriptor['sha256'],
        'policySha256': image.digest(policy_file), 'keySha256': image.digest(rings / 'pubring.gpg'),
        'scope': 'Actual debsig origin verification plus exact package inspection; no signed APT index claimed'}))
    return source, descriptor


def install_guest_sources(root):
    for source, (destination, mode) in guest_bundle.SOURCES.items():
        if not destination.startswith("payload/"):
            continue
        target = root / destination.removeprefix("payload/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes().replace(b"\r\n", b"\n"))
        target.chmod(0o600 if target.name in ("initialize_keyring.py", "supervise_keyring.py") else mode)
    for name in ("install-workspace-provider.py", "codex-workspace-provider.cjs",
                 "workspace-node-check.cjs", "workspace-python-check.py", "workspace-render-check.py"):
        target = root / "usr/local/lib/codex" / name
        target.write_bytes((ROOT / "tools/runtime" / name).read_bytes().replace(b"\r\n", b"\n"))
        target.chmod(0o644)


def engine_inputs(args):
    deadline = time.monotonic() + args.wait_engine_seconds
    while True:
        state = json.loads(args.engine_state.read_text())
        if state.get('schema') == CLOUD_IMPORT_SCHEMA:
            return load_import(args.engine_state)
        if state.get("buildCompleted") and state.get("packageCompleted"):
            break
        if state.get("buildExitCode") not in (None, 0) or time.monotonic() >= deadline:
            raise ValueError("A successfully built and packaged GNU engine is required")
        time.sleep(10)
    engine = Path(state["build"]) / "package"
    if image.digest(state["package"]) != state["packageSha256"]:
        raise ValueError("GNU engine release archive differs from its build state")
    with tarfile.open(state["package"], "r:gz") as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
    for expected in manifest["files"]:
        name = image.path_name(expected["path"])
        if ("sha256" not in expected or (engine / name).is_symlink()
                or image.digest(engine / name) != expected["sha256"]
                or (engine / name).stat().st_size != expected["bytes"]):
            raise ValueError("GNU engine package changed: " + name)
    return state, engine


def cleanup_proot_devices(root):
    """Remove only empty placeholders left by an interrupted PRoot endpoint bind."""
    root = Path(root)
    device = root / 'dev'
    info = device.lstat()
    if device.resolve(strict=True) != device or not stat.S_ISDIR(info.st_mode):
        raise ValueError('Guest /dev must be a real disposable directory')
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = line.split()[4].replace('\\040', ' ')
        if mount == str(root) or mount.startswith(str(root) + '/'):
            raise ValueError('Cannot clean a mounted disposable guest')
    pending = list(device.iterdir())
    for path in pending:
        info = path.lstat()
        if path.name not in ('null', 'random', 'urandom') or not stat.S_ISREG(info.st_mode) or info.st_size != 0:
            raise ValueError('Unknown nonempty/special device state in interrupted guest')
    for path in pending:
        path.unlink()


def assemble(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use build-host Linux root; no Android root is needed")
    resume = getattr(args, 'resume', False)
    if args.output.exists() and not resume:
        raise FileExistsError("Output must be a new release directory; explicitly resume an interrupted disposable build")
    if resume and not args.output.is_dir():
        raise ValueError("Resume requires an existing builder output")
    if (args.output / 'assets/phone-runtime/release.json').exists():
        raise FileExistsError("A completed image is never overwritten")
    args.output.mkdir(mode=0o755, exist_ok=resume)
    evidence = args.output / "evidence"
    evidence.mkdir(exist_ok=resume)
    if image.digest(args.base) != args.base_sha256 or image.digest(args.gpu) != args.gpu_sha256:
        raise ValueError("Explicit base/GPU release input digest differs")
    authentication = getattr(args, 'official_authentication', 'apt-index')
    identity = {'baseSha256': args.base_sha256, 'gpuSha256': args.gpu_sha256,
        'officialDescriptorSha256': image.digest(args.official_input / 'authenticated-input.json') if authentication == 'origin-signature' else image.digest(args.official_input / 'InRelease'),
        'officialKeySha256': image.digest(args.official_input / 'repository-key.gpg'),
        'engineState': str(args.engine_state.resolve()), 'authentication': authentication,
        'probeMode': getattr(args, 'probe_mode', 'mount')}
    journal_path = evidence / 'resume-state.json'
    recipe = {name: image.digest(ROOT / 'tools/install' / name) for name in
              ('build-phone-image.py', 'phone_image.py', 'proot_archive.py', 'verify_rootfs.py', 'guest_build.py')}
    journal = json.loads(journal_path.read_bytes()) if resume and journal_path.exists() else None
    if journal is not None and (journal['identity'] != identity or journal['recipe'] != recipe):
        raise ValueError('Interrupted phone build inputs/recipe changed; retain it and choose a new output')
    auth_evidence = evidence
    if resume:
        auth_evidence = evidence / ('origin-reverification-' + str(time.time_ns()))
        auth_evidence.mkdir()
    package_source, descriptor = (authenticated_client_origin(args.official_input, auth_evidence)
                                  if authentication == 'origin-signature' else
                                  authenticated_client(args.official_input, auth_evidence))
    if resume:
        work = Path((evidence / 'build-directory.txt').read_text().strip())
        if work.parent != Path('/var/tmp') or not work.name.startswith('codex-phone-image-'):
            raise ValueError("Resume is limited to this builder's disposable /var/tmp trees")
        root = work / 'rootfs'
        for directory in (work, root, evidence):
            info = directory.lstat()
            if directory.resolve(strict=True) != directory or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('Resume directories must be real, root-owned and not group/other writable')
    else:
        work = Path(tempfile.mkdtemp(prefix="codex-phone-image-", dir="/var/tmp"))
        root = work / "rootfs"
        root.mkdir()
        (evidence / "build-directory.txt").write_text(str(work) + "\n")
        run(["tar", "--extract", "--gzip", "--file", args.base, "--directory", root, "--numeric-owner"])
    neutral_dns = evidence / 'neutral-resolv.conf'
    if not neutral_dns.exists():
        if resume:
            # Adopt the earlier interrupted format only while it is still a
            # pristine base. Never infer trust from a partially activated guest.
            status = (root / 'var/lib/dpkg/status').read_text()
            if '\nPackage: chatgpt\n' in '\n' + status:
                raise ValueError('Legacy resume requires a pristine pre-client root or a recorded phase journal')
            with tarfile.open(args.base, 'r:gz') as archive:
                neutral_dns.write_bytes(archive.extractfile('./etc/resolv.conf').read())
        else:
            neutral_dns.write_bytes((root / 'etc/resolv.conf').read_bytes())
    if journal is None:
        pending_client = root / 'tmp/codex-official-client.deb'
        if pending_client.exists():
            if pending_client.is_symlink() or not pending_client.is_file() or image.digest(pending_client) != descriptor['sha256']:
                raise ValueError('Unknown pending client input in legacy disposable build')
            # Only a disposable, byte-authenticated copy; the signed upstream
            # archive remains intact and is restaged after pristine validation.
            pending_client.unlink()
        (root / 'etc/resolv.conf').write_bytes(neutral_dns.read_bytes())
        if getattr(args, 'probe_mode', 'mount') == 'proot':
            cleanup_proot_devices(root)
        probe = subprocess.check_output(list(map(str, [sys.executable, "-B", ROOT / "tools/install/verify_rootfs.py", root,
             '--probe-mode', getattr(args, 'probe_mode', 'mount')])))
        previous_probe = evidence / "pristine-base-verification.json"
        if previous_probe.exists() and previous_probe.stat().st_size:
            shutil.copy2(previous_probe, evidence / ('pristine-base-verification-before-' + str(time.time_ns()) + '.json'))
        previous_probe.write_bytes(probe)
        journal = {'identity': identity, 'recipe': recipe, 'clientInstalled': False}
        journal_path.write_bytes(image.canonical(journal))
    # Complete the package dependency closure on the disposable build host.
    # APT keeps signature validation enabled and saves every downloaded .deb.
    dns = root / "etc/resolv.conf"
    original_dns = neutral_dns.read_bytes()
    dns.write_bytes(Path("/etc/resolv.conf").read_bytes())
    source = root / "tmp/codex-official-client.deb"
    if not journal['clientInstalled'] and (not source.is_file() or image.digest(source) != descriptor['sha256']):
        shutil.copyfile(package_source, source)
    policy = root / 'usr/sbin/policy-rc.d'
    policy_data = b'#!/bin/sh\n# Disposable Codex image build: never start host services.\nexit 101\n'
    if not journal['clientInstalled']:
        if policy.exists() and policy.read_bytes() != policy_data:
            raise ValueError('Refusing to replace an unknown build service policy')
        policy.write_bytes(policy_data)
        policy.chmod(0o755)
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LC_ALL="C.UTF-8")
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        env.pop(name, None)
    guest = None
    if getattr(args, 'probe_mode', 'mount') == 'proot':
        # Host Bionic PRoot keeps its loader environment only until env -i
        # starts the GNU guest. Bind endpoints, not host files or real mounts.
        guest = ['proot', '-0', '-r', root, '-w', '/',
                 '-b', '/dev/null:/dev/null', '-b', '/dev/urandom:/dev/urandom',
                 '-b', '/dev/random:/dev/random', '/usr/bin/env', '-i',
                 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=/root',
                 'LC_ALL=C.UTF-8', 'DEBIAN_FRONTEND=noninteractive', 'PROOT_NO_SECCOMP=1']
        env['PROOT_NO_SECCOMP'] = '1'
    apt = ["/usr/bin/apt-get", "-o", "Acquire::ForceIPv4=true",
           "-o", "Acquire::Languages=none", "-o", "Acquire::AllowInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false",
           "-o", "Dpkg::Use-Pty=false", "-o", "Binary::apt::APT::Keep-Downloaded-Packages=true"]
    if guest is not None:
        apt = [*guest, *apt]
    else:
        apt = guest_build.command(root, apt)
    (evidence / "client-apt-command.json").write_bytes(image.canonical(list(map(str, apt))))
    if not journal['clientInstalled']:
        with (evidence / "client-apt.log").open("a" if resume else "w") as log:
            run([*apt, "update"], env=env, stdout=log, stderr=subprocess.STDOUT)
            run([*apt, "install", "-y", "--no-install-recommends", "/tmp/codex-official-client.deb"],
                env=env, stdout=log, stderr=subprocess.STDOUT)
        source.unlink()
        if policy.read_bytes() != policy_data:
            raise ValueError('Build service policy was unexpectedly replaced')
        policy.unlink()
        # A newly pulled-in systemd package may generate a build-host identity.
        # This is an inactive new image, never an existing user installation.
        for name in ('etc/machine-id', 'var/lib/dbus/machine-id'):
            identity_file = root / name
            if identity_file.is_file() and not identity_file.is_symlink():
                identity_file.write_bytes(b'')
    dns.write_bytes(original_dns)
    if getattr(args, 'probe_mode', 'mount') == 'proot':
        cleanup_proot_devices(root)
    installed = subprocess.check_output(["dpkg-query", "--admindir=" + str(root / "var/lib/dpkg"),
        "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"])
    (evidence / "complete-installed-packages.tsv").write_bytes(installed)
    extra = evidence / "additional-debs"
    extra.mkdir(exist_ok=resume)
    for archive in (root / "var/cache/apt/archives").glob("*.deb"):
        shutil.copy2(archive, extra / archive.name)
        archive.unlink()
    shutil.copytree(root / "var/lib/apt/lists", evidence / "complete-apt-lists", symlinks=True,
                    ignore=shutil.ignore_patterns(".l2s.*"), dirs_exist_ok=resume)
    # Keep the official client unchanged. Its adapter is admitted at launch;
    # optional workspace distribution selection remains an explicit later input.
    with package_source.open("rb") as stream:
        inspected = client.inspect(stream, descriptor)
    for item in inspected["files"]:
        if item["kind"] == "file" and image.digest(root / item["path"]) != item["sha256"]:
            raise ValueError("Installed official client differs: " + item["path"])
    journal['clientInstalled'] = True
    journal_path.write_bytes(image.canonical(journal))
    print("Official client installed and revalidated; waiting for the separate GNU engine package", flush=True)
    state, engine = engine_inputs(args)
    install_guest_sources(root)
    with tarfile.open(args.gpu, "r:gz") as archive:
        if any(not x.name.startswith("opt/codex-gpu/mesa-26.2.2-codex5") for x in archive.getmembers()):
            raise ValueError("GPU payload has an unexpected prefix")
        archive.extractall(root, filter="data")
    destination = root / "usr/local/libexec/codex"
    destination.mkdir(parents=True, exist_ok=True)
    for name, target in (("codex", "codex-native"), ("codex-code-mode-host", "codex-code-mode-host")):
        shutil.copy2(engine / name, destination / target)
        (destination / target).chmod(0o755)
    image.require_pristine_profile(root)
    immutable = image.inventory(root, ignore_proot_metadata=getattr(args, "probe_mode", "mount") == "proot")
    assets = args.output / "assets/phone-runtime"
    assets.mkdir(parents=True, exist_ok=resume)
    inventory = image.canonical(immutable)
    (assets / "inventory.json").write_bytes(inventory)
    archive = args.output / "codex-phone-rootfs.tar.gz"
    # Materialize hardlinked files in this separate image. This avoids requiring
    # Android link(2) and preserves guest symlinks without following host paths.
    if getattr(args, "probe_mode", "mount") == "proot":
        from proot_archive import write_archive
        write_archive(root, archive, evidence / "proot-export.json")
    else:
        with archive.open("xb") as output:
            tar = subprocess.Popen(["tar", "--sort=name", "--hard-dereference", "--numeric-owner",
                "--format=posix", "--pax-option=delete=atime,delete=ctime", "-C", root, "-cf", "-", "."], stdout=subprocess.PIPE)
            run(["gzip", "-n", "-6"], stdin=tar.stdout, stdout=output)
            tar.stdout.close()
            if tar.wait() != 0:
                raise RuntimeError("Phone image tar failed")
    spec = image.inspect_archive(archive, image.digest(archive))
    release = {"format": image.FORMAT, "archive": archive.name, "spec": spec,
        "inventorySha256": hashlib.sha256(inventory).hexdigest(), "inventoryBytes": len(inventory),
        "initializerSha256": image.digest(root / "usr/local/lib/codex/install/initialize_keyring.py"),
        "supervisorSha256": image.digest(root / "usr/local/lib/codex/install/supervise_keyring.py"),
        "baseSha256": args.base_sha256, "gpuSha256": args.gpu_sha256,
        "client": descriptor, "clientAuthentication": authentication,
        "enginePackageSha256": state["packageSha256"],
        "accountIncluded": False, "keyringIncluded": False, "androidExecuted": False}
    (assets / "release.json").write_bytes(image.canonical(release))
    shutil.copy2(args.engine_state, evidence / "engine-build-state.json")
    (evidence / "source-files.json").write_bytes(image.canonical({
        str(p.relative_to(ROOT)): image.digest(p) for p in [Path(__file__), ROOT / "tools/install/phone_image.py", ROOT / "tools/install/proot_archive.py", ROOT / "tools/install/guest_build.py",
        *[ROOT / source for source in guest_bundle.SOURCES]]}))
    print(json.dumps({"output": str(args.output), "image": spec, "androidExecuted": False}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "gpu", "engine-state", "official-input", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("base-sha256", "gpu-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--resume", action="store_true", help="Resume only this builder's inactive disposable image, retaining authenticated inputs and phase evidence")
    parser.add_argument("--wait-engine-seconds", type=int, default=0)
    parser.add_argument("--official-authentication", choices=('apt-index', 'origin-signature'), default='apt-index')
    parser.add_argument("--probe-mode", choices=('mount', 'proot'), default='mount')
    assemble(parser.parse_args())
