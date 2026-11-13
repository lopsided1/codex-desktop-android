# Native ARM64 first-install image build

`.github/workflows/phone-image-arm64.yml` runs on the disposable native
`ubuntu-24.04-arm` VM. Push an explicitly prepared `build/phone-rootfs-*` branch;
the job never edits the default branch, accesses a phone, installs an APK or
configures an Android signing identity. Repository and Actions permissions are
read-only. No personal account, project, initialized keyring or home is uploaded.

## Explicit inputs

`.ci-inputs/phone-rootfs/inputs.json` binds the successful GNU build and transfer
run IDs/commits, GitHub artifact digest and original runtime package digest.
`gnu_cloud_import.py` verifies the actual completed build, source recovery pins,
exact executable pair and provenance. Rust is **not** recompiled.

The Mesa 26.2.2 archive from the existing local source build is reused as exact
Git blob chunks on this independent build branch. Both individual chunk hashes
and the reassembled archive hash are checked. This job does not claim to rebuild
or device-qualify Mesa. The exact official client is downloaded directly from
its upstream URL, SHA-256/size checked and independently authenticated with the
pinned full origin-key fingerprint. Only that public verification key and a
descriptor are inputs; no user signing key or client login state is consumed.

## Native preparation, not device testing

The Debian 13 base is built from authenticated Debian repositories using the
maintained builder. Host read-only mount/chroot probes, source checks and package
provenance remain enabled. Version metadata accurately identifies native ARM64
rather than claiming QEMU execution. Live signed Debian package versions are not
represented as a bit-for-bit pinned historical rootfs.

`guest_build.py` gives each APT configuration operation a private mount namespace
and temporary `/dev`, devpts and `/proc`. It accepts only new, private, root-owned
`/var/tmp/codex-phone-image-*` trees. It does not bind the VM's complete device
tree, mount phone storage or leave device nodes in the exported image. Package
service startup is inhibited and the policy removed before export. APT package
and repository authentication are never disabled.

Stages emit live output and 30-second resource heartbeats. Base/image stages
have bounded timeouts; a live parent process is not treated as completion.
Failure logs are uploaded separately and cannot be mistaken for a complete image.
Old blocked PRoot attempts and caches are retained, not silently adopted.

## Outputs and local continuation

Successful output is a **separate** `codex-phone-rootfs.tar.gz` plus the release
descriptor/inventory to embed in the APK. It contains the exact imported GNU pair,
authenticated desktop client, GPU and guest launch inputs, but no activated user.

Because the connector accepts downloads only below 512 MiB, the archive is split
into at most eight 384 MiB parts. Each part has independent SHA-256/size in
`phone-cloud.json`; concatenation must also match the complete archive digest and
the embedded release descriptor. The metadata artifact includes authenticated
package-index/signature receipts, source hashes and failure diagnostics, not raw
user profiles or credentials. Artifacts are retained for seven days.

After download, verify the successful workflow's repository/commit/run identity,
GitHub artifact digests, all parts, complete archive, immutable inventory and GNU
pair linkage. Only then select these assets for `build-local-full.py`. The APK
remains the explicit r30 local debug build, not a reviewed r29/update candidate.
The first-install tarball is not embedded in the APK. A real upgrade still needs
the installed signing certificate checked before any overwrite; never uninstall
to bypass a certificate mismatch. Device desktop startup, backend response,
managed local-command/PTY/JIT execution and account/project preservation remain
separate, unperformed device checks.
