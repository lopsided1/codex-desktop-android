# GNU ARM64 backend on GitHub Actions

Use `.github/workflows/gnu-engine-arm64.yml` to compile the GNU/Linux controller
and its matching Code Mode host outside Android/PRoot. This does not rebuild
Android executors, the proprietary desktop client, the APK or the phone image.
No Android device, signing key, account or project data is required or uploaded.

## Trigger and host

- On a writable fork, push a new `build/gnu-arm64-*` branch containing the workflow
  and CI source changes. That branch's push starts the build without modifying
  `main`. Only named GNU source/workflow changes trigger this push workflow.
- Alternatively, once the workflow is on the default branch, select **Actions →
  GNU engine ARM64 → Run workflow**. The default is two Cargo jobs; one reduces
  peak memory. No paid larger-runner label is selected automatically.
- The job uses the native `ubuntu-24.04-arm` VM, not QEMU or PRoot. GitHub documents
  4 CPUs / 16 GB RAM for public repositories and 2 CPUs / 8 GB for private ones.
  See [runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
  Private 8 GB VMs are rejected by the 12 GiB RAM preflight.
- The documented standard SSD allowance is 14 GB. Existing guarded cleanup
  removes unused VM SDKs/toolchains only; compilation requires **20 GiB actually
  free afterward** and fails early if unavailable. A larger disk may therefore
  be needed. Local/device storage is never cleaned by this workflow.

## Source, cache and build checks

The workflow retains Rust **1.95.0**, `aarch64-unknown-linux-gnu`, the current
`recovery/engine/manifest.json` commit/patch hashes, `--locked`, GNU OpenSSL
**3.6.3** source verification and the upstream paired V8 artifact verifier.
It does not substitute an unpatched stock `codex` download or a musl/Bionic build.

A stable linked Git worktree permits useful Cargo cache reuse. The maintained
builder reconstructs a separate recovery snapshot and compares **all** source
files/modes/links before admitting that worktree. Parent Git indexes are not used
for patch application. Actual compiler versions, commands, exit codes, sources,
dependencies, memory/disk and failure logs are retained. An interrupted or failed
compile is never marked complete. Partial Cargo work can be cached for a retry;
successful release files are separately snapshotted before cache reuse.

The default release ThinLTO and debug-symbol retention remain unchanged. Build
and packaging run as the ordinary VM user. Privileged operations are limited to
disposable-VM prerequisite installation and a small signed Debian 13 library
baseline; that baseline is **not** the complete first-install desktop image.
Both GNU binaries' ELF dependencies and strong versioned imports must resolve
against its actual libraries before release packaging succeeds.

## Downloaded artifact

`gnu-engine-arm64-<run-id>-<attempt>` contains, after a successful run:

- `output/codex-gnu-engine-aarch64.tar.gz`: matched executables and provenance;
- `output/codex-gnu-engine-aarch64-symbols.tar.gz`: separate retained symbols;
- `output/SHA256SUMS`, `output/cloud-build.json` and original cloud build receipt;
- `output/apk-assets/gnu-engine/`: ready matched GNU assets for APK selection;
- source, dependency and ELF-compatibility receipts and CI diagnostics.

Artifact uploads also run after a failure; their presence alone is **not** build
success. Check the job conclusion and completed build/package receipts. Checksums
are integrity evidence, not an independently trusted release signature. Verify
the repository, run and source commit when obtaining the artifact.

The original state contains VM-local paths; do not pass it directly to a local
resume command or edit completion flags to make an import pass. The staged GNU
asset directory is portable for `-PcodexGnuEngineAssets=...`. Integrating the pair
into the local first-install image additionally needs a validated artifact import
and the existing complete image/APK checks. Android desktop start, backend response
and local-command execution still need independent device results.

Local configuration tests (no cloud account or downloads):

```sh
python3 -B tools/ci/gnu-engine-cloud.py plan
python3 -B -m unittest discover -s tests -p test_gnu_engine_cloud.py -v
```
