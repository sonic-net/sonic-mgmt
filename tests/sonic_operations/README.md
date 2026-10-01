# sonic-operations package tests

Delivery validation of **the latest packages published by CI**, using the
`sonic-operations` pipeline's shared ACS folder. All three testcase modules select the route in
code. **Only testcase paths are needed; no image-server or package URL arguments.**
Each pytest run pins the first valid publication identity separately for each
package and rejects a change mid-run. The former build180385146 delivery freeze
has been deliberately removed; its build ID, commit and hashes are not defaults.

The same three paths select **19 package-validation cases by default**:
15 curl/download/integrity cases, 2 direct CPHC install/corruption cases, and
2 SUP cases (integrity and direct package execution). The other **7 production-consumer integration cases are
deselected before fixture setup**, not counted as passed or skipped. This is an
intentional temporary coverage profile while real consumer scripts are unavailable,
not a substitute for production end-to-end validation.

**Temporary BJW exception:** the default conditional-mark configuration skips only
these three modules for inventories `bjw`, `bjw2`, and `bjw3` while package
image-server availability is pending. Package fixtures/downloads do not start:
the default profile reports 19 skipped and 7 deselected, not 19 passed. With
consumer integration enabled, all 26 selected cases are skipped in BJW.
Other inventories, including `str2` and `strtk5`, are unchanged.

| File | Default cases | Optional integration cases |
|---|---|---|
| `test_package_download_nightly.py` | 15 curl/download/integrity cases for both packages | None |
| `test_cphc_package_nightly.py` | 2 direct installer/corruption cases | 2 real-preload cases |
| `test_postupgrade_package_nightly.py` | Integrity and direct package execution | Wrapper run, cached-wrapper recovery, 2 real-preload cases, end-to-end flow |

`--sonic_operations_integration` selects all **26 cases** (19 package + 7 consumer).
The 7 retain their existing names and assertions. They require the genuine
`preload_firmware` and/or Networking-Metadata wrapper; absent scripts still cause
explicit skips. Cached-wrapper recovery remains a deliberate coverage-gap skip
even with opt-in, until a supported controlled recovery endpoint exists.
Selecting an integration node directly also requires the flag.

> **Warning**
> Default `test_postupgrade_package_runs_directly`, and optional real-wrapper/end-to-end
> cases, execute the real
> `postupgrade_actions` on the DUT. That script applies patches, rewrites
> configuration and restarts services, and has no dry-run mode. Run it only on a
> testbed where that is acceptable, or pass `--postupgrade_skip_execute`.

## CPHC (`test_cphc_package_nightly.py`)

1. download the tarball and its `.md5` from the image server
2. verify the md5 against the bytes as they landed on the DUT
3. unpack, and confirm the tarball contains `installer.py` and the wheel this OS
   version needs
4. `installer.py --install`, which also exercises the py2/py3 wheel selection
5. `installer.py --validate`, plus `pip show` to confirm the expected version
6. sample DUT UTC time once using `date -u`, and run
   `sonic_critical_process_checker_caller -m '<DUT-now-minus-1-hour>,<DUT-now>'`
   with `%m/%d/%Y %H:%M:%S` timestamps exactly 3600 seconds apart; require `succeeded: true`,
   an empty `execution_error`, and a fresh report matching stdout; device-health
   findings remain informational
7. `installer.py --uninstall`, and confirm the package is gone

The time interval uses the DUT clock, not the runner clock or a future end time.
This is package smoke coverage, not evidence of an actual upgrade or a requirement
for upgrade events to exist in that interval.

Steps 1-7 drive the package directly. Two optional integration tests hand the published bytes to
the **real `preload_firmware`** from `sonic-metadata` - the script that actually
accepts or rejects a CPHC package on a device - and assert it accepts a good package
and rejects a corrupted one. Re-implementing that check can only ever test our
reading of it, so the genuine script is exercised too.

`preload_firmware` cannot be pointed at our publish path: `download_util()`
derives the location from the host alone and always appends `/networkfirmware/ACS/`.
So the downloaded package is re-served on the DUT under exactly that layout and the
real script is asked to fetch it. Use `--preload_firmware` or
`--preload_firmware_src` if it is not already installed; the tests skip when it is
absent.

There is no single `preload_firmware`. Two copies ship and they disagree, so the
mirror serves the package at **both** layouts and lets the script pick:

| copy | fetches from | `EXIT_CPHC_DOWNLOAD_FAILURE` |
| --- | --- | --- |
| `sonic-metadata` (hardware proxy) | `/networkfirmware/ACS/<file>` | 33 |
| `Networking-Metadata/.../SONiC` (device) | `/networkfirmware/ACS/sonic-upgrade-packages/<file>` | 34 |

Serving only the flat layout would 404 against the device copy. Which layout a DUT
actually requests is read back from the mirror's access log and logged, so a run
records the variant it met instead of assuming one.

Corruption tests establish a valid download first, corrupt every served layout,
require HTTP200 requests for the corrupt tar and its sidecar, and establish a
valid download again after restoring the bytes. Missing commands, timeouts and
failed HTTP requests cannot count as integrity rejection. Each selected negative
case establishes its own controls; it does not depend on a sibling test passing.

No single rejection code is correct for both copies: both pass the
*name* `EXIT_CPHC_DOWNLOAD_FAILURE` to `download_util` rather than its value, so the
failing path runs `exit EXIT_CPHC_DOWNLOAD_FAILURE`, which bash rejects with
"numeric argument required" and turns into exit 2 - already the code for an HTTP
error. A corrupted package is therefore indistinguishable from a 404 in hardware
proxy telemetry. The additional controls and mirror request evidence distinguish
those causes without changing the consumer's validation algorithm.

Integrity is asserted with the production algorithm, not `md5sum -c`. They are not
equivalent: `download_util()` compares only the hash *field* of each side and strips
CR from the `.md5` first, so it accepts a `.md5` naming a different path, and a
CRLF `.md5`, where `md5sum -c` would fail. The test asserts the check hardware
proxy performs, and separately asserts the `.md5` names the tarball so a human can
still reproduce a failure with `md5sum -c`.

A corrupted-package test at each layer asserts the check rejects bad bytes.

Note `installer.py --validate` exits 0 whether or not the package is installed, so
the test reads its output rather than its return code.

## postupgrade_actions (`test_postupgrade_package_nightly.py`)

Default `test_postupgrade_package_integrity` retains its integrity checks.
The separate default `test_postupgrade_package_runs_directly` uses consumer-style
curl against the lab latest tar/MD5 URLs, verifies coherent buildinfo plus
MD5/SHA256/size before extraction, and extracts to `/tmp/postupgrade-actions`. It then runs:

```bash
cd /tmp/postupgrade-actions
timeout --signal=TERM --kill-after=30s 1800s python ./postupgrade_actions -e <new-UUID>
```

The package execution contract declares `python`, supports `-e/--event-guid`, waits for
420 seconds of uptime (or the T2 stabilization interval), runs its patch list,
saves configuration, checks device health and writes an event-specific report.
The 1800-second outer limit allows stabilization plus patches, with a 30-second
termination grace; it does not change pipeline limits or guarantee every DUT
finishes within that bound. The test requires the fresh report's GUID, package
identity, completed patch/health sequence and exit-code agreement. Caught patch
exceptions and patch failures fail even if a report exists. Reported device-health
failures alone (code125), with no internal execution exception, are informational.
Internal health exceptions represented as `Unknown error` fail. Failures which
the payload itself swallows without encoding them in its report cannot be
independently detected by this smoke test.

This directly exercises the package, **not the unavailable Networking-Metadata
wrapper**. `--postupgrade_skip_execute` skips this case before state/staging/runtime
effects; the separate integrity case remains selected.

With consumer integration opt-in, the module drives the **real production wrapper** -
the `postupgrade_actions` script
Networking-Metadata deploys to devices, which hardware proxy invokes - rather than
reimplementing what it does:

1. stage the published tarball and `.md5` at `/host/postupgrade-binaries/`
2. require a valid MD5 sidecar, matching bytes and a readable archive in the
   staging fixture before any wrapper invocation, including individually selected
   cases (an earlier integrity test is not a prerequisite)
3. run the wrapper, which extracts to `/tmp/postupgrade-actions` and executes the
   real `postupgrade_actions` with an event guid
4. assert the script ran to completion by finding its report at
   `/host/sonic-upgrade-reports/postupgrade_actions.<guid>.json`

`test_wrapper_rejects_corrupted_cached_package` currently reports an explicit
**coverage-gap skip**, before staging files or invoking the wrapper. The real
wrapper deletes invalid cache files and re-downloads from hardcoded external
mirrors; a valid replacement may then execute. An unreachable mirror or missing
interpreter is not proof of corruption rejection. This case needs a supported,
controlled recovery endpoint before it can safely test recovery using pinned
bytes. It must not execute an unpinned replacement or treat a generic nonzero
exit as success. The separate real-preload corruption tests remain available with
integration opt-in.

### Delivery by the real `preload_firmware`

The tests above stage the tarball themselves, which covers the wrapper but leaves
the *delivery* step - the one hardware proxy performs - untested. Three further
tests hand delivery to the genuine `sonic-metadata/scripts/preload_firmware` and
then follow the rest of the sequence in order:

1. `preload_firmware sonic-upgrade-package.tar.gz http://<host>/` downloads the
   tarball and its `.md5` and verifies the hash
2. both files are moved to `/host/postupgrade-binaries/`, which is what
   `download_postupgrade_binaries()` does after its own `download_util` call
3. the wrapper takes over: validate, extract to `/tmp/postupgrade-actions`,
   execute, write the report

A third test corrupts every served copy and asserts the real script refuses the
package.

**One script downloads both packages.** `download_CPHC_without_md5sum()` selects
its branch on the filename alone:

```bash
if [[ "$FILENAME" == *"sonic-upgrade-package"* ]]; then
```

and both published tarballs match it - `sonic-upgrade-package-1.0.0.tar` (CPHC)
and `sonic-upgrade-package.tar.gz` (postupgrade_actions). The postupgrade package
is therefore fetched by exactly the CPHC code path, with the filename as the only
difference, which is why both test modules share one `PackageMirror` and one
invocation shape. The script derives the rest itself: it appends `.md5`, keeps
only the host from the URL, rebuilds the location as
`http://<host>/networkfirmware/ACS/<subpath><file>`, writes both files into the
current working directory, and compares the hashes before exiting 0. The third
argument, a checksum, is mandatory for every other kind of file and deliberately
optional for these two.

The device copy reaches the postupgrade package by a second route as well:
`download_postupgrade_binaries()` lists it in `binary_info` unconditionally, ahead
of the version-gated telemetry and wol binaries.

**Why a mirror on the DUT.** `preload_firmware` cannot be pointed at the publish
path: `download_util()` derives the location from the host alone and always
appends `/networkfirmware/ACS/`. In production the download targets regional HTTP
mirrors that a lab DUT cannot reach. So the published bytes are fetched from the
image server and re-served on the DUT at exactly the production path - on both
shipped layouts - and the genuine script is asked to fetch them. The mirror's
access log then records which layout this DUT asked for, so a run *reports* the
deployed variant rather than assuming it. Each module serves on its own port
(CPHC 8910, postupgrade 8911) so two mirrors can never be mistaken for each other.

What remains uncovered is the script's mirror selection and route-wait logic.

## How production actually fetches these packages (`test_package_download_nightly.py`)

The two modules above drive each package through its own install-and-run flow.
This third module covers the step that comes before either of them and that both
depend on: getting the published bytes onto a device intact.

It is a separate module because the two consumers turned out **not** to use
`preload_firmware` for these packages at all. Both use plain `curl` over plain
HTTP, and both read the two packages out of *one* directory on the image server:

```
http://<image server>/networkfirmware/ACS/sonic-upgrade-packages/
    sonic-upgrade-package-<ver>.tar        <- CPHC, read by hardware proxy
    sonic-upgrade-package-<ver>.tar.md5
    sonic-upgrade-package.tar.gz           <- postupgrade, read by the wrapper
    sonic-upgrade-package.tar.gz.md5
```

Verified against the shipping source rather than inferred:

| | CPHC | postupgrade |
|---|---|---|
| consumer | `HwSonicSwitch.GetDeviceCriticalProcessHealth()` | `Networking-Metadata .../scripts/postupgrade_actions` |
| download | `curl -f <url> -o <file>` | `curl -s --connect-timeout 10 <url> -o <file>` |
| lands in | `/tmp/sonic-upgrade-scripts` | `/host/postupgrade-binaries` |
| expected hash read with | `cat <file>.md5` + regex `([A-Za-z0-9]{32})` | `awk '{print $1}' <file>.md5` |
| on mismatch | deletes the tarball, fails with `Md5MismatchFailure` | deletes both files and re-downloads |
| also gates on | *(nothing else)* | `tar -tf` against a tarball already on disk |

### Why the difference between those two curls matters

Hardware proxy passes `-f`, so an HTTP error is a non-zero exit and never
reaches the integrity check. **The wrapper does not**, so an HTTP error page is
written to disk as if it were the package, and the *only* thing standing between
a 404 body and `tar -xf` is the md5 comparison. A published `.md5` that is
missing, malformed, or stale therefore fails silently exactly where it is least
protected. That is the gap this module closes, and it is why
`test_md5_file_is_parseable_by_both_consumers` exists: an HTML error page saved
as a `.md5` is happily parsed by `awk`, which returns its first word.

### `tar -tf` is not a corruption check for the CPHC package

The wrapper can rely on `tar -tf` because its package is gzipped and a truncated
gzip stream cannot be inflated. A plain `.tar` has no whole-archive checksum, so
a truncation landing in a member's zero padding reads as a clean end-of-archive
and lists without error. That is why hardware proxy gates the CPHC package on
md5 alone and never runs `tar -tf` against it, and why
`test_truncated_tarball_is_rejected` asserts the checksum for both packages but
`tar -tf` only for the gzipped one. Asserting otherwise would encode a guarantee
production does not have and would flake depending on where the cut landed.

### What it checks

Each test runs once per package:

* `test_package_downloads_with_curl` - the DUT fetches the `.md5` and then the
  tarball using **that consumer's own curl command**, not a normalised one, so a
  package unreachable the way production reaches it fails here; verify those
  exact downloaded bytes against their sidecar and archive structure, since the
  wrapper-style curl returns success even for a nonempty HTTP404 error body;
* `test_md5_file_is_parseable_by_both_consumers` - both production parsers find a
  hash and agree on it;
* `test_tarball_matches_published_md5` - the check both consumers gate on,
  computed on the device so the bytes verified are the bytes that would be
  extracted;
* `test_tarball_is_a_readable_archive` - `tar -tf` succeeds, the wrapper's own
  gate;
* `test_tarball_contains_expected_members` - `installer.py` plus a wheel for
  CPHC; `postupgrade_actions`, `postupgrade_infra.py` and
  `postupgrade_actions_data/` for the wrapper. Turns a runtime failure on a
  device into a delivery failure in the nightly;
* `test_corrupted_tarball_fails_md5` and `test_truncated_tarball_is_rejected` -
  the negative cases. Without them every positive result above would be equally
  consistent with a comparison that always passes.

### Where it downloads from

Only the code-owned latest URLs listed below. Legacy source options,
including `--use_mirror_layout`, cannot redirect initial artifact downloads.
The local test mirror still serves both real preload layouts; freezing initial
sourcing does not change those production-consumer exercises.

Nothing here writes to `/tmp/sonic-upgrade-scripts` or
`/host/postupgrade-binaries`. This module deliberately creates corrupt and
truncated copies, and leaving one in a directory a real upgrade flow reads from
would change what a later genuine run consumes. Everything is staged under
unique `/tmp/package-verify-*` and `/tmp/package-curl-*` directories and removed
afterwards, including failed setup.

## Scope of these tests

They validate **delivery and execution** - that what the pipeline published is
intact, installs or extracts, and runs. They are not device health tests:

- CPHC's health verdict is logged, not asserted, but internal execution errors
  (`succeeded: false` / `execution_error`) fail the test even when the caller
  exits zero.
- `postupgrade_actions` exits with its fault code, so a non-zero exit means this
  DUT failed a health check. That is logged. What is asserted is that the script
  ran to completion and wrote its report.

A wrapper exit code of 3 *is* asserted against, because that is the wrapper failing
to obtain or extract the package - a delivery fault rather than a device one.

### Ownership, restoration and prerequisites

CPHC keeps verified source bytes in a unique directory separate from every
installer extraction. Successful uninstall deletes the installer and wheels
beside `installer.py`; it cannot delete the protected source needed by later
cases or restoration. A same-version preinstalled CPHC is restored from these
bytes; a different preinstalled version still causes a skip. Restoration errors
fail teardown and retain recovery source instead of reporting success.

Every SUP case that stages or executes at fixed production paths first moves
aside the original tar, MD5 and entire extraction tree. Teardown restores those
exact originals, including modes, and leaves unrelated binaries and reports
alone. Cleanup is registered before staging, including setup failures. Reports
are isolated by invocation and only those owned paths are removed/restored.
Copied helper scripts and local mirrors use unique owned workspaces. Mirror
cleanup verifies PID start time and command identity before signaling; an
ownership mismatch fails explicitly and retains evidence. Because Linux
`stat` and `cmdline` reads are not atomic, cleanup rechecks liveness and start
time after reading the command. Empty command lines are retried briefly, never
accepted as ownership proof; confirmed exits/zombies need no further signal.

These guarantees cover owned files and the CPHC package version, **not arbitrary
SUP changes to OS files, configuration, dependencies or services**. Default direct
SUP execution requires an approved testbed where those changes are acceptable.
`--postupgrade_skip_execute` prevents direct execution and every optional real-wrapper
invocation; it is not a dry-run mode in the payload.

Neither archive includes the production wrapper or `preload_firmware`. Supply
the actual deployed scripts using the existing source/path options or install
them through the approved testbed preparation. An explicitly missing preload
path fails clearly; absent optional discovery still skips with a reason. The
real-preload fixtures check script availability before starting a local mirror.
Until these production scripts are available, the standalone curl/integrity
cases, direct CPHC installation/execution and direct SUP package execution remain independent coverage; their success
does not stand in for real-preload or real-wrapper execution. No replacement
wrapper is fabricated: direct SUP package execution is explicitly separate from
real-wrapper coverage and does not make the missing consumer tests pass.
The installed image also needs compatible `python`/`pip` and `python3`/`pip3`,
CPHC's non-vendored dependencies, SONiC Python bindings, Docker/systemd/DB access
and root privileges. Installer `sudo pip` and the caller's chosen interpreter
must refer to the same environment. Local mirror probes are bounded; each
preload invocation has a 300-second outer deadline without changing its curl
flags. No workstation download or mock test establishes these DUT prerequisites.

## Where the packages come from

The producer retains its original Blob upload mechanism and public download
frontend, with Blob path `ACS/sonic-upgrade-packages`. Its public publication base
is `https://sonic.packages.trafficmanager.net/azmirrors/ACS/sonic-upgrade-packages/`.
That uploader configuration is separate from **lab runtime access**. The suite
uses the selected testbed's authoritative `tbinfo["inv_name"]` inventory from the
repository testbed file, not substrings in the testbed/DUT display names or a
package-source CLI option:

| Inventory (`inv_name`) | Lab package mirror |
|---|---|
| `bjw`, `bjw2`, `bjw3` | `http://10.150.22.222/azmirrors/ACS/sonic-upgrade-packages/` |
| All other inventories (including `strtk5` and `str2`) | `http://10.1.3.6/azmirrors/ACS/sonic-upgrade-packages/` |

For example, `tbtk5-t0-7260-01` has inventory `strtk5`; the BJW nightly beds
`testbed-bjw-can-2700-1` and `testbed-bjw-can-2700-3` have inventory `bjw`. No
extra URL arguments are needed. Inventory matching is case-insensitive.
Every non-BJW inventory uses `10.1.3.6`, as explicitly selected for the default
lab route. Missing or malformed inventory metadata still fails explicitly.
The first selected region is pinned for the
pytest run, so both packages and every selector/sidecar use the same lab; a
subsequent region change is rejected.

Both addresses avoid the public DNS/routing dependency. No uploader IP,
authentication or path changes are implied by the testcase endpoint.

The producer preserves historical objects below `builds/<BuildId>/` without
making testcase callers choose a build directory. `delivery_package_source` in
`sonic_operations_helper.py` resolves the regional routes. Outside BJW they are:

```
http://10.1.3.6/azmirrors/ACS/sonic-upgrade-packages/sonic-upgrade-package-1.0.0.tar
http://10.1.3.6/azmirrors/ACS/sonic-upgrade-packages/sonic-upgrade-package.tar.gz
```

For BJW, only the host changes to `10.150.22.222`; paths and filenames are identical.

Append `.md5` and `.buildinfo.json` to each tar URL. The same directory also has
`critical-process-health-checker.latest.buildinfo.json` and
`postupgrade_actions.latest.buildinfo.json`. Those stable selectors identify the
latest independently promoted package builds; CPHC and SUP need not share a
build ID or commit. Updating one package must not restamp the other.

Every initial source download, including the exact consumer-curl cases and local
preload mirror sources, uses the same fail-closed sequence: selector A, MD5 and
tar, per-tar buildinfo, then selector B. All three metadata records must agree as
whole JSON objects and with the package identity already selected in this pytest
run. The producer schema is `schemaVersion=1`, with the filename in `package`,
positive `buildId`, full source `commit`, `buildNumber`, true source `branch`,
UTC `publishedUtc`, lowercase MD5/SHA256 and positive `sizeBytes`. Both digest
algorithms and size are checked against the actual DUT bytes; the MD5 sidecar
must name the expected tar and the archive must contain the real package files.
Missing/invalid metadata, HTML, stale tar/sidecar combinations, changed selectors,
and mid-run promotions fail rather than retrying into a different release.

CPHC retains HWP's `sonic-upgrade-package-1.0.0.tar` filename. Its expected wheel
version comes from `wheelVersion` and must match both py2/py3 wheels in the
verified archive, so new CI wheel versions do not require a testcase edit.
`archiveVersion` is fixed at `1.0.0`; `reportVersion` is null for CPHC. SUP has null
archive/wheel versions and a `reportVersion` checked against its actual execution
report. An optional `--cphc_wheel_version` is an assertion, not a source selector.
Preinstalled different CPHC versions still skip instead of being overwritten
without matching recovery material.

Selected metadata is logged and attached to scoped test results as
`sonic_operations.<package>.publication` properties, including setup failures.
This records what the run selected, not a success claim when that test failed.
The gate proves coherent observed publication, not storage immutability or that
an HTTP cache could never serve an entirely coherent older generation.

No public-domain fallback, `/networkfirmware` alias, old build or other region
is used as an alternative source. Staging may try the **same selected regional URL** from
the runner when the DUT cannot; direct consumer-curl cases still require DUT
access. HTTP is intentional for this lab mirror; no credentials are sent.
Production's `/networkfirmware/ACS/` route is distinct from `/azmirrors/ACS/`;
changing a Blob prefix does not configure a server alias. Local preload mirrors
retain both production layouts.

## Running

```bash
# Default 19 cases, including REAL CPHC/SUP execution; no source/profile options.
pytest tests/sonic_operations/
pytest tests/sonic_operations/test_package_download_nightly.py
pytest tests/sonic_operations/test_cphc_package_nightly.py
pytest tests/sonic_operations/test_postupgrade_package_nightly.py

# Optional 26-case selection, only with real consumer prerequisites.
pytest tests/sonic_operations/ --sonic_operations_integration

# Optional postupgrade integration, but do not execute the real wrapper/payload.
pytest tests/sonic_operations/test_postupgrade_package_nightly.py \
    --sonic_operations_integration --postupgrade_skip_execute
```

| Option | Default | Purpose |
|---|---|---|
| `--sonic_operations_integration` | off | Include 7 production-consumer cases alongside default 19 package cases; real scripts required, recovery gap still skips |
| `--image_server_url`, `--sonic_ops_branch` | legacy defaults retained | Accepted but ignored with a warning; cannot redirect the shared latest route |
| `--package_sas_token` | - | Accepted but ignored; never sent to the anonymous latest frontend or logged |
| `--cphc_package_url`, `--sup_package_url` | - | Accepted but ignored, including conflicting full URLs |
| `--cphc_package_path`, `--sup_package_path`, `--use_mirror_layout` | legacy defaults retained | Accepted but ignored for artifact sourcing |
| `--cphc_tar_version` | `1.0.0` | Any other value fails clearly before package download |
| `--cphc_wheel_version` | auto-detect | Optional expectation, checked against selected buildinfo before payload download; archive wheel versions must agree |
| `--postupgrade_wrapper` | auto-detect | Wrapper path on the DUT |
| `--postupgrade_wrapper_src` | - | Local copy of the wrapper, copied over when the DUT has none |
| `--postupgrade_skip_execute` | off | Skip direct SUP execution before staging; prevent optional wrapper execution. Integrity cases remain selected |

Existing manual plans that pass the old Blob base still parse successfully, but
log that their source options are ignored. No package-location options are needed.

## Access to the image server

**The storage account does not permit anonymous reads.** A request to a blob URL
without credentials is answered with:

```
HTTP 409  <Code>PublicAccessNotPermitted</Code>
          Public access is not permitted on this storage account.
```

That is an account-level setting, so it cannot be worked around by opening a
single container. Two consequences:

- Direct Blob access is not used by this latest validation; legacy SAS arguments
  are ignored rather than forwarded to a different credential scope.
- Success at the public publication frontend does not establish lab access.
  Testcases use the internal HTTP mirror, without forwarding any SAS credential.

HTTP `000` means no HTTP status was received. Curl exit 28 means a timeout,
not proof of a particular routing cause or an HTTP authorization error. Inspect
curl diagnostics for DNS, connection, TLS and transfer failures. Actual HTTP
403/409 responses are different from timeouts. Do not suppress checksum failures
or replace a failed coherent-latest download with a branch/build/alternate URL.
Metadata failures include each attempted host's explicit DUT/runner label, return
code, and credential-redacted stderr/message. Missing transport return codes are
reported as such, not interpreted as invalid metadata or a missing publication.

For reference, production does not read either endpoint: the wrapper fetches from
regional HTTP mirrors over plain unauthenticated HTTP
(`http://<mirror>/networkfirmware/ACS/sonic-upgrade-packages/`).

## Running through Elastictest

Select these three module paths in an existing or manual Elastictest plan:

```
sonic_operations/test_package_download_nightly.py
sonic_operations/test_cphc_package_nightly.py
sonic_operations/test_postupgrade_package_nightly.py
```

Use `SPECIFIC_PARAM=[]` (or `test_option.specific_param=[]` in a manual plan).
The paths alone select the regional latest packages and pin their observed
identities for the run. Saved package-location arguments cannot override this
route; they warn and are ignored. Keep the plan's chosen testbed and other
settings; the temporary BJW conditional skips described above still apply.

There is no dedicated package-nightly launcher in this feature. These modules
are not automatically added to other nightly schedules.
Before the test PR merges, select `MGMT_BRANCH=ryanzhu/cphc-nightly-test` (or the
manual plan's `sonic_mgmt.branch`) and pin the intended testcase commit through
`sonic_mgmt.commit_hash` or a supported `MGMT_COMMIT_HASH` parameter.
Record the actual worker checkout commit separately from the package build/commit.

**Connectivity remains a testbed prerequisite.** `10.150.22.222` is the
user-confirmed BJW download host and the existing BJW download-server address in
`tests/common/helpers/mgmt_route.py`; this change does not apply its route
workaround or make any network configuration changes. Selecting that address is
not evidence that the current ACS selectors and packages are readable in BJW.
Previous physical 19-case success was on STR, not BJW. Local mocked regressions,
older snapshot checks and successful Blob uploads are not current regional DUT
HTTP or package-execution evidence. Failures remain explicit rather than
accepting a different endpoint or generation.

- The DUT downloads packages itself, which is what hardware proxy does. If it
  cannot reach the image server - KVM testbeds are network isolated - the tests
  fall back to downloading on the test runner and copying across. Checksums are
  always verified on the DUT.
- The wrapper is looked for on the device first, since that is the copy production
  would run. A lab DUT that has never been managed by hardware proxy will not have
  it, so pass `--postupgrade_wrapper_src` pointing at
  `src/data/Network/SONiC/scripts/postupgrade_actions` from Networking-Metadata.
- The production mirror serves these packages under a different
  `sonic-upgrade-packages/` prefix, which is a further reason not to assume the CI
  prefix used here is reachable by the same route.
