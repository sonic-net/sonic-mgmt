# Local Redis write-protection acceptance

This test uses the normal `duthosts` and `rand_one_dut_hostname` fixtures. It
copies a check script to the DUT and runs it with the existing administrator
`become` setting. The writer password stays on the DUT.

The check covers every configured local Redis process and every numeric database
reported by that process. It checks administrator writes, ordinary-user reads
and rejected writes through redis-py and the native connector. For every named
database, it also checks `sonic-db-cli`, JSON display output and raw `redis-cli`.
Stock CLI checks include stdin, binary `-x` input and `--pipe`. On a protected
process these unauthenticated writes must fail even when Linux root launches
the CLI. Administrator writes use `sonic-db-cli`; root privileges alone do not
authenticate a Redis account. Legacy preflight retains the raw write checks.
An ordinary raw CLI process runs as an unprivileged user inside the database
container, so Docker access does not hide a Redis permission failure.

Before creating test keys, the helper enumerates running Redis processes and
listening Unix/TCP sockets inside the database container. Each configured
instance must match one actual process and its listening ports. Missing or
unlisted processes and open TCP listeners with zero-port metadata fail the
check. The report includes `actual_redis_processes_checked`; preflight also
requires the runtime census.

The ordinary reader also checks scans, read transactions, `EVAL`, cached read
scripts and rejected write scripts/transactions. Temporary keys use a unique
prefix, expire after five minutes and are deleted in cleanup.

## Prerequisites

- A standalone single-host DUT with one or more ASICs with write protection already enabled for the standalone acceptance command. The mode runner below prepares activation itself.
- All configured local Redis processes included in `/run/redis-auth/local.json`.
- Updated native connectors, `sonic-db-cli`, Python support and stock Redis CLI installed.
- Normal sonic-mgmt SSH inventory and administrator access to the DUT.

The test skips an image without the activation file. A
cutover acceptance run must report a passed test; a skipped test is not evidence
of write protection. Remote Redis topologies are outside this test's scope.

## Acceptance on an already configured DUT

Use the normal SONiC management runner. Provide absolute inventory and testbed
paths. This test does not deploy a topology or use packet traffic. For a focused
run on an existing VS, use the existing `nut-single-dut` testbed profile when
no PTF host is available:

```sh
./run_tests.sh -u -a False -n <testbed> -d <dut> \
  -c redis/test_redis_write_protection.py \
  -f /absolute/path/to/testbed.yaml \
  -i /absolute/path/to/inventory.yaml \
  -p /absolute/path/to/results \
  -e "--device_type=vs --ignore-conditional-mark --skip_sanity \
  --disable_loganalyzer --disable_memory_utilization --skip_yang \
  --collect_techsupport=False --alluredir=/absolute/path/to/allure-results"
```

`-u` bypasses the runner's general preparation and cleanup groups. The normal
pytest fixtures still run. The example disables unrelated traffic, log and
health checks for this narrow acceptance run. It does not qualify a complete
network topology or replace the usual SONiC regression suites.

The DUT helper also has a `--preflight` mode for checking administrator clients
before activation. That mode creates temporary test keys and reports
`security_verified: false`; it does not test ordinary-user write denial.


## Mixed-mode validation

The default test requires every local process to be protected. To validate a
reviewed TCP exception, explicitly add `--redis-allow-tcp-exceptions` to the
runner's pytest arguments. The helper reads the common enforcement setting and
requires the prepared policy to protect exactly the processes outside its
`tcp_exceptions` list. Missing policy entries cannot create exceptions.

The mixed-mode run checks ordinary-user reads and rejected writes on protected
processes. For exceptions it checks existing administrator and unauthenticated
raw CLI operations over TCP, including stdin, binary input and pipelines. It
does not run the ordinary-user connector checks on exceptions. The report lists
them as unprotected and returns `security_verified: false`, even when the scoped
checks pass. A passing mixed-mode run does not establish whole-host protection.

For a DUT-local run of the copied helper, the corresponding argument is
`--allow-tcp-exceptions`. This option cannot be combined with `--preflight`.

## Multi-ASIC coverage

The helper derives the expected host and ASIC namespaces from `asic.conf`, then
checks the published global includes and each namespace's database map before
reading the authentication policy. It also enumerates Redis processes and their
actual TCP and Unix listeners inside every database container. Missing namespaces,
extra processes and listeners that disagree with the database map fail the check.

Each process receives a different value under the same scratch key. Named CLI
checks pass `-n asicN`, and raw CLI checks enter the matching database container.
The ordinary user has only its private primary group, with no supplemental
groups or writer-password access. TCP exceptions apply to
the named process in every namespace and remain explicitly unprotected.

This test checks a running system. It does not restart containers or qualify
reboot, upgrade or rollback. Those lifecycle operations require separate image
validation, followed by another acceptance run.

## Run the regression suite in both modes

`run_tests.sh` accepts `--redis-protection-mode=legacy` or
`--redis-protection-mode=enforce` inside its existing `-e` argument. Keep the
image artifact, runner revision, topology, test selection and feature settings
identical between runs. Use a separate result directory for each run. For example,
from the `tests` directory:

```sh
./run_tests.sh -n TESTBED -d DUT -f /absolute/path/to/testbed.yaml \
  -i /absolute/path/to/inventory -t t0,any -p /absolute/path/to/results/legacy \
  -e "--redis-protection-mode=legacy"

./run_tests.sh -n TESTBED -d DUT -f /absolute/path/to/testbed.yaml \
  -i /absolute/path/to/inventory -t t0,any -p /absolute/path/to/results/enforce \
  -e "--redis-protection-mode=enforce"
```

Use the topology and normal test options for the actual testbed. Virtual switches
also require `--device_type=vs` in `-e`. The runner saves each DUT's original
nonsecret `/etc/sonic/redis-auth.json` setting and permissions on the controller,
sets the requested mode, reboots and waits for critical services. It runs the
selected acceptance test before normal pretests and again after posttests. It
then restores the original file, or its absence, reboots and verifies the original
mode. Redis credentials stay on the DUT.

Legacy acceptance requires the startup check to report `legacy` and no generated
protected endpoint policy. The normal regression suite exercises existing client
behavior. Protected acceptance checks every DUT and its independently discovered
local Redis processes, including primary/BMP and declared ASIC namespaces. A
required missing policy or skipped acceptance test fails the job. Existing jobs
without the mode option do not change activation or reboot through these hooks.

The existing predefined PR pipeline exposes `REDIS_PROTECTION_MODE` with values
`unchanged` (the default), `legacy`, `enforce` and `both`. For a paired virtual
comparison, select `both`, set `KVM_BUILD_ID` to the completed candidate image
build and `MGMT_COMMIT_HASH` to the matching combined runner commit. Keep
`IMPACT_AREA_INFO` and `INCLUDE_JOBS` fixed. The pipeline runs separate legacy and
enforce stages sequentially and retains each result even if the other fails.
The mode argument is appended to the existing topology arguments. Hardware jobs
can pass the same runner option through their existing image and test selection.

Select deployments whose enforcement is supported for paired runs. T2/chassis,
DPU and BMC remain eligible for legacy compatibility testing, but explicitly
requested enforcement is rejected by the current image guard. This option does
not extend that guard or qualify new deployments. Reviewed TCP exceptions require
`--redis-allow-tcp-exceptions`; their processes remain reported as unprotected.

The runner writes separate `redis-mode-prepare`, `before`, `after` and `restore`
JUnit/log files under its result directory. Compare normal regression results as
well as these gates. Preserve original failures and report skipped tests and
mode-specific failures separately; passing acceptance alone does not qualify the
whole regression suite.

Setup failures, normal test failures and handled INT/TERM signals attempt
restoration. The controller prints and retains a `RESULT_PATH.redis-mode.*/state.json` record beside the result directory
before the first DUT change. A failed restoration returns a failing job status
and retains that record for a retry using the exact same DUT inventory. A copy is retained in the result directory as `redis-mode-state.json`. The original sibling record survives the log-directory cleanup of a later run. If the worker is lost or killed with SIGKILL,
its shell cannot execute cleanup. CI/testbed owners must retain the lab and
recovery record and perform the restoration hook from a surviving controller
before releasing it; provider-side recovery for that case remains required.
