# Ranking SAI test workflow

Ranking runs the existing SAI PTF cases through sonic-mgmt and produces
repeatable capability and performance reports. An operator or CI job starts the
workflow on a sonic-mgmt controller. The workflow acts on one DUT, one PTF host,
one existing PTF tooling container, and one controller output directory.

Prepare, Run, and Report are separate commands:

1. **Prepare** optionally configures and checks a lab, then publishes
   the complete SAI PTF case tree.
2. **Run** selects and executes one or more cases against an already Ready lab.
   It does not require Prepare state.
3. **Report** reads controller output offline and never contacts the devices.

This README is a complete quick start for the tracked SONiC-to-SONiC
`sonic_sonic` environment template. Copy it to a local lab package and review
every topology-specific file before using it with real devices.

## Scope and ownership

| Owner | Responsibility |
| --- | --- |
| sonic-mgmt | Standard `duthost`, `ptfhost`, `tbinfo`, SSH transport, pytest, and Ansible integration |
| Environment package | Host identity, port wiring, platform files, and lab-specific Prepare actions |
| Ranking Run | Case selection, PTF execution, evidence collection, remote temporary-file cleanup |
| Ranking Report | Offline validation and rendering of capability/spec reports |
| External scheduler/operator | Exclusive lab allocation and final reboot, reimage, or restoration policy |

This package implements the SAI PTF and offline report path from the
[community Ranking HLD](https://github.com/sonic-net/SONiC/blob/a0cb1e03316abb74387f35f941ed9f47cb2fdf60/doc/AINet-Test/Tier%201%20-%20Ranking%20Test%20HLD%20.md).
It does not provide an IXIA backend, Jenkinsfile, lab locking, image build, or
cross-chip weighted score.

The checked-in cases are pinned by `cases/source_identity.json` to:

```text
SONiC/SAI v1.10-pdx-capability
commit 3e2e3631b57d8ce9f461ece2e14e451295cb520b
SAI API 1.10.2
```

`cases/ranking-contract.json` pins the expected generated `sai_thrift` binding
identity. The binding is supplied by the PTF container and must match that
contract. An open TCP port alone does not prove that the SAI data plane is Ready.

## Phase independence and Ready contracts

The three phases exchange files and declared environment configuration, not a
hidden lifecycle receipt. Choose the first phase from the state you already
have:

| Existing state | Command sequence |
| --- | --- |
| New/reset lab that matches the SONiC-to-SONiC template | Prepare → Run → Report |
| Lab already satisfying the Generic Run Ready contract | Run → Report |
| Completed Run output that only needs rendering again | Report |
| Local configuration/case selection needs validation only | Run with `--collect-only` |

Prepare is therefore optional. Run never checks whether Prepare was called,
and Report never contacts a DUT or PTF host.

### Generic Run Ready contract

Run requires capabilities, not particular service or process names:

1. The controller can read the environment package, write the output directory,
   and reach the configured PTF execution host through sonic-mgmt SSH transport.
2. The DUT exposes a working SAI Thrift endpoint at the configured address and
   port, and that endpoint owns a usable ASIC/SAI session for the selected case.
3. The PTF execution target has the configured launcher, case directory,
   matching `sai_thrift` binding, writable collector directory, and Python
   runtime.
4. PTF packet interfaces are ready and correspond exactly to the ordered
   `environment.yml:ports` mapping and physical/virtual data path.
5. The PTF execution target can reach the DUT RPC endpoint, and the complete
   selected case source and direct dependencies are installed.

This generic contract does not require SONiC `swss`, `/usr/bin/saiserverv2.sh`,
Broadcom `bcmcmd`, or even SONiC on the DUT. For example, an SDK-only DUT does
not need a `swss` stop operation; it only needs to expose the required Ready SAI
RPC/ASIC session. Environment-specific lifecycle checks belong to that
environment package's `prepare.py`, not to Run.

### SONiC-to-SONiC/Broadcom environment only

The tracked `environments/sonic_sonic` package reaches the generic Ready state
by stopping DUT `swss`, starting DUT SAIserver, keeping PTF `swss`/`syncd`
active, stopping the SAIserver process inside the PTF tooling container, and
programming Broadcom ingress mirror-to-CPU. These are requirements of this
environment's Prepare/check implementation only. A different DUT/packet-host
architecture may use different actions or skip Prepare entirely. See
`tests/ranking/environments/sonic_sonic/README.md` for the topology and
ownership boundary.

## 1. Prerequisites

Allocate the complete DUT/PTF pair exclusively before running Prepare or Run.
SAIserver and the ASIC session are shared resources outside pytest's local
output lock.

### Controller

- Linux host with Docker access and enough permission to pull and run
  `docker-sonic-mgmt`.
- This sonic-mgmt checkout mounted into the controller container.
- Management-network reachability to both SONiC devices.
- Non-interactive SSH, or a local uncommitted password in the environment
  package as described below.
- Write access to `tests/ranking/output/`.

The standard controller image provides Python, pytest, Ansible, paramiko, and
the sonic-mgmt plugins. Do not install a second ad-hoc Python dependency set on
the DUT or PTF host.

### DUT for the SONiC-to-SONiC environment

- SONiC image with `swss`, Docker, and executable
  `/usr/bin/saiserverv2.sh`.
- A compatible SAIserver image already installed for the DUT ASIC.
- SSH user with permission to run `service`, `systemctl`, Docker, and the
  SAIserver launcher. The tracked template uses `root`.
- SAI Thrift TCP port `9092` reachable from the PTF host/container.

Read-only prerequisite checks on the DUT:

```bash
show version
test -x /usr/bin/saiserverv2.sh
systemctl is-active swss
docker images --format '{{.Repository}}:{{.Tag}}' | grep saiserver
```

### PTF host for the SONiC-to-SONiC environment

The tracked template uses a second SONiC device as the packet host. It requires:

- SONiC `swss` and `syncd` services.
- Docker and executable `/usr/bin/saiserverv2.sh`.
- A compatible `saiserverv2` tooling image containing:
  - Python 3;
  - `/SAI-TEST/test/ptf/ptf`;
  - the complete direct dependencies of the SAI PTF cases;
  - generated `sai_thrift` for SAI 1.10.2 under the configured binding path.
- A Broadcom `syncd` container with working `bcmcmd`. The checked-in mirror
  helper is Broadcom-specific and is not portable to a different SDK unchanged.
- All interfaces named by `environment.yml` present and cabled to the matching
  DUT interfaces.

Read-only prerequisite checks on the PTF host:

```bash
show version
test -x /usr/bin/saiserverv2.sh
systemctl is-active swss
docker inspect syncd >/dev/null
docker exec syncd bcmcmd -c ps
```

Prepare starts the PTF tooling container. After Prepare, these paths must exist
inside that exact container:

```bash
docker exec saiserverv2 test -x /SAI-TEST/test/ptf/ptf
docker exec saiserverv2 test -d /SAI-TEST/ptf
docker exec saiserverv2 python3 -c 'import sai_thrift; print(sai_thrift.__file__)'
```

### Network paths

The following paths must work:

```text
Controller container --SSH--> DUT management address
Controller container --SSH--> PTF management address
PTF host/container ----TCP--> DUT management address:9092
PTF data interfaces --------> DUT data interfaces
```

The environment check verifies DUT RPC reachability after configuration. It
does not discover or repair incorrect physical cabling.

## 2. Prepare an environment package

The environment package is the operator-owned input. Keep it inside the
checkout so the single repository mount exposes it to the controller container.
The canonical template is `tests/ranking/environments/sonic_sonic/`.
Start by copying the complete package to a local lab name:

```bash
cp -a tests/ranking/environments/sonic_sonic tests/ranking/examples/my-lab
```

`tests/ranking/examples/` is ignored by Git, which keeps local credentials and
internal addresses out of commits. The tracked template contains documentation
addresses only; replace them in the local copy.

### Environment package files

```text
tests/ranking/examples/my-lab/
├── environment.yml             # edit: hosts, container paths, timeout, wiring
├── environment.py              # keep: strict schema and Run compiler
├── prepare.py                  # review: lab-specific configure/check actions
├── port_mapping.py             # helper/reference; not a runtime entry point
├── dut/
│   ├── config_db.json          # edit: selected DUT PORT table
│   └── port_config.ini         # edit: DUT names, lanes, speed, FEC, index
└── ptf/
    ├── port_config.ini         # edit: PTF SONiC port names in wiring/SDK order
    └── mirror_port.py          # review: Broadcom SDK-port mirror mapping
```

| File | Used by | What the operator must do |
| --- | --- | --- |
| `environment.yml` | Prepare and Run | Set host identity, authentication, container paths, timeout, and every DUT-to-PTF link |
| `environment.py` | Prepare and Run | Normally keep unchanged; it validates the `sonic_sonic` schema and builds sonic-mgmt adapter/runtime data |
| `prepare.py` | Prepare only | Keep only when the new lab uses the same two-SONiC-device lifecycle; otherwise implement the environment's own configure/check hooks |
| `dut/config_db.json` | Case sync overlay | Replace with a top-level `PORT` table for the selected DUT ports |
| `dut/port_config.ini` | Case sync overlay | Replace with the matching DUT platform rows |
| `ptf/port_config.ini` | PTF mirror setup | List the connected PTF SONiC ports in the order expected by the SDK mapping |
| `ptf/mirror_port.py` | PTF mirror setup | Keep only if `cd0..cdN` matches the PTF SDK order; adapt for another SDK/platform |
| `port_mapping.py` | Local validation/helper code | No normal runtime edit; Prepare and Run use `environment.yml:ports` directly |

### Obtain platform port information

On each SONiC device, identify the platform and locate its platform
`port_config.ini` before editing the package:

```bash
show version
find / -name port_config.ini 2>/dev/null | grep '<platform-name-from-show-version>'
```

For `dut/config_db.json`, first export the complete DUT `PORT` table before
stopping `swss`. When `jq` is available, run this on the DUT:

```bash
sonic-cfggen -d --print-data | jq '{PORT: .PORT}' > /tmp/config_db.full.json
```

Transfer that file to the controller through the approved lab mechanism as
`tests/ranking/examples/my-lab/dut/config_db.full.json`. Then run this from the
repository root to retain only the ports selected by the environment package:

```bash
python3 - <<'PY'
import json
from pathlib import Path

import yaml

root = Path('tests/ranking/examples/my-lab')
environment = yaml.safe_load((root / 'environment.yml').read_text())
full = json.loads((root / 'dut/config_db.full.json').read_text())
selected = list(environment['ports'])
ports = full.get('PORT', {})
missing = [name for name in selected if name not in ports]
if missing:
    raise SystemExit('missing DUT PORT entries: {}'.format(', '.join(missing)))
filtered = {'PORT': {name: ports[name] for name in selected}}
(root / 'dut/config_db.json').write_text(
    json.dumps(filtered, indent=2) + '\n', encoding='utf-8')
PY

rm tests/ranking/examples/my-lab/dut/config_db.full.json
```

This writes `tests/ranking/examples/my-lab/dut/config_db.json`. Its final
`PORT` key set must equal `environment.yml:ports` exactly. Do not copy
credentials, unrelated CONFIG_DB tables, or unconnected DUT ports.

### Required consistency

The following values must describe the same cable map:

- Every key in `environment.yml:ports` is a DUT port present in both
  `dut/config_db.json` and `dut/port_config.ini`.
- DUT `lanes`, `speed`, `fec`, and `index` agree between the two DUT files.
- Every `ports.<dut-port>.interface` exists on the PTF host and appears in
  `ptf/port_config.ini` in the SDK order used by `mirror_port.py`.
- PTF ids are unique, ordered, and contiguous starting at `1`.
- The number of ports must have a matching standard sonic-mgmt topology file.
  This checkout currently provides `ansible/vars/topo_ptf32.yml` and
  `ansible/vars/topo_ptf64.yml`, so this environment adapter currently supports
  32-port and 64-port packages.

### `environment.yml` fields

| Field | Required/default | Operator action |
| --- | --- | --- |
| `schema_version` | Required, must be `1` | Keep |
| `type` | Required, must be `sonic_sonic` | Keep for this implementation |
| `controller.testbed` | Required | Choose a stable unique testbed name |
| `controller.host_pattern` | Required | Normally keep `all` |
| `controller.connection` | Optional, default `ssh` | Use `paramiko` when system SSH is incompatible or password auth is used |
| `hosts.dut.name`, `hosts.ptf.name` | Required | Unique sonic-mgmt inventory aliases |
| `hosts.<role>.address` | Required | Reachable management IPv4 address/hostname; PTF address must be IPv4 |
| `hosts.<role>.user` | Required | SSH user with the permissions listed above |
| `hosts.<role>.auth.password` | Optional | Local fallback only; never commit a populated value |
| `dut.rpc_port` | Required, exactly `9092` | Keep |
| `ptf.container` | Required | Existing tooling container name; checked-in Prepare requires `saiserverv2` |
| `ptf.workdir` | Required | PTF working directory, normally `/SAI-TEST` |
| `ptf.executable` | Required | PTF launcher, normally `/SAI-TEST/test/ptf/ptf` |
| `ptf.case_dir` | Required | Published case target, normally `/SAI-TEST/ptf` |
| `ptf.binding_dir` | Required | Directory containing the matching generated `sai_thrift` package |
| `ptf.collector_dir` | Required | Private writable absolute result path inside the container |
| `ptf.timeout_s` | Required | Per-case timeout in seconds |
| `ptf.arguments` | Required, exactly `[--relax]` | Keep |
| `ports` | Required | Ordered DUT port to `{id, interface}` mapping |

For local password authentication, add the optional field only to the excluded
lab package:

```yaml
hosts:
  dut:
    name: dut
    address: 192.0.2.10
    user: root
    auth:
      password: "local-password"
  ptf:
    name: ptf
    address: 192.0.2.20
    user: root
    auth:
      password: "local-password"
```

Passwords are excluded from Ranking context fingerprints. Credentials are
never written to artifacts, logs, state, or reports. They still exist in the
local YAML and temporary mode-`0600` Ansible inventory, so protect the package
and never commit it. For CI, inject SSH credentials through the CI secret
mechanism instead of writing them into the repository.

The single-mount Quick Start does not import the controller host's `~/.ssh`.
Unless the controller image/CI runtime already injects a usable SSH identity,
use the excluded local password fallback above. SSH key or agent injection is
deployment-specific and must be added by the CI secret mechanism.

## 3. Start the controller

Run these commands from the sonic-mgmt repository root on the controller host:

```bash
docker pull sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest

docker run --rm -it \
  --network host \
  --mount type=bind,source="$PWD",target=/work/sonic-mgmt \
  --workdir /work/sonic-mgmt \
  sonicdev-microsoft.azurecr.io:443/docker-sonic-mgmt:latest \
  bash
```

The command uses one bind mount: the sonic-mgmt checkout. `--rm` removes only the controller container. Source changes and output below the bind-mounted
checkout remain on the controller host.

All remaining commands run from `/work/sonic-mgmt` inside this controller
container. The examples use:

```text
environment package: tests/ranking/examples/my-lab
output batch:        tests/ranking/output/route-batch-001
known fast case:     sairoute.multipleRoutesTest
```

## 4. Validate configuration and case selection without devices

Use pytest collection before changing the lab:

```bash
python3 -m pytest -q \
  tests/ranking/run/test_ranking.py \
  --ranking-config tests/ranking/examples/my-lab/environment.yml \
  --ranking-output tests/ranking/output/route-batch-001 \
  --ranking-select case:sairoute.multipleRoutesTest \
  --collect-only
```

Expected result:

```text
test_ranking_case[sairoute.multipleRoutesTest]
1 test collected
```

Collection validates the local environment schema, adapter generation, source
assets, and case selection. It does not SSH to devices or prove forwarding.

## 5. Prepare the SONiC-to-SONiC environment

> **Warning:** Prepare mutates both SONiC devices. On the PTF device it starts
> the tooling container, stops the SAIserver process inside that container,
> restarts `swss`, and programs ingress mirror-to-CPU through `bcmcmd`. On the
> DUT it stops `swss` and starts SAIserver. Prepare intentionally does not
> restore either device.

For the first full deployment, configure and check the lab and atomically
replace the complete PTF case directory:

```bash
python3 -m pytest -s -v \
  tests/ranking/prepare/test_prepare.py \
  --ranking-environment tests/ranking/examples/my-lab \
  --ranking-cases tests/ranking/cases \
  --ranking-force-sync
```

Without `--ranking-force-sync`, `sync_cases` succeeds with a warning and skips
copying when the target case directory already exists. Force sync builds one
archive, transfers it through the PTF host, and atomically replaces the target;
do not manually delete the target first.

### Prepare command reference

| Option | Required/default | Meaning |
| --- | --- | --- |
| `tests/ranking/prepare/test_prepare.py` | Required entry point | Executes one pytest item that dispatches selected Prepare actions |
| `--ranking-environment DIR` | Required | Package containing `environment.yml`, `environment.py`, and `prepare.py` |
| `--ranking-cases DIR` | Required when `sync_cases` is selected | Case root containing the `ptf/` directory and environment overlays |
| `--ranking-prepare-steps LIST` | Optional; default `configure_env,check_env,sync_cases` | Unique comma-separated subset; execution is normalized to that canonical order |
| `--ranking-force-sync` | Optional; default off | Atomically replace an existing target case directory; valid only with `sync_cases` |
| `-s` | Optional pytest flag | Show live stdout/stderr |
| `-v` | Optional pytest flag | Show verbose pytest item names |

Examples for individual actions:

```bash
# Configure and then check, without copying cases.
python3 -m pytest -s -v tests/ranking/prepare/test_prepare.py \
  --ranking-environment tests/ranking/examples/my-lab \
  --ranking-prepare-steps configure_env,check_env

# Check an environment configured manually, then force-publish cases.
python3 -m pytest -s -v tests/ranking/prepare/test_prepare.py \
  --ranking-environment tests/ranking/examples/my-lab \
  --ranking-cases tests/ranking/cases \
  --ranking-prepare-steps check_env,sync_cases \
  --ranking-force-sync
```

Prepare writes no durable deployment state. Its archive, PTF-host transit
file, extraction directory, and replacement backup are owned temporary paths
and are removed by the same invocation.

## 6. Select and run cases

Run is independent of Prepare. It can attach to a manually prepared environment
or one prepared by another system when the Generic Run Ready contract is
satisfied. It does not consume Prepare state. When skipping Prepare for the
SONiC-to-SONiC environment, the operator or scheduler must establish the
environment-specific DUT/PTF state described above before starting Run.

Run the known fast case:

```bash
python3 -m pytest -s -v \
  tests/ranking/run/test_ranking.py \
  --ranking-config tests/ranking/examples/my-lab/environment.yml \
  --ranking-output tests/ranking/output/route-batch-001 \
  --ranking-select case:sairoute.multipleRoutesTest
```

### Discover available cases

The full registered case catalog and priority are in
`tests/ranking/cases/manifest.json`. List every `module.Class priority` pair:

```bash
python3 - <<'PY'
import json

with open('tests/ranking/cases/manifest.json', encoding='utf-8') as source:
    manifest = json.load(source)
for module, definition in manifest['modules'].items():
    for case, metadata in definition['cases'].items():
        print('{}.{} {}'.format(module, case, metadata['priority']))
PY
```

### Case selectors

`--ranking-select` accepts one typed selector. With no selector, Ranking runs
`priority:P0`.

| Selection | Example | Effect |
| --- | --- | --- |
| One case | `case:sairoute.multipleRoutesTest` | One exact `module.Class` |
| Several cases | `case:sairoute.multipleRoutesTest,sairoute.dropRouteTest` | Exact cases in manifest order |
| Modules | `module:sairoute,saifdb` | Every registered case in the listed modules |
| Priority | `priority:P0` | Every case with that priority (`P0`, `P1`, or `P2`) |

Each selected case becomes a separate PTF invocation and controller archive.
Different cases accumulate in the same output batch. Repeating a case replaces
its previous confirmed archive only after new files and SHA256 values are
verified.

### Run command reference

| Option | Required/default | Meaning |
| --- | --- | --- |
| `tests/ranking/run/test_ranking.py` | Required entry point | Creates one pytest item per selected case |
| `--ranking-config YAML` | Required | `environment.yml` with a sibling `environment.py` |
| `--ranking-output DIR` | Required | Batch directory shared by Run and Report |
| `--ranking-select TYPE:VALUE` | Optional; default `priority:P0` | Select exact cases, modules, or one priority |
| `--ranking-live-log MODE` | Optional; default `compact` | `compact`, `full`, or `off`; archived evidence is unchanged |
| `--collect-only` | Optional pytest flag | Validate local configuration/selection without contacting devices |
| `-s` | Optional pytest flag | Display Ranking live console output |
| `-v` | Optional pytest flag | Display verbose pytest item names |

Remote cleanup removes only the UUID paths and injected runner owned by the
current invocation. A cleanup failure preserves controller evidence and stops
the remaining pytest cases.

## 7. Generate and read the report

After all desired Run commands have finished, generate one offline report:

```bash
python3 -m tests.ranking.report.generate \
  --ranking-output tests/ranking/output/route-batch-001
```

### Report command reference

| Option | Required/default | Meaning |
| --- | --- | --- |
| `python3 -m tests.ranking.report.generate` | Required entry point | Validates final case outputs and renders three self-contained HTML files |
| `--ranking-output DIR` | Required | Existing output batch containing final case outputs |

Report always uses `cases/manifest.json` as the complete case baseline. A case
with a final result JSON is rendered with its observed result, duration, and log
link. A manifest case that was not executed is rendered as `NOT TESTED`; it does
not make Report fail. A published result whose case is absent from the manifest,
or a damaged required artifact, makes Report exit nonzero and print the error to
stderr. Report exits zero only after all three HTML files are complete.

Open the report files directly from the controller host, or serve the report
directory from the controller container:

```bash
python3 -m http.server 8000 \
  --bind 127.0.0.1 \
  --directory tests/ranking/output/route-batch-001/report
```

Then open these URLs from the controller host:

```text
http://127.0.0.1:8000/result.html
http://127.0.0.1:8000/capability.html
http://127.0.0.1:8000/spec.html
```

For a remote controller, use an SSH tunnel or copy the HTML output through the
approved lab mechanism. Do not expose the report server on an untrusted network.

- `result.html` is the pure case execution view. It lists every manifest case,
  the observed result or `NOT TESTED`, duration, and the archived log link.
- `capability.html` shows the tested SAI API/attribute capability associations.
  A passing negative test still contributes passing case evidence because the
  verdict follows the final case result, not whether every SAI call succeeded.
- `spec.html` shows registered performance, capacity, latency, and fill-rate
  measurements produced by the selected cases.

## 8. Output layout

`--ranking-output` is controller-local durable state. Relative paths resolve
from the current working directory. Use one directory per batch under
`tests/ranking/output/`; Git ignores that directory, and the repository bind
mount preserves it after the controller container exits. Output must not
overlap the environment package, case source, manifest, or runner source. Each
final case output is grouped by module below the batch root. The merged result
path is `cases/<module>/results/<Class>.json`.

```text
tests/ranking/output/route-batch-001/
├── cases/
│   └── <module>/
│       ├── results/
│       │   └── <Class>.json       # case outcome and collected measurements
│       ├── logs/
│       │   └── <Class>.log        # PTF console and internal log
│       └── pcaps/
│           └── <Class>.pcap       # optional packet capture
└── report/
    ├── result.html               # manifest-wide case result, duration and log
    ├── spec.html                 # measured performance/scale metrics
    └── capability.html           # SAI attribute capability matrix
```

Do not edit final case output by hand. Ranking does not persist or compare
batch-level environment identity. The user or scheduler owns output-directory
separation when results from different environments must remain isolated.

## 9. Environment restoration

Ranking intentionally does not restore or reboot the SONiC-to-SONiC
environment.
Immediately after successful Prepare:

- DUT `swss` is stopped and DUT SAIserver owns the ASIC.
- PTF `swss` is active, the SAIserver process inside the tooling container is
  stopped, and ingress mirror-to-CPU has been programmed.

After Run and Report, the external scheduler/operator must restore both devices
according to the lab policy. The intended Jenkins policy is to reboot or reimage
the allocated pair after evidence has been collected. Do not run the restoration
while a Ranking case is active, and do not assume that exiting pytest restores
the devices.

## 10. Common failures

| Symptom | Check |
| --- | --- |
| `Host unreachable in the inventory` | Management address, SSH user/password/key, `controller.connection`, and container network path |
| `standard sonic-mgmt topology is missing` | Port count must currently match `topo_ptf32.yml` or `topo_ptf64.yml` |
| Target case directory already exists | Rerun Prepare with `sync_cases` and `--ranking-force-sync` when replacement is intended |
| Binding identity mismatch | Use the PTF tooling image with generated SAI 1.10.2 bindings matching `ranking-contract.json` |
| RPC reachability failure | DUT SAIserver state, TCP `9092`, routes/firewalls, and PTF-to-DUT management path |
| PTF interface or packet failure | Cable map, `environment.yml:ports`, both DUT port files, PTF port order, and mirror SDK mapping |
| Report returns nonzero | Inspect the `report_generate:` reason in stderr, then the case JSON under `cases/<module>/results/` and its log under `cases/<module>/logs/` |

## 11. Local validation

The isolated unit suite does not require devices:

```bash
python3 -m pytest -q --confcutdir=tests/ranking/unit_tests \
  tests/ranking/unit_tests

python3 -m compileall -q tests/ranking
```

Collection-only validates controller wiring, but only an explicitly authorized
physical execution proves SAI initialization, physical port mapping, and packet
forwarding.
