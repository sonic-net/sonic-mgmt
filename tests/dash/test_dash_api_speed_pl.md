# DASH API Speed Test (`test_dash_api_speed_pl.py`) — Run Guide

## Overview

`test_dash_api_speed_pl.py` measures how fast DASH private-link config loads
onto a single DPU via gNMI. It:

1. Resolves the **NPU** (`duthost`) and targeted **DPU** (`dpuhosts[dpu_index]`)
   and prints both `hwsku` values.
2. Renders per-ENI DASH config (appliance + route-group + ENI/routes + VNet
   mappings) with `configs/dash_api_speed_pl/render.py` at the requested scale.
3. Pushes every rendered file onto the DPU via the gNMI client
   (`load_config_via_gnmi`), timing each push.
4. Reports **per-ENI load time**, **total load time**, and **NPU + DPU memory**
   (per-container, system `free -m`, and DPU `DPU_APPL_DB` Redis) before/after.

### Scale knobs (top of the test file)

| Variable | Default (when `None`) | Meaning |
|----------|------------------------|---------|
| `OVERRIDE_ENI_COUNT` | 64 on `Mellanox-SN4280-O28`, 32 on `Cisco-8102-28FH-DPU-O` | ENIs programmed on the DPU |
| `OVERRIDE_MAPPING_COUNT` | 64K | VNet mappings **per ENI** |
| `OVERRIDE_ROUTE_COUNT` | 10K | outbound routes **per ENI** |
| `CLEANUP_MODE` | `"precise"` | `"precise"` = gNMI DELETE each pushed file; `"flushdb"` = one `FLUSHDB` of `DPU_APPL_DB` (instant, **dedicated DPU only** — wipes all keys) |
| `MEM_TIMELINE_EVERY` | `1` | sample `free -m` (NPU+DPU) every Nth pushed file; raise to trim measurement overhead |

Set any to an int for a smaller/larger run (e.g. a quick smoke test). Defaults
target full private-link scale — those runs are large and slow.

`CLEANUP_AFTER` (default `True`): once the measurement and reports are done, the
test deletes the DASH config it just pushed so the DPU is left clean. With
`CLEANUP_MODE="precise"` (default) it gNMI-DELETEs the same files in reverse
order — only this run's keys are removed, pre-existing residue is untouched, but
it costs roughly as long as the push (~460s at 32-ENI). With
`CLEANUP_MODE="flushdb"` it issues a single `DPU_APPL_DB FLUSHDB` (seconds), which
also clears any pre-existing keys — use it only on a dedicated test DPU. Cleanup
time is **not** counted in the load measurement. Set `CLEANUP_AFTER=False` to
leave the config in place (e.g. to inspect it or drive traffic afterwards).

### gNMI client dependency (WIP, not committed)

The push uses the extracted native gNMI client at
`tests/dash/gnmi_agent_extracted/` (`gnmi_client.py`). That directory is
**git-ignored** (`.gitignore`) and must be copied onto the controller /
`sonic-mgmt` container out-of-band. The location is a single constant —
`GNMI_AGENT_EXTRACTED_DIR` in `dash_api_speed_common.py` — update it (and drop
the `.gitignore` entry) when the agent is packaged into the repo.

---

## Lab resources (already wired into `ansible/`)

The two Keysight smartswitch testbeds are defined in this repo:

| conf-name | topo | NPU host (hwsku) | NPU IP | DPU host(s) | DPU SSH (NAT on NPU) |
|-----------|------|------------------|--------|-------------|----------------------|
| `keysight-nss01` | `smartswitch-nvidia` | `keysight-nss01` (`Mellanox-SN4280-O28`) | 10.36.78.150 | `keysight-nss01-dpu0`, `keysight-nss01-dpu1` | dpu0 → :5021, dpu1 → :5022 |
| `keysight-css01` | `smartswitch-cisco` | `keysight-css01` (`Cisco-8102-28FH-DPU-O`) | 10.36.77.121 | `keysight-css01-dpu0` | dpu0 → :5021 |

Both use `--inventory=../ansible/lab`. The relevant inventory groups are
`sonic_nvidia_smartswitch` (NPU) / `sonic_nvidia_dpu` (BlueField DPUs) for the
Nvidia testbed, and `sonic_cisco_smartswitch` (NPU) / `sonic_amd_dpu`
(AMD/Pensando DPUs) for the Cisco testbed; the test server is the
`server_keysight` group (`sonic-mgmt-keysight` @ 10.36.79.161).

## Prerequisites

- The `sonic-mgmt` container running on the test server (`10.36.79.161`,
  user `dash`), with this repo checked out.
- The `dpuhosts` fixture reaches each DPU over a **NAT port-forward on the NPU**
  (DPU hosts in the inventory point at the NPU IP with `ansible_ssh_port`
  5021/5022). The test does **not** set this up — enable it **manually on the NPU,
  and re-run it after every NPU reboot** (a reboot clears the forwarding):

  ```bash
  sudo sonic-dpu-mgmt-traffic.sh inbound -e --dpus all --ports 5021,5022,5023,5024
  ```

---

## Running the test

Run from `tests/` inside the `sonic-mgmt` container. **Both `ANSIBLE_*` exports
are required** — `ansible.cfg` uses paths relative to the `tests/` CWD, so the
custom ansible modules won't import without them — and **`-s` is required** to
see the report. Use one of the examples below.

---

## NVIDIA SmartSwitch example

NVIDIA BlueField DPU smartswitch (`keysight-nss01`, DPUs `-dpu0..-dpu3`):

```bash
cd /home/dash/sonic-mgmt/sonic-mgmt/tests
export ANSIBLE_LIBRARY=$PWD/../ansible/library
export ANSIBLE_MODULE_UTILS=$PWD/../ansible/module_utils

pytest dash/test_dash_api_speed_pl.py \
  --testbed=keysight-nss01 \
  --testbed_file=../ansible/testbed.yaml \
  --inventory=../ansible/lab \
  --host-pattern=keysight-nss01 \
  --dpu-pattern=keysight-nss01-dpu0 \
  --dpu_index=0 \
  --cache-clear -v -s
```

- DPUs are NVIDIA BlueField; the NPU is a Mellanox SN4280 host.
- Change `--dpu_index` (0–3) and `--dpu-pattern` together to target a
  different DPU; use one whose midplane reachability is `True`.
- Example output: `NPU hwsku : Mellanox-SN4280-O28`,
  `DPU hwsku : Nvidia-bf3-com-dpu`.

---

## Cisco SmartSwitch example

Cisco 8102 smartswitch with AMD DPUs (e.g. `keysight-css01`,
DPUs `-dpu0..-dpu7`):

```bash
cd /home/dash/sonic-mgmt/sonic-mgmt/tests
export ANSIBLE_LIBRARY=$PWD/../ansible/library
export ANSIBLE_MODULE_UTILS=$PWD/../ansible/module_utils

pytest dash/test_dash_api_speed_pl.py \
  --testbed=keysight-css01 \
  --testbed_file=../ansible/testbed.yaml \
  --inventory=../ansible/lab \
  --host-pattern=keysight-css01 \
  --dpu-pattern=keysight-css01-dpu0 \
  --dpu_index=0 \
  --cache-clear -v -s
```

- DPUs are AMD; the NPU is a Cisco 8102 host (hwsku reports as a
  `Cisco-...` string).
- Cisco smartswitches expose up to **8** DPUs, so `--dpu_index` can be 0–7.
  Only `dpu0` is wired in the inventory/testbed by default; add more
  `keysight-css01-dpuN` entries to target others.
- Example output: `NPU hwsku : Cisco-8102-28FH-DPU-O`,
  `DPU hwsku : Pensando-elba`.

---

## Expected output

Sample run below: **32 ENIs × 64K mappings/ENI × 10K routes/ENI**
(`OVERRIDE_ENI_COUNT=32`, mappings/routes at their defaults). This renders **97
config files** (1 appliance + 32×{grp, eni, map}) and programs ~2.05M mappings +
320K routes. Long per-file / per-ENI / timeline lists are elided with `...`.

```
==================== DASH API SPEED PL ====================
NPU host   : keysight-nss01 or keysight-css01
NPU hwsku  : Mellanox-SN4280-O28 or Cisco-8102-28FH-DPU-O
DPU index  : 0
DPU host   : keysight-nss01-dpu0 or keysight-css01-dpu0
DPU hwsku  : Nvidia-bf3-com-dpu or Pensando-elba
===========================================================
Scale: ENIs=32, mappings/ENI=64000, routes/ENI=10000 (override None => hwsku/default; full-scale is slow)
Render scale: ENI_COUNT=32, mappings/ENI=64000 (requested 64000), routes/ENI=10001 (requested 10000)
Rendered 97 config files to push to hardware DPU0
  [1/97] pl_100.dpu0.000apl.json                     0.67s  ok
  [2/97] pl_100.dpu0.000grp.json                     0.66s  ok
  [3/97] pl_100.dpu0.000eni.json                     2.12s  ok
  [4/97] pl_100.dpu0.000map.json                    10.17s  ok
  ...
  [97/97] pl_100.dpu0.031map.json                   11.14s  ok
Programmed (DPU_APPL_DB): landed 2368194 keys vs 2368194 SET ops sent [DASH_APPLIANCE_TABLE=1, DASH_ENI_ROUTE_TABLE=32, DASH_ENI_TABLE=32, DASH_ROUTE_GROUP_TABLE=32, DASH_ROUTE_RULE_TABLE=32, DASH_ROUTE_TABLE=320032, DASH_ROUTING_TYPE_TABLE=1, DASH_VNET_MAPPING_TABLE=2048000, DASH_VNET_TABLE=32]

========================================================================
  DASH API LOAD SPEED — PER-ENI LOAD TIMES
========================================================================
  ENI              grp       eni       map       total
  --------------------------------------------------------
  appliance                                       0.67
  eni 000         0.66      2.12     10.17       12.95
  eni 001         0.66      2.22     10.19       13.07
  ...
  eni 031         0.64      2.29     11.14       14.07
  --------------------------------------------------------
  SUM(push)                                     427.32
  WALL TOTAL                                    559.64
  avg/ENI                                        13.33
  ENIs pushed: 32
========================================================================

========================================================================
  DASH API LOAD SPEED TEST — RESULTS
========================================================================

  Per-file load times:
  File                                          Time (s)
  --------------------------------------------------------
  pl_100.dpu0.000apl.json                           0.67
  pl_100.dpu0.000grp.json                           0.66
  pl_100.dpu0.000eni.json                           2.12
  pl_100.dpu0.000map.json                          10.17
  ...
  TOTAL (file pushes)                             427.32
  WALL TOTAL                                      559.64
  Average per file                                  4.41
  Files loaded: 97

  Memory usage — NPU (MiB):
  Container                         Before     After     Delta
  ----------------------------------------------------------
  gnmi                                61.0     229.6    +168.6
  databasedpu1                         96.4    1209.3   +1113.0
  syncd                             1110.0    1110.0      +0.0
  ...
  Containers total                  4568.7    5851.6   +1283.0
  System used (free -m)             7920.0    9249.0   +1329.0
  System free                     118585.0  115264.0   -3321.0
  System available                120874.0  119545.0   -1329.0
  System total                    128794.0

  Memory usage — DPU (MiB):
  Container                         Before     After     Delta
  ----------------------------------------------------------
  swss                               360.4    3632.1   +3271.7
  syncd                              273.7    1565.7   +1292.0
  ...
  Containers total                  1375.1    5938.9   +4563.8
  System used (free -m)            26771.0   31503.0   +4732.0
  System free                      29627.0   25435.0   -4192.0
  System available                 37371.0   32639.0   -4732.0
  System total                     64142.0

  DPU Redis memory — DPU_APPL_DB (bytes):
  Key                                                       Before       After       Delta
  --------------------------------------------------------------------------------------
  used_memory (total)                                      1676880  1171275776  +1169598896
  used_memory_human                                          1.60M       1.09G
========================================================================
Cleanup: deleting 97 pushed config file(s) to restore DPU state ...
  cleanup [1/97] pl_100.dpu0.031map.json                  ok
  ...
Cleanup done (0 error(s)); DPU_APPL_DB DBSIZE: 2368194 -> 0

  PHASE BREAKDOWN (s): render=20.9  push+verify=559.6  cleanup=459.7  total=1040.3
```

### Timing & expected run time (32-ENI Nvidia run above)

| Phase | What it does | Time |
|-------|--------------|------|
| `render` | Generate the 97 JSON config files locally | **~21 s** |
| `push+verify` | gNMI push of all files + DPU_APPL_DB count verify (the measured window) | **~560 s** |
| `cleanup` | gNMI DELETE of the same files (reverse order), DBSIZE → 0 | **~460 s** |
| **total** | render + push + cleanup | **~1040 s (~17 min)** |

Add ~1–2 min of pytest fixture setup (NPU/DPU facts, cert staging) on top, so
budget **~18–19 min wall** end-to-end for a 32-ENI run. The dominant cost is the
per-ENI **map** push (~10 s each × 32 ≈ 5 min) since each programs 64K mappings;
`grp`/`eni` pushes are ~0.7 s / ~2.2 s. Full 64-ENI scale roughly doubles
`push+verify` and `cleanup`. `avg/ENI` (13.33 s) is push time only — it excludes
the appliance file and fixture overhead.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `No module named 'ansible.module_utils.parse_utils'` / `No module named 'module_utils'` | The `ANSIBLE_LIBRARY` / `ANSIBLE_MODULE_UTILS` env vars are not set (see run command). |
| `duthosts fixture failed: ... no attribute 'sonic_basic_facts'` | Same root cause — ansible custom modules failed to import; set the two env vars. |
| `dpuhosts fixture failed: Host unreachable in the inventory` | (a) NAT not enabled on the NPU — run `sonic-dpu-mgmt-traffic.sh inbound -e ...`; **or** (b) the targeted DPU is down. Check `show chassis module midplane-status` on the NPU and target a DPU whose reachability is `True`. |
| `conn_graph_facts failed` | The NPU/DPU host is missing from `ansible/files/sonic_lab_devices.csv`. The keysight hosts are already added there. |
| `minigraph_facts failed: ... /etc/sonic/minigraph.xml` | The `fanouthosts` fixture tried to build fanout for a smartswitch (which has none). Fixed by the `smartswitch` guard in `tests/conftest.py:fanouthosts` (already in this repo). |
| `IndexError` on `dpuhosts[dpu_index]` | `--dpu_index` is larger than the number of DPUs returned for `--dpu-pattern`. Lower it (NVIDIA: 0–3, Cisco: 0–7). |
| Test skipped | The testbed topology is not `smartswitch`; check the testbed entry in `testbed.yaml`. |

> The `conditional_mark: Failed to load minigraph basic facts` line printed at
> collection time is **non-fatal** (the plugin ignores it) and does not affect
> the result.

---

## Key files

| File | Purpose |
|------|---------|
| `tests/dash/test_dash_api_speed_pl.py` | This test |
| `tests/dash/test_dash_api_speed_pl.md` | This guide |
| `tests/conftest.py` | Defines `dpuhosts` / `dpuhost` fixtures (NAT-gated) |
| `tests/dash/conftest.py` | Defines the `dpu_index` fixture (`--dpu_index`) |
