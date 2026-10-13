# OTG traffic generator (dpdk-tgen) and sonic-mgmt tests

This directory holds the **sonic-mgmt** pytest for a DPDK traffic generator
that speaks a subset of the Open Traffic Generator (OTG) REST API. The engine
source lives in a separate tree (`dpdk-tgen`). The two talk **only** over HTTP
on port **8443**. Currently, the sonic-mgmt does not import engine code.

Phase 1 is one **unidirectional** Ethernet/IPv4/UDP flow through a routed DUT:
configure ports, MAC/IP, rate, frame size, duration, then publish Tx/Rx stats.

```
sonic-mgmt pytest  --OTG HTTP :8443-->  dpdk-tgen (OTG server + DPDK engine)
TGEN Card1/Port1  ------------------>  DUT ingress (e.g. Ethernet16)
TGEN Card1/Port2  <------------------  DUT egress  (e.g. Ethernet24)
```

Engine repo (build, container, resource JSON): Code provided in the pull-request. This README is the operator view for **engine bring-up** and **OTG pytest only**.

---

## 1. DPDK engine

One container process starts both pieces:

| Process | Role |
| ------- | ---- |
| Python `dpdk_tgen.server` | OTG REST (`/config`, `/control/state`, `/monitor/metrics`, `/capabilities/version`) |
| C++ `dpdk-tgen-engine` | DPDK TX/RX, hugepages, mlx5 ports, counters in shared memory |

Location of the DPDK engine: tests/snappi_tests/otg/dpdk-tgen.tar.gz

### 1.1 Host requirements

- Dual-port 100G NIC on the traffic-generator host (host-server example: PCI
  `0000:12:00.0` / `0000:12:00.1`, NUMA 0).
- Hugepages (template uses 4 GiB socket memory on NUMA 0).
- Isolated cores in the JSON template (`lcores.main` / `tx` / `rx`).
- Docker, DPDK libraries staged into the image (`scripts/stage-docker-libs.sh`).
- Do **not** run a bare-metal server and the container at the same time
  (same PCI and DPDK `file-prefix`).

### 1.2 Resource template (machine facts, not traffic)

Traffic (rate, size, duration, headers) arrives over OTG. The JSON template
owns cores, PCI, MTU, and **CardN/PortM → PCI**. Instance for host-server:

`dpdk-tgen/config/<host-server>.json`

Important fields:

| Field | Meaning |
| ----- | ------- |
| `chassis.api_address` / `api_port` | Address used in port locations (`<host-server mgmt IP>:8443`) |
| `ports[].card` / `port` / `pci` | `Card1/Port1` → `0000:12:00.0` |
| `ports[].mtu` | Jumbo (9000 in the host-server template) |
| `engine.allowed_ipv4_subnets` | Flow IPv4 must be in these prefixes (`20.1.1.0/31`, `20.1.2.0/31`) |
| `container.network` | `host` so the API is on the host |

That Card/Port mapping **must** match the sonic-mgmt links CSV. The template
is the source of truth.

### 1.3 Build and run the engine (container)

On the **traffic-generator host**:

```bash
cd /path/to/dpdk-tgen
make -j$(nproc)
./scripts/stage-docker-libs.sh
docker build -f docker/Dockerfile -t dpdk-tgen:0.1 .

./scripts/stop-host-server.sh
./scripts/cleanup-engine-state.sh
./scripts/run-container.sh --replace config/<host-server>.json
```

Health check:

```bash
curl -s http://127.0.0.1:8443/capabilities/version
```

The image listens on **`0.0.0.0:8443` HTTP** (`--no-tls`) so sonic-mgmt in a
bridge Docker network can use `http://<DPDK Engine Container IP>:8443`.

Later start/stop (same container):

```bash
./scripts/stop-container.sh
./scripts/start-container.sh
```

### 1.4 Run the engine stand-alone (no sonic-mgmt)

**Stand-Alone — container** After `run-container.sh`, drive OTG with the engine-tree scripts (pytest host can be the TG host):

**Back-to-back** (ports cabled to each other, **not** a DUT):

```bash
export TGEN_API=http://127.0.0.1:8443
no_proxy=127.0.0.1,localhost
python3 tests/b2b_flow.py --api "$TGEN_API"
```

**Through a DUT** (same L3 path as the sonic-mgmt test):

```bash
export TGEN_API=http://127.0.0.1:8443
no_proxy=127.0.0.1,localhost
python3 tests/dut_flow.py \
  --src-mac <host-server interface MAC>\
  --dst-mac <DUT-MAC-on-ingress-link> \
  --src-ip 20.1.1.0 \
  --dst-ip 20.1.2.0 \
  --rate-pps 200000 \
  --seconds 60
```

Example env: `dpdk-tgen/config/phase1c-<host-server>.example.sh`.


### 1.5 OTG API subset (what the engine implements)

| Endpoint | Used for |
| -------- | -------- |
| `GET /capabilities/version` | Snappi version check |
| `POST /config` | `set_config` |
| `GET /config` | `get_config` |
| `POST /control/state` | start / stop transmit |
| `POST /monitor/metrics` | flow and port counters |

Supported traffic: one flow, `tx_rx.port`, ethernet/ipv4/udp, `size.fixed`,
`rate.pps` / `rate.percentage` / `rate.gbps`, `duration.fixed_seconds`,
`metrics.enable`.

Unsupported OTG fields (`layer1`, PFC, devices, …) are **warnings**, not
errors, unless `engine.strict_unsupported` is true.

Port `location` forms the server accepts:

| Form | Example |
| ---- | ------- |
| `CardN/PortM` | `Card1/Port1` (links CSV / this test) |
| `ip;card;port` | `<host-server mgmt ip>;1;1` |
| PCI | `0000:12:00.0` |

Not in phase 1: ARP/ND, capture, latency, multiple flows, bidirectional
line-rate, layer1/FEC, PFC/ECN, BGP.

---

## 2. sonic-mgmt OTG test and inventory

### 2.1 Files (this repository)

| Path | Role |
| ---- | ---- |
| [`test_otg_throughput.py`](test_otg_throughput.py) | Incremental Gbps steps through the DUT |
| [`conftest.py`](conftest.py) | OTG env (`TGEN_API`, proxy bypass) and ports from conn graph |
| [`../../common/snappi_tests/otg_throughput_helpers.py`](../../common/snappi_tests/otg_throughput_helpers.py) | Config, DUT counter clear, verification |
| [`../../common/snappi_tests/otg_metrics.py`](../../common/snappi_tests/otg_metrics.py) | HTTP poll of `/monitor/metrics` |

The test **skips** unless `tbinfo['ptf_image_name']` contains `OTG`.

### 2.2 Testbed YAML

`ptf_ip` / `tg_api_server` is the **OTG API** (dpdk-tgen), not a PTF docker.
`ptf_image_name` must include `OTG`. Example shape (edit IPs/names for the lab):

```yaml
- conf-name: <dut-topo>
  group-name: ....
  topo: tgen
  ptf_image_name: docker-otg-dpdk-tgen
  ptf: <host-server>
  ptf_ip: <host-server-mgmt-ip>
  tg_api_server: <host-server-mgmt-ip>:8443
  server: <host-server>
  dut:
    - <dut-name>
  inv_name: <inventory_yaml>
  comment: dpdk-tgen OTG on <host-server>
```

`snappi_api_serv_ip` is taken from `ptf_ip`. API port for metrics is **8443**
(`tg_api_server` or `TGEN_API`).

### 2.3 Inventory

Ansible inventory must resolve the DUT hostname used as `--host-pattern`
(example: `DUT` in `westford_hw_inventory`). The generator host does not
need to be an Ansible target for this test; pytest talks to OTG over HTTP.

### 2.4 Connection graph / links CSV

Every DUT front-panel port used by the test must be cabled 1:1 to a generator
port named **`Card<N>/Port<M>`** (same names as `config/<host-server>.json`).

Host-server example:

```
StartDevice,StartPort,EndDevice,EndPort,BandWidth,VlanID,VlanMode
<dut-name>,Ethernet16,<host-mgmt ip>,Card1/Port1,100000,,Access
<dut-name>,Ethernet24,<host-mgmt ip>,Card1/Port2,100000,,Access
```

`otg_snappi_ports` builds locations as `Card1/Port1` from this graph (not
IxNetwork `ip;card;port`).

### 2.5 DUT configuration.

Persist this on the DUT (`config_db.json` is fine).

Host-server defaults:

```
TGEN Card1/Port1 (host-server-interface-1-MAC) ---- DUT Ethernet16   20.1.1.0/31
TGEN Card1/Port2 (host-server-interface-2-MAC) ---- DUT Ethernet24   20.1.2.0/31
```

- Ethernet16: `20.1.1.1/31` (flow source `20.1.1.0`)
- Ethernet24: `20.1.2.1/31` (flow dest `20.1.2.0`)
- IPv4 forwarding on
- Jumbo MTU matching the template (9000)
- Static neighbors, for example:


Flow IPv4 must stay inside `engine.allowed_ipv4_subnets` or `set_config` fails.

### 2.6 API reachability from sonic-mgmt docker

`conftest.py` strips HTTP proxies and, for OTG testbeds, sets
`TGEN_API=http://<DPDK Engine Container IP>:8443` so a **bridge-network** sonic-mgmt container
on the **same host** as dpdk-tgen can reach `--listen 0.0.0.0`.

| How pytest runs | Typical API URL |
| --------------- | ---------------- |
| sonic-mgmt Docker, default bridge, same host as tgen | `http://<DPDK Engine Container IP>:8443` |
| sonic-mgmt `--network host` on tgen host | `http://127.0.0.1:8443` or `http://<ptf_ip>:8443` |
| pytest on another machine | `http://<ptf_ip>:8443` (routable); put that IP in `no_proxy` |

Overrides: `TGEN_API`, `TGEN_API_SCHEME`, `OTG_DOCKER_HOST_GATEWAY`,
`OTG_USE_DOCKER_HOST_GATEWAY`.

`snappi_api` used by the test must be a **native OTG** session against that
URL (not `ext="ixnetwork"`). Metrics polling uses `TGEN_API` via
`build_otg_api_base()`.

### 2.7 Run the pytest

Engine container must already be up (`curl` version as above). From
**sonic-mgmt** `tests/`:

```bash
cd ~/sonic-mgmt/tests

python3 -m pytest \
  --inventory ../ansible/westford_hw_inventory \
  --host-pattern <dut name> \
  --testbed <dut-topo> \
  --testbed_file ../ansible/testbed.yaml \
  --topology tgen \
  --skip_sanity \
  snappi_tests/otg/test_otg_throughput.py \
  -v --log-cli-level=INFO
```

Each parametrized step (default 5, 15, … 95 Gbps) clears DUT counters, runs
one flow, then checks generator `frames_tx == frames_rx`, DUT `RX_DRP`/`TX_DRP`
== 0 on the two ports, and DUT egress TX ≥ ingress RX.

### 2.8 Environment overrides

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `OTG_GBPS_START` | 5 | First target rate (Gbps) |
| `OTG_GBPS_STEP` | 10 | Step size |
| `OTG_GBPS_MAX` | 95 | Last target rate |
| `OTG_DURATION_SEC` | 60 | Per-step duration |
| `OTG_FRAME_SIZE` | 9000 | Frame size |
| `OTG_DUT_INGRESS_PORT` | Ethernet16 | DUT port on generator TX |
| `OTG_DUT_EGRESS_PORT` | Ethernet24 | DUT port on generator RX |
| `OTG_SRC_IP` / `OTG_DST_IP` | 20.1.1.0 / 20.1.2.0 | Flow IPv4 |
| `OTG_SRC_MAC` | <host-server-interface-MAC> | Generator TX MAC |
| `OTG_DST_MAC` | DUT `router_mac` | Dest MAC on ingress link |
| `OTG_SRC_PORT` / `OTG_DST_PORT` | 5001 / 5002 | UDP ports |
| `OTG_COUNTER_TOLERANCE` | 0 | Used with `OTG_STRICT_DUT_COUNTERS` |
| `OTG_STRICT_DUT_COUNTERS` | unset | If `1`, require DUT counters to match tgen exactly |
| `TGEN_API` | set by conftest on OTG tbs | OTG base URL |


### 2.9 What this test does **not** cover

Existing `snappi_tests` PFC/ECN/PFCWD/BGP suites are not run against dpdk-tgen.
Those need OTG features the engine in future or later phase.

---

## 3. Rate expectations (Host-server / ConnectX-4)

Unidirectional jumbo (~9000 B) is the line-rate case.

---

## 4. Troubleshooting

| Symptom | Check |
| ------- | ----- |
| pytest skip `ptf_image_name contains OTG` | Testbed YAML `ptf_image_name` |
| Connection refused / proxy 504 | `curl` from the pytest network; `TGEN_API`; `no_proxy`; listen `0.0.0.0` |
| `set_config` IPv4 refused | Address in `allowed_ipv4_subnets` |
| DUT `(incomplete)` neighbor / zero RX on tgen | Static `ip neigh`; dest MAC = DUT MAC on ingress |
| `Need at least two Card*/Port* links` | Links CSV peer ports named `Card1/Port1` style |
| PCI / hugepage bind error | Stop host server; `cleanup-engine-state.sh`; one engine only |
| `b2b_flow.py` zero RX with DUT cabling | Expected; use `dut_flow.py` or this pytest |
