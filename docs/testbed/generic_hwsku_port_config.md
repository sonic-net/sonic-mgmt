# Generic HwSKU PORT Table Generation

## Problem

Each HwSKU variant (e.g., `Arista-7060X6-64PE-O128S2`, `-C256S2`, `-C224O8`) requires
its own `port_config.ini` file in `sonic-buildimage`. Changing the breakout layout
means creating a new HwSKU name, a new directory, a new `port_config.ini`, and a new
`sonic-buildimage` PR. This doesn't scale.

## Solution

Generate the PORT table dynamically from two data sources:

- **`links.csv`** — the lab topology file on the sonic-mgmt server. Provides port names
  and speeds (the "what").
- **`platform.json`** — the hardware description on the DUT (or in a `sonic-buildimage`
  checkout). Provides physical lanes, aliases, indices, and valid breakout modes
  (the "how").

No `port_config.ini` or `hwsku.json` is needed. No HwSKU name parsing.

## Architecture

```
 ┌────────────┐     ┌──────────────┐
 │ links.csv  │     │ devices.csv  │
 │ (mgmt srv) │     │ (mgmt srv)   │
 │            │     │              │
 │ port names │     │ hostname →   │
 │ + speeds   │     │ hwsku        │
 └─────┬──────┘     └──────┬───────┘
       │                   │
       │    ┌──────────────┘
       │    │    ┌───────────────┐
       │    │    │ platform.json │
       │    │    │ (on DUT or    │
       │    │    │  buildimage)  │
       │    │    │               │
       │    │    │ lanes, index, │
       │    │    │ aliases,      │
       │    │    │ breakout_modes│
       ▼    ▼    └───────┬───────┘
 ┌───────────────────────┴──────────────┐
 │       generate_port_config.py        │
 │                                      │
 │  1. read_links_csv()  → port:speed   │
 │  2. validate()        → warnings     │
 │  3. generate_port_table()            │
 │     for each cage in platform.json:  │
 │       • find ports in cage range     │
 │       • match breakout mode          │
 │       • split lanes evenly           │
 │       • assign alias from platform   │
 │  4. output JSON                      │
 └──────────────┬───────────────────────┘
                │
                ▼
     PORT table JSON → scp to DUT → sonic-cfggen --write-to-db
```

## How It Works

### Physical Switch Layout

A switch like the Arista 7060X6-64PE has 64 physical cages (QSFP-DD), each with
8 SerDes lanes. `platform.json` describes all cages and their valid breakout modes:

```json
{
  "interfaces": {
    "Ethernet0": {
      "lanes": "17,18,19,20,21,22,23,24",
      "index": "1,1,1,1,1,1,1,1",
      "breakout_modes": {
        "1x800G[400G]": ["etp1"],
        "2x400G": ["etp1a", "etp1b"],
        "4x200G": ["etp1a", "etp1b", "etp1c", "etp1d"],
        "8x100G": ["etp1a", "etp1b", "etp1c", "etp1d", "etp1e", "etp1f", "etp1g", "etp1h"]
      }
    }
  }
}
```

### The Matching Algorithm

For each cage in `platform.json`, the script:

1. **Collects** which `links.csv` ports fall into this cage's address range
2. **Matches** the port count + speed against `breakout_modes` to find the right mode
3. **Splits** the cage's lanes evenly among the ports
4. **Assigns** aliases from the matched breakout mode

Example for cage `Ethernet0` with 8 lanes `[17,18,19,20,21,22,23,24]`:

| links.csv ports in cage | Breakout matched | Lane assignment |
|-------------------------|-----------------|-----------------|
| 1 port × 800G | `1x800G` | Ethernet0 → lanes=17,18,19,20,21,22,23,24 |
| 2 ports × 400G | `2x400G` | Ethernet0 → 17,18,19,20; Ethernet4 → 21,22,23,24 |
| 4 ports × 200G | `4x200G` | Ethernet0 → 17,18; Ethernet2 → 19,20; ... |
| 8 ports × 100G | `8x100G` | Ethernet0 → 17; Ethernet1 → 18; ... |

### Mixed Breakout

Each cage is processed independently, so mixed breakout is supported:

```
Cage 1: 1 port at 800G  → 1x800G (all 8 lanes)
Cage 2: 2 ports at 400G → 2x400G (4 lanes each)
Cage 3: 8 ports at 100G → 8x100G (1 lane each)
```

## Usage

### Step 1: Generate PORT table JSON (on mgmt server)

```bash
python3 ansible/scripts/generate_port_config.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --devices-csv ansible/files/sonic_str4_devices.csv \
    --hostname str4-7060x6-64pe-11 \
    --platform-json ~/sonic-buildimage/device/arista/x86_64-arista_7060x6_64pe/platform.json \
    --full-config \
    -o /tmp/port_config_override.json
```

Or auto-detect `platform.json` from a `sonic-buildimage` checkout:

```bash
python3 ansible/scripts/generate_port_config.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --devices-csv ansible/files/sonic_str4_devices.csv \
    --hostname str4-7060x6-64pe-11 \
    --buildimage-root ~/sonic-buildimage \
    -o /tmp/port_config_override.json
```

### Step 2: Apply to DUT (after load_minigraph)

```bash
# Copy override to DUT
scp /tmp/port_config_override.json dut:/etc/sonic/

# Apply (overwrites PORT table in config_db)
ssh dut "sudo sonic-cfggen -j /etc/sonic/port_config_override.json --write-to-db && sudo config save -y"
```

### Changing Breakout (update links.csv)

To remap `links.csv` for a new breakout layout:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --hostname str4-7060x6-64pe-11 \
    --target-breakout 2x400G \
    --dry-run

# Remove --dry-run to apply
```

## Integration with Existing Flow

All other config_db tables (DEVICE_NEIGHBOR, VLAN, BGP_NEIGHBOR, LOOPBACK, etc.)
continue to come from minigraph via `config load_minigraph`. This script only
overrides the PORT table:

```
config load_minigraph -y         ← all tables from minigraph
generate_port_config.py          ← PORT override from links.csv + platform.json
sonic-cfggen -j ... --write-to-db  ← overwrite just PORT
```

## Validation

The script validates the `links.csv` ports against `platform.json`:

- **Orphan ports** — ports not mapping to any physical cage
- **Mixed speeds** — different speeds within the same cage
- **Invalid breakout** — port count + speed not in `breakout_modes`
- **HwSKU pattern checks** — copper (C*) and split (P*) pattern validation

## End-to-End HWSKU Conversion (C256 → O128 Example)

This walkthrough converts a DUT from `Arista-7060X6-64PE-C256S2` (4x200G, 256 ports)
to `Arista-7060X6-64PE-O128S2` (2x400G, 128 ports).

### Prerequisites

- Testbed name (e.g., `str4-t1-lag`)
- Links CSV path (e.g., `ansible/files/sonic_str4_links.csv`)
- Devices CSV path (e.g., `ansible/files/sonic_str4_devices.csv`)
- Inventory file (e.g., `str4-inventory`)
- Vault password file (e.g., `~/.password`)

### Step 1: Pre-checks — verify current state

```bash
# Check current HWSKU and port count on DUT
ssh dut "show platform summary"
ssh dut "show interfaces status | wc -l"
ssh dut "show interfaces status | grep -c 'up'"
ssh dut "show bgp summary"
```

Save the output for comparison after conversion.

### Step 2: Update links.csv for new breakout

Preview the changes first with `--dry-run`:

```bash
# From sonic-mgmt/ansible/ directory
./testbed-cli.sh update-breakout str4-t1-lag \
    files/sonic_str4_links.csv 2x400G --dry-run
```

Verify the output shows:
- Correct number of new DUT entries (128 ports for O128)
- VLANs preserved for existing ports, new VLANs assigned for new ports
- Trunk VLAN range updated for root fanout

Apply when satisfied:

```bash
./testbed-cli.sh update-breakout str4-t1-lag \
    files/sonic_str4_links.csv 2x400G
```

### Step 3: Update devices.csv — change HwSKU

Edit `ansible/files/sonic_str4_devices.csv` and change the DUT's HwSKU:

```
# Before:
str4-7060x6-64pe-11,...,Arista-7060X6-64PE-C256S2,...
# After:
str4-7060x6-64pe-11,...,Arista-7060X6-64PE-O128S2,...
```

### Step 4: Redeploy leaf fanout

The leaf fanout needs to be reconfigured for the new breakout and VLANs:

```bash
cd ansible
ansible-playbook -i str4-inventory fanout.yml \
    -l str4-fanout-01 \
    --vault-password-file ~/.password
```

### Step 5: Update root fanout VLAN trunks

The root fanout trunk ports need the updated VLAN range:

```bash
ansible-playbook -i str4-inventory fanout_connect.yml \
    --vault-password-file ~/.password \
    -e dut=str4-7060x6-64pe-11
```

### Step 6: Deploy minigraph with golden config

This generates minigraph with the new port layout, builds the golden config
(which replaces the PORT table using platform.json), and applies both:

```bash
./testbed-cli.sh deploy-mg str4-t1-lag str4-inventory ~/.password
```

What happens under the hood:
1. Minigraph is generated with the new 128-port layout
2. `generate_golden_config_db` rebuilds the PORT table from `platform.json`
   with correct lanes, aliases, indices, speed, and FEC
3. `config load_minigraph --override_config -y` applies minigraph + PORT override

### Step 7: Verify port status

Wait ~60 seconds for ports to come up, then verify:

```bash
# All ports should be operationally up
ssh dut "show interfaces status"

# Count should match expected (128 data ports + management)
ssh dut "show interfaces status | grep -c 'up'"

# Check for any ports that are admin up but oper down
ssh dut "show interfaces status | grep 'up.*down'"

# Verify port speeds are correct (all should be 400G)
ssh dut "show interfaces status | awk '{print \$5}' | sort | uniq -c"

# Verify PORT table in config_db has correct lanes and aliases
ssh dut "sonic-cfggen -d --var-json PORT" | python3 -m json.tool | head -30
```

### Step 8: Verify BGP sessions

```bash
# All BGP neighbors should be in Established state
ssh dut "show bgp summary"

# Check for any non-established sessions
ssh dut "show bgp summary | grep -v Established | grep -v 'Neighbor\|entries'"

# Verify neighbor count matches expected topology
ssh dut "show bgp summary | grep -c Established"
```

### Step 9: Verify LLDP neighbors

```bash
# LLDP confirms physical connectivity matches links.csv
ssh dut "show lldp table"
ssh dut "show lldp table | wc -l"
```

### Step 10: Run sanity tests

```bash
cd tests

# Run pretest checks (interfaces, BGP, basic connectivity)
pytest test_pretest.py \
    --testbed=str4-t1-lag \
    --inventory=../ansible/str4-inventory \
    -v

# Run link flap test to verify all links recover
pytest platform_tests/test_link_flap.py \
    --testbed=str4-t1-lag \
    --inventory=../ansible/str4-inventory \
    -v
```

### Troubleshooting

| Symptom | Check | Fix |
|---------|-------|-----|
| Ports admin up but oper down | `show interfaces status` | Verify fanout is configured for new breakout; check cable/transceiver |
| Wrong port count | `sonic-cfggen -d --var-json PORT \| python3 -c "import json,sys; print(len(json.load(sys.stdin)))"` | Re-run `deploy-mg`; verify links.csv has correct entries |
| BGP sessions not established | `show bgp summary` | Wait longer (up to 180s); check `show ip interface` for correct IPs |
| VLANs not trunked | Check root fanout: `show vlan` | Re-run `fanout_connect.yml` |
| Wrong lanes/aliases in PORT | `sonic-cfggen -d --var-json PORT` | Verify `platform.json` exists on DUT at `/usr/share/sonic/device/<platform>/` |
| Golden config not applied | `cat /etc/sonic/golden_config_db.json` | Check that topo is `ft2-64`, `lt2-p32o64`, or `lt2-o128` |
