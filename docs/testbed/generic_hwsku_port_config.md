# Generic HwSKU PORT Table Generation — Without port_config.ini

## Problem

Each HwSKU variant (e.g., `Arista-7060X6-64PE-O128S2`, `-C256S2`, `-C224O8`) traditionally
requires its own `port_config.ini` file in `sonic-buildimage`. Changing the breakout layout
means creating a new HwSKU name, a new directory, a new `port_config.ini`, and a new
`sonic-buildimage` PR. This doesn't scale.

## Solution

Generate the PORT table dynamically at deploy time using the existing Ansible playbook
(`config_sonic_basedon_testbed.yml`) and the `generate_golden_config_db` module — no
`port_config.ini`, `hwsku.json`, or manual file copies needed.

The playbook uses two data sources already available in every testbed:

- **`links.csv`** — the lab topology file on the sonic-mgmt server. Provides port names
  and speeds (the "what").
- **`platform.json`** — the hardware description already present on the DUT at
  `/usr/share/sonic/device/<platform>/platform.json`. Provides physical lanes, aliases,
  indices, and valid breakout modes (the "how").

## Architecture

```
 sonic-mgmt server                              DUT
 ┌──────────────────────────────────┐           ┌──────────────────────┐
 │  ansible/files/                  │           │  /usr/share/sonic/   │
 │    sonic_<lab>_links.csv         │           │  device/<platform>/  │
 │    sonic_<lab>_devices.csv       │           │    platform.json     │
 └───────────┬──────────────────────┘           └──────────┬───────────┘
             │                                             │
             ▼                                             │
 ┌───────────────────────────────────┐                     │
 │ config_sonic_basedon_testbed.yml  │                     │
 │                                   │                     │
 │  1. Extract port_speeds + hwsku   │                     │
 │     from links.csv & devices.csv  │                     │
 │     (delegated to localhost)      │                     │
 │                                   │                     │
 │  2. Call generate_golden_config_db│                     │
 │     on DUT with port_speeds       │─────────────────────┤
 └───────────┬───────────────────────┘                     │
             │                                             │
             ▼                                             ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  generate_golden_config_db (Ansible module, runs on DUT)        │
 │                                                                 │
 │  generate_port_table_from_platform(port_speeds, platform.json): │
 │    for each cage in platform.json:                              │
 │      • find ports from port_speeds in cage's address range      │
 │      • match port count + speed against breakout_modes          │
 │      • split lanes evenly among ports                           │
 │      • assign aliases from matched breakout mode                │
 │      • add FEC=rs for speeds ≥ 200G                             │
 │                                                                 │
 │  Output: golden_config_db.json with PORT table                  │
 └──────────────────────────────────┬──────────────────────────────┘
                                    │
                                    ▼
                 config load_minigraph --override_config -y
                   ├── minigraph → all tables (BGP, VLAN, etc.)
                   └── golden_config_db.json → PORT table override
```

## How It Works

### Step 1: Playbook extracts port speeds from links.csv

When `port_override_from_links=true` is passed to the playbook, a task
delegated to `localhost` reads `links.csv` and `devices.csv` to extract:

- **port_speeds** — `{port_name: speed}` for the target DUT hostname
- **hwsku** — the HwSKU string from `devices.csv`

These are passed to the `generate_golden_config_db` Ansible module as parameters.

### Step 2: Module rebuilds PORT table from platform.json on the DUT

The `generate_golden_config_db` module (in `ansible/library/`) runs on the DUT.
For FT2/LT2 topologies, it calls `generate_port_table_from_platform()` which:

1. Opens `/usr/share/sonic/device/<platform>/platform.json` (already on the DUT)
2. For each physical cage defined in `platform.json`:
   - Collects which ports from `port_speeds` fall into this cage's lane range
   - Matches the port count + speed against the cage's `breakout_modes`
   - Splits the cage's SerDes lanes evenly among the matched ports
   - Assigns aliases from the matched breakout mode entry
   - Adds `fec: rs` for port speeds ≥ 200G
3. Writes the result as `golden_config_db.json`

If `port_speeds` is provided from `links.csv`, those speeds are used (they
reflect the desired breakout layout). Otherwise, the module falls back to the
minigraph PORT table speeds.

### Step 3: Minigraph + golden config applied together

The playbook runs `config load_minigraph --override_config -y`, which:

- Loads all config_db tables from minigraph (BGP, VLAN, LOOPBACK, etc.)
- Overrides the PORT table with the one from `golden_config_db.json`

The result is a PORT table with correct lanes, aliases, indices, speeds, and
FEC — derived entirely from `links.csv` + `platform.json`, with no
`port_config.ini` involved.


### Fallback Behavior

If `platform.json` is missing or has no `interfaces` section, the module falls
back to using the minigraph PORT table directly, adding `fec: rs` for ports
with speeds ≥ 200G. This preserves backward compatibility with DUTs that lack
`platform.json`.

## Usage

### Deploy with PORT override (recommended)

```bash
# Deploy minigraph + golden config with PORT table generated from links.csv
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <password> \
    -e port_override_from_links=true -e lab_name=<lab>
```

This single command:
1. Reads port speeds from `ansible/files/sonic_<lab>_links.csv` on the mgmt server
2. Reads the DUT's HwSKU from `ansible/files/sonic_<lab>_devices.csv`
3. On the DUT, rebuilds the PORT table from the local `platform.json` using those speeds
4. Applies minigraph + PORT override with `config load_minigraph --override_config -y`

### Deploy without PORT override (default behavior)

Without `port_override_from_links`, the module uses minigraph PORT speeds and
adds FEC. This is the existing behavior and requires no extra flags:

```bash
./testbed-cli.sh deploy-mg <testbed-name> <inventory> <password>
```

### Standalone generation (optional)

For debugging or offline use, the standalone script `generate_port_config.py`
can generate the same PORT table JSON on the mgmt server:

```bash
python3 ansible/scripts/generate_port_config.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --devices-csv ansible/files/sonic_str4_devices.csv \
    --hostname str4-7060x6-64pe-11 \
    --platform-json ~/sonic-buildimage/device/arista/x86_64-arista_7060x6_64pe/platform.json \
    --full-config \
    -o /tmp/port_config_override.json
```

### Changing Breakout (update links.csv)

To remap `links.csv` for a new breakout layout, use the `update-breakout`
command in `testbed-cli.sh`, which wraps `update_links_for_breakout.py` and
automatically resolves the DUT hostname from the testbed definition:

```bash
# From the ansible/ directory

# Uniform breakout — all cages get the same mode
./testbed-cli.sh update-breakout str4-t1-lag \
    files/sonic_str4_links.csv 2x400G --dry-run

# Mixed breakout — different modes per port range
./testbed-cli.sh update-breakout str4-t1-lag \
    files/sonic_str4_links.csv "1x800G:0-255,2x400G:256-504" --dry-run

# Remove --dry-run to apply
```

Alternatively, call the script directly with an explicit hostname:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --hostname str4-7060x6-64pe-11 \
    --target-breakout 2x400G \
    --dry-run
```

The port range in mixed breakout refers to Ethernet port numbers. Each range
gets its own breakout mode. Cages are determined by `--lanes-per-cage` (default: 8).

#### What the Script Does

The script groups DUT ports by physical cage, maps existing source ports to
target ports in the new breakout, removes entries that don't exist in the new
layout, and generates expansion entries for any target ports that lack a source
mapping. This ensures the CSV is always complete for the new port layout. VLAN
assignments are updated sequentially and trunk VLAN ranges are adjusted.

#### Updating HwSku

Use `--hwsku` to update both `links.csv` and `devices.csv` in one command:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --hostname str4-7060x6-64pe-11 \
    --target-breakout 2x400G \
    --hwsku Arista-7060X6-64PE-O128S2
```

The script auto-detects the companion `devices.csv` from the `links.csv` path
and updates the HwSku column for the specified hostname.



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

Use `--hwsku` during Step 2 to handle this automatically, or edit
`ansible/files/sonic_str4_devices.csv` manually:

```bash
python3 ansible/scripts/update_links_for_breakout.py \
    --links-csv ansible/files/sonic_str4_links.csv \
    --hostname str4-7060x6-64pe-11 \
    --target-breakout 2x400G \
    --hwsku Arista-7060X6-64PE-O128S2
```

### Step 4: Update the devices.csv and Redeploy leaf fanout(Uses another change in port_config_gen.py by PR:https://github.com/sonic-net/sonic-mgmt/pull/23536/changes)

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

### Step 6: Deploy minigraph with PORT override

This generates minigraph with the new port layout, builds the golden config
(which rebuilds the PORT table from `platform.json`), and applies both:

```bash
./testbed-cli.sh deploy-mg str4-t1-lag str4-inventory ~/.password \
    -e port_override_from_links=true -e lab_name=str4
```

What happens under the hood:
1. Playbook reads `links.csv` on the mgmt server → extracts `port_speeds` for 128 ports
2. `generate_golden_config_db` runs on the DUT, reads local `platform.json`
3. PORT table is rebuilt with correct lanes, aliases, indices, speed=400000, fec=rs
4. `config load_minigraph --override_config -y` applies minigraph + PORT override

No `port_config.ini` is read or needed at any step.

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
