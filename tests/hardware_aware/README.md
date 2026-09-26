# Hardware-Aware Pre-Run Deselect

Hardware-aware deselect removes tests during pytest collection when the current
platform/topology/run setup cannot satisfy the facts required by those tests.

Users mainly work with two YAML files:

```text
setup_profiles.yaml
  Current setup facts: platform, topology, run options, feature flags, and
  resource availability.

skip_rules.yaml
  Skip rules: which setup facts make a rule apply, and which tests are affected.
```

The generated `run_context` and `test_capabilities` objects are internal plugin
artifacts. Users should not create or edit them by hand.

## Quick Start

Run from `sonic-mgmt/tests` or `/data/tests`.

### Option 1: Use A Known Setup

Use this when the setup already exists in `setup_profiles.yaml`.

```bash
RUN_ID=ring4-5697-42221-t0-m6-28-superbolt

./run_tests.sh ... \
  -e "-p tests.common.plugins.hardware_aware" \
  -e "--hardware-aware-deselect" \
  -e "--hardware-aware-setup=8122-64EHF-O:t0" \
  -e "--hardware-aware-missing-run-context-policy=deselect" \
  -e "--hardware-aware-report-path=logs_hwaware/${RUN_ID}_hardware_aware.json" \
  -e --collect-only
```

The plugin also writes a concise text summary next to the JSON report, for
example `logs_hwaware/${RUN_ID}_hardware_aware_summary.txt`. When multiple
reports named `*_hardware_aware.json` are written in the same log directory,
the plugin also refreshes `hardware_aware_deselect_summary.txt` in that
directory.

View the readable summaries with:

```bash
cat logs_hwaware/${RUN_ID}_hardware_aware_summary.txt
cat logs_hwaware/hardware_aware_deselect_summary.txt
```

Use report-only mode to inspect decisions without removing tests:

```bash
-e "--hardware-aware-report-only"
```

### Option 2: Override A Known Setup

Use this when most setup facts are already correct, but one or two values differ
for the current run.

`my_override.yaml`:

```yaml
parameters:
  features.nat.enabled: true
```

Command:

```bash
./run_tests.sh ... \
  -e "-p tests.common.plugins.hardware_aware" \
  -e "--hardware-aware-deselect" \
  -e "--hardware-aware-setup=x86_64-8122_64ehf_o-r0:t0" \
  -e "--hardware-aware-setup-input=my_override.yaml" \
  -e --collect-only
```

### Option 3: Provide A New Setup File

Use this when the platform/topology setup is not in `setup_profiles.yaml` yet.

`my_setup.yaml`:

```yaml
key: FAS1000-32D:t0
metadata:
  platform: FAS1000-32D
  topology: t0
parameters:
  run.options.include_long_tests: false
  topology.type: t0
  topology.available_tags:
    - t0
  topology.is_dualtor: false
  topology.multi_dut.supported: false
  topology.single_dut_multi_asic.supported: false
  platform.is_multi_asic: false
  features.nat.enabled: false
  features.macsec.enabled: false
  resources.tgen_port_info.available: false
```

Command:

```bash
./run_tests.sh ... \
  -e "-p tests.common.plugins.hardware_aware" \
  -e "--hardware-aware-deselect" \
  -e "--hardware-aware-setup-input=my_setup.yaml" \
  -e --collect-only
```

Prefer external identifiers such as SONiC platform, PID, or HwSKU. Cisco
internal names such as `superbolt` are aliases only.

The output report records the selected setup and generated rule counts under
`inputs.catalog_setup`.

## Maintaining The YAML Files

### Add Setup Facts

Add platform identity and validated setup facts in `setup_profiles.yaml`.

```yaml
setups:
  x86_64-8122_64ehf_o-r0:t0:
    aliases:
      - superbolt:t0
      - 8122-64EHF-O:t0
    metadata:
      platform: x86_64-8122_64ehf_o-r0
      topology: t0
    parameters:
      topology.type: t0
      topology.multi_dut.supported: false
      platform.is_multi_asic: false
      features.nat.enabled: false
```

### Add Skip Rules

Add or refine skip rules in `skip_rules.yaml`.

```yaml
skip_rules:
  nat_feature_disabled:
    reason_patterns:
      - "^nat feature is not enabled with image version .*$"
    parameters:
      features.nat.enabled: false
    tests:
      - tests/nat/
```

Readable test selectors can be folders, files, tests, or selected
parametrizations:

```yaml
tests:
  - tests/nat/
  - tests/qos/test_buffer.py
  - tests/qos/test_qos_sai.py::TestQosSai::testQosSaiBufferPoolWatermark
  - nodeid: tests/qos/test_qos_sai.py::TestQosSai::testQosSaiBufferPoolWatermark
    param_contains: multi_dut
```

## Internal Flow

The plugin keeps the old capability comparison logic, but hides the generated
files from users:

```text
user passes setup key or setup YAML
-> plugin loads setup_profiles.yaml
-> plugin loads skip_rules.yaml
-> matching skip rules become internal test_capabilities
-> selected setup facts become internal run_context
-> plugin compares test requirements with current setup facts
-> unsupported tests are reported or deselected
```

`generate_runtime_inputs.py` is the converter used by the plugin. It can also
be run directly for debugging or report-seeded validation:

```bash
python3 hardware_aware/generate_runtime_inputs.py \
  --catalog hardware_aware/skip_rules.yaml \
  --setup-profiles hardware_aware/setup_profiles.yaml \
  --setup x86_64-8122_64ehf_o-r0:t0 \
  --test-capabilities-output out/test_capabilities.json \
  --run-context-output out/run_context.json \
  --audit-output out/audit.json
```

`audit_selector_scope.py` is optional. Use it to validate whether readable test
selectors are too narrow or too broad against historical skipped-reason reports.

By default, `topology_unavailable` has `enabled: false` in `skip_rules.yaml`
because SONiC `custom_markers` already handles `pytest.mark.topology` when
`--topology` is passed. Set that YAML value to `true` if hardware-aware should
own topology gating. The `--hardware-aware-include-topology-rules` flag is only
a temporary override for debugging.
