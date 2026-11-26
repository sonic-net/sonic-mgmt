# FEC Attribute-Based Test Infrastructure HLD

> **Proposal:** Reuse the existing transceiver attribute hierarchy and parser to
> make FEC test capabilities and hardware-dependent parameters data-driven and
> overrideable by platform, HWSKU,
> deployment, transceiver vendor, part number, platform+HWSKU, and DUT.

## 1. Scope

### 1.1 Goals

- Reuse one JSON hierarchy, one merge implementation, and one normalization
  model.
- Support FEC capabilities and hardware-dependent parameters at platform,
  HWSKU, deployment, vendor, part-number, platform+HWSKU, and DUT scopes.
- Resolve policy for the exact DUT selected by each parametrized FEC test.
- Treat the three FEC capability fields as optional overrides; an omitted key
  uses that test's existing legacy predicate.
- Preserve today's policy when the FEC category is absent.
- Keep histogram, BER, and FLR availability in the existing runtime test logic,
  whether the FEC category is present or absent.

This HLD focuses on test infrastructure and configuration. It does not propose
new FEC features in SONiC, new CLI behavior, or a redesign of the FEC tests.

## 2. Background and Current Problem

Forward Error Correction (FEC) adds redundancy so a receiver can correct some
bit or symbol errors without retransmission of packets. Correctable errors can
occur on a healthy high-speed link; uncorrectable errors mean the codeword
could not be recovered.

### 2.1 Terminology

| Term | Meaning |
| --- | --- |
| FEC symbol | A smaller encoded unit inside a FEC codeword. |
| FEC codeword | A complete FEC-protected block containing data and parity. |
| Correctable FEC error | The codeword had errors, but FEC repaired them. |
| Uncorrectable FEC error | The codeword had more errors than FEC could repair. |
| FEC histogram bin | A counter bucket grouping codewords by the number of symbol errors observed. |

### 2.2 Hardcoded Inputs in Scope

In this section, the target scripts are:

- `tests/platform_tests/test_intf_fec.py`
- `tests/layer1/test_fec_error.py`

| Current hardcoded input or policy | JSON attribute | Initial contract |
| --- | --- | --- |
| Basic FEC-statistics applicability predicate | `basic_fec_stats_supported` | Optional Boolean override; omission uses the existing test predicate. |
| Operational-mode verification predicate | `verify_fec_oper_mode_supported` | Optional Boolean override; omission uses the existing test predicate. |
| Mode reapply/configuration predicate | `configure_fec_oper_mode_supported` | Optional Boolean override; omission uses the existing test predicate. |
| Eligible speeds | `supported_speeds` | Category default: `["50G", "100G", "200G", "400G", "800G", "1600G"]`. |
| Mode recovery timeout | `fec_mode_restore_timeout_sec` | Category default: `30` seconds. |
| Counter-clear wait | `clear_counters_wait_sec` | Category default: `60` seconds. |
| Stale-histogram aging wait | `fec_histogram_stale_error_wait_sec` | Category default: `600` seconds. |
| Critical histogram indices | `critical_histogram_bins` | Category default: `[7, 8, 9, 10, 11, 12, 13, 14, 15]`. |

## 3. Existing Attribute Framework

### 3.1 Existing Contract

The framework builds a per-port dictionary from:

- `dut_info/<dut_hostname>.json`, which supplies `BASE_ATTRIBUTES`;
- normalized vendor and part-number mappings;
- category shards under `attributes/<category>/`; and
- optional deployment templates for completeness validation.

For FEC, the new category-specific output will be:

```python
port_attributes_dict[port]["FEC_ATTRIBUTES"]
```

### 3.2 Resolution Precedence

Higher-priority attributes override lower-priority values:

```text
defaults < platform < HWSKU < deployment < vendor < part number
         < platform+HWSKU override < DUT override
```

The shared parser, originally implemented for transceiver onboarding, already
performs this merge.

## 4. Proposed Design

### 4.1 Inventory Ownership and File Organization

Real lab data is expected at:

```text
ansible/files/transceiver/inventory/
```

That tree is lab-owned and is not populated with real lab identities upstream.
The upstream change adds sanitized examples at:

```text
docs/testplan/transceiver/examples/inventory/attributes/fec/
```

If the `attributes/fec/` directory is absent, the tests use the legacy policy
without requiring transceiver inventory solely for FEC. If it is present, that
directory is the enrollment boundary: the framework requires the shared
normalization mappings and `dut_info/<dut_hostname>.json` for the selected DUT,
even when no vendor-specific FEC override exists. It then validates and merges
the supplied defaults and overrides. An omitted capability override continues
to use the corresponding legacy predicate.

The following inventory tree is intentionally abridged and is preserved from
the original design. Deployment and DUT policy live inside the category-level
`fec.json`; PN-scoped platform+HWSKU policy lives inside the PN shard.

```text
ansible/files/transceiver/inventory/
+-- normalization_mappings.json
+-- dut_info/
|   +-- <dut_hostname>.json
|   +-- ...
+-- attributes/
|   +-- fec/
|       +-- fec.json
|       +-- platforms/
|       |   +-- <PLATFORM>/
|       |       +-- fec.json
|       |       +-- hwskus/
|       |           +-- <HWSKU>.json
|       +-- transceivers/
|           +-- vendors/
|               +-- <NORMALIZED_VENDOR_NAME>/
|                   +-- fec.json
|                   +-- part_numbers/
|                       +-- <NORMALIZED_VENDOR_PART_NUMBER>/
|                           +-- fec.json
+-- templates/
    +-- deployment_templates.json
```

### 4.2 FEC Category Examples

The implementation should add the category root plus one platform example:

```text
docs/testplan/transceiver/examples/inventory/attributes/fec/
+-- fec.json
+-- platforms/
    +-- x86_64-acme_as7726_32x-r0/
        +-- fec.json
```

The existing example `normalization_mappings.json` and
`dut_info/lab-dut-01.json` are reused; FEC-specific copies are not needed. A
vendor or part-number FEC shard is optional and should be added only to
demonstrate a real exception. `deployment_templates.json` may provide extra
deployment validation, but it is not required for this example.

The category-level shard supplies common defaults. No FEC attribute is
mandatory in the initial rollout.

`attributes/fec/fec.json`:

```json
{
  "defaults": {
    "supported_speeds": ["50G", "100G", "200G", "400G", "800G", "1600G"],
    "fec_mode_restore_timeout_sec": 30,
    "clear_counters_wait_sec": 60,
    "fec_histogram_stale_error_wait_sec": 600,
    "critical_histogram_bins": [7, 8, 9, 10, 11, 12, 13, 14, 15]
  }
}
```

A platform shard is a flat body, not a wrapped `platforms` object:

`attributes/fec/platforms/x86_64-acme_as7726_32x-r0/fec.json`:

```json
{
  "basic_fec_stats_supported": true,
  "verify_fec_oper_mode_supported": true,
  "configure_fec_oper_mode_supported": true
}
```

These optional values override the matching legacy predicates for the platform.
If a key is omitted, that key independently uses legacy behavior. Histogram,
BER, and FLR availability remains owned by the existing test code.

### 4.3 Resolved Output

`port_attributes_dict` is a nested dictionary keyed by port. Each port stores
its FEC settings under `FEC_ATTRIBUTES`:

```python
port_attributes_dict = {
    "Ethernet0": {
        "BASE_ATTRIBUTES": {
            "vendor_name": "ACME Corp.",
            "vendor_pn": "QSFP-2X100G-AOC-15M",
            "normalized_vendor_name": "ACME_CORP",
            "normalized_vendor_pn": "QSFP-2X100G-AOC-GENERIC_2_ENDM",
            "deployment": "2x100G_200G_SIDE",
            "speed_gbps": 200,
        },
        "FEC_ATTRIBUTES": {
            "supported_speeds": ["50G", "100G", "200G", "400G", "800G", "1600G"],
            "basic_fec_stats_supported": True,
            "verify_fec_oper_mode_supported": True,
            "configure_fec_oper_mode_supported": True,
            "fec_mode_restore_timeout_sec": 30,
            "clear_counters_wait_sec": 60,
            "critical_histogram_bins": [7, 8, 9, 10, 11, 12, 13, 14, 15],
            "fec_histogram_stale_error_wait_sec": 600,
        },
    }
}
```

The three capability keys appear here because the matching platform shard
supplies them; another port may omit any key and use its legacy predicate.

## 5. Attribute Contract

The initial rollout supports incremental onboarding:

| Inventory state | Behavior |
| --- | --- |
| FEC category absent | Use the existing values and predicates. Transceiver inventory is not required solely for FEC. |
| FEC category present | Merge category defaults and any applicable scoped overrides. |
| Optional capability omitted | Use that test's existing legacy predicate for that capability. |
| Override supplied | Use the supplied Boolean value. |
| Supplied JSON or value malformed | Fail schema validation. |

The inventory contract contains only test applicability, hardware capability,
and parameters with a demonstrated platform, vendor, or part-number variance.
It does not make correctness criteria or internal test-loop mechanics
configurable.

### 5.1 Optional Capability Overrides and Defaults

| Attribute | Type | Contract | Purpose |
| --- | --- | --- | --- |
| `basic_fec_stats_supported` | Boolean | Optional expected-support override | Basic corrected-codeword, uncorrectable-codeword, and symbol-error statistics. |
| `verify_fec_oper_mode_supported` | Boolean | Optional expected-support override | Operational-mode validation. |
| `configure_fec_oper_mode_supported` | Boolean | Optional expected-support override | Reapply the current mode and verify recovery. |
| `supported_speeds` | List of strings | Category default | Speeds eligible for FEC validation; this does not configure interface speed. |

A supplied capability Boolean takes precedence over the corresponding legacy
platform or ASIC applicability predicate for that port. Omission preserves that
predicate and is never interpreted as `false`. A capability override changes
only its named check. In particular, `basic_fec_stats_supported: false` disables
only corrected-codeword, uncorrectable-codeword, and symbol-error validation; it
does not suppress the existing CLI execution or the runtime-detected BER and FLR
checks when the test is otherwise eligible. Supplied value attributes override
their corresponding legacy hardcoded defaults; omitted values retain those
defaults.

The FEC infrastructure does not impose a universal mandatory list. Each lab or
testbed owner may place these capability attributes in `mandatory` after
adoption; that policy remains owned by the lab inventory.

Histogram, BER, and FLR availability remains handled by the existing test code
and is not part of this initial override contract.

### 5.2 Hardware-Dependent Parameters

These parameters have category defaults equal to today's values. Narrower
scopes override them only for a demonstrated hardware difference.

| Attribute | Type | Category default | Purpose |
| --- | --- | --- | --- |
| `fec_mode_restore_timeout_sec` | Integer | `30` | Maximum hardware recovery time after reapplying the current FEC mode. |
| `clear_counters_wait_sec` | Integer | `60` | Time required before cleared FEC counters are reliably visible. |
| `fec_histogram_stale_error_wait_sec` | Integer | `600` | Hardware-specific aging wait when an initial histogram contains stale errors. |
| `critical_histogram_bins` | List of integers | `[7, 8, 9, 10, 11, 12, 13, 14, 15]` | Histogram indices to inspect; the pass/fail threshold remains fixed in code. |

Schema validation requires `supported_speeds` and `critical_histogram_bins` to
be non-empty and contain no duplicates. Each speed must use the canonical
positive `<N>G` form (for example, `100G`), and each histogram bin must be a
non-negative integer. `fec_mode_restore_timeout_sec` must be at least `1`;
`clear_counters_wait_sec` and `fec_histogram_stale_error_wait_sec` must be
non-negative.

When one DUT-wide operation covers several eligible ports, the test uses the
maximum resolved wait. Per-port operations use that port's resolved value.

### 5.3 Values That Remain in Test Code

The following are not inventory attributes:

- zero uncorrectable codewords;
- the existing corrected-codeword and symbol-error consistency validation;
- initial nonzero critical histogram bins trigger the stale-error aging wait;
  increases in follow-up snapshots fail;
- polling intervals and histogram snapshot count;
- CLI commands, parsing, numeric conversion, and failure aggregation; and
- histogram, BER, and FLR availability discovery and validation logic.

## 6. Python Code Organization

The parser originally implemented under `tests/transceiver/attribute_parser/`
is shared by moving its canonical implementation to
`tests/common/port_attributes/`. The corresponding modules under
`tests/transceiver/attribute_parser/` remain thin compatibility re-exports, so
existing transceiver imports and behavior are preserved. Common modules do not
depend on `tests/transceiver/`.

- `tests/common/port_attributes/` owns the shared loader, parser, merge,
  normalization, path, and template-validation implementation.
- `tests/common/port_attributes/builder.py` composes the shared parser and
  applies FEC schema validation only for explicit FEC-category requests.
- `tests/common/port_attributes/pytest_plugin.py` exposes the selected-DUT
  fixture factory and is registered by `tests/conftest.py`.
- `tests/transceiver/conftest.py` retains its package-local fixture and delegates
  loading and merging to the common builder.
- `tests/common/port_attributes/fec_schema.py` validates FEC attribute names,
  types, formats, and ranges.
- `tests/common/platform/fec_utils.py` owns legacy fallback values and helpers
  for resolving FEC attributes, capability overrides, waits, and eligible
  speeds.

The FEC fixtures request only the FEC category with missing-category fallback
enabled. Category absence returns legacy behavior before transceiver inventory
is required. When the category is present, consumers read:

```python
port_attributes_dict[port]["FEC_ATTRIBUTES"]
```

Each supplied capability Boolean overrides the corresponding legacy predicate;
an omitted capability continues to use that predicate.

## 7. Validation Model

FEC onboarding uses three separate validation layers. Completeness checks must
not be confused with static value validation or runtime DUT behavior.

| Layer | Owner | Responsibility |
| --- | --- | --- |
| 1. Static schema validation | JSON loader and `tests/common/port_attributes/fec_schema.py` | Validate supplied JSON names, shapes, types, formats, and ranges before merge. |
| 2. Attribute resolution | `tests/common/port_attributes/attribute_manager.py` | Apply the existing precedence rules to defaults and supplied scoped overrides. Optional capability keys may be absent. |
| 3. Test consumption | Shared FEC helpers and the two FEC test modules | Use a resolved capability override when present; otherwise use the existing test-specific legacy predicate. Continue the existing runtime CLI and counter validation. |

This initial change does not define new BER, FLR, or histogram result-reporting
behavior. Any such test-flow change should be handled separately with its own
implementation and tests.
