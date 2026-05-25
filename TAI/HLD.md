# High-Level Design: TAI (Test Abstraction Interface)

## 1. Overview

TAI (Test Abstraction Interface) is the platform abstraction layer for SONiC tests. Different ASIC generations behave differently. They count drops on different sides, have different counter index layouts, tolerate different amounts of background noise, and handle packet leakout differently. Without a shared abstraction, every test that touches counters or QoS config has to know about all of this.

TAI puts platform-specific knowledge into per-platform adapter classes. Tests call a single interface and the right behavior for that hardware is applied automatically. Adding support for a new ASIC generation means writing one adapter class. Existing tests require no changes.

**Without TAI**, tests carry this kind of logic directly:
```python
if asic_type == 'broadcom-dnx':
    drop_count = recv_counters[1]   # ingress, index 1 only on DNX
    margin = 10
else:
    drop_count = xmit_counters[3]   # egress on Tomahawk
    margin = 2
assert drop_count <= margin, f"Unexpected drops: {drop_count}"
```

**With TAI**, the test just asks the question:
```python
ok, reason = platform_adapter.check_rx_drop(recv_delta, ingress_counters)
assert not ok, reason
```

The margin, which counter to read, and which indices are reliable all live in the adapter for that platform.

## 2. Components

### 2.1 Directory Structure

```
TAI/
  core/
    base.py       - root class all adapters inherit from
    thrift.py     - SAI thrift counter operations (PTF context)
    qos.py        - Redis / DUT shell operations
    factory.py    - platform detection and adapter creation
    facade.py     - the single entry point tests use
  platforms/
    tomahawk/
      th5/        - Tomahawk 5
      th6/        - Tomahawk 6, inherits th5
    qumran/
      q3d/        - Qumran Q3D
  generate.py     - scaffolds new adapters from the command line
  report.py       - emits COVERAGE.md showing per-platform method resolution
  COVERAGE.md     - auto-generated coverage matrix (run report.py to refresh)
```

### 2.2 ThriftAdapter (`core/thrift.py`)

Handles SAI thrift counter reads inside PTF tests, including reading counters, checking drops and PFC, controlling TX, and sending packets. Each platform subclass overrides only what differs for that generation and inherits everything else from the base.

### 2.3 QoSAdapter (`core/qos.py`)

Handles DUT-side operations via Redis and the DUT shell, covering scheduler config, buffer profile management, and drop counters. Platform subclasses override the parts that differ, such as queue key format or any extra ASIC commands required before applying config.

Adapter methods accept a `**platform_params` dict for passing parameters that only make sense for specific platforms. For example, Qumran requires a credit worth value when creating a STRICT scheduler but Tomahawk does not. The caller passes `credit_worth=4096` and only the Qumran adapter picks it up. Others ignore what they do not need.

### 2.4 AdapterFactory (`core/factory.py`)

Each adapter registers itself with the factory using a decorator at the top of its file:

```python
@AdapterFactory.register(ThriftAdapter, 'th6')
class TH6ThriftAdapter(TH5ThriftAdapter):
    ...
```

This runs at import time. When Python imports the `platforms` package, it walks through each family and generation `__init__.py`, imports the adapter modules, and the decorator fires, adding the class to the factory registry. By the time any test creates a `PlatformAdapter`, all adapters are already registered.

When `PlatformAdapter` is initialized, the factory figures out which platform is running by matching the DUT's `hwsku` against a prefix table. Variant SKUs hit their base prefix entry so they do not need individual registrations.

If no prefix matches, the factory raises an `AssertionError` naming the unknown hwsku. There is no fallback to a base adapter. A missing adapter means platform behavior is unknown, so the test fails loudly rather than running against assumptions that do not hold on that hardware.

Mappings live in each platform adapter's `@AdapterFactory.register(...)` decorator. Run `python TAI/report.py` to see the current set.

### 2.5 PlatformAdapter (`core/facade.py`)

The only class tests interact with. Create one `PlatformAdapter(duthost)` and call any method on it. ThriftAdapter and QoSAdapter methods are all accessible from the same object. Adapters are created and cached on first use.

It also supports feature checking before a test runs so a test can skip cleanly if the platform does not support what it needs.

## 3. Platform Adapters

Each platform adapter lives under `platforms/{family}/{generation}/` and contains a `thrift.py` and a `qos.py`.

### 3.1 TH5 - Tomahawk 5 (`platforms/tomahawk/th5/`)

The base of the Tomahawk line. Inherits from the core adapter and overrides only what differs.

### 3.2 TH6 - Tomahawk 6 (`platforms/tomahawk/th6/`)

Inherits from TH5 and overrides only what differs from it.

### 3.3 Q3D - Qumran Q3D (`platforms/qumran/q3d/`)

Inherits from the core base directly. Qumran uses the broadcom-dnx architecture which behaves differently from Tomahawk in how it counts drops, tracks counters, and handles noise. All those differences live here.

## 4. Adding New Platforms

Adding a new ASIC generation is a single command. The generator creates the platform directory, writes the adapter files, and patches the factory so the new ASIC is detected automatically. The new adapter inherits from its parent so everything already working continues to work. You only fill in what actually differs.

```bash
# New generation within an existing family
python TAI/generate.py th7 --family tomahawk --parent th6 --hwsku <hwsku-prefix>

# First of a new family
python TAI/generate.py q5d --family qumran --parent core --hwsku <hwsku-prefix>
```

After running the command, hardware matching the given hwsku prefix maps to `TH7ThriftAdapter` and `TH7QoSAdapter` automatically. Existing tests pick up the new platform without any changes. Add overrides only where TH7 actually behaves differently from TH6. If nothing differs yet, the files can stay empty.

## 5. How a Call Flows Through TAI

### Call flow diagram

```
┌─────────────────────────────────────────────────┐
│  Test                                           │
│  platform_adapter.check_rx_drop(...)            │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  PlatformAdapter  (facade.py)                   │
│  looks up adapter type in cache                 │
│  not found → asks AdapterFactory to create one  │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│  AdapterFactory  (factory.py)                   │
│  reads duthost.facts['hwsku']                   │
│  hwsku matches th6 prefix → TH6 adapter         │
│  creates and returns adapter instance           │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│  TH6ThriftAdapter                               │
│  method not overridden, fallback to TH5         │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│  TH5ThriftAdapter                               │
│  method not overridden, fallback to base        │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│  ThriftAdapter  (core/thrift.py)                │
│  executes method, returns result                │
└─────────────────────────────────────────────────┘
```

### What changes on a different platform

The test code stays the same regardless of hardware. What changes is which adapter the factory created. On a Q3D the factory creates a `Q3DThriftAdapter` and the same call uses Q3D-specific margins and counter indices with no change to the test.

```
Same test call: platform_adapter.check_rx_drop(recv_d, ingress_counters)

  On TH6:                          On Q3D:
  PlatformAdapter                  PlatformAdapter
    -> TH6ThriftAdapter               -> Q3DThriftAdapter
      -> TH5ThriftAdapter                margin = 10
        -> ThriftAdapter                 only counter index 1 used
           margin = 2
           all indices active
```

### Factory detection

When `PlatformAdapter(duthost)` is first called, the factory reads `duthost.facts['hwsku']` and walks the prefix table. The first prefix that matches wins, so variant SKUs are absorbed by their base entry. If no prefix matches, the factory raises an `AssertionError` with the unknown hwsku in the message. The test fails rather than silently running against an unregistered platform since the adapter is what makes the test's assumptions correct.

The resolved adapter is cached. Every subsequent call reuses the same instance. The factory only runs once.

## 6. Current Coverage

| Generation | Family |
|-----------|--------|
| th5 | tomahawk |
| th6 | tomahawk |
| q3d | qumran |

For a method-level view of which class actually implements each call on each platform, run `python TAI/report.py`. It walks the MRO of every registered adapter and writes `TAI/COVERAGE.md`: one table per family per adapter type (ThriftAdapter / QoSAdapter). Each cell names the nearest class that defines the method; bold cells are overrides at the platform itself, everything else is inherited. The layout reads the same whether the family is a linear chain (`TH5 < base, TH6 < TH5`) or a branching tree (`TH7 < base` alongside the TH5/TH6 lineage) since inheritance structure is encoded per cell, not per column.

## 7. Design Decisions

**Per-generation adapters.** Each generation has its own adapter and inherits from the previous one. TH5 and TH6 share most behavior but differ on a few values. That difference is a one-line override in TH6 rather than a conditional spread across tests.

**hwsku prefix is the only detection signal.** `hwsku` is always present on `duthost.facts`, and prefix matching handles variant SKUs without needing per-variant entries.

**No fallback to a base adapter, fail instead.** If the hwsku does not match any registered prefix, the factory raises an `AssertionError` naming the unknown hwsku. A missing adapter means the platform's behavior is not yet encoded, and running the base adapter there would produce results that look valid but are not. Failing makes it obvious that an adapter must be added before the test can run on that hardware.

**Check functions report what happened.** All check methods return whether the condition is true. Whether that is a pass or fail is up to the test. This means one function instead of two.

## 8. Future Work

**More adapter types.** ThriftAdapter and QoSAdapter cover PFC and QoS buffer tests. Reboot, link management, and thermal tests still carry platform conditionals and would benefit from the same treatment.

**Platform capability matrix.** Each adapter declares a `supported_features` set. This could be surfaced so CI can decide which tests to run on which hardware rather than relying on tests to skip at runtime.

**Debug mode.** When a test fails it is not always clear which adapter was selected or why. A debug flag that logs the detection path would help narrow down platform detection issues quickly.

**Platform configuration in TAI.** Platform-specific values like buffer thresholds, queue depths, and PFC watermarks currently live in test param files across the repo. Moving them into TAI alongside the adapters would put all platform knowledge in one place.
