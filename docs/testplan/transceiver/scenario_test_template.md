# Scenario Coverage Test-Case Template

Shared skeleton for a feature plan's **scenario-coverage** test cases — validating that a feature's
data/state recovers after a disruptive operation (shut/no-shut, reboot, config reload, daemon/service
restart, `sfputil` reset, low-power toggle).

Primary consumers: **EEPROM, DOM, VDM, PM**. **System** owns the operations; **OIR** and
**CDB Firmware Upgrade** own their own operations and validate affected features around them. Each
feature owns its scenario TCs today; keeping them uniform lets a single orchestrator later drive one
operation and call every verifier — a refactor, not a rewrite.

## Contract

| Element | Contract |
|---------|----------|
| **Operation helper** | `perform_<op>(duthost, ...)` in `tests/transceiver/common/scenario_ops.py`, **wrapping** the existing repo helper (`tests/common/reboot.py::reboot`, `config_reload`). Never inline a reboot/reload/restart. |
| **Verifier** | `verify_<feature>_recovered(duthost, ports=None, baseline=None)` — iterates ports under test (`port_attributes_dict` if applicable) and aggregates failures; `ports` scopes a subset; standalone so an orchestrator can call it after one operation. Asserts **only state the feature owns** (no link/flap checks in a content verifier). |
| **Pre-check** | Assert the feature is healthy before the operation — reusing the parent's [session prerequisites](test_plan.md#common-session-level-prerequisites) / [health checks](test_plan.md#common-per-test-health-checks), not re-implementing presence/link/core checks — so a failure is attributable to the operation. |
| **Baseline (optional)** | `capture_<feature>_baseline(duthost, ports=None)` — returns a per-port snapshot `{port: {...}}` (keyed like `port_attributes_dict`, feature-defined payload) that the matching verifier consumes for its relative comparison. Only for **relative** checks (deviation ranges, flap-count delta); absolute checks against `port_attributes_dict` need no baseline. |
| **Settle timers** | Reuse the `*_settle_sec` attributes from the [System Test Plan](system_test_plan.md#attributes); don't redefine per feature. |

## Operation catalog

`shut_noshut`, `cold_reboot`, `warm_reboot`, `fast_reboot`, `config_reload`,
`daemon_restart` (xcvrd/pmon/swss/syncd), `sfputil_reset`, `lpm_toggle`.

Shut/no-shut is often a fuller "interface state change" test that also validates feature state
*while the port is down*, not just recovery after.

`sfputil_reset` takes an optional `recover_with_port_toggle` parameter —
`perform_sfputil_reset(duthost, port, recover_with_port_toggle=True)`. With the default `True` the helper runs
`config interface shutdown` → `sfputil reset` → `config interface startup`, since on some modules a
bare reset leaves the port oper-down and does not auto-recover; pass `False` for modules/platforms
whose datapath auto-recovers after a bare reset.

## Test-case skeleton

Each feature adds a **Scenario Coverage Test Cases** subsection with an applicability table and one
row per applicable scenario:

| TC No. | Test | Steps | Expected Results |
|--------|------|-------|------------------|
| S`<n>` | `<FEATURE>` recovery after `<SCENARIO>` | 1. **Pre-check** (capture baseline here if the feature has relative checks).<br>2. **Operate**: `perform_<scenario>(duthost, ...)` (skip via the `*_supported` gate).<br>3. **Recover**: **poll** (`wait_until`) up to `<scenario>_settle_sec` for the DUT back + module **Present** — don't blind-`sleep`. Link-dependent features also run the [Standard Port Recovery Procedure](system_test_plan.md#standard-port-recovery-and-verification-procedure); content-only features (EEPROM) don't need link-up.<br>4. **Verify**: `verify_<feature>_recovered(...)` — absolute checks vs `port_attributes_dict` plus any relative checks; aggregate.<br>5. **Teardown**: restore mutated state. | Feature data recovers to expected values; no I2C errors or core files; every port passes the verifier. |

> **Reboot/restart gotcha:** these change process PIDs and may add core files, so re-establish the
> autouse health-check baseline afterward (as System's recovery/process-restart conftests do) to
> avoid false failures.

See the [EEPROM Test Plan](eeprom_test_plan.md) Scenario Coverage section for a worked example.

## Applicability table (each feature fills in)

| Scenario | Applicable? | Scenario TC | Notes |
|----------|:-----------:|:-----------:|-------|
| Shut / no-shut | | | often a fuller "interface state change" test |
| Cold reboot | | | |
| Warm reboot | | | gate on `warm_reboot_supported` |
| Fast reboot | | | gate on `fast_reboot_supported` |
| Config reload | | | |
| Daemon/docker restart | | | xcvrd / pmon / swss / syncd |
| sfputil reset | | | |
| LPM toggle | | | |

> **Cost:** reboots multiply per feature. A module/session-scoped fixture can share one reboot across
> a feature's scenarios, at the cost of coupling those TCs.
