# WRED Config Test Results

SONiC build: `fx3_cmaster.88-dirty-20260401.095209` | Run date: 2026-04-08

Sources:

- `[test_wred_config_propagation.py](../config/test_wred_config_propagation.py)` — Tests 1, 2, 3, 8 (config)
- `[test_wred_threshold_validation.py](../config/test_wred_threshold_validation.py)` — Tests 6, 7, 9
- `[test_wred_negative_input.py](../config/test_wred_negative_input.py)` — Tests 15-18 (invalid `ecnconfig`; no IXIA traffic)
- `[test_wred_enable_disable.py](../config/test_wred_enable_disable.py)` — Tests 19, 20 (unbind/re-enable; no IXIA traffic)

**7/7 passed** in 7m 55s for propagation + threshold (no IXIA traffic required).

**4/4 passed** in 3m 54s for negative/invalid input (no Ixia traffic required)

**2/2 passed** in 2m 09s for enable/disable (no IXIA traffic required)

Tests 2, 3, 6, 7, 8, 9 include DCHAL HW register validation
(`verify_wred_config_values_prog_in_dchal`) to verify actual ASIC programming
beyond ASIC_DB.

Tests 15-18 compare CONFIG_DB, ASIC_DB, and DCHAL before/after invalid `ecnconfig`
invocations; hardware and ASIC_DB must stay unchanged.

## Results


| Test | Function                           | Duration | Result   | Detail                                                                                                                   |
| ---- | ---------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| 1    | `test_config_reaches_config_db`    | 17s      | **PASS** | WRED profile and queue bindings match baseline                                                                           |
| 2    | `test_config_applied_to_asic_db`   | 2m 09s   | **PASS** | 6 SAI attrs verified, 378 queues bound, DCHAL HW OK                                                                      |
| 3    | `test_ecnconfig_set_thresholds`    | 28s      | **PASS** | CONFIG_DB, ASIC_DB, and DCHAL updated to 2 MB, restored to 3 MB                                                          |
| 8    | `test_narrowest_wred_zone`         | 23s      | **PASS** | 1-byte WRED zone accepted in CONFIG_DB, ASIC_DB, and DCHAL, then restored                                                |
| 6    | `test_reject_min_gt_max`           | 37s      | **PASS** | min>max rejected at SAI, ASIC_DB and DCHAL unchanged                                                                     |
| 7    | `test_reject_min_zero`             | 38s      | **PASS** | gmin=0 rejected at SAI, ASIC_DB and DCHAL unchanged                                                                      |
| 9    | `test_reject_max_above_limit`      | 37s      | **PASS** | gmax=4 MB rejected at SAI, ASIC_DB and DCHAL unchanged                                                                   |
| 15   | `test_wred_invalid_profile_name`   | 24s      | **PASS** | CONFIG_DB, ASIC_DB, and DCHAL unchanged after rejecting non-existent profile                                             |
| 16   | `test_wred_non_numeric_threshold`  | 25s      | **PASS** | CONFIG_DB, ASIC_DB, and DCHAL unchanged after rejecting gmin=`abc`                                                       |
| 17   | `test_wred_missing_required_args`  | 31s      | **PASS** | CONFIG_DB, ASIC_DB, and DCHAL unchanged after both incomplete `ecnconfig` invocations                                    |
| 18   | `test_wred_negative_threshold`     | 25s      | **PASS** | CONFIG_DB, ASIC_DB, and DCHAL unchanged after rejecting gmin=-1                                                          |
| 19   | `test_wred_disable_unbind_profile` | 43s      | **PASS** | WRED unbound — CONFIG_DB profile persists, queue bindings cleared, ASIC_DB unbound, DCHAL HW zeroed                      |
| 20   | `test_wred_reenable_after_disable` | 1m 26s   | **PASS** | WRED re-enabled — CONFIG_DB profile + bindings restored, ASIC_DB WRED object + queue binding OK, DCHAL HW matches golden |


## Notes

- Threshold rejection tests (6, 7, 9) verify both **ASIC_DB** and **DCHAL HW registers**
are unchanged. `ecnconfig` writes to CONFIG_DB unconditionally; SAI rejects invalid
values before they reach hardware. Each test restores CONFIG_DB via `config qos reload`.
- Test 2 takes ~2 min because it queries all 432 queue OIDs in ASIC_DB to verify WRED bindings.
- Tests 19 and 20 use `COUNTERS_QUEUE_NAME_MAP` in COUNTERS_DB to resolve per-port queue
OIDs, then check `SAI_QUEUE_ATTR_WRED_PROFILE_ID` in ASIC_DB for only the egress port's  
queues (0-7). 
- Test 8 config portion (steps 1-3 of the test plan) is covered here. The traffic
portion (`test_wred_narrowest_zone`) is in `test_wred_profile_validation.py`;
see [WRED Profile Change](WRED_PROFILE_CHANGE.md) for results.
- Negative-input tests (15-18) assert **no state drift** on invalid CLI; they do not require
`ecnconfig` to print usage/errors. A separate CLI-UX test (e.g. "Test 17" in the broader
plan) may still fail if `-gmin` without `-p` is silent today.

