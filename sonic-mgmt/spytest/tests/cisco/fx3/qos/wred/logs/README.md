# WRED Test Cases — FX3 QoS SpyTest

All 29 test cases from the [WRED test plan](https://wwwin-github.cisco.com/whitebox/cisco-nx-sai/blob/apjoshi/qos-testplans/docs/qos/testplans/wred_test_plan.md).

## Test Case Tracking

| #   | Test Case                                     | Section | Type        | Status             | Owner       | File                                                                                                     |
| --- | --------------------------------------------- | ------- | ----------- | ------------------ | ----------- | -------------------------------------------------------------------------------------------------------- |
| 1   | Config reaches CONFIG_DB                      | A       | Manual      | DONE               | Aidan       | `wred/config/test_wred_config_propagation.py`                                                            |
| 2   | Config applied to ASIC_DB                     | A       | Manual/Auto | DONE               | Aidan       | `wred/config/test_wred_config_propagation.py`                                                            |
| 3   | ecnconfig -p set thresholds                   | B       | Manual      | DONE               | Aidan       | `wred/config/test_wred_config_propagation.py`                                                            |
| 4   | End-to-end WRED drop behavior                 | C       | Auto/Manual | DONE               | Peter/Diego | `wred/test_wred_drop_probability.py`, `qos/test_fx3_qos_integration.py`                                  |
| 5   | Clear queue stats + delta verification        | C       | Manual      | DONE               | Diego       | `wred/test_wred_counter_stats.py`                                                                        |
| 6   | min_threshold > max_threshold (REJECTED)      | D       | Manual      | DONE               | Aidan       | `wred/config/test_wred_threshold_validation.py`                                                          |
| 7   | min_threshold = 0 (below HAL min, REJECTED)   | D       | Manual      | DONE               | Aidan       | `wred/config/test_wred_threshold_validation.py`                                                          |
| 8   | max_threshold at lower practical limit        | E       | Manual      | DONE               | Aidan       | `wred/config/test_wred_config_propagation.py` (config), `wred/test_wred_profile_validation.py` (traffic) |
| 9   | max_threshold above platform limit (REJECTED) | E       | Manual      | DONE               | Aidan       | `wred/config/test_wred_threshold_validation.py`                                                          |
| 10  | drop_probability = 0 (no WRED drops)          | F       | Manual      | DONE               | Diego       | `wred/config/test_wred_threshold_validation.py` (config), `wred/test_wred_profile_validation.py` (traffic) |
| 11  | drop_probability = 5 (default SONiC)          | F       | Manual      | DONE               | Peter       | `wred/test_wred_drop_probability.py`                                                                     |
| 12  | drop_probability = 50 (mid-range)             | F       | Manual      | DONE               | Peter       | `wred/test_wred_drop_probability.py`                                                                     |
| 13  | drop_probability = 100 (maximum)              | F       | Manual      | DONE               | Peter       | `wred/test_wred_drop_probability.py`                                                                     |
| 14  | drop_probability = 101 (REJECTED)             | F       | Manual      | DONE               | Peter       | `wred/test_wred_drop_probability.py`                                                                     |
| 15  | Invalid profile name                          | G       | Manual      | DONE               | Diego       | `wred/config/test_wred_negative_input.py`                                                                |
| 16  | Non-numeric threshold value                   | G       | Manual      | DONE               | Diego       | `wred/config/test_wred_negative_input.py`                                                                |
| 17  | Missing required arguments                    | G       | Manual      | DONE               | Diego       | `wred/config/test_wred_negative_input.py`                                                                |
| 18  | Negative threshold value                      | G       | Manual      | DONE               | Diego       | `wred/config/test_wred_negative_input.py`                                                                |
| 19  | Disable WRED (unbind profile)                 | H       | Manual      | DONE               | Diego       | `wred/config/test_wred_enable_disable.py` (config), `wred/test_wred_profile_validation.py` (traffic)     |
| 20  | Re-enable WRED after disable                  | H       | Manual      | DONE               | Diego       | `wred/config/test_wred_enable_disable.py` (config), `wred/test_wred_profile_validation.py` (traffic)     |
| 21  | WRED Zone A: Below min (0% drops)             | I       | Auto        | DONE               | Peter/Diego | `qos/test_fx3_qos_integration.py`                                                                        |
| 22  | WRED Zone B: Active zone (0-5% drops)         | I       | Auto        | DONE               | Peter/Diego | `qos/test_fx3_qos_integration.py`                                                                        |
| 23  | WRED Zone C: Tail drop (>5% drops)            | I       | Auto        | DONE               | Peter/Diego | `qos/test_fx3_qos_integration.py`                                                                        |
| 24  | WRED Linearity: Drop rate vs margin           | I       | Auto        | DONE               | Peter/Diego | `qos/test_fx3_qos_integration.py`                                                                        |
| 25  | drop_probability = 200 (REJECTED)             | I       | Auto        | DONE               | Diego       | `wred/test_wred_profile_validation.py`                                                                   |
| 26  | drop_probability 5 -> 10%                     | I       | Auto        | DONE               | Diego       | `wred/test_wred_profile_validation.py`                                                                   |
| 27  | min and max thresholds doubled                | I       | Auto        | DONE               | Diego       | `wred/test_wred_profile_validation.py`                                                                   |
| 28  | scheduler+gdrop change                        | I       | Auto        | DONE               | Diego       | `wred/test_wred_profile_validation.py`                                                                   |
| 29  | min = max threshold                           | I       | Auto        | DONE               | Diego       | `wred/config/test_wred_negative_input.py`                                                                |

## Directory Structure

```
wred/
├── config/                                  # No-traffic config/validation tests
│   ├── test_wred_config_propagation.py      # Tests 1, 2, 3, 8 (config only)
│   ├── test_wred_threshold_validation.py    # Tests 6, 7, 9, 10 (config only)
│   ├── test_wred_negative_input.py          # Tests 15, 16, 17, 18, 29
│   └── test_wred_enable_disable.py          # Tests 19, 20 (config only)
├── test_wred_drop_probability.py            # Tests 4, 11-14
├── test_wred_profile_validation.py          # Tests 8 (traffic), 10 (traffic), 19-20 (traffic), 25-28
├── test_wred_counter_stats.py               # Test 5
└── logs/
    ├── README.md                            # This file
    ├── WRED_CONFIG_TESTS.md
    └── WRED_PROFILE_CHANGE.md
```

Tests 21-24 live in the parent directory at `qos/test_fx3_qos_integration.py`.

## Log Summaries

| Summary                                       | Tests Covered                                                                                                                                         |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [WRED Config Tests](WRED_CONFIG_TESTS.md)     | Tests 1, 2, 3, 6, 7, 8 (config), 9, 15-18, 19, 20                                                                                                     |
| [WRED Profile Change](WRED_PROFILE_CHANGE.md) | `test_wred_reject_invalid_gdrop`, `test_wred_custom_gdrop_profile`, `test_wred_custom_threshold_profile`, `test_wred_narrowest_zone` (Test 8 traffic) |
