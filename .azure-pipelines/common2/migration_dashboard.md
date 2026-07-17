# common → common2 Migration Dashboard

_Generated 2026-07-17 05:04 UTC by `.azure-pipelines/common2/scripts/migration_dashboard.py`._

## Summary

| Metric | Value |
| --- | ---: |
| Modules available to migrate | 261 |
| Modules already migrated | 0 |
| Distinct tests impacted (direct) | 650 |
| Distinct tests impacted (transitive) | 650 |
| Granular function/class sub-tasks | 2006 |

**How to read the numbers** (all follow _lower = easier_): **rank** = global order 1..261 (rank 1 is the single easiest); **tier** = difficulty band 1 (easy) .. 6 (hard); **score** = raw weighted effort (higher = more work).

Column key: **Tests** = tests importing the module directly · **Tx** = tests impacted transitively (hidden cascade) · **Deps** = other common modules it imports · **Typed** = % of params/returns already annotated · **UT** = has common2 unit tests.

## Migration work queue (easiest first) — showing top 60 of 261

| Rank | Tier | Score | Tests | Tx | Deps | LOC | Fns | Typed | UT | Module | Target domain |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :-: | --- | --- |
| 1 | 1 | 6.53 | 0 | 1 | 0 | 41 | 1 | 100% | N | `plugins/proc_mem_cpu_monitor/tcmalloc_parser.py` | `utilities/plugins` |
| 2 | 1 | 7.80 | 0 | 15 | 0 | 92 | 1 | 100% | N | `grpc_config.py` | `utilities/helpers` |
| 3 | 1 | 9.46 | 0 | 15 | 0 | 77 | 1 | 66% | N | `dut_gnoi.py` | `utilities/helpers` |
| 4 | 1 | 11.80 | 0 | 0 | 0 | 12 | 1 | 0% | N | `helpers/yaml_utils.py` | `utilities/helpers` |
| 5 | 1 | 11.90 | 0 | 64 | 0 | 16 | 1 | 0% | N | `helpers/cache_utils.py` | `utilities/helpers` |
| 6 | 1 | 12.10 | 0 | 0 | 0 | 24 | 1 | 0% | N | `dualtor/bsl_utils.py` | `network/dualtor` |
| 7 | 1 | 12.18 | 0 | 0 | 0 | 27 | 1 | 0% | N | `helpers/yang_utils.py` | `utilities/helpers` |
| 8 | 1 | 12.34 | 0 | 0 | 0 | 53 | 2 | 33% | N | `telemetry/fixtures.py` | `monitoring/telemetry` |
| 9 | 1 | 12.40 | 0 | 0 | 0 | 36 | 1 | 0% | N | `platform/args/cont_warm_reboot_args.py` | `system/reboot` |
| 10 | 1 | 12.90 | 0 | 0 | 0 | 56 | 1 | 0% | N | `ptf_agent_updater.py` | `utilities/helpers` |
| 11 | 1 | 13.00 | 0 | 0 | 2 | 37 | 1 | 67% | N | `telemetry/metrics/gauge.py` | `monitoring/telemetry` |
| 12 | 1 | 13.15 | 0 | 1 | 0 | 66 | 1 | 0% | N | `helpers/minimum_table.py` | `utilities/helpers` |
| 13 | 1 | 13.25 | 1 | 1 | 0 | 22 | 1 | 0% | N | `helpers/base_helper.py` | `utilities/helpers` |
| 14 | 1 | 13.45 | 1 | 48 | 0 | 30 | 1 | 0% | N | `plugins/ansible_fixtures.py` | `utilities/plugins` |
| 15 | 1 | 14.28 | 0 | 561 | 1 | 19 | 1 | 0% | N | `helpers/custom_msg_utils.py` | `utilities/helpers` |
| 16 | 1 | 14.30 | 0 | 0 | 1 | 8 | 1 | 0% | N | `devices/local.py` | `utilities/connection` |
| 17 | 1 | 14.50 | 0 | 0 | 1 | 16 | 1 | 0% | N | `devices/vmhost.py` | `utilities/connection` |
| 18 | 1 | 14.50 | 0 | 0 | 0 | 60 | 2 | 0% | N | `plugins/pdu_controller/controller_base.py` | `utilities/plugins` |
| 19 | 1 | 14.55 | 0 | 0 | 0 | 2 | 1 | 0% | N | `barefoot_data.py` | `platform/vendor` |
| 20 | 1 | 14.55 | 0 | 2 | 0 | 62 | 2 | 25% | N | `sai_validation/gnmi_client_internal.py` | `platform/sai` |
| 21 | 1 | 14.57 | 0 | 0 | 0 | 3 | 1 | 0% | N | `nokia_data.py` | `platform/vendor` |
| 22 | 1 | 14.57 | 0 | 0 | 0 | 3 | 1 | 0% | N | `platform/args/normal_reboot_args.py` | `system/reboot` |
| 23 | 1 | 14.60 | 2 | 2 | 0 | 28 | 1 | 0% | N | `helpers/crm.py` | `utilities/helpers` |
| 24 | 1 | 14.60 | 0 | 0 | 0 | 4 | 1 | 0% | N | `marvell_prestera_data.py` | `platform/vendor` |
| 25 | 1 | 14.65 | 0 | 0 | 0 | 6 | 1 | 0% | N | `str_utils.py` | `utilities/helpers` |
| 26 | 1 | 14.80 | 0 | 0 | 2 | 97 | 1 | 67% | N | `telemetry/metrics/histogram.py` | `monitoring/telemetry` |
| 27 | 1 | 14.82 | 0 | 0 | 0 | 13 | 3 | 0% | N | `plugins/dut_monitor/errors.py` | `utilities/plugins` |
| 28 | 1 | 15.00 | 0 | 0 | 0 | 20 | 1 | 0% | N | `plugins/log_section_start/postimport.py` | `utilities/plugins` |
| 29 | 1 | 15.10 | 0 | 0 | 0 | 24 | 1 | 0% | N | `helpers/bmp_utils.py` | `utilities/helpers` |
| 30 | 1 | 15.15 | 0 | 16 | 0 | 326 | 2 | 100% | N | `cert_utils.py` | `security/auth` |
| 31 | 1 | 15.15 | 0 | 42 | 0 | 26 | 1 | 0% | N | `snappi_tests/multi_dut_params.py` | `monitoring/traffic_gen` |
| 32 | 1 | 15.45 | 0 | 3 | 0 | 38 | 1 | 0% | N | `fixtures/consistency_checker/constants.py` | `utilities/fixtures` |
| 33 | 1 | 15.50 | 0 | 561 | 0 | 100 | 2 | 0% | N | `connections/linecard_console_conn.py` | `utilities/connection` |
| 34 | 1 | 15.62 | 0 | 1 | 1 | 61 | 1 | 0% | N | `devices/ixia.py` | `monitoring/traffic_gen` |
| 35 | 1 | 15.65 | 0 | 42 | 0 | 46 | 1 | 0% | N | `snappi_tests/traffic_flow_config.py` | `monitoring/traffic_gen` |
| 36 | 1 | 15.72 | 0 | 0 | 0 | 109 | 2 | 0% | N | `fixtures/populate_fdb.py` | `utilities/fixtures` |
| 37 | 1 | 15.82 | 0 | 561 | 0 | 53 | 1 | 0% | N | `connections/conserver_console_conn.py` | `utilities/connection` |
| 38 | 1 | 16.02 | 0 | 48 | 0 | 61 | 1 | 0% | N | `platform/controlplane_gating.py` | `platform` |
| 39 | 1 | 16.12 | 0 | 0 | 2 | 109 | 1 | 50% | N | `telemetry/reporters/db_reporter.py` | `monitoring/telemetry` |
| 40 | 1 | 16.25 | 0 | 2 | 0 | 130 | 2 | 0% | N | `helpers/mellanox_sensor_control_test_helper.py` | `platform/vendor` |
| 41 | 1 | 16.27 | 1 | 561 | 0 | 23 | 1 | 0% | N | `plugins/loganalyzer/utils.py` | `utilities/plugins` |
| 42 | 1 | 16.30 | 1 | 1 | 0 | 24 | 1 | 0% | N | `helpers/firmware_helper.py` | `utilities/helpers` |
| 43 | 1 | 16.43 | 0 | 0 | 0 | 77 | 3 | 0% | N | `telemetry/examples/example_ts_reporter.py` | `monitoring/telemetry` |
| 44 | 1 | 16.45 | 0 | 64 | 1 | 46 | 2 | 0% | N | `platform/ssh_utils.py` | `platform` |
| 45 | 1 | 16.52 | 2 | 2 | 1 | 13 | 1 | 0% | N | `helpers/monit.py` | `utilities/helpers` |
| 46 | 1 | 16.52 | 0 | 0 | 0 | 21 | 2 | 0% | N | `plugins/ptfadapter/dummy_testutils.py` | `utilities/plugins` |
| 47 | 1 | 16.61 | 1 | 15 | 0 | 339 | 1 | 76% | N | `ptf_gnoi.py` | `utilities/helpers` |
| 48 | 1 | 16.62 | 0 | 0 | 0 | 85 | 3 | 0% | N | `telemetry/tests/ut_metrics.py` | `monitoring/telemetry` |
| 49 | 1 | 16.82 | 0 | 0 | 1 | 121 | 1 | 0% | N | `helpers/inventory_utils.py` | `utilities/helpers` |
| 50 | 1 | 16.95 | 2 | 3 | 0 | 2 | 1 | 0% | N | `marvell_teralynx_data.py` | `platform/vendor` |
| 51 | 1 | 16.95 | 2 | 561 | 0 | 2 | 1 | 0% | N | `vs_data.py` | `platform/vendor` |
| 52 | 1 | 17.00 | 0 | 0 | 0 | 220 | 2 | 25% | N | `fixtures/consistency_checker/query-asic/parser.py` | `utilities/fixtures` |
| 53 | 2 | 17.07 | 2 | 51 | 0 | 7 | 1 | 0% | N | `broadcom_data.py` | `platform/vendor` |
| 54 | 2 | 17.10 | 0 | 0 | 2 | 28 | 1 | 0% | N | `telemetry/metrics/device/queue_metrics.py` | `monitoring/telemetry` |
| 55 | 2 | 17.12 | 0 | 0 | 1 | 13 | 1 | 0% | N | `plugins/custom_fixtures/check_dut_asic_type.py` | `utilities/plugins` |
| 56 | 2 | 17.12 | 0 | 0 | 2 | 29 | 1 | 0% | N | `telemetry/metrics/device/fan_metrics.py` | `monitoring/telemetry` |
| 57 | 2 | 17.23 | 0 | 15 | 0 | 109 | 4 | 25% | N | `ptf_gnmic.py` | `utilities/helpers` |
| 58 | 2 | 17.25 | 0 | 83 | 0 | 20 | 4 | 25% | N | `plugins/loganalyzer/bug_handler_helper.py` | `utilities/plugins` |
| 59 | 2 | 17.27 | 0 | 0 | 2 | 35 | 1 | 0% | N | `telemetry/metrics/device/psu_metrics.py` | `monitoring/telemetry` |
| 60 | 2 | 17.38 | 0 | 0 | 0 | 115 | 3 | 0% | N | `telemetry/examples/example_db_reporter.py` | `monitoring/telemetry` |

_… and 201 more. Download the YAML/JSON artifact for the full list and per-function sub-tasks._

