
## Run pytest ##

### General ###
* Please use [tests/run_test.sh](/tests/run_tests.sh) to execute test case(s).

### Run nightly tests ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -t t1,any
    * -d: specify the dut host name
    * -n: specify the testbed name
    * -t: specify the testbed topology type, in this example, 't1' test cases and 'any' will be executed.

### Run a group of tests ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -t t1 -u
    * -u: bypass the utility test cases.
    * executed t1 test cases.


### Run all tests in a single test file ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c platform_tests/test_link_flap.py
    * execute link flap test case.
    * when specifying test cast list, no need to specify topology with -t.

### Run test cases in a single test file with filter ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c arp/test_arpall.py -C garp
    * execute all tests that has garp in the name in arp/test_arpall.py
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c arp/test_arpall.py -C "garp or unicast"
    * execute all tests that has garp or unicast in the name in arp/test_arpall.py
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c arp/test_arpall.py -C "not garp"
    * execute all tests that don't have garp in the name in arp/test_arpall.py
* For more information on the filter, please refer to the [pytest documentation](https://docs.pytest.org/en/latest/example/markers.html#using-k-expr-to-select-tests-based-on-their-name)

### Run scripts under a folder ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> -u -c "snmp/test_*.py" -s "snmp/test_snmp_cpu.py"
    * execute all the scripts under `snmp`, skip script `snmp/test_snmp_cpu.py`.
    * the test scripts pattern **MUST** be double quoted, otherwise there would be problem of running correct scripts.

### Run a list of test cases ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c "platform_tests/test_link_flap.py platform_tests/test_reboot.py::test_cold_reboot"
    * execute link flap test and cold reboot test case.
    * when specifying test cast list, no need to specify topology with -t.

### Run tests by `pytest`

Optionally, we can directly use the `pytest` command to run tests. The best practice of using `pytest` to run scripts is to follow below syntax:
```
pytest [test script files or directories containing test script files] [options listed in "pytest --help" only] [options extended in sonic-mgmt]
```

For example:
```
pytest test_announce_routes.py --inventory ../ansible/veos_vtb --host-pattern all --testbed_file vtestbed.yaml --log-cli-level info
```

Please ensure that the command line options extended in sonic-mgmt are always added **AFTER** the test script files or directories containing test script files. Otherwise, pytest may complain that the options defined in `conftest.py` of sub-folders are unrecognized.

The reason is that pytest will do a pre-parse for all of the supplied command line arguments. During pre-parse, all the options extended in sonic-mgmt are unknown to the argparser yet. In this phase, pytest will try to figure out which of the supplied arguments are test scripts.

For example, if the pytest command line is like this:

```
pytest example/test_example.py --inventory ../ansible/veos_vtb --host-pattern all --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --log-cli-level debug --disable_loganalyzer --skip_sanity --example_option1 my_value1
```

Arguments that are known to pytest during pre-parse phase:
* `--inventory ../ansible/veos_vtb`
* `--host-pattern all`
* `--log-cli-level debug`

Please be noted that although there is a symbolic link `tests/veos_vtb` pointing to `ansible/veos_vtb`, we still have to specify `../ansible/veos_vtb`. The reason is that under the hood, ansible will try to locate some group and host variables under the same folder of the inventory file. Currently, all the ansible group and host variables are stored under the `ansible` folder. If we run `pytest` under the `tests` folder and specify inventory file using argumetn like `--inventory veos_vtb`, ansible will try to find group and host variables under `tests` folder. Consequently, lost access to group and host variables under the `ansible` folder.

Rest of the arguments are unknown to pytest yet.

Since `--testbed` has double `-` in the front of it. Argparser knows that it must be an option. However, the value `vms-kvm-t0` after it is considered as a test script name by argparser.

After pre-parse is done, pytest will try to locate all the `conftest.py` files related the discovered test scripts, which is `vms-kvm-t0` in this example. File `sonic-mgmt/tests/conftest.py` will be loaded by pytest because it is in the same directory of `vms-kvm-t0`. However, file `sonic-mgmt/tests/example/conftest.py` is not loaded as expected. Then pytest will parse all the command line arguments and complain that `--example_option1` is unrecognized argument.

If we run the command like below, then there is no problem.

```
pytest example/test_example.py --inventory ../ansible/veos_vtb --host-pattern vlab-01 --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --log-cli-level debug --disable_loganalyzer --skip_sanity --example_option1 my_value1
```

During pre-parse, pytest recognizes that `example/test_example.py ` is a test script. Then pytest will try to load file `sonic-mgmt/tests/try_opt/conftest.py`. After this conftest.py file is loaded, there is no problem of parsing argument `--example_option1`.

## Run BGP tests in traditional (bgpcfgd) and/or frr_mgmt_framework (frrcfgd) mode ##

SONiC programs FRR from CONFIG_DB either through bgpcfgd (traditional) or frrcfgd
("frr_mgmt_framework"). Tests that use the `frr_config_mode` fixture (most of `tests/bgp`,
plus BFD and the config-writing FRR tests) run in **both** modes by default; the fixture
switches the DUT's mode mid-module and restores it on exit.

Select the mode(s) with `--frr-config-mode`:

* `both` (default): run each opted-in test in traditional **and** frr_mgmt_framework.
* `traditional`: run only the bgpcfgd variant.
* `frr_mgmt_framework`: run only the frrcfgd variant.

```
pytest bgp/test_bgp_speaker.py --inventory ../ansible/veos_vtb --host-pattern all \
    --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --frr-config-mode=frr_mgmt_framework
```

Notes:
* The DUT should boot traditional; the fixture switches it to frr_mgmt_framework and back. A DUT
  booting frr_mgmt_framework runs the frrcfgd variant natively but cannot run the traditional
  one (the translator only converts traditional->frr).
* Persisting a switch across the reload needs `/etc/sonic/golden_config_db.json` on the DUT;
  without it, mode-switching tests skip with a clear reason.
* Switching is single-ASIC only; multi-ASIC and supervisor nodes run their native mode only.
* All `[traditional]` variants run before all `[frr_mgmt_framework]` ones, so a run switches
  the DUT once and restores it once.

### `frr_generic` modules: one mode instead of two

Many modules assert FRR / zebra / dataplane / kernel behavior over boot config rather than
the bgpcfgd<->frrcfgd translation (whose render equivalence the fixture's fingerprint already
checks), so running them twice only re-tests FRR. They carry `pytest.mark.frr_generic` and
run in **one** mode:

| `--frr-config-mode` | `frr_generic` module runs in |
|---|---|
| `both` (default) | `--frr-generic-mode`, default `FRR_GENERIC_DEFAULT_MODE` (`traditional`) |
| `traditional` | `traditional` |
| `frr_mgmt_framework` | `frr_mgmt_framework` |

`FRR_GENERIC_DEFAULT_MODE` lives in `tests/common/fixtures/frr_config_mode.py`; pass
`--frr-generic-mode=frr_mgmt_framework` to prefer frrcfgd. If the preferred mode is unreachable
(e.g. frrcfgd without `golden_config_db.json`, multi-ASIC, supervisor, `--enable_macsec`; or
traditional on a DUT that boots frrcfgd), a `both` run falls back to the other mode so the
module still runs. Both test IDs are still generated (so `conditional_mark` keys and `-k`
selection are unchanged); the unused variant skips, naming the mode that ran.

Modules **without** the marker are those where the config daemon is the subject (render
equivalence, `BGP_GLOBALS.router_id`, `BGP_BBR`, `BGP_ALLOWED_PREFIXES`, `ROUTE_MAP.set_src`,
GCU patch paths, listen-range peer-groups, ...) and run in both modes.
