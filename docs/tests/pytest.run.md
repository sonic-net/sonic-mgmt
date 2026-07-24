
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

SONiC can program FRR from CONFIG_DB either through the traditional per-feature daemons
(bgpcfgd for BGP) or through the newer frrcfgd daemon (the "frr_mgmt_framework" / unified
config mode). Tests that opt into the `frr_config_mode` fixture (most of `tests/bgp`, plus
BFD and the config-writing FRR tests) run in **both** modes by default -- the fixture
switches the DUT's routing-config mode mid-module and restores it on exit.

Select which mode(s) to run with `--frr-config-mode`:

* `--frr-config-mode=both` (default): run each opted-in test in traditional (bgpcfgd) **and**
  frr_mgmt_framework (frrcfgd).
* `--frr-config-mode=traditional`: run only the traditional (bgpcfgd) variant.
* `--frr-config-mode=frr_mgmt_framework`: run only the frrcfgd variant -- i.e. exercise
  frrcfgd only and bypass the bgpcfgd variant.

```
pytest bgp/test_bgp_speaker.py --inventory ../ansible/veos_vtb --host-pattern all \
    --testbed vms-kvm-t0 --testbed_file vtestbed.yaml --frr-config-mode=frr_mgmt_framework
```

Notes:
* To run frrcfgd only, the DUT should boot in traditional (bgpcfgd) mode -- the fixture
  switches it into frr_mgmt_framework for the run and restores traditional afterwards. A DUT
  that already boots in frr_mgmt_framework mode runs the frrcfgd variant natively (no switch),
  but cannot run the traditional variant (the translator only converts traditional->frr).
* Persisting a mode switch across the reload requires `/etc/sonic/golden_config_db.json` on
  the DUT; without it, mode-switching tests skip with a clear reason.
* Mode-switching is single-ASIC only for now; on multi-ASIC / supervisor nodes the fixture
  runs the DUT's native mode only.
