# Software for Open Networking in the Cloud - SONiC
# Management - tests

# Description
Hosting pytest test infrastructure and test cases


# Guidelines:
## Creating new test cases ##
* Please add custom marker to specify if the test case is applicable to t0/t1/any/util/t0-soak topology.
    * t0/t1: test case can run on either t0 or t1 toplogy but not the other.
    * any: test case can run on both t0 and t1 topology.
    * util: test case is a utility, eitehr pre-test or post-test. Usually only need to be run once per test session.
    * t0-soak: special test case that could take very long time to finish and applicable to t0 topology.

## Run pytest ##

### General ###
* Please use [tests/run_test.sh](https://github.com/Azure/sonic-mgmt/blob/master/tests/run_tests.sh) to execute test case(s).

### Run nightly tests ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -t t1,any
    * -d: specify the dut host name
    * -n: specify the testbed name
    * -t: specify the testbed topology type, in this example, 't1' test cases and 'any' will be executed.

### Run a group of tests ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -t t1 -u
    * -u: bypass the utility test cases.
    * executed t1 test cases.


### Run a single test case ###
* ./run_tests.sh -d <dut_name> -n <testbed_name> [-s <list of test cases or files to skip>] -u -c platform_tests/test_link_flap.py
    * execute link flap test case.
    * when specifying test cast list, no need to specify topology with -t.


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
pytest test_announce_routes.py --inventory veos_vtb --host-pattern vlab-01 --testbed_file vtestbed.csv --log-cli-level info
```

Please ensure that the command line options extended in sonic-mgmt are always added **AFTER** the test script files or directories containing test script files. Otherwise, pytest may complain that the options defined in `conftest.py` of sub-folders are unrecognized.

The reason is that pytest will do a pre-parse for all of the supplied command line arguments. During pre-parse, all the options extended in sonic-mgmt are unknown to the argparser yet. In this phase, pytest will try to figure out which of the supplied arguments are test scripts.

For example, if the pytest command line is like this:

```
pytest --inventory veos_vtb --host-pattern vlab-01 --testbed vms-kvm-t0 --testbed_file vtestbed.csv --log-cli-level debug --disable_loganalyzer --skip_sanity example/test_example.py --example_option1 my_value1
```

Arguments that are known to pytest during pre-parse phase:
* `--inventory veos_vtb`
* `--host-pattern vlab-01`
* `--log-cli-level debug`

Rest of the arguments are unknown to pytest yet.

Since `--testbed` has double `-` in the front of it. Argparser knows that it must be an option. However, the value `vms-kvm-t0` after it is considered as a test script name by argparser.

After pre-parse is done, pytest will try to locate all the `conftest.py` files related the discovered test scripts, which is `vms-kvm-t0` in this example. File `sonic-mgmt/tests/conftest.py` will be loaded by pytest because it is in the same directory of `vms-kvm-t0`. However, file `sonic-mgmt/tests/example/conftest.py` is not loaded as expected. Then pytest will parse all the command line arguments and complain that `--example_option1` is unrecognized argument.

If we run the command like below, then there is no problem.

```
pytest --inventory veos_vtb --host-pattern vlab-01 example/test_example.py --testbed vms-kvm-t0 --testbed_file vtestbed.csv --log-cli-level debug --disable_loganalyzer --skip_sanity --example_option1 my_value1
```

During pre-parse, pytest recognizes that `example/test_example.py ` is a test script. Then pytest will try to load file `sonic-mgmt/tests/try_opt/conftest.py`. After this conftest.py file is loaded, there is no problem of parsing argument `--example_option1`.
