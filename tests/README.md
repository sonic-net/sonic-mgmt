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
