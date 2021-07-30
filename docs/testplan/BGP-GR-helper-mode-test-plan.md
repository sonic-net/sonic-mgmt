- [Overview](#overview)
    - [Scope](#scope)
    - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
    - [Arista VM configuration](#arista-vm-configuration)
    - [Ansible scripts to setup and run test](#ansible-scripts-to-setup-and-run-test)
        - [everflow_testbed.yml](#everflow-testbed-yml)
- [PTF Test](#ptf-test)
    - [Input files for PTF test](#input-files-for-ptf-test)
    - [Traffic validation in PTF](#traffic-validation-in-ptf)
- [Test cases](#test-cases)
- [TODO](#todo)
- [Open Questions](#open-questions)

## Overview
The purpose is to test a functionality of BGP GR mode on the SONIC switch DUT, closely resembling production environment.
The test assumes all necessary configuration is already pre-configured on the SONIC switch before test runs.

### Scope
The test is targeting a running SONIC system with fully functioning configuration.
The purpose of the test is not to test specific API, but functional testing of BGP GR helper mode on SONIC system, making sure that traffic flows correctly, according to BGP routes advertised by BGP peers of SONIC switch.

### Testbed
The test will run on the following testbeds:
- t1
- t1-lag

## Setup configuration

#### Arista VM configuration

Test assumes that BGP GR is enabled and preconfigured on Arista VMs. BGP GR timer value should be more than time required for VM reboot.

#### Ansible scripts to setup and run test

##### bgp_gr_helper.yml

bgp_gr_helper.yml when run with tag "bgp_gr_helper" will do the following:

1. Randomly choose VM.
2. Run test.

BGP GR helper test consists of a number of subtests, and each of them will include the following steps:

1. Run lognanalyzer 'init' phase
2. Run BGP GR helper Sub Test
3. Run loganalyzer 'analyze' phase

## PTF Test

To run traffic FIB PTF test will be reused.

## Test cases

Each test case will be additionally validated by the loganalizer utility.

### Test case \#1 - BGP GR helper mode.

#### Test objective

Verify that routes are preserved during neighbor graceful restart.

#### Test steps

- Randomly choose VM for the test.
- Reboot VM.
- Verify BGP timeout (at least 115 seconds routes should stay in fib).
- Verify all routes are preserved (no reinstallation after BGP open message from the neighbor).
- Verify that BGP session with the VM established.

### Test case \#2 - BGP GR helper mode routes change.

#### Test objective

Verify that traffic run without changes during neighbor graceful restart.

#### Test steps

- Randomly choose VM for the test.
- Change VM startup config (advertised routes should be different). 
- Reboot VM.
- Verify that preserved routes are removed when VM back.
- Verify that new routes are installed when VM back.
- Restore VM startup config.

## TODO

## Open Questions
- Should tests run for neighbors behind physical interfaces only or behind LAGs as well?
- On which topologies test should run?
