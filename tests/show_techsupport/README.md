# show techsupport Test Plan

### Table of contents:
- [Overview](#overview)

  * [Scope](#scope)

  * [Testbed](#testbed)

- [Setup Configurations](#setup-configurations)

- [Test Cases](#test-cases)

- [Execution Example](#execution-example)


## Overview
The purpose is to test execution of “show techsupport” command in a loop. 

Verify that log analyzer, memory and CPU are valid. 


### Scope
The test is targeting a running SONiC system, with basic setup configuration. 

Additional configurations available: **ACL** , **Mirroring**


### Testbed
With ACL configurations - The test will run on testbeds with all possible topologies.

With Mirroring configurations  The test will run on testbed with all topologies except ptf32.

## Setup configurations

In order to setup additional configurations, the user will insert the wanted configuration name via command line.
The test will configure and clean all additional configurations after test ends. 

A configuration fixture will call the suitable fixtures in order to setup the configurations.


Using a parametrized fixture, for each supported configuration named in test execution, the fixture will generate the configuration on the DUT. 

- For additional configurations support, add a fixture to setup the configurations, and execute the test with the suitable configuration name. 



## Test Cases

### Test - execute show techsupport in a loop

#### Test Objectives

- Configure required configuration
- Execute "show techsupport" command in a loop 
- Clean additional configurations 

 Verify CPU, memory and log analyzer are valid. 


## Execution Example


from sonic-mgmt, docker container, tests folder:

```
$  pytest --inventory ../ansible/inventory --host-pattern <host> --module-path ../ansible/library/
--testbed <host>-<topology> --testbed_file ../ansible/testbed.csv --show-capture=no --capture=no
 --log-cli-level debug -ra -vvvvv techsupport/test_techsupport.py 
 --loop_num=5 --loop_delay=8 --logs_since=3
 -k test_techsupport[acl]
 ```
 


_user parameters:_ 


**loop_num**  - number of times the "show techsupport" command should run.

**loop_delay** - number of seconds to wait between command executions.

**logs_since** - number of minutes to pass to 'show techsupport' command.
If nothing specified, a random number of minutes will be raffled between 1 and 60. 



