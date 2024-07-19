### Scope
This document provides a high level description of the memory utilization verification design and instructions on using the "memory_utilization" fixture in SONiC testing.

### Overview
During testing, the memory usage of the DUT can vary due to different configurations, environment setups, and test steps. To ensure the safe use of memory resources, it is necessary to check the memory usage after the test to confirm that it has not exceeded the high memory usage threshold and that no memory leaks have occurred.

The purpose of the current feature is to verify that memory resources do not increase during test runs and do not exceed the high memory usage threshold.

### Module Design
Newly introduced a plugin "memory_utilization" and config files.

#### Config files
Config files, including common file and platform dependence file.
- **memory_utilization_common.json**: Common configurations for memory utilization.
- **memory_utilization_dependence.json**: Dependency configruations for memory utilization, currently supporting special configurations for specific HwSku devices. This configuration file should be left empty in the public branch, with special configurations added in internal branch.

Memory utilization config files include memory items which need to check.
Each memory item include "name", "cmd", "memory_params" and "memory_check".
- **name**:          The name of the memory check item.
- **cmd**:           The shell command is run on the DUT to collect memory information.
- **memory_params**: The items and thresholds for memory usage, defined as a Dict type in the configuration JSON file.
- **memory_check**:  The function used to parse the output of the shell command takes two input parameters: cmd's output string and memory_params. It returns the parsered memory inforamtion, which will be compared with "memory_params" to check for memory threshold.

#### Workflow
1. Collect memory information based on memory utilization config files before running a test case.
    - Execute the "cmd" and use the "memory_check" function to collect the memory information before running the test case.
2. Collect memory information based on memory utilization config files after the test case is completed.
    - Execute the "cmd" and use the "memory_check" function to collect the memory information after running the test case.
3. Compare the memory information from before and after the test run.
    - Compare the collected memory information with the thresholds in "memory_params".
4. Raise an alarm if there is any memory leak or if the memory usage exceeds the high memory threshold based on the memory utilization config files.


### Memory Utilization usage example

Below is a description of the possible uses for the "memory_utilization" fixture/module.

##### memory_utilization fixture
In the root conftest there is an implemented "memory_utilization" pytest fixture that starts automatically for all test cases.
The main flow of the fixture is as follows:
- memory_utilization collects memory information before the test case starts.
- memory_utilization collects memory information after the test case finishes.
- memory_utilization compares DUT memory usage and displays the results.
- if memory_utilization finds any exceeded thresholds for high memory usage or memory increase, it will display the result and pytest will generate an 'error'.

#### To skip memory_utilization for:
- all test cases - use pytest command line option ```--memory_utilization```
- specific test case: mark test case with ```@pytest.mark.memory_utilization``` decorator. Example is shown below.
    ```python
    pytestmark = [
        pytest.mark.disable_memory_utilization
    ]
    ```

#### Example of memory items configuration in json file
Example memory item's name is "monit", using the command "sudo monit status" to get the memory item's information.
The threshold for high memory is 70%, and for an increase is 5%.
The function "parse_monit_status_output" parses the output of the command "sudo monit status" and returns the memory information {"memory_usage" : 41.2}
The Memory utilization fixture uses the function "parse_monit_status_output" to parse the output of "sudo monit status" before and after the test case. It then compares the value with the threshold. If the value exceeds the threshold, an 'error' will be raised.

```json
    {
      "name": "monit",
      "cmd": "sudo monit status",
      "memory_params": {
        "memory_usage": {
          "memory_increase_threshold": 5,
          "memory_high_threshold": 70
        }
      },
      "memory_check": "parse_monit_status_output"
    }
```

```shell
System 'sonic'
  status                       Running
  monitoring status            Monitored
  monitoring mode              active
  on reboot                    start
  load average                 [1.44] [1.10] [1.04]
  cpu                          22.7%us 3.3%sy 0.0%wa
  memory usage                 3.2 GB [41.2%]
  swap usage                   0 B [0.0%]
  uptime                       4d 3h 55m
  boot time                    Thu, 11 Jul 2024 06:41:46
  data collected               Mon, 15 Jul 2024 10:36:45
```
