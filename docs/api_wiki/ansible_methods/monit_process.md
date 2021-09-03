# monit_process

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve process cpu and memory usage

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    monit_results = duthost.monit_process(iterations=12)
```


## Arguments
- `delay_interval` - delay between polling (in seconds)
    - Required: `False`
    - Type: `Integer`
    - Default: `5`
- `iterations` - Number of polling iterations
    - Required: `False`
    - Type: `Integer`
    - Default: `12`

## Expected Output
Dictionary describing the cpu and memory usage of all processes. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary: 

- `monit_results` - List of dictionaries, where each dictionary refers to a separate process
    - `status` - Whether process is runing or not
    - `memory_percent` - What percent of memory is in use by the process
    - `pid` - pid for processes
    - `name`- process name
    - `cpu_percent` - What percent of cpu is in use by the process
