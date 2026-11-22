# monit_process

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieve process cpu and memory usage

Samples are collected on the DUT within one Ansible invocation, avoiding an SSH
round trip and CLI startup for every reading. Both the psutil implementation and
the `top` fallback retain process names such as `orchagent` without terminal-width
truncation.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    monit_results = duthost.monit_process(iterations=12)
```

The eBGP readiness helper uses five one-second samples rather than five separate
`show processes cpu` calls:

```python
samples = duthost.monit_process(delay_interval=1, iterations=5, verbose=False)["monit_results"]
for processes, memory in samples:
    orch_cpu = {proc["pid"]: proc["cpu_percent"] for proc in processes if proc["name"] == "orchagent"}
```

Readiness requires an orchagent reading in every sample and checks every
orchagent instance against the existing CPU threshold. Incomplete samples are
logged and do not count as ready.

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
