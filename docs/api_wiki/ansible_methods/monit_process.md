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

The eBGP readiness helper polls continuously on the DUT until five consecutive
samples satisfy its CPU threshold. It does not spend its polling budget on SSH
round trips between batches, which can miss quiet periods on a busy testbed:

```python
result = duthost.monit_process(
    delay_interval=1, iterations=5, process_name="orchagent",
    cpu_threshold=10, timeout=60, verbose=False
)
for processes, memory in result["monit_results"]:
    orch_cpu = {proc["pid"]: proc["cpu_percent"] for proc in processes if proc["name"] == "orchagent"}
assert result["cpu_ready"], "Orchagent did not become ready"
```

Readiness requires an orchagent reading in every sample and checks every
orchagent instance against the existing CPU threshold. Incomplete samples are
logged and do not count as ready. The existing integer CPU comparison is retained.
On timeout, `cpu_ready` is false and the last samples are returned for the caller
to report. Ordinary fixed-count monitoring is unchanged when the three readiness
arguments are omitted. Readiness results contain only matching processes; the
psutil path avoids collecting expensive statistics for unrelated processes on
every sample.

## Arguments
- `delay_interval` - delay between polling (in seconds)
    - Required: `False`
    - Type: `Integer`
    - Default: `5`
- `iterations` - Number of polling iterations
    - Required: `False`
    - Type: `Integer`
    - Default: `12`
- `process_name`, `cpu_threshold`, `timeout` - Optional CPU readiness arguments;
  supply all three together. The timeout, polling interval and sample count must
  be positive, the process name nonempty, and the threshold nonnegative.
  `iterations` is the required consecutive sample count in this mode. Every
  matching process must be present and at or below the integer CPU threshold.
  A high reading or a sample with no matching process resets the consecutive
  count. The returned `monit_results` contains at most the last `iterations`
  samples, whether readiness succeeds or times out.

## Expected Output
Dictionary describing the cpu and memory usage of all processes. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `cpu_ready` - Present only in readiness mode; true only after the required
  consecutive low-CPU samples, false on timeout.
- `monit_results` - List of dictionaries, where each dictionary refers to a separate process
    - `status` - Whether process is runing or not
    - `memory_percent` - What percent of memory is in use by the process
    - `pid` - pid for processes
    - `name`- process name
    - `cpu_percent` - What percent of cpu is in use by the process
