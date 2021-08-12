# console_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Retrieves console feature and status information using Quagga.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    con_facts = duthost.console_facts()
```

## Arguments
This method takes no arguments

## Expected Output