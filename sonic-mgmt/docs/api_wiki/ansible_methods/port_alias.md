# port_alias

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Find port-alias mapping if there is any configured.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    hwsku = duthost.facts['hwsku']
    port_alias_facts = duthost.port_alias(hwsku=hwsku, include_internal=False)
```

## Arguments
- `hwsku` - Type of hardware switch being used
    - Required: `True`
    - Type: `String`
- `num_asic` - Number of ASICs on a multi-ASIC device.
    - Required: `False`
    - Type: `Integer`
- `include_internal` - Whether or not to include internal ports
    - Required: `False`
    - Type: `Boolean`
    - Default: `False`
- `card` - Type of linecard being used
    - Required: `False`
    - Type: `String`
- `hostname` - desired hostname
    - Required: `False`
    - Type: `String`
- `start_switchid` - id for desired switch
    - Required: `False`
    - Type: `Integer`

## Expected Output
Returns dictionary with port aliases and port speeds. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - Dictionary containing port info
    - `port_alias` - list of port aliases
    - `port_speed` - Dictionary that maps aliases to thier speed
        - `{PORT_ALIAS}` - speed of specified port