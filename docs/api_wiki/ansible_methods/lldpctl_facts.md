# lldpctl_facts

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gathers LLDP facts from the SONiC device.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    lldp_info = duthost.minigraph_facts(host=duthost.hostname)
```

## Arguments
- `asic_instance_id` - numeric id identifing an ASIC
    - Required: `False`
    - Type: `Integer`
    - Default: `None`
- `skip_interface_pattern_list` - list of regex patterns that will be used to ignore interfaces with matching names
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
    - Default: `None`

## Expected Output
Dictionary containing facts gathered by the LLDP protocol. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts` - Dictionary containing info gathered by LLDP
    - `lldpctl` - Dictionary mapping port names to information regarding them
        - `{PORT_NAME}` - Dictionary containing information on the specified port
            - `rid` - numeric id for entry
            - `via` - method for getting LLDP facts
            - `age` - age of the ports configuration
            - `chassis` - Dictionary containig information on chassis
                - `Bridge` - Dictionary containing config for bridge
                    - `enabled` - Whether or not Bridge is enabled
                - `Wlan` - Dictionary containing config for Wlan
                    - `enabled` - Whether or not WLAN is enabled
                - `name` - Name for device
                - `descr` - String description for device
                - `mac` - Device router mac address
                - `Station` - dictionary containing config info on Station
                    - `enabled` - Whether Station is enabled or not
                - `Router` - Dictionary containing config info on Router
                    - `enabled` - Whether or not Router is enabled
            - `port` - Dictionary containing config info on the port
                - `auto-negotiation` - Dictionary containing info on auto-negotiation
                    - `current` - String description of current configuration
                    - `supported` - Whether or not current config supports auto-negotiation
                    - `enabled` - Whether or not auto-negotiation is enabled
                - `local` - Local alias for port
                - `aggregation` - port for link aggregation
                - `descr` - name for port
                - `ttl` - time to live
