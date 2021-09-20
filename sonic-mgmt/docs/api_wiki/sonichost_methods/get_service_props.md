# get_service_props

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Gets detailed properties of a service

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    service_props = duthost.get_service_props("procdockerstatsd")
```

## Arguments
- `service` - name of service properties are desired for
    - Required: `True`
    - Type: `String`
- `props` - List of properties desired for service
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`
    - Default:
        - `ActiveState`
        - `SubState`

## Expected Output
Will return dictionary where the key is the property name and the value is the property's value. Below is an example key-value pairing, though the output depends to the value of `props`:

- `AcitveState` - state of the property
- `SubState` - Whether the property is running or not