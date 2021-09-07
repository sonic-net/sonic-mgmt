# get_asic_or_sonic_host_from_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Returns corresponding sonichost instance if arg `namespace` is not specified, or corresponding ASIC instance if arg `namespace` is specified.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    namespaces = duthost.get_backend_asic_namespace_list()

    sonic_host = duthost.get_asic_or_sonic_host_from_namespace()
    sonic_asic = duthost.get_asic_or_sonic_host_from_namespace(namespaces[0])
```

## Arguments
- `namespace` - namespace for desired ASIC, or unspecified for sonic host
    - Required: `False`
    - Type: `String`

## Expected Output
Either a sonichost instance or an ASIC instance depending on input.