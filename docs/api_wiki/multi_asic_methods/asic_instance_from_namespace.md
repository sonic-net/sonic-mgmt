# asic_instance_from_namespace

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Provides ASIC instance given a corresponding namespace.

Will return default ASIC if no namespace is provided.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    namespaces = duthost.get_backend_asic_namespace_list()

    backend_sonic_asic = duthost.asic_instance_from_namespace(namespaces[0])
```

## Arguments
- `namespace` - namespace corresponding to desired ASIC instance
    - Required: `False`
    - Type: `String`
    - Default: `$DEFAULT_NAMESPACE`

## Expected Output
An ASIC instance corresponding to provided `namespace`