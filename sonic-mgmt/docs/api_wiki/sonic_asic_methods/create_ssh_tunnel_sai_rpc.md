# create_ssh_tunnel_sai_rpc

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Create ssh tunnel between host and ASIC namespace on syncd RPC port.

This is used to forward thrift calls to and from the syncd running on this ASIC.

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo, enum_frontend_asic_index):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_asic = duthost.asic_instance(asic_index=enum_frontend_asic_index)

    sonic_asic.create_ssh_tunnel_sai_rpc()
```

## Arguments
Takes no arguments

## Expected Output
Provides no output