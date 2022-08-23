# remove_ssh_tunnel_sai_rpc

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Removes any ssh tunnels if present created for syncd RPC communication

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    duthost.remove_ssh_tunnel_sai_rpc()
```

## Arguments
Takes no arguments

## Expected Output
Provides no output