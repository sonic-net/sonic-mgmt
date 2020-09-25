# NAT Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test-cases)

## Revision

| Rev |     Date    |       Author       | Change Description                 |
|:---:|:-----------:|:-------------------|:-----------------------------------|
| 0.1 |  24/09/2020 | Roman Savchuk      |          Initial version           |

## Overview

The purpose is to test the functionality of NAT feature on the SONIC switch DUT. The tests expecting that
all necessary configuration for NAT are pre-configured on SONiC switch before test runs.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify a SONiC switch system correctly performs NAT translations based on configured rules.

## Testbed

Supported topologies t0, t0-64-32, t0-64

## Setup configuration

Each NAT test case needs client/server traffic transmission.
NAT starts address/port translation only if connection tracking is taking place(i.e. for TCP handshake).

PTF performs traffic transmission as a client and as a server at the same time.
That approach needs testbed be customized to:

- avoid limitaion of PTFs injected interfaces(i.e. traffic on DUT's ingress from VMs cannot be captured)
- keep PTF's client/server traffic isolated (using VRFs)

The customized testbed with applied T0 topo for each NAT test case looks as follows:

```
       ________________________________
      |              |                 |                  VM    VM    VM
      |              |   Server's VRF  |_____________      |     |     |
      |              |_________________|       ______|_____|_____|_____|______
      |                                |      |                               |
      |    PTF                         |      |              DUT              |
      |               _________________|      |                               |
      |              |                 |      |_______________________________| 
      |              |   Clinet's VRF  |_____________|
      |______________|_________________|

```

After end of the test session teardown procedure turns testbed to the initial state.

## Python scripts to setup and run test

NAT test suite is located in tests/nat folder. The are two separate files test_nat_dynamic.py and test_nat_static.py

### Setup of DUT switch

Setup of SONIC DUT will be done by python script.

During setup, python will use jinja template and convert in to JSON file containing configuration for
NAT type to DUT and pushed to SONiC config DB via sonic-cfggen. Data will be consumed by orchagent.
global_nat_config.j2
```
   {
    "NAT_GLOBAL": {
        "Values": {
            "admin_mode": "{{ nat_admin_mode }}",
            "nat_timeout": {{ global_nat_timeout }},
            "nat_tcp_timeout": {{ tcp_timeout }},
            "nat_udp_timeout": {{ udp_timeout }}
            }
    }
```

## Test cases

All test cases will be parametrize by protocol type (TCP, UDP, ICMP), interface type ("loopback", "port_in_lag") and direction ("host-tor", "leaf-tor")

## Test case #1 test_nat_static_basic

### Test objective

Verify that NAT will happen when NAT basic static configuration applied on DUT

### Test set up

- setup_test_env fixture(scope="module"): configures vrf interfaces
- apply_global_nat_config fixture(scope="module"): enable and configures NAT globally

### Test steps

- Define network data and L4 ports
- Apply Static NAT table config on DUT
- Perform handshake
- Send bidirecional traffic
- Verify that packet was SNAT and DNAT in both direction

### Test teardown

- setup_test_env fixture(scope="module"): remove ptf interfaces
- apply_global_nat_config fixture(scope="module"):  remove temporary folders, reload DUT configuration
- teardown fixture(scope="function"): remove all NAT related configuration
