# Sub-port interfaces Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test-cases)
  - [test_packet_routed_with_valid_vlan](#Test-case-test_packet_routed_with_valid_vlan)
  - [test_packet_routed_with_invalid_vlan](#Test-case-test_packet_routed_with_invalid_vlan)


## Revision

| Rev |     Date    |       Author           | Change Description                 |
|:---:|:-----------:|:-----------------------|:-----------------------------------|
| 0.1 |  30/11/2020 | BFN: Oleksandr Kozodoi |          Initial version           |


## Overview

The purpose is to test the functionality of sub-port interfaces feature on the SONIC switch DUT. The tests expecting that
all necessary configuration for sub-ports are pre-configured on SONiC switch before test runs.

## Scope

The test is targeting a running SONiC system with fully functioning configuration.
Purpose of the test is to verify a SONiC switch system correctly performs sub-ports implementation based on configured rules.

## Testbed

Supported topologies: t0

## Setup configuration

Each sub-ports test case needs traffic transmission.
Traffic starts transmission, if DUT and PTF directly connected interfaces have the same VLAN IDs. So we need configure correct sub-ports on the DUT and PTF.

For example the customized testbed with applied T0 topo for test_packet_routed test case looks as follows:

```
              VM    VM    VM    VM
              []    []    []    []
       _______[]____[]____[]____[]______
      |                                 |
      |   _________   DUT   _________   |
      |  [Ethernet4]       [Ethernet8]  |
      |__[_.10_.20_]_______[_.10_.20_]__|
         [  |   |  ]       [  |   |  ] 
         [  |   |  ]       [  |   |  ]
         [  |   |  ]       [  |   |  ]
       __[__|___|__]_______[__|___|__]__
      |  [ .10 .20 ]       [.10 .20  ]  |
      |  [__eth1___]       [__eth2___]  |
      |               PTF               |
      |_________________________________|

```
Port mapping:
| DUT        |             |  PTF       |             |
|:----------:|:-----------:|:-----------|:------------|
|**Sub-port**|**IP**       |**Sub-port**|**IP**       |
|Ethernet4.10|172.16.0.1/30|eth1.10     |172.16.0.2/30|
|Ethernet4.20|172.16.0.5/30|eth1.20     |172.16.0.6/30|
|Ethernet8.10|172.16.4.1/30|eth2.10     |172.16.4.2/30|
|Ethernet8.20|172.16.4.5/30|eth2.20     |172.16.4.6/30|

After end of the test session teardown procedure turns testbed to the initial state.

## Python scripts to setup and run test

Sub-ports test suite is located in tests/sub_port_interfaces folder. There is one files test_sub_port_interfaces.py

### Setup of DUT switch

During setup procedure python mgmt scripts perform DUT configuration via jinja template to convert it in to the JSON file containing configuration to be pushed to the SONiC config DB via sonic-cfggen. Setup procedure configures sub-port interfaces with fixture ```define_sub_ports_configuration```.

sub_port_config.j2
```
{
    "VLAN_SUB_INTERFACE": {
{% for sub_port, value in sub_ports.items() %}
        "{{ sub_port }}": {
            "admin_status" : "up"
        },
        "{{ sub_port }}|{{ value['ip'] }}": {}{% if not loop.last %},
{% endif %}{% endfor %}
    }
}
```

## Test cases

## Test case test_packet_routed_with_valid_vlan

### Test objective

Verify that packet routed if sub-ports have valid VLAN ID.

### Test set up

- apply_config_on_the_dut fixture(scope="function"): enable and configures sub-port interfaces on the DUT
- apply_config_on_the_ptf fixture(scope="function"): enable and configures sub-port interfaces on the PTF

### Test steps

- Setup configuration of sub-ports on the DUT.
- Setup configuration of sub-ports on the PTF.
- Create ICMP packet.
- Send ICMP request packet from PTF to DUT.
- Verify that DUT sends ICMP reply packet to PTF.

### Test teardown

- reload_dut_config function: reload DUT configuration
- reload_ptf_config function: remove all sub-ports configuration

## Test case test_packet_routed_with_invalid_vlan

### Test objective

Validates that packet aren't routed if sub-ports have invalid VLAN ID.

### Test set up
DUT and PTF directly connected interfaces have different VLAN IDs
- apply_config_on_the_dut fixture(scope="function"): enable and configures sub-port interfaces on the DUT
- apply_config_on_the_ptf fixture(scope="function"): enable and configures sub-port interfaces on the PTF

### Test steps

- Setup configuration of sub-ports on the DUT.
- Setup different VLAN IDs on directly connected interfaces of sub-ports on the PTF.
- Create ICMP packet.
- Send ICMP request packet from PTF to DUT.
- Verify that DUT doesn't sends ICMP reply packet to PTF.

### Test teardown

- reload_dut_config function: reload DUT configuration
- reload_ptf_config function: remove all sub-ports configuration
