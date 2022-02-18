# MCLAG Test Plan

## Rev 0.1

- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test-cases)
  - [MCLAG L3](#MCLAG-L3)
    - [test_check_keepalive_link](#Test-case-test_check_keepalive_link)
    - [test_check_teamd_system_id](#Test-case-test_check_teamd_system_id)
    - [test_mclag_intf_status_down](#Test-case-test_mclag_intf_status_down)
    - [test_mclag_intf_status_up](#Test-case-test_mclag_intf_status_up)


## Revision

| Rev |     Date    |       Author                 | Change Description                 |
|:---:|:-----------:|:-----------------------------|:-----------------------------------|
| 0.1 |  04/02/2022 |Intel : Andrii-Yosafat Lozovyy|          Initial version           |


## Overview

The purpose is to test the functionality of MCLAG feature on the SONIC switch DUT. The tests expecting that
all necessary configuration for MCLAG are pre-configured on SONiC switch before test runs.

## Scope

The test is running on real SONIC switch with testbed's basic configuration.
The purpose of the test isn't targeting to specific class or API which are coverd by vs test cases, but functional test of MCLAG on SONIC system.

## Testbed

Supported topologies t0-mclag

## Topology

# Physical topology
MCLAG test must use two DUTs, you can connect those two DUTs to two different leaf fanout switches, and to one root fanout

# Logical topologies
Testbeds t0-mclag is modified based on the Testbeds t0


- Requires 2 VMs
- 2 DUT ports areconnected to VMs
- PTF container have 2 injected interfaces and 52 directly connected ports
- 2 ports on each DUT is interconnected


# Mclag logical topology


### Application scenarios

#### L3 scenario

All links to PTF ports are L3 mode. DUT binds MCLAG's interface ip address must be the same except peer-link and keep-alive link. Establish BGP neighbors between the VMs and two DUTs. MCLAG keepalive link will be established through a separate link.

## Setup configuration

There are 2 VM, each is connected to a separete DUT, each VM advertise a unique 32 routes on DUT to which its connected.
2 links are interconnected beetween DUTs, these links will be used as a PeerLink and KeepAlive links for MCLAG feature.
Each DUT will have 24 configured MCLAG interfaces with 1 member, on both DUTs.
```

                              VM              VM
                               |               |
                           ____|____       ____|____
                          |         |-----|         |
                          |   DUT1  |     |   DUT2  |
                          |_________|-----|_________|
                               \             /
                                \           /
                                 |         |
                              ___|_________|__
                             |                |
                             |      PTF       |
                             |________________|
```

After end of the test session teardown procedure turns testbed to the initial state.

### Setup of DUT switch

During setup procedure python mgmt scripts perform DUT configuration with CLI commands via corresponding wrappers.
During setup procedure using jinga template there will be configured all necessary settings on PTF side.

ptf_portchannel.j2
```
#!/bin/bash

{% for l1 in ptf_map[dut1_index] %}
{% if l1|int < ptf_map[dut1_index]|length -2 %}
ip link add PortChannel{{ '%04d' | format(l1|int + 1) }} type bond mode 802.3ad
ip link set eth{{ptf_map[dut1_index][l1]}} down
ip link set eth{{ptf_map[dut2_index][l1]}} down
ip link set eth{{ptf_map[dut1_index][l1]}} master PortChannel{{'%04d' | format(l1|int + 1)}}
ip link set eth{{ptf_map[dut2_index][l1]}} master PortChannel{{'%04d' | format(l1|int + 1)}}
ip addr add 172.16.{{l1|int + 1}}.2/24 dev PortChannel{{'%04d' | format(l1|int + 1)}}
ip link set PortChannel{{'%04d' | format(l1|int + 1)}} up
sleep 1
{% else %}
ip link set eth{{ptf_map[dut1_index][l1]}} down
ip addr add 172.16.{{l1|int + 1}}.2/24 dev eth{{ptf_map[dut1_index][l1]}}
ip link set eth{{ptf_map[dut1_index][l1]}} up
ip link set eth{{ptf_map[dut2_index][l1]}} down
ip addr add 172.16.{{ptf_map[dut2_index][l1]|int + 1}}.2/24 dev eth{{ptf_map[dut2_index][l1]}}
ip link set eth{{ptf_map[dut2_index][l1]}} up
{% endif %}
{% endfor %}
```

Example of MCLAG configuration:

```
"MC_LAG": {
    "100": {
        "local_ip": "10.100.1.1",
        "peer_ip": "10.100.1.2",
        "mclag_interface": "PortChannel0001, PortChannel0002, PortChannel0003, PortChannel0004, PortChannel0005, PortChannel0006, PortChannel0007, PortChannel0008, PortChannel0009, PortChannel0010, PortChannel0011, PortChannel0012, PortChannel0013, PortChannel0014, PortChannel0015, PortChannel0016, PortChannel0017, PortChannel0018, PortChannel0019, PortChannel0020, PortChannel0021, PortChannel0022, PortChannel0023, PortChannel0024"
    }
}
```

## Ansible scripts to setup and run test

# Command to deploy the topo t0-mclag

- ./testbed-cli.sh add-topo vms-t0-mclag ~/.password

# Deploy the initial configuration for both devices

- ./testbed-cli.sh deploy-mg vms-t0-mclag lab ./password.txt

## Test cases

## MCLAG L3

## Test case test_check_keepalive_link

### Test objective

Verify that MCLAG status after MCLAG build is OK on both DUTs

### Test set up

- None

### Test steps

- Check MCLAG status on both MCLAG PEERS
- Verify that MCLAG status is OK

### Test teardown

- None

## Test case test_check_teamd_system_id

### Test objective

Verify standby device changes its LACP system ID to be the same as active device

### Test set up

- None

### Test steps

- Check MAC of MCLAG interface on active device (DUT1)
- Check MAC of MCLAG interface on standby device (DUT2)
- Verify that MAC of MCLAG interface is identical

### Test teardown

- None

## Test case test_mclag_intf_status_down

### Test objective

Verify data forwarding is correct when mclag enabled interface status change to down

### Test set up

- pre_setup(scope='function'): Shut down MCLAG interface members on both DUTs, checks that links changed status from PTF side

### Test steps

- Define network data
- From MCLAG interfaces on PTF, send TCP packet with such dst_ip, that the traffic will go trough PeerLink to its destination
- Verify that packets was received on expected destination ports

### Test teardown

- pre_setup(scope='function'): Start up MCLAG interface members on both DUTs, checks that links changed status from PTF side


## Test case test_mclag_intf_status_up

### Test objective

Verify data forwarding is correct when mclag enabled interface status change to up

### Test set up

- None

### Test steps

- Define network data
- From MCLAG interfaces on PTF, send TCP packet with varios dst_ip
- Verify that packets was received on expected destination ports

### Test teardown

- None