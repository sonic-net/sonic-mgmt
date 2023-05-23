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
    - [test_keepalive_link_down](#Test-case-test_keepalive_link_down)
    - [test_session_timeout](#Test-case-test_session_timeout)
    - [test_active_down](#Test-case-test_active_down)
    - [test_standby_down](#Test-case-test_standby_down)
    - [test_peer_link_status_change](#Test-case-test_peer_link_status_change)


## Revision

| Rev |     Date    |       Author          |         Change Description         |
|:---:|:-----------:|:---------------------:|:----------------------------------:|
| 0.1 |  04/02/2022 | Andrii-Yosafat Lozovyy|          Initial version           |
|:---:|:-----------:|:---------------------:|:----------------------------------:|
| 0.2 |  04/03/2022 | Andrii-Yosafat Lozovyy|           New test cases           |


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

![152551826-d1e37522-94d7-447e-8097-56cf25194018](https://user-images.githubusercontent.com/73100001/154721286-c3423b73-cdd8-434f-80de-20a3640437bf.png)


- Requires 2 VMs
- 2 DUT ports areconnected to VMs
- PTF container have 2 injected interfaces and 52 directly connected ports
- 2 ports on each DUT is interconnected


# Mclag logical topology
![152551603-482a945e-482a-4b2e-881b-87a014bb056f](https://user-images.githubusercontent.com/73100001/154721388-a2973228-9b9c-4c28-a3b1-24c846b6d551.png)


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

- Check MAC of MCLAG interface on active device
- Check MAC of MCLAG interface on standby device
- Verify that MAC of MCLAG interface is identical

### Test teardown

- None

## Test case test_mclag_intf_status_down

### Test objective

Verify data forwarding is correct when mclag enabled interface status change to down
![mclag_intf_down](https://user-images.githubusercontent.com/73100001/160277837-54e54d67-9e72-4baf-8302-4adf65becedb.gif)

### Test set up

- Shut down MCLAG interface members on both DUTs, checks that links changed status from PTF side

### Test steps

- Define network data
- From MCLAG interfaces on PTF, send TCP packet with such dst_ip, that the traffic will go trough PeerLink to its destination
- Verify that packets was received on expected destination ports

### Test teardown

- Start up MCLAG interface members on both DUTs, checks that links changed status from PTF side


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


## Test case test_keepalive_link_down

### Test objective

Verify data forwarding is correct when keepalive link is in down state
![keepalive_down](https://user-images.githubusercontent.com/73100001/160277878-8b2d6b50-8627-4098-bcff-446b50132307.gif)

### Test set up

- Shutdown keepalive link and wait default session-timeout

### Test steps

- Verify that MAC of MCLAG interfaces on standby device changed to its default MAC
- Verify that MCLAG status is ERROR on both PEERs
- Define network data
- From MCLAG interfaces on PTF, send TCP packet with varios dst_ip
- Verify that packets was received on expected destination ports

### Test teardown

- Startup keepalive link and wait default session-timeout


## Test case test_session_timeout

### Test objective

Verify that session_timeout can be changed

### Test set up

- Change default session-timeout to new value, shutdown keepalive link

### Test steps

- Verify that after default session-timeout MCLAG status is still OK
- Verify after new session-timeout MCLAG status changed to ERROR
- Verify MAC of MCLAG interfaces on standby device changed to its default MAC

### Test teardown

- Change session-timeout to default value, startup keepalive link


## Test case test_active_down

### Test objective

Verify data forwarding is correct when active device of mclag status change
![active_down](https://user-images.githubusercontent.com/73100001/160277894-cb6eb2c3-e281-4301-a316-9c8d22b6c8b5.gif)

### Test set up

- Shutdown mclag interfaces, peer and keepalive links, perform cold reboot

### Test steps

- Verify that MCLAG status is ERROR on both PEERs
- Verify that MAC of MCLAG interfaces on standby device changed to its default MAC
- Define network data
- From MCLAG interfaces on PTF, send TCP packet with default dst_mac of standby device
- Verify that packets was received on uplink after standby device
- Verify that packets was droped on uplink after active device

### Test teardown

- Startup mclag interfaces, peer and keepalive links


## Test case test_standby_down

### Test objective

Verify data forwarding is correct when standby device of mclag status change
![standby_down](https://user-images.githubusercontent.com/73100001/160277900-c47e68b9-36cb-43c3-afd4-cb86c933fd57.gif)

### Test set up

- Shutdown mclag interfaces, peer and keepalive links, perform cold reboot

### Test steps

- Verify that MCLAG status is ERROR on both PEERs
- Define network data
- From MCLAG interfaces on PTF, send TCP packet dst_mac of active device
- Verify that packets was received on uplink after active device
- Verify that packets was droped on uplink after standby device

### Test teardown

- Startup mclag interfaces, peer and keepalive links


## Test case test_peer_link_status_change

### Test objective

Verify data forwarding is correct when peerlink is lost
![peerlink_down](https://user-images.githubusercontent.com/73100001/160277912-6714281c-0366-4369-a59f-05358999d7aa.gif)

### Test set up

- Shutdown peerlink

### Test steps

- Verify that MCLAG status is OK on both PEERs
- Verify that MAC of MCLAG interfaces on standby device is equal to MAC on active device
- Define network data
- Use PortChannel members as sorce_ports to be able to control on which PEER traffic will go
- Verify that packets which travers trough active device can reach only its direct upstream, and will be droped when trying to reach standby uplink
- Verify that packets which travers trough standby device can reach only its direct upstream, and will be droped when trying to reach active uplink

### Test teardown

- Startup peerlink
