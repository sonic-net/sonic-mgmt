# Port mirroring test plan

## Rev 0.1

- [Revision](#revision)
- [Definition/Abbrevation](#definition/abbrevation)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#setup-configuration)
- [Test cases](#test-cases)
  - [test_port_mirroring_rx](#Test-case-test_port_mirroring_rx)
  - [test_port_mirroring_tx](#Test-case-test_port_mirroring_tx)
  - [test_port_mirroring_rx_tx](#Test-case-test_port_mirroring_rx_tx)
  - [test_port_mirroring_from_multiple_ports](#Test-case-test_port_mirroring_from_multiple_ports)

## Revision

| Rev |     Date    |       Author            |     Change Description      |
|:---:|:-----------:|:------------------------|:----------------------------|
| 0.1 |  05/02/2021 | Intel : Viktor Cheketa  |       Initial version       |

## Definition/Abbrevation

| **Term**     | **Meaning**                            |
|--------------|----------------------------------------|
|    SPAN      | Switched Port ANalyzer                 |
| Monitor port | Destination port of mirroring session  |
| Mirrored port| Source port of mirroring session       |

## Overview

The purpose is to test the functionality of port mirroring (SPAN) feature on SONiC switch DUT.

## Scope

The test is targeting a runninc SONiC system with fully functioning configuration.
Purpose of test is to verify that a SONiC switch system correctly performs port mirroring implementation
based on configured sessions.

## Testbed

Supported topologies: t0

## Setup configuration

No setup pre-configuration is required, test will configure and clean-up all the configuration.

### Setup of DUT switch

Each test creates a mirroring session with specific parameters. In order to create a session, monitor port must not
be a VLAN member.

On setup, tests create a mirroring session via CLI commands on DUT:
```
sudo config vlan member del {VLAN} {monitor_port}
sudo config mirror-session span add {session_name} {monitor_port} {mirrored_port} {direction}
```

On teardown, these changes are reverted:
```
sudo config mirror-session remove {session_name}
sudo config vlan member add {VLAN} {monitor_port}
```
## Test cases

## Test case test_port_mirroring_rx

### Test objective

Verify that INGRESS traffic is mirrored.

### Test steps

- Create mirroring session on DUT with direction 'rx'.
- Create ICMP packet.
- Send ICMP packet from PTF to DUT.
- Verify that DUT mirrors packet to monitor port.

## Test case test_port_mirroring_tx

### Test objective

Verify that EGRESS traffic is mirrored.

### Test steps

- Create mirroring session on DUT with direction 'tx'.
- Create ICMP packet.
- Send packet to PTF.
- Verify that DUT mirrors packet to monitor port.

## Test case test_port_mirroring_rx_tx

### Test objective

Verify that both INGRESS and EGRESS traffic is mirrored.

### Test steps

- Create mirroring session on DUT with direction 'both'.
- Create ICMP packets.
- Send packet from PTF to DUT.
- Verify that DUT mirrors packet to monitor port.
- Send ICMP packet to PTF.
- Verify that DUT mirrors packet to monitor port.

## Test case test_port_mirroring_from_multiple_ports

### Test objective

Verify that packets from multiple ports within same session are mirrored

### Test steps

- Create mirroring session with two mirrored ports.
- Create ICMP packets.
- Send packets from first and second mirrored ports.
- Verify that DUT mirrors both packets to monitor port.
