# Standalone SONiC Console Server Test Plan

## Overview

This purpose is to define the SONiC console server test topology and provide detailed testbed setup and test plan.

## Definitions/Abbreviations

| Abbreviation | Description                               |
| ------------ | ----------------------------------------- |
| DCE          | Data Circuit Terminating Equipment        |
| DTE          | Data Terminal Equipment |
| BGP          | Border Gateway Protocol |

### Scope

The test is targeting a running SONiC system with console server capbility.


### Testbed

Tests are avaialble on the following topology:

- c0


## Setup

### Test topology

A new test topology `c0` will be introdueced for standalone SONiC console server test.

![c0 topo](c0_topo.drawio.svg)

The console server(C0) has 3 upstream paths via BGP.

1. C0 -> M1
1. C0 -> M0 -> M1(multiple)
1. C0 -> C1

The first path is the default data path as it has shorter ASN path length.
The second path is mainly for redundency in case first path not avaialable.
The thrid path suppose to be only used for provision purpose.

The topo illustrated 3 different scenarios and we will going to consider them all in this test plan.

#### Scenario #1 Regular data path

![c0 topo](c0_topo_s1.drawio.svg)

#### Scenario #2 Backup data path

![c0 topo](c0_topo_s2.drawio.svg)

#### Scenario #3 Provision data path (for C0)

![c0 topo](c0_topo_s3.drawio.svg)

#### Scenario #4 Provision data path (for M1)

This is only scenario that the C0 is not the endpoint in the network. It is been used as a L3 ethernet switch in this scenario and forward traffic from `Secondary Network` to devices that not reachable from `Primary Network` directly.

![c0 topo](c0_topo_s4.drawio.svg)

### Physical Testbed


