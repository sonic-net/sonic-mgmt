# Routing policies test plan

- [Routing Policies testplan](#bgp-routing-policies-testplan)
  - [Overview](#Overview)
    - [Scope](#Scope)
    - [Testbed](#Keysight-Testbed)
  - [Topology](#Topology)
  - [Test methodology](#Test-methodology)
  - [Test cases](#Test-cases)
    - [Test case # 1 – Peer Routing Policies](#test-case--1--peer-routing-policies)
      - [Test objective](#Test-objective)
      - [Test steps](#Test-steps)
      - [Test results](#Test-results)
    - [Test case # 2 – Community List Filtering](#test-case--2--community-list-filtering)
      - [Test objective](#Test-objective-1)
      - [Test steps](#Test-steps-1)
      - [Test results](#Test-results-1)
    - [Test case # 3 – Prefix List Filtering](#test-case--3--prefix-list-filtering)
      - [Test objective](#Test-objective-2)
      - [Test steps](#Test-steps-2)
      - [Test results](#Test-results-2)
    - [Test case # 4 – Metric Filter](#test-case--4--metric-filter)
      - [Test objective](#Test-objective-3)
      - [Test steps](#Test-steps-3)
      - [Test results](#Test-results-3)
    - [Test case # 5 – Group-As-Path Modified](#test-case--5--group-as-path-modified)
      - [Test objective](#Test-objective-4)
      - [Test steps](#Test-steps-4)
      - [Test results](#Test-results-4)
    - [Test case # 6 – Group Origin Code Modification](#test-case--6--group-origin-code-modification)
      - [Test objective](#Test-objective-5)
      - [Test steps](#Test-steps-5)
      - [Test results](#Test-results-5)


## Overview
The purpose of these tests is to evaluate the BGP Routing Policies Using Match Conditions and Actions. The routing policy consists of multiple terms. Each term consists of match conditions and actions to apply to matching routes.

### Scope
These tests are targeted on fully functioning SONiC system. The purpose of these tests are to evaluate the BGP Routing Policies Using Match Conditions and Actions.

### Keysight Testbed
The tests will run on following testbeds:
* t0

![Single DUT Topology ](Img/Single_DUT_Topology.png)

## Topology

```
                     _________
                    |         |
IXIA TGEN1 -------- |   DUT   |------ IXIA TGEN2
                    |_________|
```

## Test Methodology
Following test methodology will be used to evaluate routing policies.
* Traffic generator will be used to configure ebgp peering between TGEN1 and SONiC DUT by advertising IPv4/IPv6, dual-stack routes.
* Advertise 2 IPv4 and 2 IPv6 routes from TGEN1.
* Create four flows from TGEN2 to TGEN1
    1. `permit` -- TGEN2 to TGEN1("200.1.0.0")
    2. `permit_ipv6` -- TGEN2 to TGEN1("4000::1")
    3. `deny`   -- TGEN2 to TGEN1("20.1.0.0")
    4. `deny_ipv6` -- TGEN2 to TGEN1("6000::1")
* update the BGP attributes as per route policy for route in `permit` & `permit_ipv6`
and validate the actions applied to match routes.


## Test cases
### Test case # 1 – Peer Routing Policies
#### Test objective
Routing policy in the DUT match conditions with BGP attributes (community, as-path, metric, origin) and permit the routes.


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.

        1. "200.1.0.0" & "4000::1" with Attributes
        a) community-list 1:2
        b) as-path append AS 100
        c) Origin ebgp
        d) Metric 50
        2. "20.1.0.0" & "6000::1" without Attributes
3.  Create route-map in DUT to permit only `200.1.0.0`
   & `4000::1` based on BGP Attributes
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit','deny','permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'


### Test case # 2 – Community List Filtering
#### Test objective
Routing policy in the DUT match conditions with BGP Community and permit the routes with Community.


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.

        1. "200.1.0.0" & "4000::1" with Community List
        2. "20.1.0.0" & "6000::1" without Community List
3.  Create route-map in DUT to permit only `200.1.0.0`
   & `4000::1` based on BGP Community List
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit', 'deny', 'permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'

### Test case # 3 – Prefix List Filtering
#### Test objective
Routing policy in the DUT match conditions with Prefix-list and permit based on Prefix List Filtering.


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.
        
        1. "200.1.0.0" & "4000::1"
        2. "20.1.0.0" & "6000::1"
3.  Create Prefix-list route-map in DUT to permit only `200.1.0.0`
   & `4000::1`
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit','deny','permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'


### Test case # 4 – Metric Filter
#### Test objective
Routing policy in the DUT match conditions with Metric and permit based on Metric Filtering.


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.

        1."200.1.0.0" & "4000::1" with Metric 50
        2."20.1.0.0" & "6000::1" with default Metric
3.  Create route-map in DUT to permit only `200.1.0.0`
   & `4000::1` with Metric 50
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit','deny','permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'


### Test case # 5 – Group-As-Path Modified
#### Test objective
Routing policy in the DUT match conditions with group-as-path and permit based on group-as-path Modification.


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.
        
        1."200.1.0.0" & "4000::1" with group AS 100
        2."20.1.0.0" & "6000::1" without group AS 100
3.  Create route-map in DUT to permit only `200.1.0.0`
   & `4000::1` with group AS 100
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit','deny','permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'


### Test case # 6 – Group Origin Code Modification
#### Test objective
Routing policy in the DUT match conditions with Origin and permit based on Origin


#### Test steps
1. Configure BGP between DUT and TGEN1.
2. Generate 2 ipv4 routes & 2 ipv6 routes from TGEN1 via BGP.
        
        1."200.1.0.0" & "4000::1" with Origin 'egp'
        2."20.1.0.0" & "6000::1"
3.  Create route-map in DUT to permit only `200.1.0.0`
   & `4000::1` with Origin 'egp'
4. Create four flows from TGEN2 to TGEN1

        1) permit -- TGEN2 to TGEN1("200.1.0.0")
        2) permit_ipv6 -- TGEN2 to TGEN1("4000::1")
        3) deny   -- TGEN2 to TGEN1("20.1.0.0")
        4) deny_ipv6 -- TGEN2 to TGEN1("6000::1")

#### Test results
1. Send traffic without applying route-map

        Result: Should not observe traffic loss in the flows 'permit','deny','permit_ipv6' & 'deny_ipv6'
2. Apply route-map

        Result: Should observe 100% traffic loss in the flows 'deny' & 'deny_ipv6'
