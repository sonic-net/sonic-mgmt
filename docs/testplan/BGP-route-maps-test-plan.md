# Route maps Test Plan

## Rev 0.1
- [Revision](#revision)
- [Overview](#overview)
  - [Scope](#scope)
  - [Testbed](#testbed)
- [Setup configuration](#Setup-configuration)
- [Test Cases](#Test)
  - [test_access_list](#Test-case-#1-test_access_list)
  - [test_BGP_attributes](#Test-case-#2-test_BGP_attributes)
  - [test_new_next_hop](#Test-case-#3-test_new_next_hop)
## Revision

| Rev |     Date    |       Author                |      Change Description            |
|:---:|:-----------:|:----------------------------|:-----------------------------------|
| 0.1 |  10.22.2021 | Intel: Vladyslav Morokhovych |          Initial version           |

# Overview 

The goal of the test is to check that route maps feature works correctly. Route maps provide a means to both filter and/or apply actions to route, hence allowing policy to be applied to routes. Route maps are an ordered list of route map entries. 

# Scope 

The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is to test route maps feature. 

# Testbed 

The test could run on T1 testbed 

# Setup configuration 

This test requires a change in default route maps configuration. We need to add call to our test route maps in already created route maps. 

### Routing from T0(PTF) to T2(VM) trough T1(DUT) when route matches route-map entry
```
              T2     T2    T2    T2
              VM     VM    VM    VM
              [^]    [^]    [^]    [^]
              [|]    [|]    [|]    [|]
       _______[|]____[|]____[|]____[|]___
      |        |      |      |      |   |
      |________|______|__    |      |   |
      |                 |_ _ |      |   |
      |  BGP route-map  |_ _ _ _ ___|   |
      |_________________|               |
      |        ^              T1        |
      |        |              DUT       |
      |    Ethernet64                   |
      |_________________________________|
              [^]    []    []    []
              [|]    []    []    []
              [|]    []    []    []
       _______[|]____[]____[]____[]______ 
      |                                 |
      |     mgmt_ip                     |
      |              T0                 |
      |              PTF                |
      |_________________________________|
```
# Test 

The test configures route-maps feature with predefined rules. After that, the test announces routes to check what routes will be passed from the T0 to T1 and T2 with new BGP attributes, and which routes are being dropped. 

## Test case #1 test_access_list 
### Test objective

Verify that Route-map can permit and deny routes, based on IP access-list. 

### Test steps
- Set route-map entry with permit rule that filter IP access-list.  
- Announce predefined ipv4 routes that in/out of range of created IP access-lists from one of the T0s to DUT. 
- Check that routes from range of IP access-list announced to DUT and T2 peers, and other routes are not announced. 
- Remove created route maps, IP access-list and withdraw announced routes. 

## Test case #2 test_BGP_attributes
### Test objective

Verify that Route-map can set new BGP attributes to announced routes.

### Test steps
- Set route-map entry with permit rule that set custom distance value to use for the route. 
- Announce predefined ipv4 routes from one of the T0s to DUT. 
- Check that routes announced to DUT with custom distance value. 
- Remove created route maps and withdraw announced routes. 

## Test case #3 test_new_next_hop
### Test objective

Verify that Route-map can set new next-hop address for routes from specified interface.

### Test steps
- Set route-map entry with permit rule that match route from specified interface and set new next-hop address. 
- Announce predefined ipv4 routes from one of the T0s to DUT. 
- Check that routes announced to DUT with the new next-hop address. 
- Remove created route maps and withdraw announced routes. 