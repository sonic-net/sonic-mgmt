# **gNMI Get Modes Test Plan**

# **Overview**

This document outlines the approach for testing the functionality of different GET modes of the gNMI protocol as part of Ondatra end-to-end testing framework in SONiC. gNMI is responsible for monitoring, streaming telemetry, and configuration management based on the standard OpenConfig YANG models. 
 
The gNMI Get RPC is intended to retrieve the set of data elements for which the target should return a snapshot of data, for example a part of the configuration. A Get request acts as a single request/response channel where the target creates the relevant update messages, transmits them, and subsequently closes the RPC. 


# **gNMI Feature Description**
The types of data currently defined are:

*   CONFIG - specified to be data that the target considers to be read/write. 
*   STATE - specified to be the read-only data on the target. 
*   OPERATIONAL - specified to be the read-only data on the target that is related to software processes operating on the device, or external interactions of the device. These are a subset of the state paths - the ones which do not have a corresponding config path (For example: admin-status, oper-status, counters etc)
*   ALL - the entire set of values in the tree. If the type field is not specified, the target must return CONFIG, STATE and OPERATIONAL data fields in the tree. ALL is the default value of the field/subtree and if the type is not provided, it is the same as ALL data type.
  
<td style="background-color: #fafafa">

```
root +
     |
     +--rw interfaces
     |    +--rw interface* [name]
     |        +--rw name 
     |        +--rw config
     |        |  +--rw name 
     |        |  +--rw type
     |           ....                       
     |        +--ro state
     |        |  +--ro name
     |        |  +--ro type 
     |        |  +--ro admin-status
     |           ....
     |        +--rw oc-eth:ethernet
     |        |  +--rw oc-eth:config
     |        |  |  +--rw oc-eth:mac-address
     |                 ....
     |        |  +--ro oc-eth:state
     |        |  |  +--ro oc-eth:mac-address 
     |                 ....
     +--rw components
```


   </td>

   # **Test Strategy**

For end-to-end tests, we cannot be sure of what config or state nodes are set in the system beforehand and hence cannot determine what paths to validate against. A few options to address this are:
1. After a config push, issue a GET request for an ALL type after a config push followed by a GET request for specified (config/state/operational) data type. This would use the existing paths in the GET ALL response to generate a list of expected paths and subsequently verify from the GET response. 
2. After a config push, validate the GET response against a set of predefined config/state/operational paths of interest for the intended client. This set of predefined paths could be any set of paths with near constant values (helpful to verify consistency for Operational paths).

The first approach assumes that the ALL type GET request works fine. This option does add some complexity to the test to separate the incoming GET ALL response into structures for interfaces, components modules (this might be easier in Ondatra). The resulting structure would not be optimized since most of the data nodes would not be used in the test. \
For the second approach, the assumption is that the default values are present for all predefined paths, which is true for most of the supported paths today. This would be simpler and easier to support since the majority of the paths would be used for the SET request operation to do the initial config push. \
For this test plan design, we will go with using predefined paths (option 2) as well as the specific, centralized gNMI feature test suite for the implementation.

# **Test Setup**

In the test setup, a test client initializes a gNMI client that connects to the gNMI server running on a single switch under test (SUT).  A detailed overview of the test topology can be found [here](https://github.com/sonic-net/sonic-mgmt/tree/master/sdn_tests#topologies) 

# End-to-end Test Summary 


<table>
  <tr>
   <td style="background-color: #bbbbbb"><strong>Test Case</strong>
   </td>
   <td style="background-color: #bbbbbb"><strong>GET CONFIG</strong>
   </td>
   <td style="background-color: #bbbbbb"><strong>GET STATE</strong>
   </td>
   <td style="background-color: #bbbbbb"><strong>GET OPERATIONAL</strong>
   </td>
   <td style="background-color: #bbbbbb"><strong>GET ALL</strong>
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Config Subtree (Ex. /interfaces/interface[name=EthernetX]/config/*)
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Config Leaf (Ex. /interfaces/interface[name=EthernetX]/config/name)
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">State Subtree (Ex. /interfaces/interface[name=EthernetX]/state/*)
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree (Operational leaves only)
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">State Leaf (Ex. /interfaces/interface[name=EthernetX]/state/name)
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Operational Subtree (Ex. /interfaces/interface[name=EthernetX]/state/counters/*)
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree (State leaves only)
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Operational Leaf (Ex. /interfaces/interface[name=EthernetX]/state/counters/in-octets)
   </td>
   <td style="background-color: #ffe599">Returns Empty
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
   <td style="background-color: #b6d7a8">Returns Value
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Root Path (Ex. /)
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
   <td style="background-color: #b6d7a8">Returns Subtree
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Non-Existent Path (Ex. /interfaces/interface[name=EthernetX]/state/fake-leaf)
   </td>
   <td colspan="4" style="background-color: #ea9999">
Returns Error
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Invalid Type
   </td>
   <td colspan="4" style="background-color: #ea9999">Returns Error
   </td>
  </tr>
  <tr>
   <td style="background-color: #e0e0e0">Missing Type
   </td>
   <td colspan="4" style="background-color: #b6d7a8">Returns ALL Subtree
   </td>
  </tr>
</table>

# Detailed Test Cases

## GET for CONFIG type

### Expectation
Send a GET request for CONFIG type and expect only the configuration portion of the requested path should be returned in the response message.

<td style="background-color: #fafafa">

```
root +
     |
     +--rw interfaces
     |    +--rw interface* [name]
     |        +--rw name 
     |        +--rw config
     |        |  +--rw name 
     |        |  +--rw type
     |           ....                       
     |        +--ro state
     |        |  +--ro name 
     |        |  +--ro type
     |           ....  
     |        +--rw subinterfaces
     |        |  +--rw subinterface* [index]
     |        |     +--rw index
     |        |     +--rw config
     |        |     |  +--rw index             
     |                 ....
     |        |     +--ro state
     |        |     |  +--ro index 
     |                 ....
     |        +--rw oc-eth:ethernet
     |        |  +--rw oc-eth:config
     |        |  |  +--rw oc-eth:mac-address
     |                 ....
     |        |  +--ro oc-eth:state
     |        |  |  +--ro oc-eth:mac-address 
     |                 ....
     +--rw components
```


   </td>

### Test #1: GET Config at the subtree level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: DataType_CONFIG
```

Validation: 
Verify that only the config subtrees and their leaf paths are returned:

Example:
```
request:
'prefix: { origin: "openconfig", target: "<Target>" }, path: { elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: 1'

response:
  update: <
    path: <
      elem: <
        name: "interfaces"
      >
      elem: <
        name: "interface"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
    >
    val: <
      json_ietf_val: "{\"openconfig-interfaces:interface\":[{\"config\":{\"enabled\":true,\"mtu\":<MTU>,\"name\":\"EthernetX\",\"type\":\"iana-if-type:ethernetCsmacd\"},\"name\":\"EthernetX\",\"subinterfaces\":{\"subinterface\":[{\"config\":{\"index\":0},\"index\":0,\"openconfig-if-ip:ipv4\":{\"addresses\":{\"address\":[{\"config\":{\"ip\":\"<IP_ADD>\",\"prefix-length\":XX},\"ip\":\"<IP_ADD>\"}]},\"config\":{\"enabled\":false}},\"openconfig-if-ip:ipv6\":{\"config\":{\"enabled\":false}}}]}}]}"
    >
  >
>
```

### Test #2: GET Config at the root level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"/" } } type: DataType_CONFIG
```

Validation: 
Verify that only the config subtrees and their leaf paths are returned. 

### Test #3: GET Config at the leaf level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"mtu" } } type: DataType_CONFIG
```

Validation: 
Verify that /interfaces/interface/[name=EthernetX]/config/mtu value (scalar value) is returned.

<td style="background-color: #fafafa">

Example:
```
request:
'prefix: { origin: "openconfig", target: "<target>" }, path: { elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } elem: { name:"config" }  elem : {name:"mtu"} } type: 1'

response:
  update: <
    path: <
      elem: <
        name: "interfaces"
      >
      elem: <
        name: "interface"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
      elem: <
        name: "config"
      >
      elem: <
        name: "mtu"
      >
    >
    val: <
      json_ietf_val: "{\"openconfig-interfaces:mtu\":<MTU>}"
    >
  >
>
```


   </td>

### Test #4: Negative test case - GET Config type with state/operational subtree
Condition to test: Config type with state/operational subtree

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } elem: { name:"state"} } } type: DataType_CONFIG
```

Validation: should return empty subtree
<td style="background-color: #fafafa">

Example:
```
request:
'prefix: { origin: "openconfig", target: "<target>" }, path: { elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } elem: { name:"state" } } type: 1'

response:
  update: <
    path: <
      elem: <
        name: "interfaces"
      >
      elem: <
        name: "interface"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
      elem: <
        name: "state"
      >
    >
    val: <
      json_ietf_val: "{}"
    >
  >
>
```


   </td>

### Test #5: Negative test case - GET Config Type with state leaf
Condition to test: Config Type with state leaf

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"serial-no" } } type: DataType_CONFIG
```

Validation: should return empty subtree.

### Test #6: Negative test case - GET Config type with operational leaf
Condition to test: Config type with operational leaf
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"oper-status" } } type: DataType_CONFIG
```

Validation: should return empty value
Example:

<td style="background-color: #fafafa">

```
request:
'prefix: { origin: "openconfig", target: "<target>" }, path: { elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } elem: { name:"state" }  elem : {name:"oper-status"} } type: 1'

response:
  update: <
    path: <
      elem: <
        name: "interfaces"
      >
      elem: <
        name: "interface"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
      elem: <
        name: "state"
      >
      elem: <
        name: "oper-status"
      >
    >
    val: <
      json_ietf_val: "{}"
    >
  >
>

root@sonic:/# 
```


   </td>

## GET for STATE type

### Expectation
Send a GET request for STATE type and expect only the state portion of the requested path should be returned in the response message.


   <td style="background-color: #fafafa">

```
root +
     |
     +--rw interfaces
     |    +--rw interface* [name]
     |        +--rw name 
     |        +--rw config
     |        |  +--rw name 
     |        |  +--rw type
     |           ....                       
     |        +--ro state
     |        |  +--ro name 
     |        |  +--ro type
     |           ....  
     |        +--rw subinterfaces
     |        |  +--rw subinterface* [index]
     |        |     +--rw index
     |        |     +--rw config
     |        |     |  +--rw index             
     |                 ....
     |        |     +--ro state
     |        |     |  +--ro index 
     |                 ....
     |        +--rw oc-eth:ethernet
     |        |  +--rw oc-eth:config
     |        |  |  +--rw oc-eth:mac-address
     |                 ....
     |        |  +--ro oc-eth:state
     |        |  |  +--ro oc-eth:mac-address 
     |                 ....
     +--rw components
```


   </td>

### Test #1: GET State at the subtree level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interface" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: DataType_STATE
```

Validation: 
Verify that only the state subtrees and their leaf paths are returned:
Example:
```
request:
'prefix: { origin: "openconfig", target: "<Target>" }, path: { elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: 2'

response:
  update: <
    path: <
      elem: <
        name: "interfaces"
      >
      elem: <
        name: "interface"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
    >
    val: <
      json_ietf_val: "{\"openconfig-interfaces:interface\":[{\"state\":{\"enabled\":true,\"mtu\":<MTU>,\"name\":\"EthernetX\",\"type\":\"iana-if-type:ethernetCsmacd\",\"oper-status\":\"UP\"},\"name\":\"EthernetX\",\"subinterfaces\":{\"subinterface\":[{\"state\":{\"index\":0},\"index\":0,\"openconfig-if-ip:ipv4\":{\"addresses\":{\"address\":[{\"state\":{\"ip\":\"<IP_ADD>\",\"prefix-length\":XX},\"ip\":\"<IP_ADD>\"}]},\"state\":{\"enabled\":false}},\"openconfig-if-ip:ipv6\":{\"state\":{\"enabled\":false}}}]}}]}"
    >
  >
>
```

### Test #2: GET State at the root level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"/" } } type: DataType_STATE
```

Validation: 
Verify that only the state subtrees and their leaf paths are returned.

### Test #3: GET State at the leaf level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"oper-status" } } type: DataType_STATE
```

Validation: 
Verify that interfaces/interface[name=EthernetX]/state/oper-status value is returned.

### Test #4: Negative test case - GET State type with config subtree

Condition to test: State type with config subtree

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"config"} } type: DataType_STATE
```

Validation: should return empty subtree
```
request:
'path: { elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"config" } } type: 2'

response:
  update: <
    path: <
      elem: <
        name: "components"
      >
      elem: <
        name: "component"
        key: <
          key: "name"
          value: "EthernetX"
        >
      >
      elem: <
        name: "config"
      >
    >
    val: <
      json_ietf_val: "{}"
    >
  >
>
```

### Test #5: Negative test case - GET State Type with config leaf
Condition to test: State Type with config leaf
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"mtu" } } type: DataType_STATE
```

Validation: should return empty subtree

## GET for OPERATIONAL type

### Expectation
Send a GET request for OPERATIONAL type and expect only the operational portion of the requested path should be returned in the response message.

### Test #1: GET Operational at the subtree level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: DataType_OPERATIONAL
```

Validation: 
Verify that only the operational leafs (like counters, admin-status, oper-status) are returned.

### Test #2: GET Operational at the root level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"/" } } type: DataType_OPERATIONAL
```

Verify that only the operational leafs (like counters, admin-status, oper-status) are returned.

### Test #3: GET Operational at the leaf level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"oper-status" } } type: DataType_OPERATIONAL
```

Validation: 
Verify that /interfaces/interface/[name=EthernetX]/state/oper-status value is returned.

### Test #4: Negative test case - GET Operational type with Config subtree
Condition to test: Operational type with config subtree
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } elem: { name:"config"} } } type: DataType_OPERATIONAL
```

Validation: should return empty subtree

### Test #5: Negative test case - GET Operational type with Config leaf
Condition to test: Operational type with Config leaf
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"name" } } type: DataType_OPERATIONAL
```

Validation: should return empty subtree

### Test #6: Negative test case - GET Operational type with State (non-operational) leaf
Condition to test: Operational type with State (non-operational) leaf

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"name" } } type: DataType_OPERATIONAL
```
Validation: should return empty subtree

## GET for ALL type
### Expectation
Send a GET request for ALL type and expect that the complete tree for the requested path should be returned (all of Config, State, and Operational types) in the response message.

### Test #1: GET ALL at the subtree level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: DataType_ALL
```

Validation: 
Verify that the /interfaces/interface/[name=EthernetX]/* 

### Test #2: GET ALL at the root level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"/" } } type: DataType_ALL
```

Validation: 
Verify that the subtrees and their leaf paths are returned. 

### Test #3: GET ALL at the leaf level
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"mtu" } } type: DataType_ALL
```

Validation: 
Verify that interfaces/interface/[name=EthernetX]/config/mtu value is returned.

### Test #4: GET ALL type returns GET CONFIG+STATE+OPERATIONAL data
Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } } type: DataType_ALL
```

Validation: 
Verify that the response has config, state, and operational subtree data.

## GET for Invalid/Missing types

### Expectation
Send a Get request for Invalid type (>4) or with type field not specified and expect that the target returns CONFIG, STATE and OPERATIONAL data fields in the resulting tree in the response message, i.e. the complete tree (=ALL type) for the requested path is returned in the response.

### Test #1: Invalid path with data type specified

   <td style="background-color: #fafafa">

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"fake-leaf" } } type: DataType_CONFIG
```


   </td>

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"fake-leaf" } } type: DataType_STATE
```



```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"counters" } elem: { name:"fake-counter" } } type: DataType_OPERATIONAL
```


  <tr>
   <td style="background-color: #fafafa">

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"fake-path" } } type: DataType_ALL
```

Validation: should return error

### Test #2: Invalid type for subtree

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } elem: { name:"config"} } type: 7
```


   </td>

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"state"} } type: 9
```



```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"state"} elem: { name:"counters"} } type: 6
```


  <tr>
   <td style="background-color: #fafafa">

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } } type: 7
```

Validation: should return error

### Test #3: Missing type for subtree

   <td style="background-color: #fafafa">

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } } elem: { name:"config"} }
```


   </td>

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"state"} }
```



```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } elem: { name:"state"} elem: { name:"counters"} }
```


  <tr>
   <td style="background-color: #fafafa">

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "EthernetX" } } }
```

Validation: should return Get response for default ALL type for subtree

## Consistency Tests 


### Expectation

Send multiple GET requests for subtree/leaf with different types and verify if the response structure and values are the same for the following mapping: 

- Config path : Same response across Config and All types,

- State path : Same response across State and All types,

- Operational path : Same response across Operational, State and All types

### Test #1: GET at the leaf level for Config path

Condition to test:

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"id" } } type: DataType_CONFIG
```

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"id" } } type: DataType_ALL
```

Validation: Verify that the value in the response is the same for both cases
```
json_ietf_val: "{\"openconfig-pins-interfaces:id\":1}"
```

### Test #2: GET at the leaf level for State path

Condition to test:

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"id" } } type: DataType_STATE
```

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"state" } elem: { name:"id" } } type: DataType_ALL
```

Validation: Verify that the value in the response is the same for both cases
```
json_ietf_val: "{\"openconfig-pins-interfaces:id\":1}"
```

### Test #3 - GET at the leaf level for Operational path

Condition to test:

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } elem: { name:"part-no" } } type: DataType_OPERATIONAL
```

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } elem: { name:"part-no" } } type: DataType_STATE
```

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } elem: { name:"part-no" } } type: DataType_ALL
```

Validation: Verify that the value in the response is the same for all cases
```
json_ietf_val: "{\"openconfig-platform:part-no\":\"1234\"}"
```

 ### Test #4: GET at the subtree level for Config path

Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } } type: DataType_CONFIG
```

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } } type: DataType_ALL
```

Validation: Verify that the value and structure in the response is the same for both cases

```
json_ietf_val: "{\"openconfig-interfaces:config\":{\"enabled\":true,\"mtu\":9100,\"name\":\"EthernetX\",\"type\":\"iana-if-type:ethernetCsmacd\"}}"
```

### Test #5: GET at the subtree level for State path

Condition to test:

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } } type: DataType_STATE
```
```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } } type: DataType_ALL
```

Validation: Verify that the value and structure in the response is the same for both cases

```
json_ietf_val: "{\"openconfig-platform:component\":[{\"chassis\":{\"state\":{\"openconfig-pins-platform-chassis:base-mac-address\":\"aa:bb:cc:dd:ee:ff\",\"openconfig-pins-platform-chassis:mac-address-pool-size\":0,\"openconfig-pins-platform-chassis:platform\":\"switch\"}},\"name\":\"chassis\",\"state\":{\"firmware-version\":\"BIOS version\",\"hardware-version\":\"10\",\"mfg-date\":\"2024-01-01\",\"name\":\"chassis\",\"oper-status\":\"openconfig-platform-types:ACTIVE\",\"part-no\":\"1234\",\"serial-no\":\"FFF\",\"type\":\"openconfig-platform-types:CHASSIS\"}}]}"
```

### Test #6: GET at the subtree level for Operational path
Condition to test:

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } } type: DataType_OPERATIONAL
```

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } } type: DataType_STATE
```

```
path: { origin: "openconfig" elem: { name:"components" } elem: { name:"component" key: { key: "name" value: "chassis" } }  elem: { name:"state" } } type: DataType_ALL
```
Validation: Verify that the value and structure in the response is the same for all cases

```
json_ietf_val: "{\"openconfig-platform:component\":[{\"chassis\":{\"state\":{\"openconfig-pins-platform-chassis:base-mac-address\":\"aa:bb:cc:dd:ee:ff\",\"openconfig-pins-platform-chassis:mac-address-pool-size\":0,\"openconfig-pins-platform-chassis:platform\":\"switch\"}},\"name\":\"chassis\",\"state\":{\"firmware-version\":\"BIOS version\",\"hardware-version\":\"10\",\"mfg-date\":\"2024-01-01\",\"name\":\"chassis\",\"oper-status\":\"openconfig-platform-types:ACTIVE\",\"part-no\":\"1234\",\"serial-no\":\"FFF\",\"type\":\"openconfig-platform-types:CHASSIS\"}}]}"
```
