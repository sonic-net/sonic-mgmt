# **gNMI GET and SET Operations Test Plan**

# **Overview**

This document outlines the approach for testing the functionality of different gNMI GET/SET operations supported by the gNMI protocol as part of Ondatra end-to-end testing framework in SONiC. gNMI is responsible for monitoring, streaming telemetry, and configuration management which is based on the standard OpenConfig YANG models. 
From the gNMI specification, the gNMI client can invoke a GET and/or SET request. The SET operations can be further categorized into UPDATE, REPLACE, and DELETE operations.


# **Test Setup**

In the test setup, a test client initializes a gNMI client that connects to the gNMI server running on a single switch under test (SUT).  A detailed overview of the test topology can be found [here](https://github.com/sonic-net/sonic-mgmt/tree/master/sdn_tests#topologies) 


# **End-to-End Test Cases**

## Methodology
The gNMI test client will always use gNMI SET replace/update/delete operation for modifying/removing the values on the switch and gNMI GET for fetching the values.
To validate any of the SET operations and their correctness of data, the test client will invoke a gNMI Get operation for corresponding nodes and cache the result before invoking a Set operation. The cached values will be adjusted based on the Set request payload. Once the Set operation is successful, the client will invoke another Get operation and validate the response against the expected response. The below example shows the operations in sequential order:


```
cached_response = gNMI Get for the interface/interface[name=EthernetX]/ path 
gNMI Set for the interface/interface[name=EthernetX]/config/mtu path
expected_response = Update the MTU value for both config and state leafs in the cached response
response = gNMI Get for the interface/interface[name=EthernetX]/ path
Validate the response against the expected_response
```

The gNMI server only supports encoding as PROTO and JSON and does not support any other encoding. The SET only accepts the payload as JSON values today.


## Summary of SET Operation Test Cases


<table>
  <tr>
   <td style="background-color: #b7b7b7"><p style="text-align: right">
<strong>Test Case </strong></p>

   </td>
   <td style="background-color: #b7b7b7"><strong>SET Update</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>SET Replace</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>SET Delete</strong>
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated leaf</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated leaf with no payload</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated leaf with  no payload</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated leaf</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid data for a leaf</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">N/A
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid leaf path </p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Read only leaf</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Unpopulated subtree</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Populated subtree</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid data for a subtree</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Read only subtree</p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Invalid subtree path </p>

   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Multiple payload</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #ea9999">Returns failure
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
Root level operation</p>

   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">Success
   </td>
   <td style="background-color: #b6d7a8">N/A
   </td>
  </tr>
</table>

## Tests

### Set Update Expectation

The expectation is for the gNMI server to process the valid Set Update request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload, then the server should not populate them with the default values and leave those leaf values as-is (not modify them).

### Test #1: Send a valid Set Update request for an existing leaf

Condition to test:

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```

Validation:
  - Make sure that the chosen leaf (e.g. `description`) is existing on the switch for a random interface, else create the leaf.
  - gNMI Set RPC succeeds without error and all the fields in the response matches the expectation.
  - Get for interfaces/interface/[name=EthernetX]/config/description matches the payload value ("Test_config").
  - Verify that other fields for the EthernetX subtree are not updated

### Test #2: Send a valid Set Update request for a non-existing leaf

Condition to test:
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_description"}
```

Validation:
  - Make sure that the chosen leaf (e.g. `description`) is not existing on the switch for a random interface before the test.
  - gNMI Set RPC succeeds without error and all the fields in the response matches the expectation.
  - Verify that the Leaf should be created and an appropriate response received.
  - Get for interfaces/interface/[name=EthernetX]/config/description matches the payload value ("Test_description").
  - Verify that other fields for the EthernetX subtree are not updated

### Test #3: Send a Set Update request with 2 valid updates
Condition to test: Send a Set Update request with 2 valid update payload.
```
path: { origin: "openconfig" elem: { name:"interfaces" } }

payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {   
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },  
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {   
                      "config" : {
                         "index" : 0
                      },  
                      "index" : 0, 
                      "openconfig-if-ip:ipv4" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  }, 
                                  "ip" : "<IP_ADDR>"
                               }, 
                               {  
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  }, 
                                  "ip" : "<IP_ADDR>"
                               }  
                            ]     
                         }     
                      }     
                   }     
                ]     
             }     
          }     
       ]     
    },    
    "openconfig-interfaces:interfaces" : {
       "interface" : [ 
          {   
             "config" : { 
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             },
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      },
                      "index" : 0,
                      "openconfig-if-ip:ipv6" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADDR>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADDR>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
}
```
Validation: 
  - Verify that the Leaf should be created and appropriate response received. In this case the loopback interfaces should be along with both IPV4 and IPV6 addresses.

### Test #4: Negative test case - Interface description for the platform subtree

Condition to test: Send interface description for the platform subtree  
```
path: { origin: "openconfig" elem: { name:"platform" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```

Validation: 
  - SET response should contain a failure message
  - Verify that none of the other paths values are changed for the platform subtree.

### Test #5: Negative test case - Send invalid path in Set Update request

Condition to test: Send invalid path
```
path: { origin: "openconfig" elem: { name:"xyz" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
  - SET response should contain a failure message
  - Verify that none of the other paths values are changed and there shouldn’t be any values populated for the xyz path

### Set Replace Expectation

The expectation is for the gNMI server to process the valid Set Replace request and populate the leaf nodes with the values specified in the request payload and return the valid response to the client. If the leaf nodes are not present in the payload, then the server should populate them with the default values.

### Test #1: Send a Set Replace request to mutate a single leaf

Condition to test: Set Replace request for a single leaf

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
  - Verify that the value for interfaces/interface/[name=EthernetX]/config/description is replaced and an appropriate response is returned without any errors.

### Test #2: Send a Set Replace request to mutate few leafs in a branch that has other modified values

Condition to test: Set Replace request for multiple leafs
```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {  
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopback4"
             }, 
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      }, 
                      "index" : 0,
                      "openconfig-if-ip:ipv4" : {  
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  },
                                  "ip" : "<IP_ADDR>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  },
                                  "ip" : "<IP_ADDR>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
 }

```

Validation: 
  - Verify that the Leaf should be created and appropriate response received. In this case the loopback interfaces should be created in the configuration and all the unset values for this interface should be set to default values ( example: mtu )

### Test #3: Send a Set Replace request with 2 valid updates

Condition to test: send a Set Replace request with 2 valid update payloads

```
path: { origin: "openconfig" elem: { name:"interfaces" } }
Payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {   
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "LoopbackX"
             },  
             "name" : "LoopbackX",
             "subinterfaces" : {
                "subinterface" : [
                   {   
                      "config" : {
                         "index" : 0
                      },  
                      "index" : 0, 
                      "openconfig-if-ip:ipv4" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  }, 
                                  "ip" : "<IP_ADDR>"
                               }, 
                               {  
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 32
                                  }, 
                                  "ip" : "<IP_ADDR>"
                               }  
                            ]     
                         }     
                      }     
                   }     
                ]     
             }     
          }     
       ]     
    },    
    "openconfig-interfaces:interfaces" : {
       "interface" : [ 
          {   
             "config" : { 
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "LoopbackX"
             },
             "name" : "Loopback4",
             "subinterfaces" : {
                "subinterface" : [
                   {
                      "config" : {
                         "index" : 0
                      },
                      "index" : 0,
                      "openconfig-if-ip:ipv6" : {
                         "addresses" : {
                            "address" : [
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADDR>"
                               },
                               {
                                  "config" : {
                                     "ip" : "<IP_ADDR>",
                                     "prefix-length" : 64
                                  },
                                  "ip" : "<IP_ADDR>"
                               }
                            ]
                         }
                      }
                   }
                ]
             }
          }
       ]
    }
}
```
Validation: 
  - Verify that the Leaf should be created and appropriate response received. In this case the loopback interfaces should be along with both IPV4 and IPV6 addresses.

### Test #4: Negative test case - Send a Set Replace request with 1 valid and 1 invalid operation

Condition to test: Set Replace request with 1 valid and 1 invalid operation 
```
path: { origin: "openconfig" elem: { name:"interfaces" } }
payload:
{   
    "openconfig-interfaces:interfaces" : {
       "interface" : [
          {  
             "config" : {
                "description" : "Loopback interface",
                "enabled" : true,
                "name" : "Loopbackx"
             }, 
             "name" : "Loopbackx",
             "mtu"  : "mtu"
             }
          }
       ]
    }
 }
```

Validation: 
  - The SET request should be rejected and SET response should contain a failure message, also verifies none of the other paths values are changed.

### Test #5: Negative test case - Interface description for the platform subtree 
Condition to test: Send interface description for the platform subtree 
```
path: { origin: "openconfig" elem: { name:"platform" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```
Validation: 
  - SET response should contain a failure message
  - Verify that none of the other paths values are changed for the platform subtree

### Test #6: Negative test case - Send invalid path
 Condition to test: Send invalid path
```
path: { origin: "openconfig" elem: { name:"xyz" } }

Payload: {"openconfig-interfaces:description":"Test_config"}
```
Validation: 
  - SET response should contain a failure message
  - Verify that none of the other paths values are changed and there shouldn’t be any values populated for xyz path.

### Set Delete Expectation
The expectation is for the gNMI server to process the valid Set Delete request and remove those nodes from the system. The server should send a valid response to the client once the request has been processed successfully. 

### Test #1: Send a valid Set Delete request for an existing leaf 

Condition to test: Send a Set Delete request for an existing interface

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }
```

Validation: 
  - Verify that the interfaces/interface/[name=EthernetX] is properly removed from the config and a valid response is returned to the client.

### Test #2: Send a Set Delete request for a non-existing leaf

Condition to test: Send a Set Delete request for an invalid interface

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetY" } }
```

Validation: 
   - Verify that the Set delete request fails with an appropriate error message.

### Test #3: Send a Set Delete request with 2 valid delete messages

Condition to test: Send a Set Delete request with 2 delete messages

```
request:
	SetRequest{
		Prefix: prefix,
		Delete: []*gpb.Path{</interfaces/interface[name=EthernetX]/config/mtu>, </interfaces/interface[name=EthernetX]/config/description>}
  }
```

Validation: 
  - Verify that the given leafs should be deleted and appropriate response received.

### Set Mixed type operations Expectation
A valid request containing a Set Delete, Set Replace and a Set Update operation. The server must follow the processing order specified in gNMI specification and handle the request without any errors. The server should send a valid response to the client once the request has been processed successfully.

### Test #1: Send a valid Set request with delete, replace and update for an existing subtree

Condition to test: Send a Set delete for an interface, replace for other interfaces followed by an update request.
```
request:
	SetRequest{
		Prefix: prefix,
		Delete: []*gpb.Path{</interfaces/interface[name=EthernetX]/config/mtu>, </interfaces/interface[name=EthernetX]/config/description>},
		Replace: []*gpb.Update{
			{
				Path: </interfaces/interface[name=EthernetX]/config/mtu>,
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(<100>),
					},
				},
			},
			{
				Path: </interfaces/interface[name=EthernetX]/config/id>,
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_JsonIetfVal{
						JsonIetfVal: []byte(<1>),
					},
				},
			},
		},
		Update: []*gpb.Update{
      {
			  Path: </interfaces/interface[name=EthernetX]/config/id>,
			  Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(<2>)}},
		  }
    }
  }
```

Validation: 
  - Verify that the specified interface has been deleted (not present in the response) and other specified interfaces have been replaced (present in the response) with the updated leaf values.

### Test #2: Send a valid delete and update request for an existing subtree 

Condition to test: Send a delete for an interface followed by an update request
```
request:
	SetRequest{
		Prefix: prefix,
		Delete: []*gpb.Path{</interfaces/interface[name=EthernetX]/config/mtu>, </interfaces/interface[name=EthernetX]/config/description>},
		Update: []*gpb.Update{
      {
			  Path: </interfaces/interface[name=EthernetX]/config/mtu>,
			  Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(<100>)}},
		  }
    }
  }

```
Validation: 
  - Verify that the specified interface has been deleted (not present in the response) and other specified interfaces attributes have been updated.

### Test #3: Send a valid delete and invalid update request for an existing subtree

Condition to test: Send a delete for an interface followed by an update request
```
request:
	SetRequest{
		Prefix: prefix,
		Delete: []*gpb.Path{</interfaces/interface[name=EthernetX]/config/mtu>, </interfaces/interface[name=EthernetX]/config/description>},
		Update: []*gpb.Update{
      {
			  Path: </interfaces/interface[name=EthernetX]/config/mtu>,
			  Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: []byte(<-100>)}},
		  }
    }
  }
```

Validation: 
  - Verify the SET response contains an error message related to the invalid update message in the SET request.

### Test #4: Send a valid replace request at the root level

Condition to test: Send a replace request at the root level

```
path: { origin: "openconfig" elem: { name:"/" } }
```

Validation: 
  - Verify that the specified payload has been replaced across all subtrees.

### Test #5: Send a valid set request without any path 

Condition to test: Send a valid request with empty path list

```
path: { origin: "openconfig" elem: { name:"{}" } }
payload:
```

Validation: 
  - Verify that there are no errors returned by the server and it has been processed by the server and a valid response has been sent to the client, also verifies that none of the paths are changed.

### Test #6: Send a valid set request from two clients 

Condition to test: Create two gNMI clients with two different connection IDs. Send the Set Request from both clients

```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }  elem: { name:"config" } elem: { name:"description" } }

Payload: {"openconfig-interfaces:description":"Test_config"}

```

Validation: 
   - Verify that gNMI Set RPC responds without error and all the fields in the response matches the expectation.
   - Verify that interfaces/interface/[name=EthernetX]/config/description matches the payload value ("Test_config").
   - Verify that the second client set request has been rejected by the gNMI server due to [master arbitration](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-master-arbitration.md) feature

### GET operation

#### Expectation
The GET response should contain the value of the requested nodes. The expectation for the gNMI server is to process the valid Get request and send a valid response containing the values of the requested nodes. Only PROTO and JSON encodings are currently supported.

#### Challenges
For end-to-end tests, we cannot be sure of what config nodes are set in the system beforehand and hence cannot determine what paths to validate against. The GET request can be issued after a SET request and validate the values that have been used in the SET request.

### Test cases
This test can extend an existing config push and subsequent GET request path test to validate the following test cases.

### Test #1: Get at the subtree level
Condition to test: 
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetX" } }
} 
```

Validation: 
  - Verify that the values under interfaces/interface/[name=EthernetX]/* are returned.

### Test #2: Get at the module level
Condition to test:
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"}
}
```

Validation: 
  - Verify that the interfaces/interface/[name=<*>]/* are returned.

### Test #3: Get at the root level
Condition to test:
```
path:{
 origin: "openconfig" elem: { name:"/" }
 }
```

Validation: 
  - Verify that the interfaces/interface/[name=<*>]/* are returned.

### Test #4: Valid encoding
Condition to test: Issue a GET request with proto encoding 
```
path: { origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"} } encoding: PROTO
```

Verify that the interfaces/interface/[name=<*>]/* are returned with PROTO format.

### Test #5: Invalid data
Verify that appropriate error message returned when requesting an GET request for an invalid path
Condition to test: Config type with state/operational subtree
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface" key: { key: "name" value: "EthernetY" }
}
```
Validation: Test should return response with an error.

### Test #6: Invalid path
Verify that appropriate error message returned when requesting an GET request for an invalid path
Condition to test: Config type with state/operational subtree
```
path: { origin: "openconfig" elem: { name:"xye" } }
```
Validation: Test should return response with an error.

### Test #7: Invalid encoding
Condition to test: Issue a GET request with ASCII encoding 
```
path: {
origin: "openconfig" elem: { name:"interfaces" } elem: { name:"interface"} }
encoding: ASCII
```

Validation: Verify that the response returned with an error.

# **End-to-end Test Summary**

<table>
  <tr>
   <td style="background-color: #b7b7b7"><p style="text-align: right">
<strong>TEST </strong></p>

   </td>
   <td style="background-color: #b7b7b7"><strong>TOTAL</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>PASS</strong>
   </td>
   <td style="background-color: #b7b7b7"><strong>FAIL</strong>
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
SET UPDATE Tests</p>

   </td>
   <td style="background-color: #b6d7a8">5
   </td>
   <td style="background-color: #b6d7a8">-
   </td>
   <td style="background-color: #ea9999">-
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
SET REPLACE Tests</p>

   </td>
   <td style="background-color: #ea9999">6
   </td>
   <td style="background-color: #ea9999">-
   </td>
   <td style="background-color: #ea9999">-
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
SET DELETE Tests</p>

   </td>
   <td style="background-color: #ea9999">3
   </td>
   <td style="background-color: #ea9999">-
   </td>
   <td style="background-color: #b6d7a8">-
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
SET Misc Tests</p>

   </td>
   <td style="background-color: #b6d7a8">6
   </td>
   <td style="background-color: #b6d7a8">-
   </td>
   <td style="background-color: #b6d7a8">-
   </td>
  </tr>
  <tr>
   <td style="background-color: #d9d9d9"><p style="text-align: right">
GET Tests</p>

   </td>
   <td style="background-color: #ea9999">7
   </td>
   <td style="background-color: #ea9999">-
   </td>
   <td style="background-color: #ea9999">
   </td>
  </tr>
</table>

# **References**

[gNMI Get specification](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#331-the-getrequest-message)
[gNMI Set specification](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#341-the-setrequest-message)
[gNMI GET proto](https://github.com/openconfig/gnmi/blob/master/proto/gnmi/gnmi.proto#L395)
[gNMI SET proto](https://github.com/openconfig/gnmi/blob/8eae1937bf841842e2e0864c34562c8352d56bb2/proto/gnmi/gnmi.proto#L339)
