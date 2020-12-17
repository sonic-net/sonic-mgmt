# Testbed V2 Design
# High Level Design Document


# Table of Contents
  * [About this Manual](#about-this-manual)
  * [Requirement Overview](#Requirement-Overview)
  * [Components](#Components)
  * [Database Schema](#Database-Schema)
  * [Implementation Plan](#Implementation-Plan)


## About this Manual
This documentation provides general information about the Testbed V2 feature implementation for `sonic-mgmt`. Testbed V2 aims to support multi-DUTs deployment with dynamic VLAN assignment and inter-DUTs link state propagation.

## Requirement Overview
* Maintain compatibility with existing testbed.
* Support testbed/topology with multiple DUTs that have inter-DUTs connections.
* Support flexible VLAN assignment.

## Components
* `test user`
* `connection_db`
  * Redis databases running on certain test server hosting connection-related metadata.
* `servercfgd`
  * running on the same server as `connection_db`
  * a RPC server that is responsible for `connection_db` initial setup and provision.
* `labcfgd`
  * running on root/fanout switches
  * subscribe to keyspace events of `connection_db` and act accordingly.

## Database Schema
* `DB_CONNECTION_GRAPH_VERSIONS`
```
; ZSET that stores md5sum values of connection graph files that are used to provision `connection_db`
key                              = LAB_CONNECTION_GRAPH_VERSIONS
```
* `DB_META`
```
; Defines database metadata
key                              = DB_META
; field                          = value
ServerState                      = "active"/"provisioning"/"down"
```
* `SWITCH_TABLE`
```
; Defines switch metadata
key                              = SWITCH_TABLE:switch_name
; field                          = value
HwSku                            =                                                  ; switch platform hwsku
ManagementIp                     =
Type                             = "leaf_fanout"/"root_fanout"/"dev_sonic"
ProvisionStatus                  = "not_provisioned"/"in_progress"/"provisioned"    ; provision status for "dev_sonic"
```
* `DUT_LIST`
```
; List contains all the SONiC DUTs defined in the lab
key                              = DUT_LIST                                         ; contains DUT names that are FK to `SWITCH_TABLE`
```
* `SERVER_TABLE`
```
; Defines server metadata
key                              = SERVER_TABLE:server_name
; field                          = value
HwSku                            = "TestServ"
ManagementIp                     =
ServerStatus                     = "active"/"down"
```
* `PORT_LIST`
```
; List contains physical ports of either a root/leaf fanout switch, DUT or server 
key                              = PORT_LIST:<switch_name|dut_name|server_name>
```
* `PORT_TABLE`
```
; Defines port metadata
key                              = PORT_TABLE:<switch_name|dut_name|server_name>:port_name
; field                          = value
BandWidth                        =
VlanType                         = "access"/"trunk"
PhyPeerPort                      =                                                  ; physical peer port
```
* `VLAN_LIST`
```
; List contains VLAN ids assigned to a physical port
key                              = VLAN_LIST:endport                                ; endport is FK to `PORT_TABLE`
```
* `USED_VLANIDPOOL_SET`
```
; Set contains used available VLAN ids
key                              = VLANIDPOOL_SET
```
* `VIRTLINK_TABLE`
```
; a virtual link between DUTs
key                              = VIRTLINK_TABLE:endport0:endport1                  ; endport0 and endport1 are FK to `PORT_TABLE
; field                          = value
Status                           = "active"/"inactive"
```

## Implementation Plan
* The whole process is divided into three stages:
   1. stage#1: initial `connection_db` setup and provision
   2. stage#2: dynamic vlan assignment support
   3. stage#3: link state propagation support

### Stage#1
* In stage#1, only initial `connection_db` setup and provision is covered.
* In the db provision during `add_topo`, the md5sum value of the connection graph file of current inventory will be calculated and check if it is in `LAB_CONNECTION_GRAPH_VERSIONS`.
  * If yes, `add_topo` will skip provision the database because it indicates that current connection graph file had been used to provision the database.
  * If no, `add_topo` will try to provision the database with the connection graph and add the md5sum value to `LAB_CONNECTION_GRAPH_VERSIONS` with current timestamp as score. Also, it will also trim `LAB_CONNECTION_GRAPH_VERSION` to only keep most-recent 20 entries.
#### Ansible variables added:  

| `variable name` | `behavior` |
| - | - |
| `enable_connection_db` | `True` to enable `connection_db` setup and provision in `add_topo`. |
| `connection_db_host_mapping` | mapping from connection graph filename to server name that will be used to host `connection_db`. |
| `enforce_provision_servercfgd` | enforce install `servercfgd` even there is one running. |
|`provision_connection_db`| `True` to try to provision `connection_db` with the connection graph file. |
| `enforce_provision_connection_db` | <br>enforce provision `connection_db` with current connection graph file.</br><br>**NOTE**: this will skip the version check and provision the `connection_db`.</br> |
| `disable_connection_db` | `True` to disable `connection_db` and stops `servercfgd` in `remove_topo`. |

#### changes to `conn_graph_files`
There will be an extra parameter added to `conn_graph_facts`: `conn_graph_facts_src`, it could be either `from_db`, which will retrieve the connection data from `connection_db`, or it could be `from_file` to get the data from parsing connection graph file like before. One thing to notice is that if `conn_graph_facts` fails with `conn_graph_facts_src=from_db`, it will fall back to `from_file`.
