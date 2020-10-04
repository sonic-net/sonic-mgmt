# Requirements for designing a customized ansible module to support multi-ASIC

PR https://github.com/Azure/SONiC/pull/644 introduced the HLD to support multi ASIC. In the future, multi DUT or Chassis will be supported by SONiC as well. Some of the customized ansible modules need to be updated to support testing of the upcoming new architectures. This document tries to propose some requirements for designing customized ansible modules that need to deal with multi-ASIC. The idea is to have a clean and easy to use interface for calling these ansible modules in scripts testing multi DUT and multi ASIC system. Meanwhile, the ansible modules need to maintain backward compatibility for single DUT and single ASIC testing.

## Requirements

* The module must take optional argument for specifying ASIC index.
* The module must not take argument for specifying the number of ASICs the host has. Instead the module must figure out by itself whether the current host supports multi ASIC and how many ASICs it has.
* When ASIC index is supplied, return a single result. Do not return a list of results.
* When ASIC index is not supplied, the module should find out whether multiple ASICs is supported by the current host.
  * If the host supports multiple ASICs, then the module should find out the number of ASICs, do its job for each of the ASICs and return the results in a list. Each item in the list is the result of one ASIC.
  * If the host does not support multiple ASICs, return a single result. Do not return a list of results. This is for backward compatibility.

## Possible interfaces for calling the modules

This section tries to add some dummy examples for how to call the multi ASCI aware ansible modules in test scripts. Assume:
* module `foo` is a multi ASIC aware customized ansible module
* fixture `duthost` is an instance representing single host with single ASIC
* fixture `duthost_multi_asic` is an instance representing single host with multi ASIC
* fixture `duthosts` is an instance representing a testbed with multi DUTs or a Chassis. The `duthosts` have attributes like:
  * `duthosts.nodes`: A list of all the hosts in the testbed.
  * `duthosts.frontend_nodes`: A list of all the frontend hosts in the testbed.

### Call the module for single host supports single ASIC

```
duthost.foo()  # No behavior change, for backward compatibility
```

### Call the module for single host supports multi ASICs

```
duthost_multi_asic.foo()  # Run `foo` for each of the asic. return results in a list

duthost_multi_asic.foo(asic_index=0)  # Run `foo` for asic_index=0, and return a single result.

duthost_multi_asic.foo(asic_index=1)  # Run `foo` for asic_index=0, and return a single result.
```

### Call the module for multiple hosts support single ASIC

```
# Run `foo` for each of the frontend node. Return results in a dict: {'node1': foo_result, 'node2': foo_result}
{node.hostname: node.foo() for node in duthosts.frontend_nodes}
```

### Call the module for multiple hosts support multiple ASICs

```
# Run `foo` for each of the frontend node and each of the ASIC. Return results in a dict like:
#     {'node1': [asic0_foo_result, asic1_foo_result], 'node2': [asic0_foo_result, asic1_foo_result]}
{node.hostname: node.foo() for node in duthosts.frontend_nodes}

# Run `foo` for asic_index=0 for each of the frontend node. Return results in a dict like:
#     {'node1': asic0_foo_result, 'node2': asic0_foo_result}
{node.hostname: node.foo(asic_index=0) for node in duthosts.frontend_nodes}

```

## How to detect a multi ASIC system

According to https://github.com/Azure/SONiC/pull/644, multi ASIC system should have file `/usr/share/sonic/device/<platform>/asic.conf`:

Sample asic.conf:
```
NUM_ASIC=3
DEV_ID_ASIC_0=03:00.0
DEV_ID_ASIC_1=06:00.0
DEV_ID_ASIC_2=11:00.0
```
Ansible module can check existence of this file to tell the current host is a multi ASIC system or single ASIC system.

Content like `NUM_ASIC=3` in `asic.conf` indicates the number of ASICs the current system has.

The ansible module also can take advantage of the `sonic_py_common` package on the SONiC image. This package has modules like `device_info` and `multi_asic` that can be handy.

```
admin@sonic-host1:~$ python
Python 2.7.16 (default, Oct 10 2019, 22:02:15)
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from sonic_py_common import device_info, multi_asic
>>> dir(device_info)
['ASIC_CONF_FILENAME', 'BACKEND_ASIC_SUB_ROLE', 'CONTAINER_PLATFORM_PATH', 'ConfigDBConnector', 'FRONTEND_ASIC_SUB_ROLE', 'HOST_DEVICE_PATH', 'MACHINE_CONF_PATH', 'NAMESPACE_PATH_GLOB', 'NPU_NAME_PREFIX', 'PLATFORM_JSON_FILE', 'PORT_CONFIG_FILE', 'SONIC_VERSION_YAML_PATH', 'SonicDBConfig', 'USR_SHARE_SONIC_PATH', '__builtins__', '__doc__', '__file__', '__name__', '__package__', '_valid_mac_address', 'get_all_namespaces', 'get_asic_conf_file_path', 'get_hwsku', 'get_machine_info', 'get_namespaces', 'get_npu_id_from_name', 'get_num_npus', 'get_path_to_port_config_file', 'get_paths_to_platform_and_hwsku_dirs', 'get_platform', 'get_platform_and_hwsku', 'get_sonic_version_info', 'get_system_mac', 'get_system_routing_stack', 'glob', 'is_multi_npu', 'natsorted', 'os', 're', 'subprocess', 'yaml']
>>> device_info.get_num_npus()
1
>>> device_info.is_multi_npu()
False
>>> dir(multi_asic)
['ASIC_CONF_FILENAME', 'ASIC_NAME_PREFIX', 'BACKEND_ASIC_SUB_ROLE', 'BGP_NEIGH_CFG_DB_TABLE', 'CONTAINER_PLATFORM_PATH', 'ConfigDBConnector', 'DEFAULT_NAMESPACE', 'EXTERNAL_PORT', 'FRONTEND_ASIC_SUB_ROLE', 'HOST_DEVICE_PATH', 'INTERNAL_PORT', 'NAMESPACE_PATH_GLOB', 'NEIGH_DEVICE_METADATA_CFG_DB_TABLE', 'PORT_CFG_DB_TABLE', 'PORT_CHANNEL_CFG_DB_TABLE', 'PORT_ROLE', 'SonicDBConfig', 'SonicV2Connector', '__builtins__', '__doc__', '__file__', '__name__', '__package__', 'connect_config_db_for_ns', 'connect_to_all_dbs_for_ns', 'get_all_namespaces', 'get_asic_conf_file_path', 'get_asic_id_from_name', 'get_external_ports', 'get_namespace_for_port', 'get_namespace_list', 'get_namespaces_from_linux', 'get_num_asics', 'get_platform', 'get_port_role', 'get_port_table', 'get_port_table_for_asic', 'glob', 'is_bgp_session_internal', 'is_multi_asic', 'is_port_channel_internal', 'is_port_internal', 'natsorted', 'os']
>>> multi_asic.is_multi_asic()
False
>>> multi_asic.get_num_asics()
1
```
