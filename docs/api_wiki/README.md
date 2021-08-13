# SONiC Management API Wiki

- [Ansible Modules](#ansible-modules)
- [Sonichost Methods](#sonichost-methods)
- [Multi ASIC Methods](#multi-asic-methods)
- [SONIC ASIC Methods](#sonic-asic-methods)
- [Ptfhost Methods](#ptfhost-methods)
- [Pre-configured Function Arguments](#pre-configured-function-arguments)

There are many ways to communicate and interact with the PTF container and the DUT from the localhost. This wiki serves as a place to document these API calls. Below is a list of _some_ of the many API calls.

localhost, ptfhost and sonichost objects can use the ansible modules. Many may not provide meaningful output if ptfhost is used (like `reduce_and_add_sonic_images`).

```
# These arguments are examples of the pre-configured function arguments

def test_fun(duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    # example dut api call
    duthost.get_extended_minigraph_facts()
    
    # example ptf api call
    ptfhost.shell("ls")
```

## Ansible Modules

- [acl_facts](ansible_methods/acl_facts.md) - Retrieves ACL information from remote host.

- [announce_routes](ansible_methods/announce_routes.md) - Announces Routes to the exabgp processes running in the PTF container

- [bgp_facts](ansible_methods/bgp_facts.md) - Retreives BGP information using Quagga

- [bgp_route](ansible_methods/bgp_route.md) - Provides BGP routing info from Quagga using VTYSH cli.

- [config_facts](ansible_methods/config_facts.md) - Retreives configuration facts for a device

- [conn_graph_facts](ansible_methods/conn_graph_facts.md) - Retreives info on lab fannout siwtches and vlan connections.

- [console_facts](ansible_methods/console_facts.md) - Retrieves console feature and status information using Quagga.

- [copy](ansible_methods/copy.md) - Used to copy local files to remote host.

- [exabgp](ansible_methods/exabgp.md) - Start or stop exabgp instance with certain configurations

- [extract_log](ansible_methods/extract_log.md) - Unrotate logs and extract information starting from a row with predefined string.

- [feature_facts](ansible_methods/feature_facts.md) - Provides the statuses for all active features on a host.

- [fetch](ansible_methods/fetch.md) - Copies file from remote host to local host.

- [file](ansible_methods/file.md) - Allows for setting attributes of file, symlinks, directories. Can be used to remove files.

- [find](ansible_methods/find.md) - Finds list of files based on specified criteria.

- [get_ip_in_range](ansible_methods/get_ip_in_range.md) - Get certain number of ips within a prefix

- [image_facts](ansible_methods/image_facts.md) - Get information on image from remote host.

- [interface_facts](ansible_methods/interface_facts.md) - Retrieves information on device interfaces.

- [lag_facts](ansible_methods/lag_facts.md) - Retrieve Ling Aggregation Group information from a device.

- [lldpctl_facts](ansible_methods/lldpctl_facts.md) - Gathers LLDP facts from the SONiC device.

- [lldp_facts](ansible_methods/lldp_facts.md) - Retrieve LLDP facts using SNMP

- [minigraph_facts](ansible_methods/minigraph_facts.md) - Retrieve minigraph facts for a device.

- [monit_process](ansible_methods/monit_process.md) - Retrieve process cpu and memory usage

- [ping](ansible_methods/ping.md) - Pings the remote host

- [port_alias](ansible_methods/port_alias.md) - Find port-alias mapping if there is any configured.

- [reduce_and_add_sonic_images](ansible_methods/reduce_and_add_sonic_images.md) - Removes excess sonic images and installs a new image if requested.

- [replace](ansible_methods/replace.md) - Replaces all instances of a pattern within a specified file. When using this method make sure that the pattern being used to match does not match the replacement text, otherwise the results may be undesirable.

- [sensors_facts](ansible_methods/sensors_facts.md) - Retrieves sensor facts for a device.

- [service](ansible_methods/service.md) - Controls services on the dut.

- [setup](ansible_methods/setup.md) - Gather facts about the duthost.

- [shell_cmds](ansible_methods/shell_cmds.md) - Allows you to run mutliple commands on a remote host.

- [show_interface](ansible_methods/show_interface.md) - Retrieves status and counter values from DUT.

- [show_ip_interface](ansible_methods/show_ip_interface.md) - Retrieve ipv4 address of itnerface and ipv4 addres for corresponding neighbor

- [snmp_facts](ansible_methods/snmp_facts.md) - Retreives facts for device using SNMP

- [sonic_pfc_counters](ansible_methods/sonic_pfc_counters.md) - Get or clear PFC counter for a device

- [stat](ansible_methods/stat.md) - Retrieves facts on specified file.

- [switch_arptable](ansible_methods/switch_arptable.md) - Reterives ARTP table from the SONiC switch

- [switch_capabilities_facts](ansible_methods/switch_capabilities_facts.md) - Retreive switch capability information.

- [sysfs_facts](ansible_methods/sysfs_facts.md) - Get sysfs information from switch

- [tempfile](ansible_methods/tempfile.md) - Generates temp file or directory on remote host.


## Sonichost Methods

- [all_critical_process_status](sonichost_methods/all_critical_process_status.md) - Provides summary and status of all critical services and their processes

- [check_bgp_session_nsf](sonichost_methods/check_bgp_session_nsf.md) - Checks if BGP neighbor session has entered Nonstop Forwarding(NSF) state

- [critical_process_status](sonichost_methods/critical_process_status.md) - Gets status of service and provides list of exited and running member processes.

- [critical_services](sonichost_methods/critical_services.md) - Provides a list of critical services running on the SONiC host.

- [critical_services_fully_started](sonichost_methods/critical_services_fully_started.md) - Whether all critical services have started on the SONiC host.

- [critical_services_status](sonichost_methods/critical_services_status.md) - Checks status for cirtical services.

- [facts](sonichost_methods/facts.md) - Returns platform information facts about the sonic device.

- [get_bgp_neighbors](sonichost_methods/get_bgp_neighbors.md) - This command provides a summary of the bgp neighbors peered with the DUT. Returns a dictionary that maps the BGP address for each neighbor to another dictionary listing information on that neighbor device.

- [get_container_autorestart_states](sonichost_methods/get_container_autorestart_states.md) - Get container names and their autorestart states. Containers that do not have the autorestart feature implemented are skipped by this test.

- [get_critical_group_and_process_lists](sonichost_methods/get_critical_group_and_process_lists.md) - Provides lists of cirtical groups and processes

- [get_crm_facts](sonichost_methods/get_crm_facts.md) - Parses `crm show` commands to gather facts on CRM.

- [get_crm_resources](sonichost_methods/get_crm_resources.md) - Gets information on CRM resources from host

- [get_dut_iface_mac](sonichost_methods/get_dut_iface_mac.md) - Gets the AMC address for specified interface

- [get_extended_minigraph_facts](sonichost_methods/get_extended_minigraph_facts.md) - Gets detailed facts on configured minigraph.

- [get_feature_status](sonichost_methods/get_feature_status.md) - Returns features and their states.

- [get_monit_services_status](sonichost_methods/get_monit_services_status.md) - Get metadata on services monitored by Monit.

- [get_namespace_ids](sonichost_methods/get_namespace_ids.md) - Gets ids of namespace where the container should reside in.

- [get_now_time](sonichost_methods/get_now_time.md) - Gets datetime as defined on the remote host

- [get_pmon_daemon_db_value](sonichost_methods/get_pmon_daemon_db_value.md) - Gets the db value in state db to check the daemon expected status

- [get_running_config_facts](sonichost_methods/get_running_config_facts.md) - Provides information on the currently running configuration of the dut.

- [get_service_props](sonichost_methods/get_service_props.md) - Gets detailed properties of a service

- [get_supported_speeds](sonichost_methods/get_supported_speeds.md) - Gets a list of all supported speeds for a given interface.

- [get_vlan_intfs](sonichost_methods/get_vlan_intfs.md) - Retrieves list of interfaces belonging to a VLAN.

- [hostname](sonichost_methods/hostname.md) - Provides hostname for device.

- [is_container_running](sonichost_methods/is_container_running.md) - Checks whether a docker container is running.

- [is_frontend_node](sonichost_methods/is_frontend_node.md) - Checks whether the DUT is a frontend node. Used in multi-DUT setups.

- [is_multi_asic](sonichost_methods/is_multi_asic.md) - Returns whether remote host is multi-ASIC

- [is_service_fully_started](sonichost_methods/is_service_fully_started.md) - Checks whether a service is fully started on the SONiC host.

- [is_service_running](sonichost_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [is_supervisor_node](sonichost_methods/is_supervisor_node.md) - Checks if current node is a supervisor node. Used for multi-DUT setups.

- [kernel_version](sonichost_methods/kernel_version.md) - Provides version of Sonic kernel on remote host

- [mgmt_ip](sonichost_methods/mgmt_ip.md) - Provides management ip for host.

- [num_asics](sonichost_methods/num_asics.md) - Provides number of asics

- [os_version](sonichost_methods/os_version.md) - Provides string representing the version of SONiC being used

- [reset_critical_services_tracking_list](sonichost_methods/reset_critical_services_tracking_list.md) - Modifies the list of critical services used by the SONiC Host.

- [show_and_parse](sonichost_methods/show_and_parse.md) - Runs a show command on the host and parses the input into a computer readable format, usually a list of entries. Works on any show command that has suimilar structure to `show interface status`

- [shutdown](sonichost_methods/shutdown.md) - Shuts down a specified interface

- [stop_service](sonichost_methods/stop_service.md) - Stops a specified service


## Multi ASIC Methods

- [asics](multi_asic_methods/asics.md) - Get list of ASIC hosts

- [asic_instance](multi_asic_methods/asic_instance.md) - Retrieves the asic instance given an asic id. Device must be multi-ASIC

- [get_asic_id_from_namespace](multi_asic_methods/get_asic_id_from_namespace.md) - Returns numeric ID for ASIC given a namespace. This command only works if the dut is a multi-asic device.

- [get_asic_namespace_list](multi_asic_methods/get_asic_namespace_list.md) - Provides list of namspaces corresponding to ASICs on the duthost. The dut must be a multi-ASIC device for this method to work.

- [get_asic_or_sonic_host](multi_asic_methods/get_asic_or_sonic_host.md) - Returns ASIC instance provided a corresponding ASIC instance id.

- [get_namespace_from_asic_id](multi_asic_methods/get_namespace_from_asic_id.md) - Gets the namespace provided an ASIC ID. This only works on multi-ASIC devices.

- [get_port_asic_instance](multi_asic_methods/get_port_asic_instance.md) - Returns the numeric ASIC instance that a provided port belongs to. Will fail test if ASIC instance is not found for provided port.

- [get_route](multi_asic_methods/get_route.md) - Retreives BGP routes on a provided an ip prefix that the route must match.

- [get_sonic_host_and_frontend_asic_instance](multi_asic_methods/get_sonic_host_and_frontend_asic_instance.md) - Returns sonic host and all frontend asic instances. Only works on multi-asic devices

- [get_vtysh_cmd_for_namespace](multi_asic_methods/get_vtysh_cmd_for_namespace.md) - Provides modified VTYSH command provided ASIC namespace and command.

- [has_config_subcommand](multi_asic_methods/has_config_subcommand.md) - Check if a config or show subcommand exists on the remote host. *WARNING*: to test whether it exists, the method will run the command. Ensure that there will be no negative sid-effects of having this command run on 
the remote host.

- [is_service_running](multi_asic_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [stop_service](multi_asic_methods/stop_service.md) - Stops a specified service


## Sonic ASIC Methods

- [get_active_ip_interfaces](sonic_asic_methods/get_active_ip_interfaces.md) - Provides a information on active IP interfaces. Works on ASIC devices.

- [get_extended_minigraph_facts](sonic_asic_methods/get_extended_minigraph_facts.md) - Gets detailed facts on configured minigraph.

- [is_service_running](sonic_asic_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [stop_service](sonic_asic_methods/stop_service.md) - Stops a specified service


## Ptfhost Methods

- [hostname](ptfhost_methods/hostname.md) - Provides hostname for device.

- [mgmt_ip](ptfhost_methods/mgmt_ip.md) - Provides management ip for host.


## Preconfigured Function Arguments

- [duthosts](preconfigured/duthosts.md) - Provides a dictionary that maps DUT hostnames to DUT instances

- [localhost](preconfigured/localhost.md) - The localhost instance. Used to run ansible modules from the localhost.

- [ptfhost](preconfigured/ptfhost.md) - The PTF container host instance. Used to run ptf methods and anisble modules from the PTF.

- [rand_one_dut_hostname](preconfigured/rand_one_dut_hostname.md) - A random hostname belonging to one of the DUT instances defined by the deployed testbed.