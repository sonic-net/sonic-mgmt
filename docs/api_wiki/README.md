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

- [command](ansible_methods/command.md) - Used to run commands via shell on remote host.

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

- [shell](ansible_methods/shell.md) - Runs commands on the remote host.

- [shell_cmds](ansible_methods/shell_cmds.md) - Allows you to run mutliple commands on a remote host.

- [show_interface](ansible_methods/show_interface.md) - Retrieves status and counter values from DUT.

- [show_ip_interface](ansible_methods/show_ip_interface.md) - Retrieve ipv4 address of interface and ipv4 address for corresponding neighbor

- [snmp_facts](ansible_methods/snmp_facts.md) - Retreives facts for device using SNMP

- [sonic_pfc_counters](ansible_methods/sonic_pfc_counters.md) - Get or clear PFC counter for a device

- [stat](ansible_methods/stat.md) - Retrieves facts on specified file.

- [switch_arptable](ansible_methods/switch_arptable.md) - Reterives ARP table from the SONiC switch

- [switch_capabilities_facts](ansible_methods/switch_capabilities_facts.md) - Retreive switch capability information.

- [sysfs_facts](ansible_methods/sysfs_facts.md) - Get sysfs information from switch

- [tempfile](ansible_methods/tempfile.md) - Generates temp file or directory on remote host.


## Sonichost Methods

- [active_ip_interfaces](sonichost_methods/active_ip_interfaces.md) - Provides information on all active IP (Ethernet or Portchannel) interfaces given a list of interface names.

- [all_critical_process_status](sonichost_methods/all_critical_process_status.md) - Provides summary and status of all critical services and their processes

- [check_bgp_session_nsf](sonichost_methods/check_bgp_session_nsf.md) - Checks if BGP neighbor session has entered Nonstop Forwarding(NSF) state

- [check_bgp_session_state](sonichost_methods/check_bgp_session_state.md) - Check whether the state of the bgp session matches a specified state for a list of bgp neighbors.

- [check_default_route](sonichost_methods/check_default_route.md) - Provides the status of the default route

- [critical_process_status](sonichost_methods/critical_process_status.md) - Gets status of service and provides list of exited and running member processes.

- [critical_services](sonichost_methods/critical_services.md) - Provides a list of critical services running on the SONiC host.

- [critical_services_fully_started](sonichost_methods/critical_services_fully_started.md) - Whether all critical services have started on the SONiC host.

- [critical_services_status](sonichost_methods/critical_services_status.md) - Checks status for cirtical services.

- [delete_container](sonichost_methods/delete_container.md) - Removes a docker container from the DUT.

- [facts](sonichost_methods/facts.md) - Returns platform information facts about the sonic device.

- [get_asic_name](sonichost_methods/get_asic_name.md) - Returns name of current ASIC. For use in multi-ASIC environments.

- [get_auto_negotiation_mode](sonichost_methods/get_auto_negotiation_mode.md) - Gets the auto negotiation status for a provided interface

- [get_bgp_neighbors](sonichost_methods/get_bgp_neighbors.md) - This command provides a summary of the bgp neighbors peered with the DUT. Returns a dictionary that maps the BGP address for each neighbor to another dictionary listing information on that neighbor device.

- [get_bgp_neighbor_info](sonichost_methods/get_bgp_neighbor_info.md) - Provides BGP neighbor info

- [get_container_autorestart_states](sonichost_methods/get_container_autorestart_states.md) - Get container names and their autorestart states. Containers that do not have the autorestart feature implemented are skipped by this test.

- [get_critical_group_and_process_lists](sonichost_methods/get_critical_group_and_process_lists.md) - Provides lists of cirtical groups and processes

- [get_crm_facts](sonichost_methods/get_crm_facts.md) - Parses `crm show` commands to gather facts on CRM.

- [get_crm_resources](sonichost_methods/get_crm_resources.md) - Gets information on CRM resources from host

- [get_dut_iface_mac](sonichost_methods/get_dut_iface_mac.md) - Gets the AMC address for specified interface

- [get_extended_minigraph_facts](sonichost_methods/get_extended_minigraph_facts.md) - Gets detailed facts on configured minigraph.

- [get_facts](sonichost_methods/get_facts.md) - Returns `facts` property. See [facts](facts).

- [get_feature_status](sonichost_methods/get_feature_status.md) - Returns features and their states.

- [get_image_info](sonichost_methods/get_image_info.md) - Get list of images installed on the DUT.

- [get_ip_route_info](sonichost_methods/get_ip_route_info.md) - Returns route information for a destionation. The destination could an ip address or ip prefix.

- [get_monit_services_status](sonichost_methods/get_monit_services_status.md) - Get metadata on services monitored by Monit.

- [get_namespace_ids](sonichost_methods/get_namespace_ids.md) - Gets ids of namespace where the container should reside in.

- [get_networking_uptime](sonichost_methods/get_networking_uptime.md) - Returns time since `networking` service started on the host.

- [get_now_time](sonichost_methods/get_now_time.md) - Gets current datetime as defined on the remote host

- [get_pmon_daemon_db_value](sonichost_methods/get_pmon_daemon_db_value.md) - Gets the db value in state db to check the daemon expected status

- [get_pmon_daemon_states](sonichost_methods/get_pmon_daemon_states.md) - Get states of daemons from the pmon docker.

- [get_pmon_daemon_status](sonichost_methods/get_pmon_daemon_status.md) - Get daemon status in pmon docker using `supervisorctl status` command.

- [get_rsyslog_ipv4](sonichost_methods/get_rsyslog_ipv4.md) - Returns the rsyslog ipv4 address.

- [get_running_config_facts](sonichost_methods/get_running_config_facts.md) - Provides information on the currently running configuration of the dut.

- [get_service_props](sonichost_methods/get_service_props.md) - Gets detailed properties of a service

- [get_speed](sonichost_methods/get_speed.md) - Gets configured speed for a given interface.

- [get_supported_speeds](sonichost_methods/get_supported_speeds.md) - Gets a list of all supported speeds for a given interface.

- [get_swss_docker_names](sonichost_methods/get_swss_docker_names.md) - Gets list of swss docker names.

- [get_syncd_docker_names](sonichost_methods/get_syncd_docker_names.md) - Gets list of syncd docker names.

- [get_uptime](sonichost_methods/get_uptime.md) - Returns the amount of time since device was started

- [get_up_ip_ports](sonichost_methods/get_up_ip_ports.md) - Gets list of all `up` interfaces

- [get_up_time](sonichost_methods/get_up_time.md) - Returns `datetime` object representing date/time that device was started.

- [get_vlan_intfs](sonichost_methods/get_vlan_intfs.md) - Retrieves list of interfaces belonging to a VLAN.

- [hostname](sonichost_methods/hostname.md) - Provides hostname for device.

- [is_backend_portchannel](sonichost_methods/is_backend_portchannel.md) - Returns whether or not a provided portchannel is a backend portchannel.

- [is_bgp_state_idle](sonichost_methods/is_bgp_state_idle.md) - Checks if all BGP peers are in IDLE state.

- [is_container_running](sonichost_methods/is_container_running.md) - Checks whether a docker container is running.

- [is_frontend_node](sonichost_methods/is_frontend_node.md) - Checks whether the DUT is a frontend node. Used in multi-DUT setups.

- [is_multi_asic](sonichost_methods/is_multi_asic.md) - Returns whether remote host is multi-ASIC

- [is_service_fully_started](sonichost_methods/is_service_fully_started.md) - Checks whether a service is fully started on the SONiC host.

- [is_service_running](sonichost_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [is_supervisor_node](sonichost_methods/is_supervisor_node.md) - Checks if current node is a supervisor node. Used for multi-DUT setups.

- [kernel_version](sonichost_methods/kernel_version.md) - Provides version of Sonic kernel on remote host

- [kill_pmon_daemon_pid_w_sig](sonichost_methods/kill_pmon_daemon_pid_w_sig.md) - Stops daemon in pmon docker using kill with a sig.

- [mgmt_ip](sonichost_methods/mgmt_ip.md) - Provides management ip for host.

- [no_shutdown](sonichost_methods/no_shutdown.md) - Starts up a specied interface.

- [no_shutdown_multiple](sonichost_methods/no_shutdown_multiple.md) - Startup multiple interfaces.

- [num_asics](sonichost_methods/num_asics.md) - Provides number of asics

- [os_version](sonichost_methods/os_version.md) - Provides string representing the version of SONiC being used

- [ping_v4](sonichost_methods/ping_v4.md) - Pings ipv4 address and provides result.

- [remove_ssh_tunnel_sai_rpc](sonichost_methods/remove_ssh_tunnel_sai_rpc.md) - Removes any ssh tunnels if present created for syncd RPC communication

- [reset_critical_services_tracking_list](sonichost_methods/reset_critical_services_tracking_list.md) - Modifies the list of critical services used by the SONiC Host.

- [reset_service](sonichost_methods/reset_service.md) - Resets a service on a specified docker.

- [restart_service](sonichost_methods/restart_service.md) - Restarts a service on a specified docker.

- [run_redis_cli_cmd](sonichost_methods/run_redis_cli_cmd.md) - Run redis command through the redis cli.

- [set_auto_negotiation_mode](sonichost_methods/set_auto_negotiation_mode.md) - Sets the auto negotiation mode for a provided interface

- [set_speed](sonichost_methods/set_speed.md) - Sets speed for desired interface.

- [show_and_parse](sonichost_methods/show_and_parse.md) - Runs a show command on the host and parses the input into a computer readable format, usually a list of entries. Works on any show command that has suimilar structure to `show interface status`

- [shutdown](sonichost_methods/shutdown.md) - Shuts down a specified interface

- [shutdown_multiple](sonichost_methods/shutdown_multiple.md) - Shuts down multiple specified interfaces.

- [start_pmon_daemon](sonichost_methods/start_pmon_daemon.md) - Start daemon in pmon docker using `supervisorctl start`

- [start_service](sonichost_methods/start_service.md) - Starts service on a specified docker.

- [stop_pmon_daemon](sonichost_methods/stop_pmon_daemon.md) - Stop daemon in pmon docker.

- [stop_pmon_daemon_service](sonichost_methods/stop_pmon_daemon_service.md) - Stops daemon in pmon docker using `supervisorctl stop`

- [stop_service](sonichost_methods/stop_service.md) - Stops a specified service


## Multi ASIC Methods

- [asics](multi_asic_methods/asics.md) - Get list of ASIC hosts

- [asic_instance](multi_asic_methods/asic_instance.md) - Retrieves the asic instance given an asic id. Device must be multi-ASIC

- [asic_instance_from_namespace](multi_asic_methods/asic_instance_from_namespace.md) - Provides ASIC instance given a corresponding namespace.

- [critical_services_tracking_list](multi_asic_methods/critical_services_tracking_list.md) - Gets the list of services running on the DUT.

- [delete_container](multi_asic_methods/delete_container.md) - Deletes container on sonichost if container's associated service is a default service. Otherwise, container is deleted on each ASIC.

- [get_asic_ids](multi_asic_methods/get_asic_ids.md) - Provides all ASIC indexes for the ASICs on the Multi-ASIC device.

- [get_asic_id_from_namespace](multi_asic_methods/get_asic_id_from_namespace.md) - Returns numeric ID for ASIC given a namespace. This command only works if the dut is a multi-asic device.

- [get_asic_index_for_portchannel](multi_asic_methods/get_asic_index_for_portchannel.md) - Gets asic index associated with provided portchannel.

- [get_asic_namespace_list](multi_asic_methods/get_asic_namespace_list.md) - Provides list of namspaces corresponding to ASICs on the duthost. The dut must be a multi-ASIC device for this method to work.

- [get_asic_or_sonic_host](multi_asic_methods/get_asic_or_sonic_host.md) - Returns ASIC instance provided a corresponding ASIC instance id.

- [get_asic_or_sonic_host_from_namespace](multi_asic_methods/get_asic_or_sonic_host_from_namespace.md) - Returns corresponding sonichost instance if arg `namespace` is not specified, or corresponding ASIC instance if arg `namespace` is specified.

- [get_backend_asic_ids](multi_asic_methods/get_backend_asic_ids.md) - Provides list of ASIC indexes corresponding to ASICs on the Multi-ASIC device.

- [get_backend_asic_namespace_list](multi_asic_methods/get_backend_asic_namespace_list.md) - Provides list of namespaces for each ASIC on the Multi-ASIC device.

- [get_default_critical_services_list](multi_asic_methods/get_default_critical_services_list.md) - Provides the default list of critical services for Multi-ASIC device.

- [get_frontend_asic_ids](multi_asic_methods/get_frontend_asic_ids.md) - Provides a list of ASIC indexes representing the ASICs on the device.

- [get_frontend_asic_namespace_list](multi_asic_methods/get_frontend_asic_namespace_list.md) - Provides list of all namespaces corresponding to ASICs on Multi-ASIC device.

- [get_linux_ip_cmd_for_namespace](multi_asic_methods/get_linux_ip_cmd_for_namespace.md) - Specifies a linux `ip` command for the provided namespace.

- [get_namespace_from_asic_id](multi_asic_methods/get_namespace_from_asic_id.md) - Gets the namespace provided an ASIC ID. This only works on multi-ASIC devices.

- [get_port_asic_instance](multi_asic_methods/get_port_asic_instance.md) - Returns the numeric ASIC instance that a provided port belongs to. Will fail test if ASIC instance is not found for provided port.

- [get_queue_oid](multi_asic_methods/get_queue_oid.md) - Get the queue OID of given port and queue number.

- [get_queue_oid_asic_instance](multi_asic_methods/get_queue_oid_asic_instance.md) - Returns the ASIC instance which has the queue OID saved.

- [get_route](multi_asic_methods/get_route.md) - Retreives BGP routes on a provided an ip prefix that the route must match.

- [get_sonic_host_and_frontend_asic_instance](multi_asic_methods/get_sonic_host_and_frontend_asic_instance.md) - Returns sonic host and all frontend asic instances. Only works on multi-asic devices

- [get_vtysh_cmd_for_namespace](multi_asic_methods/get_vtysh_cmd_for_namespace.md) - Provides modified VTYSH command provided ASIC namespace and command.

- [has_config_subcommand](multi_asic_methods/has_config_subcommand.md) - Check if a config or show subcommand exists on the remote host. *WARNING*: to test whether it exists, the method will run the command. Ensure that there will be no negative sid-effects of having this command run on 
the remote host.

- [is_bgp_state_idle](multi_asic_methods/is_bgp_state_idle.md) - Checks if all BGP peers are in IDLE state on the sonichost.

- [is_container_running](multi_asic_methods/is_container_running.md) - Returns whether or not a container is running on sonichost if the container's associated service is a default service. Otherwise, it returns whether or not the container is running on _any_ ASIC.

- [is_service_running](multi_asic_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [restart_service](multi_asic_methods/restart_service.md) - Restarts a service on the sonichost if the service is a default service. Otherwise service is restarted on each ASIC.

- [start_service](multi_asic_methods/start_service.md) - Starts service on sonichost if service is a default service. Otherwise service is started on each ASIC.

- [stop_service](multi_asic_methods/stop_service.md) - Stops a service on the sonichost if service is a default service. Otherwise serviec is stopped on all ASICs.


## Sonic ASIC Methods

- [bgp_drop_rule](sonic_asic_methods/bgp_drop_rule.md) - Programs iptable rule to either add or remove DROP for BGP control frames

- [bgp_facts](sonic_asic_methods/bgp_facts.md) - Provides BGP facts for current ASIC.

- [check_bgp_statistic](sonic_asic_methods/check_bgp_statistic.md) - Checks that the BGP statistic matches some expected value.

- [command](sonic_asic_methods/command.md) - Runs commands specified for the ASIC calling the method.

- [config_facts](sonic_asic_methods/config_facts.md) - Current config facts for ASIC.

- [config_ip_intf](sonic_asic_methods/config_ip_intf.md) - Allows for addition or removal of ip addresses to existing interfaces on the ASIC instance.

- [config_portchannel](sonic_asic_methods/config_portchannel.md) - Creates or removes a portchannel on the ASIC instance

- [config_portchannel_member](sonic_asic_methods/config_portchannel_member.md) - Adds or removes portchannel member for a specified portchannel on the ASIC instance.

- [create_ssh_tunnel_sai_rpc](sonic_asic_methods/create_ssh_tunnel_sai_rpc.md) - Create ssh tunnel between host and ASIC namespace on syncd RPC port.

- [delete_container](sonic_asic_methods/delete_container.md) - Deletes a ASIC specific docker.

- [get_active_ip_interfaces](sonic_asic_methods/get_active_ip_interfaces.md) - Provides a information on active IP interfaces. Works on ASIC devices.

- [get_asic_namespace](sonic_asic_methods/get_asic_namespace.md) - Provides namespace for ASIC.

- [get_bgp_statistic](sonic_asic_methods/get_bgp_statistic.md) - Get the value corresponding to a named statistic for BGP.

- [get_critical_services](sonic_asic_methods/get_critical_services.md) - Gets the critical services for the ASIC.

- [get_docker_cmd](sonic_asic_methods/get_docker_cmd.md) - Provides modified command to be run on a specific docker container given an initail command and the name of the desired container.

- [get_docker_name](sonic_asic_methods/get_docker_name.md) - Gets ASIC specific name for docker container.

- [get_extended_minigraph_facts](sonic_asic_methods/get_extended_minigraph_facts.md) - Gets detailed facts on configured minigraph.

- [get_ip_route_info](sonic_asic_methods/get_ip_route_info.md) - Returns route information for a destionation. The destination could an ip address or ip prefix.

- [get_portchannel_and_members_in_ns](sonic_asic_methods/get_portchannel_and_members_in_ns.md) - Finds a portchannel present on ASIC interface's namspace and returns its name and members.

- [get_queue_oid](sonic_asic_methods/get_queue_oid.md) - Get the queue OID of given port and queue number.

- [get_service_name](sonic_asic_methods/get_service_name.md) - Provides ASIC specific service name.

- [interface_facts](sonic_asic_methods/interface_facts.md) - Gets information about interfaces associated with the ASIC calling the method.

- [is_backend_portchannel](sonic_asic_methods/is_backend_portchannel.md) - Checks whether specified portchannel is a backend portchannel.

- [is_container_running](sonic_asic_methods/is_container_running.md) - Returns whether or not a specified ASIC specific container is running.

- [is_it_backend](sonic_asic_methods/is_it_backend.md) - Checks whether the ASIC is a backend node

- [is_it_frontend](sonic_asic_methods/is_it_frontend.md) - Checks whether ASIC is a frontend node.

- [is_service_running](sonic_asic_methods/is_service_running.md) - Checks if a specified service is running. Can be a service within a docker.

- [os_version](sonic_asic_methods/os_version.md) - Provides the SONiC OS version for the sonichost associated with the calling ASIC

- [ping_v4](sonic_asic_methods/ping_v4.md) - Pings specified ipv4 address via ASIC.

- [portchannel_on_asic](sonic_asic_methods/portchannel_on_asic.md) - CHecks whether a specified portchannel is configured on ASIC instance

- [port_exists](sonic_asic_methods/port_exists.md) - Checks whether a provided port exists in the ASIC instance calling the method.

- [port_on_asic](sonic_asic_methods/port_on_asic.md) - Checks if provided port is configured on ASIC instance

- [remove_ssh_tunnel_sai_rpc](sonic_asic_methods/remove_ssh_tunnel_sai_rpc.md) - Removes any ssh tunnels if present created for syncd RPC communication

- [reset_service](sonic_asic_methods/reset_service.md) - Resets an ASIC service on the corresponding docker.

- [restart_service](sonic_asic_methods/restart_service.md) - Restarts an ASIC service on the corresponding docker.

- [run_redis_cli_cmd](sonic_asic_methods/run_redis_cli_cmd.md) - Runs redist cmd through redis CLI for ASIC that calls method.

- [run_redis_cmd](sonic_asic_methods/run_redis_cmd.md) - Runs a redis command on the DUT.

- [shell](sonic_asic_methods/shell.md) - Runs a shell command via the sonichost associated with the ASIC instance calling the method.

- [show_interface](sonic_asic_methods/show_interface.md) - Show status and counter values for a given interface on the ASIC.

- [show_ip_interface](sonic_asic_methods/show_ip_interface.md) - Retrieve ipv4 address for interface and ipv4 address for corresponding neighbor

- [shutdown_interface](sonic_asic_methods/shutdown_interface.md) - Shuts down interface specified for the ASIC instance calling the method.

- [startup_interface](sonic_asic_methods/startup_interface.md) - Starts up interface specified for ASIC instance calling the method.

- [start_service](sonic_asic_methods/start_service.md) - Starts an ASIC service on its corresponding ASIC docker.

- [stop_service](sonic_asic_methods/stop_service.md) - Stops a specified ASIC service on the corresponding docker

- [switch_arptable](sonic_asic_methods/switch_arptable.md) - Gets ARP table information from sonichost device specified for ASIC instance calling the method.


## Ptfhost Methods

- [change_mac_addresses](ptfhost_methods/change_mac_addresses.md) - Updates interface mac addresses.

- [hostname](ptfhost_methods/hostname.md) - Provides hostname for device.

- [mgmt_ip](ptfhost_methods/mgmt_ip.md) - Provides management ip for host.

- [remove_ip_addresses](ptfhost_methods/remove_ip_addresses.md) - Removes all Interface IP Addresses


## Preconfigured Function Arguments

- [duthosts](preconfigured/duthosts.md) - Provides a dictionary that maps DUT hostnames to DUT instances

- [localhost](preconfigured/localhost.md) - The localhost instance. Used to run ansible modules from the localhost.

- [ptfhost](preconfigured/ptfhost.md) - The PTF container host instance. Used to run ptf methods and anisble modules from the PTF.

- [rand_one_dut_hostname](preconfigured/rand_one_dut_hostname.md) - A random hostname belonging to one of the DUT instances defined by the deployed testbed.