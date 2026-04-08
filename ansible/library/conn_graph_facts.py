#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import yaml
import os
import logging
import traceback

try:
    from ansible.module_utils.debug_utils import config_module_logging
    from ansible.module_utils.graph_utils import LabGraph
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.debug_utils import config_module_logging
    from module_utils.graph_utils import LabGraph

config_module_logging('conn_graph_facts')


DOCUMENTATION = '''
module: conn_graph_facts.py
short_description: Retrieve lab devices and physical connections information.
Description:
    Retrieve lab devices information and the physical connections between the devices.
options:
    host:
        [fanout switch name|Server name|Sonic Switch Name]
        required: False
    hosts:
        List of hosts. Applicable for multi-DUT and single-DUT setup. The host option for single DUT setup is kept
        for backward compatibility.
        required: False
    anchor:
        List of hosts. When no host and hosts is provided, the anchor option must be specified with list of hosts.
        This option is to supply the relevant list of hosts for looking up the connection graph xml file which has
        all the supplied hosts. The whole graph will be returned when this option is used. This is for configuring
        the root fanout switch.
        required: False
    filepath:
        Folder of the csv graph files.

    group:
        The csv files are organized in multiple groups. Each group has a set of csv files describing the connections
        and devices connected to a same root fanout switch. Usually devices within a same group are also tracked
        in a dedicated inventory file under the `ansible` folder.
        When the group file is not supplied, this module will try to find the group based on the supplied
        host/hosts/anchor information.
        required: False

    forced_mgmt_routes:
        List of forced management routes (IPv4/IPv6). Will be parsed into
        forced_mgmt_routes_v4 and forced_mgmt_routes_v6 and added to each
        device entry in graph facts.
        required: False

    Mutually exclusive options: host, hosts, anchor

Ansible_facts:
    device_info: The device(host) type and hwsku
    device_conn: each physical connection of the device(host)
    device_vlan_range: all configured vlan range for the device(host)
    device_port_vlans: detailed vlanids for each physical port and switchport mode
    server_links: each server port vlan ids
    device_console_info: The device's console server type, mgmtip, hwsku and protocol
    device_console_link:  The console server port connected to the device
    device_bmc_info: The device's bmc server type, mgmtip, hwsku and protocol
    device_bmc_link:  The bmc server port connected to the device
    device_pdu_info: A dict of pdu device's pdu type, mgmtip, hwsku and protocol
    device_pdu_links: The pdu server ports connected to the device and pdu info
    device_from_l1_links: The L1 switch ports connected to the filtered devices.
    device_to_l1_links: The switch ports connected to the L1 switches.
    device_l1_cross_connects: The cross connect ports in L1 switches.

'''


EXAMPLES = '''
    - name: conn_graph_facts: host = "str-7260-11"

    return:
          "device_info": {
              "ManagementIp": "10.251.0.76/24",
              "HwSku": "Arista-7260QX-64",
              "Type": "FanoutLeaf"
            },
          "device_conn": {
              "str-7260-11": {
                  "Ethernet0": {
                      "peerdevice": "str-7050qx-2",
                      "peerport": "Ethernet4",
                      "speed": "40000"
                  },
              }
          },
           "device_vlan_range": {
              "VlanRange": "201-980,1041-1100"
            },
           "device_vlan_port:=: {
                ...
              "Ethernet44": {
                "vlanids": "801-860",
                "mode": "Trunk"
              },
              "Ethernet42": {
                "vlanids": "861-920",
                "mode": "Trunk"
               },......
            }

'''


LAB_GRAPHFILE_PATH = "files/"
LAB_GRAPH_GROUPS_FILE = "graph_groups.yml"


def find_graph(hostnames, part=False, forced_mgmt_routes=None):
    """Find the graph file for the target device

    Args:
        hostnames (list): List of hostnames
        part (bool, optional): Select the graph file if over 80% of hosts are found in conn_graph when part is True.
                               Defaults to False.

    Returns:
        obj: Instance of LabGraph or None if no graph file is found.
    """
    graph_group_file = os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE)
    with open(graph_group_file) as fd:
        graph_groups = yaml.safe_load(fd)

    target_graph = None
    target_group = None
    for group in graph_groups:
        logging.debug("Looking at graph files of group {} for hosts {}".format(group, hostnames))
        lab_graph = LabGraph(LAB_GRAPHFILE_PATH, group, forced_mgmt_routes=forced_mgmt_routes)
        graph_hostnames = set(lab_graph.graph_facts["devices"].keys())
        logging.debug("For graph group {}, got hostnames {}".format(group, graph_hostnames))

        if not part:
            if set(hostnames) <= graph_hostnames:
                target_graph = lab_graph
                target_group = group
                break
        else:
            THRESHOLD = 0.8
            in_graph_hostnames = set(hostnames).intersection(graph_hostnames)
            if len(in_graph_hostnames) * 1.0 / len(hostnames) >= THRESHOLD:
                target_graph = lab_graph
                target_group = group
                break

    if target_graph is not None:
        logging.debug("Returning lab graph of group {} for hosts {}".format(target_group, hostnames))

    return target_graph


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=False),
            hosts=dict(required=False, type='list'),
            filepath=dict(required=False),
            group=dict(required=False),
            anchor=dict(required=False, type='list'),
            ignore_errors=dict(required=False, type='bool', default=False),
            forced_mgmt_routes=dict(required=False, type='list'),
        ),
        mutually_exclusive=[['host', 'hosts', 'anchor']],
        supports_check_mode=True
    )
    m_args = module.params
    anchor = m_args['anchor']
    if m_args['hosts']:
        hostnames = m_args['hosts']
    elif m_args['host']:
        hostnames = [m_args['host']]
    else:
        # return the whole graph
        hostnames = []

    try:
        # When called by pytest, the file path is obscured to /tmp/.../.
        # we need the caller to tell us where the graph files are with
        # filepath argument.
        if m_args["filepath"]:
            global LAB_GRAPHFILE_PATH
            LAB_GRAPHFILE_PATH = m_args['filepath']

        if m_args["group"]:
            lab_graph = LabGraph(
                LAB_GRAPHFILE_PATH,
                m_args["group"],
                forced_mgmt_routes=m_args.get("forced_mgmt_routes")
            )
        else:
            # When calling passed in anchor instead of hostnames,
            # the caller is asking to return the whole graph. This
            # is needed when configuring the root fanout switch.
            target = anchor if anchor else hostnames
            lab_graph = find_graph(
                target,
                forced_mgmt_routes=m_args.get("forced_mgmt_routes")
            )

        if not lab_graph:
            results = {
                'device_info': {},
                'device_conn': {},
                'device_port_vlans': {},
            }
            module.exit_json(ansible_facts=results)

        # early return for the whole graph
        if not hostnames:
            results = {
                'device_info': lab_graph.graph_facts["devices"],
                'device_conn': lab_graph.graph_facts["links"],
                'device_port_vlans': lab_graph.graph_facts["port_vlans"]
            }
            module.exit_json(ansible_facts=results)
        succeed, results = lab_graph.build_results(hostnames, m_args['ignore_errors'])
        if succeed:
            module.exit_json(ansible_facts=results)
        else:
            module.fail_json(msg=results)
    except (IOError, OSError):
        module.fail_json(msg="Can not find required file, exception: {}".format(traceback.format_exc()))
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
