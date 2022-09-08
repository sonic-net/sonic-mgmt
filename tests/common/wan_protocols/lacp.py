import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class LACPProtocol:
    def __init__(self, dut_handler, dut_interface=None, neighbor_device=None, neighbor_interface=None):
        self.device_a = dut_handler
        self.interface_a = dut_interface
        self.device_b = neighbor_device
        self.interface_b = neighbor_interface

    def get_lacp_port_status_for_topology(self, topologies):
        """
        :param topologies:
        :return: dictionary with status of all port-channels in the topology.
        One list for each port-channel having pc-status(boolean) and
        pc_message (str) which is show interface raw output
        """
        lacp_port_status_results = {}
        for pc_name in topologies.keys():
            # check interface status from device
            pc_status, pc_message = self.device_a.check_interface_status(pc_name)
            # save interface status for all port-channels in a dict
            lacp_port_status_results[pc_name] = [pc_status, pc_message]
        return lacp_port_status_results

    def get_lacp_port_status_summary_for_topology(self, topologies):
        """
        :param topologies:
        :return: pc_ports_status e.g. {'PortChannel16': 'Up', 'PortChannel206': 'Up'}
        """
        lacp_port_status_results = self.get_lacp_port_status_for_topology(topologies)
        pc_ports_status = {}
        for pc_nam, pc_stat in lacp_port_status_results.items():
            if not pc_stat[0]:
                pc_ports_status[pc_nam] = "Down"
            else:
                pc_ports_status[pc_nam] = "Up"
        return pc_ports_status

    def compare_topology_ngs_actual(self, topologies):
        """
        :param topologies:
        :return: pc_members
        e.g.
        {
            "PortChannel15": {
                "active_members": [
                    "et-2/0/12",
                    "et-2/0/13"
                ],
                "expected_members": [
                    "et-2/0/12",
                    "et-2/0/13"
                ]
            },
            "PortChannel206": {
                "active_members": [
                    "et-2/0/8",
                    "et-2/0/9"
                ],
                "expected_members": [
                    "et-2/0/9",
                    "et-2/0/8"
                ]
            }
        }
        """
        pc_members = {}
        for pc_name, pc_details in topologies.items():
            expected_pc_members = []
            for links in pc_details:
                expected_pc_members.append(links["InterfaceA"])

            active_members = self.device_a.get_all_interfaces_in_pc(pc_name)

            pc_members[pc_name] = dict(expected_members=expected_pc_members, active_members=active_members)
            if any(set(expected_pc_members) != set(active_members) for pc_mem in pc_members.values()):
                topo_comparison_result = False
            else:
                topo_comparison_result = True
        return topo_comparison_result, pc_members

    def check_if_port_is_in_pc(self, port, pc):
        active_members = self.device_a.get_all_interfaces_in_pc(pc)
        if port in active_members:
            return True
        else:
            return False
