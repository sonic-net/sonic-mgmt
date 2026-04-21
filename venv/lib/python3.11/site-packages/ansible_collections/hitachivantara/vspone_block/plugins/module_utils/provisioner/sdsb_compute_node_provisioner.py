try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_port_models import SDSBComputePortsInfo
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_port_models import SDSBComputePortsInfo
    from common.ansible_common import log_entry_exit


class SDSBComputeNodeProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_COMPUTE_NODE
        )

    @log_entry_exit
    def get_compute_nodes(self, spec=None):
        return self.gateway.get_compute_nodes(spec)

    @log_entry_exit
    def get_compute_node_by_id(self, id):
        return self.gateway.get_compute_node_by_id(id)

    @log_entry_exit
    def get_compute_node_details_by_id(self, id):
        cn = self.gateway.get_compute_node_by_id(id)
        if cn.numberOfPaths > 0:
            cn.paths = []
            hba_data = {}
            paths = self.gateway.get_hba_paths(id)
            for path in paths:
                port_data = {
                    "portId": path.portId,
                    "portName": path.portNickname,
                }
                if path.hbaName not in hba_data:
                    hba_data[path.hbaName] = {
                        "hbaName": path.hbaName,
                        "hbaId": path.hbaId,
                        "ports": [],
                    }
                hba_data[path.hbaName]["ports"].append(port_data)
            cn.paths.append(list(hba_data.values()))
        return cn

    @log_entry_exit
    def get_compute_node_by_name(self, name):
        return self.gateway.get_compute_node_by_name(name)

    @log_entry_exit
    def delete_compute_node_by_id(self, id, vps_id=None):
        return self.gateway.delete_compute_node_by_id(id, vps_id)

    @log_entry_exit
    def create_compute_node(self, name, os_type, vps_id=None):
        return self.gateway.create_compute_node(name, os_type, vps_id)

    @log_entry_exit
    def add_iqn_to_compute_node(self, compute_node_id, iqn, vps_id=None):
        return self.gateway.add_iqn_to_compute_node(compute_node_id, iqn, vps_id)

    @log_entry_exit
    def add_nqn_to_compute_node(self, compute_node_id, nqn, vps_id=None):
        return self.gateway.add_nqn_to_compute_node(compute_node_id, nqn, vps_id)

    @log_entry_exit
    def get_compute_port_ids(self):
        return self.gateway.get_compute_port_ids()

    @log_entry_exit
    def get_compute_ports(self, spec):
        ports = self.gateway.get_compute_ports(spec)
        if spec.nicknames is not None:
            ret_list = []
            if spec.nicknames:
                for x in spec.nicknames:
                    for port in ports.data:
                        if x == port.nickname:
                            ret_list.append(port)

            return SDSBComputePortsInfo(data=ret_list)
        return ports

    @log_entry_exit
    def add_compute_node_path(self, compute_node_id, iqn_id, port_id, vps_id=None):
        return self.gateway.add_compute_node_path(
            compute_node_id, iqn_id, port_id, vps_id
        )

    @log_entry_exit
    def get_compute_node_hba_ids(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_hba_ids(compute_node_id, vps_id)

    @log_entry_exit
    def get_compute_node_nqn_ids(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_nqn_ids(compute_node_id, vps_id)

    @log_entry_exit
    def get_compute_node_nqn_pairs(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_nqn_pairs(compute_node_id, vps_id)

    @log_entry_exit
    def get_compute_node_iscsi_pairs(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_iscsi_pairs(compute_node_id, vps_id)

    @log_entry_exit
    def attach_volume_to_compute_node(self, compute_node_id, volume_id, vps_id=None):
        return self.gateway.attach_volume_to_compute_node(
            compute_node_id, volume_id, vps_id
        )

    @log_entry_exit
    def update_compute_node(self, compute_node_id, spec):
        self.gateway.update_compute_node(compute_node_id, spec)

    @log_entry_exit
    def get_compute_node_hba_names(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_hba_names(compute_node_id, vps_id)

    @log_entry_exit
    def get_compute_node_nqn_names(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_nqn_names(compute_node_id, vps_id)

    @log_entry_exit
    def get_hba_paths(self, compute_node_id, vps_id=None):
        return self.gateway.get_hba_paths(compute_node_id, vps_id)

    @log_entry_exit
    def delete_hba_path(self, compute_node_id, hba_port_id_pair, vps_id=None):
        return self.gateway.delete_hba_path(compute_node_id, hba_port_id_pair, vps_id)

    @log_entry_exit
    def delete_hba(self, compute_node_id, hba_id, vps_id=None):
        return self.gateway.delete_hba(compute_node_id, hba_id, hba_id)

    @log_entry_exit
    def get_compute_node_volume_ids(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_volume_ids(compute_node_id, vps_id)

    @log_entry_exit
    def get_volume_compute_node_ids(self, vol_id, vps_id=None):
        return self.gateway.get_volume_compute_node_ids(vol_id, vps_id)

    @log_entry_exit
    def detach_volume_from_compute_node(
        self, compute_node_id, vol_id_to_detach, vps_id=None
    ):
        self.gateway.detach_volume_from_compute_node(
            compute_node_id, vol_id_to_detach, vps_id
        )

    @log_entry_exit
    def get_compute_node_hba_name_id_pairs(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_hba_name_id_pairs(compute_node_id, vps_id)

    @log_entry_exit
    def get_compute_node_nqn_name_id_pairs(self, compute_node_id, vps_id=None):
        return self.gateway.get_compute_node_nqn_name_id_pairs(compute_node_id, vps_id)
