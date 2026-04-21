try:
    from ..provisioner.sdsb_control_port_provisioner import SDSBControlPortProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from ..provisioner.sdsb_control_port_provisioner import SDSBControlPortProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBControlPortReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBControlPortProvisioner(self.connection_info)

    @log_entry_exit
    def get_control_ports(self, spec=None):
        return self.provisioner.get_control_ports(spec)

    @log_entry_exit
    def get_internode_ports(self, spec=None):
        return self.provisioner.get_internode_ports(spec)

    @log_entry_exit
    def get_storage_node_network_settings(self, spec=None):
        return self.provisioner.get_storage_node_network_settings(spec)
