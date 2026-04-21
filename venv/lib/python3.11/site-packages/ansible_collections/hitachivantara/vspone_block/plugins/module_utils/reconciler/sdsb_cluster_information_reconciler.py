try:
    from ..provisioner.sdsb_cluster_information_provisioner import (
        SDSBClusterInformationProvisioner,
    )
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from ..provisioner.sdsb_cluster_information_provisioner import (
        SDSBClusterInformationProvisioner,
    )
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBClusterInformationReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBClusterInformationProvisioner(self.connection_info)

    @log_entry_exit
    def get_storage_time_settings(self):
        return self.provisioner.get_storage_time_settings()

    @log_entry_exit
    def get_storage_network_settings(self):
        return self.provisioner.get_storage_network_settings()

    @log_entry_exit
    def get_protection_domain_settings(self, spec):
        if spec and spec.id:
            return self.provisioner.get_protection_domain_by_id(spec.id)
        return self.provisioner.get_protection_domain_settings()
