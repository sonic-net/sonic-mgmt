try:
    from ..provisioner.sdsb_fault_domain_provisioner import SDSBFaultDomainProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from provisioner.sdsb_fault_domain_provisioner import SDSBFaultDomainProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBFaultDomainReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBFaultDomainProvisioner(self.connection_info)

    @log_entry_exit
    def get_fault_domains(self, spec=None):
        return self.provisioner.get_fault_domains(spec)
