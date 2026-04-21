try:
    from ..common.ansible_common import log_entry_exit
    from ..provisioner.sdsb_storage_system_provisioner import (
        SDSBStorageSystemProvisioner,
    )
except ImportError:
    from common.ansible_common import log_entry_exit
    from provisioner.sdsb_storage_system_provisioner import SDSBStorageSystemProvisioner


class SDSBStorageSystemReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBStorageSystemProvisioner(self.connection_info)

    def sdsb_storage_system_reconcile(self):
        """TO DO: will add more logic here"""

    @log_entry_exit
    def sdsb_get_storage_system(self):
        return self.provisioner.sdsb_get_storage_system()
