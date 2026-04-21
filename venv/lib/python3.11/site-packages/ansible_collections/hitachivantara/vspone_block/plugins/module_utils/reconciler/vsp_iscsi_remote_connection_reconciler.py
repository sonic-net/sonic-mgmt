try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..provisioner.vsp_iscsi_remote_connection_provisioner import (
        VSPIscsiRemoteConnectionProvisioner,
    )
    from ..model.vsp_remote_connection_models import RemoteIscsiConnectionSpec
    from ..common.hv_constants import StateValue


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from plugins.module_utils.provisioner.vsp_iscsi_remote_connection_provisioner import (
        VSPIscsiRemoteConnectionProvisioner,
    )
    from common.hv_constants import StateValue


class VSPRemoteIscsiConnectionReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        self.provisioner = VSPIscsiRemoteConnectionProvisioner(
            self.connection_info, serial
        )

    @log_entry_exit
    def remote_iscsi_connection_reconcile(
        self, state: str, spec: RemoteIscsiConnectionSpec
    ):
        #  reconcile the journal pool based on the desired state in the specification
        state = state.lower()
        self.provisioner.remote_serial = spec.remote_storage_serial_number
        self.provisioner.get_remote_connection_info()
        if state == StateValue.PRESENT:
            return self.provisioner.create_update_iscsi_remote_connection(spec)
        else:
            return self.provisioner.delete_iscsi_remote_connection(spec)

    @log_entry_exit
    def remote_iscsi_connection_facts(self, spec=None):
        return self.provisioner.get_remote_connection_facts(spec)
