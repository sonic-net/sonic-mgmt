try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..provisioner.vsp_quorum_disk_provisioner import VSPQuorumDiskProvisioner
    from ..model.vsp_quorum_disk_models import QuorumDiskSpec
    from ..common.hv_constants import StateValue

    # from ..message.vsp_quorum_disk_msgs import VSPSQuorumDiskValidateMsg
    from ..common.hv_log import Log
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.ansible_common import (
        log_entry_exit,
    )
    from plugins.module_utils.provisioner.vsp_quorum_disk_provisioner import (
        VSPQuorumDiskProvisioner,
    )
    from model.vsp_quorum_disk_models import QuorumDiskSpec
    from common.hv_constants import StateValue
    from common.hv_log import Log

logger = Log()


class VSPQuorumDiskReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        self.serial = serial
        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPQuorumDiskProvisioner(self.connection_info, self.serial)

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def quorum_disk_reconcile(self, state: str, spec: QuorumDiskSpec):
        #  reconcile based on the desired state in the specification
        state = state.lower()

        if state == StateValue.PRESENT:
            return self.provisioner.register_quorum_disk(spec)
        else:
            if spec is None:
                raise Exception("The parameter id is required for absent state.")
            return self.provisioner.delete_quorum_disk(spec.id)

    @log_entry_exit
    def quorum_disk_facts(self, spec: QuorumDiskSpec):
        rsp = self.provisioner.quorum_disk_facts(spec)
        if rsp is None:
            rsp = []
        return rsp
