try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..model.vsp_parity_group_models import DrivesFactSpec
    from ..provisioner.vsp_parity_group_provisioner import VSPParityGroupProvisioner
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from provisioner.vsp_parity_group_provisioner import VSPParityGroupProvisioner
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from model.vsp_parity_group_models import DrivesFactSpec

logger = Log()


class VSPDiskDriveReconciler:

    def __init__(self, connectionInfo, state=None):
        self.logger = Log()
        self.connectionInfo = connectionInfo
        self.state = state
        self.provisioner = VSPParityGroupProvisioner(self.connectionInfo)

    @log_entry_exit
    def disk_drive_reconcile(self, state: str, spec: DrivesFactSpec):
        # reconcile the disk drive based on the desired state in the specification
        state = state.lower()
        if state == StateValue.PRESENT:
            return self.provisioner.change_drive_setting(spec)
