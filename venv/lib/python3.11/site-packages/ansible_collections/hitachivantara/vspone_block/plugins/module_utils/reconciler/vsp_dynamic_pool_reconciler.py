try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..provisioner.vsp_dynamic_pool_provisioner import (
        VspDynamicPoolProvisioner,
    )
    from ..common.hv_constants import StateValue


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from plugins.module_utils.provisioner.vsp_dynamic_pool_provisioner import (
        VspDynamicPoolProvisioner,
    )
    from common.hv_constants import StateValue


class VspDynamicPoolReconciler:
    """
    This class is responsible for reconciling the VSP dynamic pool.
    """

    def __init__(self, connection_info):
        """
        Initialize the VspDynamicPoolReconciler with connection information and optional serial number.
        :param connection_info: Connection information for the VSP.
        """
        self.connection_info = connection_info
        self.provisioner = VspDynamicPoolProvisioner(self.connection_info)

    @log_entry_exit
    def dynamic_pool_reconcile(self, state: str, spec):
        """
        Reconcile the dynamic pool based on the desired state in the specification.
        :param state: Desired state (e.g., 'present' or 'absent').
        :param spec: Specification for the dynamic pool.
        """
        state = state.lower()
        if state == StateValue.ABSENT:
            return self.provisioner.delete_dynamic_pool(spec)
        elif state == StateValue.EXPAND:
            return self.provisioner.expand_dynamic_pool(spec)
        else:
            return self.provisioner.create_update_dynamic_pool(spec)

    @log_entry_exit
    def dynamic_pool_facts(self, spec=None):
        """
        Get the facts of the dynamic pool.
        :param spec: Specification for the dynamic pool.
        """
        return self.provisioner.dynamic_pool_facts(spec)
