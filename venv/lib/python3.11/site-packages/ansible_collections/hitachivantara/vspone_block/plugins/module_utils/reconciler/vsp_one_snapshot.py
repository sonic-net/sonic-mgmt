from typing import Any

from ..common.ansible_common import (
    log_entry_exit,
)
from ..common.hv_log import Log
from ..provisioner.vsp_one_snapshot_provisioner import VspOneSnapshotProvisioner
from ..common.hv_constants import StateValue


logger = Log()


class VspOneSnapshotReconciler:

    def __init__(self, connection_info):

        self.connectionInfo = connection_info
        self.provisioner = VspOneSnapshotProvisioner(connection_info)

    @log_entry_exit
    def reconcile(self, spec: Any) -> Any:
        spec.comments = []
        return self.provisioner.change_port_settings(spec.port_id, spec)

    @log_entry_exit
    def get_snapshot_facts(self, spec=None) -> Any:
        return self.provisioner.vsp_one_snapshot_facts(spec)

    @log_entry_exit
    def get_snapshot_groups_facts_reconcile(self, spec=None) -> Any:
        return self.provisioner.get_snapshot_groups(spec)

    @log_entry_exit
    def snapshot_group_reconcile(self, state, spec: str) -> bool:
        if state == StateValue.PRESENT:
            response = self.provisioner.gateway.get_snapshot_group_by_name(
                spec.snapshot_group_name
            )
            if response:
                return response.camel_to_snake_dict()
            else:
                return None
        else:
            return self.provisioner.delete_snapshot_group(spec)

    @log_entry_exit
    def reconcile(self, state: str, spec: Any) -> Any:
        spec.comments = []
        spec.errors = []
        # Define state to method mapping for better maintainability
        state_handlers = {
            StateValue.PRESENT: self.provisioner.create_update_snapshot,
            StateValue.MAP: self.provisioner.map_snapshot,
            StateValue.RESTORE: self.provisioner.restore_snapshot,
            StateValue.ABSENT: self.provisioner.delete_snapshot,
        }

        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        else:
            spec.errors.append(f"Unsupported state: {state}")
            return spec
