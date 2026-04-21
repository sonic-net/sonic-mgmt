from typing import Any

try:
    from ..provisioner.sdsb_snapshot_provisioner import SDSBSnapshotProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
    )
except ImportError:
    from provisioner.sdsb_snapshot_provisioner import SDSBSnapshotProvisioner
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
    )

logger = Log()


class SDSBSnapshotReconciler:
    """
    Reconciler for SDSB snapshots.
    This class handles the reconciliation of SDSB snapshots.
    """

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBSnapshotProvisioner(self.connection_info)

    @log_entry_exit
    def snapshot_reconcile(self, state: str, spec: Any) -> Any:
        existing_snapshot = self.provisioner.prepare_snapshot_info(spec, state)
        snapshots = None
        msg = None
        if state in (StateValue.ABSENT, StateValue.RESTORE) and not existing_snapshot:
            logger.writeDebug(
                "RC:get_snapshots:No existing snapshot found for spec: {}", spec
            )
            raise ValueError("No existing snapshot found for spec.")

        if state == StateValue.PRESENT:
            if not existing_snapshot:
                snapshots, msg = self.provisioner.create_snapshot(spec)
                logger.writeDebug("RC:get_snapshots:snapshots={}", snapshots)
            else:
                snapshots = existing_snapshot

        elif state == StateValue.RESTORE:
            snapshots, msg = self.provisioner.restore_snapshot(spec)
            logger.writeDebug("RC:get_snapshots:snapshots={}", snapshots)

        elif state == StateValue.ABSENT:
            snapshots, msg = self.provisioner.delete_snapshot(spec)
            logger.writeDebug("RC:get_snapshots:snapshots={}", snapshots)
            return snapshots, msg

        return snapshots.camel_to_snake_dict() if snapshots else None, msg

    @log_entry_exit
    def snapshot_facts(self, spec: Any) -> Any:
        """
        Retrieve snapshot facts.
        """
        snapshots = self.provisioner.snapshot_facts_query(spec)
        return snapshots
