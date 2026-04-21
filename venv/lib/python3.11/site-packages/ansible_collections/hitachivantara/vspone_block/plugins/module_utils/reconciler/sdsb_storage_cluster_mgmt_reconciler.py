from typing import Any

from ..provisioner.sdsb_storage_cluster_mgmt_provisioner import (
    SDSBStorageClusterMgmtProvisioner,
)
from ..common.hv_constants import StateValue
from ..common.hv_log import Log
from ..common.ansible_common import log_entry_exit

from ..model.sdsb_storage_controller_model import SNMPModelSpec

logger = Log()


class SDSBStorageControllerReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBStorageClusterMgmtProvisioner(self.connection_info)

    @log_entry_exit
    def snmp_reconcile(self, spec: SNMPModelSpec) -> Any:

        return self.provisioner.edit_snmp_settings(spec)

    @log_entry_exit
    def snmp_facts_reconcile(self) -> Any:

        return self.provisioner.get_snmp_settings().camel_to_snake_dict()

    @log_entry_exit
    def protection_domain_reconcile(self, state: StateValue, spec) -> Any:

        if state == StateValue.PRESENT:
            self.provisioner.update_protection_domain(spec)
        elif state == StateValue.RESUME_DRIVE_DATA_RELOCATION:
            self.provisioner.resume_drive_data(spec)
        elif state == StateValue.SUSPEND_DRIVE_DATA_RELOCATION:
            self.provisioner.suspend_drive_data(spec)

        return self.provisioner.gateway.get_protection_domain_settings_by_id(
            spec.id
        ).camel_to_snake_dict()

    @log_entry_exit
    def spare_node_reconcile(self, state: StateValue, spec) -> Any:
        if state == StateValue.PRESENT:
            spare_node = self.provisioner.register_update_spare_node(spec)
            return spare_node.camel_to_snake_dict() if spare_node else None
        elif state == StateValue.ABSENT:
            self.provisioner.unregister_spare_node(spec)
            return

    @log_entry_exit
    def spare_node_facts_reconcile(self, spec) -> Any:
        if spec.id is not None:
            spare_node = self.provisioner.gateway.get_spare_node_by_id(spec.id)
            return spare_node.camel_to_snake_dict() if spare_node else None
        return self.provisioner.gateway.get_all_spare_nodes().data_to_snake_case_list()

    @log_entry_exit
    def storage_system_reconciler(self, state, spec):

        if state == StateValue.PRESENT:
            self.provisioner.edit_storage_system_settings(spec)
        elif state == StateValue.IMPORT_ROOT_CERTIFICATE:
            self.provisioner.import_root_certificate(spec)
        elif state == StateValue.DELETE_ROOT_CERTIFICATE:
            self.provisioner.delete_root_certificate(spec)
        elif state == StateValue.DOWNLOAD_ROOT_CERTIFICATE:
            self.provisioner.download_root_certificate(spec)

        return (
            self.provisioner.gateway.get_storage_system_details().camel_to_snake_dict()
        )
