from typing import Any

from ..common.ansible_common import (
    log_entry_exit,
)
from ..common.hv_log import Log
from ..provisioner.vsp_one_server_provisioner import (
    VSPServerSimpleApiProvisioner,
)
from ..common.hv_constants import StateValue


class VSPServerSimpleAPIReconciler:

    def __init__(self, connection_info):

        self.logger = Log()
        self.connectionInfo = connection_info
        self.provisioner = VSPServerSimpleApiProvisioner(connection_info)

    @log_entry_exit
    def reconcile(self, state: str, spec: Any) -> Any:
        spec.comments = []
        spec.errors = []
        # Define state to method mapping for better maintainability
        state_handlers = {
            StateValue.PRESENT: self.provisioner.create_update_server,
            StateValue.SYNC_SERVER_NICK_NAME: self.provisioner.sync_server_nick_name,
            StateValue.ADD_HG_TO_SERVER: self.provisioner.add_hg_to_server,
            StateValue.ADD_HBA: self.provisioner.add_wwn_of_hba,
            StateValue.REMOVE_HBA: self.provisioner.remove_wwn_of_hba,
            StateValue.ADD_PATH: self.provisioner.add_path_to_server,
            StateValue.REMOVE_PATH: self.provisioner.remove_path_from_server,
            StateValue.CHANGE_ISCSI_TARGET_SETTINGS: self.provisioner.change_iscsi_target_settings,
            StateValue.ABSENT: self.provisioner.delete_server,
        }

        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        else:
            spec.errors.append(f"Unsupported state: {state}")
            return spec

    @log_entry_exit
    def server_facts_reconcile(self, spec=None) -> Any:
        """
        Retrieve server facts for a given server ID.
        """
        if spec and spec.server_id:
            server = self.provisioner.gateway.get_server_by_id_with_details(
                spec.server_id
            )
            return server.camel_to_snake_dict() if server else "Server not found."
        else:
            return self.provisioner.gateway.get_all_servers_with_filter(
                spec.nick_name, spec.hba_wwn, spec.iscsi_name, spec.include_details
            ).data_to_snake_case_list()

    @log_entry_exit
    def server_hbas_facts_reconcile(self, spec=None) -> Any:
        """
        Retrieve server HBA facts for a given server ID.
        """
        return self.provisioner.get_server_hbas(spec)
