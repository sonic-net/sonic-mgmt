from typing import Any

try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..common.hv_log import Log
    from ..provisioner.vsp_volume_simple_api_provisioner import (
        VSPVolumeSimpleApiProvisioner,
    )
    from ..common.hv_constants import StateValue

except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from common.hv_log import Log
    from provisioner.vsp_volume_simple_api_provisioner import (
        VSPVolumeSimpleApiProvisioner,
    )
    from common.hv_constants import StateValue


class VSPVolumeSimpleAPIReconciler:

    def __init__(self, connection_info):

        self.logger = Log()
        self.connectionInfo = connection_info
        self.provisioner = VSPVolumeSimpleApiProvisioner(connection_info)

    @log_entry_exit
    def reconcile(self, state: str, spec: Any) -> Any:
        if state == StateValue.PRESENT:
            return self.provisioner.create_update_volume(spec)
        elif state == StateValue.ABSENT:
            return self.provisioner.salamander_delete_volume(spec)
        elif state == StateValue.UPDATE_QOS:
            return self.provisioner.update_qos_settings(spec)
        elif state == StateValue.ATTACH_SERVER:

            return self.provisioner.attach_server_to_volume(spec, spec.server_ids)
        elif state == StateValue.DETACH_SERVER:
            return self.provisioner.detach_server_from_volume(spec, spec.server_ids)
        elif state == StateValue.SERVER_PRESENT:
            return self.provisioner.attach_servers_to_volumes(spec)

    @log_entry_exit
    def volume_facts_reconcile(self, spec=None) -> Any:
        """
        Retrieve volume facts for a given LDEV ID.
        """
        if spec and spec.volume_id:
            volume = self.provisioner.gateway.salamander_get_volume_by_id_with_details(
                spec.volume_id
            )
            return volume.camel_to_snake_dict() if volume else "Volume not found."
        else:
            return self.provisioner.volume_facts_request_calls(
                spec
            ).data_to_snake_case_list()
