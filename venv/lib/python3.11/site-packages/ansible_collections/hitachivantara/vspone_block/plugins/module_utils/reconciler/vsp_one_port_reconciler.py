from typing import Any

from ..common.ansible_common import (
    log_entry_exit,
)
from ..common.hv_log import Log
from ..provisioner.vsp_one_port_provisioner import VSPPortSimpleApiProvisioner


class VSPOnePortSimpleAPIReconciler:

    def __init__(self, connection_info):

        self.logger = Log()
        self.connectionInfo = connection_info
        self.provisioner = VSPPortSimpleApiProvisioner(connection_info)

    @log_entry_exit
    def reconcile(self, spec: Any) -> Any:
        spec.comments = []
        return self.provisioner.change_port_settings(spec.port_id, spec)

    @log_entry_exit
    def port_facts_reconcile(self, spec=None) -> Any:
        """
        Retrieve server facts for a given server ID.
        """
        return self.provisioner.vsp_one_port_facts(spec)
