try:
    from ..provisioner.sdsb_storage_cluster_mgmt_provisioner import (
        SDSBStorageClusterMgmtProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from provisioner.sdsb_storage_cluster_mgmt_provisioner import (
        SDSBStorageClusterMgmtProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBWebServerSettingsReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBStorageClusterMgmtProvisioner(self.connection_info)

    @log_entry_exit
    def reconcile_web_server_settings(self, state, spec):
        """
        Reconcile the web server settings based on the state and spec.
        :param state: The desired state (e.g., 'present', 'import_certificate').
        :param spec: Specification for the web server settings.
        :return: Response from the provisioner.
        """
        if state.lower() == StateValue.IMPORT_CERTIFICATE:
            self.provisioner.import_server_certificate(spec)
        else:
            self.provisioner.update_web_server_access_settings(spec)

        return self.provisioner.get_web_server_access_settings().camel_to_snake_dict()

    @log_entry_exit
    def web_server_settings_facts(self):
        """
        Ensure that the web server settings are present.
        :param spec: Specification for the web server settings.
        :return: Response from the provisioner.
        """
        response = self.provisioner.get_web_server_access_settings()
        return response.camel_to_snake_dict()
