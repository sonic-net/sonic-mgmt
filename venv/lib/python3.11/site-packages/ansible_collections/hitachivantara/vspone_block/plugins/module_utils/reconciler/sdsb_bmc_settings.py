try:
    from ..provisioner.sdsb_bmc_settings_provisioner import SDSBBmcSettingsProvisioner
    from ..provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from ..provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue
    from ..message.sdsb_bmc_connection_msgs import SDSBBmcConnectionValidationMsg
    from ..message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg
except ImportError:
    from provisioner.sdsb_bmc_settings_provisioner import SDSBBmcSettingsProvisioner
    from provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue
    from message.sdsb_bmc_connection_msgs import SDSBBmcConnectionValidationMsg
    from message.sdsb_storage_node_msgs import SDSBStorageNodeValidationMsg

logger = Log()


class SDSBBmcSettingsReconciler:

    cloud_platforms = ["Google, Inc.", "Msft", "Amazon.com, Inc"]

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBBmcSettingsProvisioner(self.connection_info)
        self.cluster_prov = SDSBClusterProvisioner(self.connection_info)
        self.node_prov = SDSBStorageNodeProvisioner(self.connection_info)
        self.platform = self.cluster_prov.get_platform()

    @log_entry_exit
    def check_support_for_bmc(self):
        logger.writeDebug(f"check_support_for_bmc:platform = {self.platform}")
        if self.platform in self.cloud_platforms:
            raise ValueError(
                SDSBBmcConnectionValidationMsg.NOT_SUPPORTED_ON_CLOUD.value
            )

    @log_entry_exit
    def get_storage_node_bmc_settings(self, spec=None):
        self.check_support_for_bmc()

        if spec is None:
            return self.provisioner.get_bmc_settings_for_all_storage_nodes()
        else:
            return self.provisioner.get_bmc_settings_for_one_storage_node(spec.id)

    @log_entry_exit
    def reconcile_storage_node_bmc_settings(self, spec, state):
        self.check_support_for_bmc()
        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.update_bmc_settings(spec)
            return resp_data
        else:
            return None

    @log_entry_exit
    def is_change_required(self, bmc_settings, spec):
        if bmc_settings is None:
            return False
        change_required = False
        if bmc_settings["bmc_name"] != spec.bmc_name:
            change_required = True
        if bmc_settings["bmc_user"] != spec.bmc_user:
            change_required = True
        return change_required

    @log_entry_exit
    def update_bmc_settings(self, spec):
        node = None
        if spec.id is None:
            spec.id = self.node_prov.get_node_id_by_node_name(spec.name)
            logger.writeDebug("RC:update_bmc_settings:spec.id={} ", spec.id)
        else:
            try:
                node = self.node_prov.get_storage_node_by_id(spec.id)
            except Exception as e:
                if "HTTP Error 404: Not Found" in str(e):
                    raise ValueError(SDSBStorageNodeValidationMsg.WRONG_NODE_ID.value)
                else:
                    raise Exception(e)

        if spec.id is None:
            raise ValueError(
                SDSBStorageNodeValidationMsg.STORAGE_NODE_NOT_FOUND.value.format(
                    spec.name
                )
            )

        if spec.bmc_password:
            self.connection_info.changed = True
            resp = self.provisioner.update_bmc_settings(
                spec.id, spec.bmc_name, spec.bmc_user, spec.bmc_password
            )
            return self.provisioner.get_bmc_settings_for_one_storage_node(spec.id)
        else:
            bmc_settings = self.provisioner.get_bmc_settings_for_one_storage_node(
                spec.id
            )
            logger.writeDebug("RC:update_bmc_settings:bmc_settings={} ", bmc_settings)
            self.connection_info.changed = self.is_change_required(bmc_settings, spec)
            logger.writeDebug(
                "RC:update_bmc_settings:changed={} ", self.connection_info.changed
            )
            if self.connection_info.changed:
                resp = self.provisioner.update_bmc_settings(
                    spec.id, spec.bmc_name, spec.bmc_user, spec.bmc_password
                )
                return self.provisioner.get_bmc_settings_for_one_storage_node(spec.id)
            else:
                return bmc_settings
