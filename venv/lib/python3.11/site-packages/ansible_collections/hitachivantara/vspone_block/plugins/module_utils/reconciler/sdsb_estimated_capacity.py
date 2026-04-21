try:
    from ..provisioner.sdsb_estimated_capacity_provisioner import (
        SDSBEstimatedCapacityProvisioner,
    )
    from ..provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from ..provisioner.sdsb_storage_pool_provisioner import SDSBStoragePoolProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_estimated_capacity_msgs import SDSBEstimatedCapacityValidateMsg
except ImportError:
    from provisioner.sdsb_estimated_capacity_provisioner import (
        SDSBEstimatedCapacityProvisioner,
    )
    from provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from provisioner.sdsb_storage_pool_provisioner import SDSBStoragePoolProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_estimated_capacity_msgs import SDSBEstimatedCapacityValidateMsg

logger = Log()


class SDSBEstimatedCapacityReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBEstimatedCapacityProvisioner(self.connection_info)
        self.cluster_prov = SDSBClusterProvisioner(self.connection_info)
        self.pool_prov = SDSBStoragePoolProvisioner(self.connection_info)

    @log_entry_exit
    def get_estimated_capacity(self, spec=None):

        platform = self.cluster_prov.get_platform()
        if platform != "Amazon.com, Inc":
            raise ValueError(
                SDSBEstimatedCapacityValidateMsg.ONLY_SUPPORTED_FOR_AWS.value
            )

        try:
            if spec.id:
                s_pool = self.pool_prov.get_storage_pool_by_id(spec.id)
                logger.writeDebug("RC:get_storage_pools:s_pool={}", s_pool)
            else:
                if spec.name:
                    spec.id = self.pool_prov.get_pool_id_by_pool_name(spec.name)
            if spec.id is None:
                raise ValueError(
                    SDSBEstimatedCapacityValidateMsg.STORAGE_POOL_NOT_FOUND.value.format(
                        spec.name
                    )
                )
            if spec.query == "specified_configuration":
                return self.get_estimated_capacity_for_specified_configuration(spec)
            elif spec.query == "updated_configuration":
                return self.get_estimated_capacity_for_updated_configuration(spec)
        except Exception as e:
            if "HTTP Error 412: Precondition Failed" in str(e):
                raise ValueError(
                    SDSBEstimatedCapacityValidateMsg.ONLY_SUPPORTED_FOR_AWS.value
                    + SDSBEstimatedCapacityValidateMsg.ENSURE_FLOATING_BASE_LIC.value
                )
            elif "HTTP Error 404: Not Found" in str(e):
                raise ValueError(SDSBEstimatedCapacityValidateMsg.WRONG_POOL_ID.value)
            elif "HTTP Error 400: Bad Request" in str(e):
                raise ValueError(SDSBEstimatedCapacityValidateMsg.WRONG_POOL_ID.value)
            else:
                raise Exception(e)

    @log_entry_exit
    def get_estimated_capacity_for_specified_configuration(self, spec=None):
        return self.provisioner.get_estimated_capacity_for_specified_configuration(spec)

    @log_entry_exit
    def get_estimated_capacity_for_updated_configuration(self, spec=None):
        return self.provisioner.get_estimated_capacity_for_updated_configuration(spec)
