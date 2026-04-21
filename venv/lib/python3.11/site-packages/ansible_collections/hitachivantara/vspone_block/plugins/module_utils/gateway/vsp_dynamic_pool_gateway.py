try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_dynamic_pool_models import (
        VspDynamicPoolInfo,
        VspDynamicPoolSpec,
        VspDynamicPoolsInfo,
        PoolConfigurationResponseList,
    )
    from ..common.vsp_constants import Endpoints, VspDDPConst

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_dynamic_pool_models import (
        VspDynamicPoolInfo,
        VspDynamicPoolSpec,
        VspDynamicPoolsInfo,
        PoolConfigurationResponseList,
    )
    from common.vsp_constants import Endpoints, VspDDPConst

logger = Log()


class VspDynamicPoolGateway:
    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
        )
        self.connection_info = connection_info

    @log_entry_exit
    def get_all_dynamic_pools_info(self):
        """
        Get all dynamic pools information.
        :return: List of VspDynamicPoolInfo
        """
        end_point = Endpoints.GET_ALL_DDP_POOL_INFO
        logger.writeDebug("Getting all dynamic pool information.")
        response = self.connection_manager.pegasus_get(end_point)
        return VspDynamicPoolsInfo().dump_to_object(response)

    @log_entry_exit
    def get_dynamic_pool_by_id(self, pool_id):
        """
        Get all dynamic pool information.
        :return: List of VspDynamicPoolInfo
        """
        end_point = Endpoints.SINGLE_DDP_POOL.format(pool_id)
        logger.writeDebug("Getting all dynamic pool information.")
        try:
            response = self.connection_manager.pegasus_get(end_point)
            data = VspDynamicPoolInfo(**response)
            return (
                data
                if any(drive.parityGroupType == "DDP" for drive in data.drives)
                else None
            )
        except Exception as e:
            logger.writeEnter(f"Error getting dynamic pool information: {e}")
            return None

    @log_entry_exit
    def get_all_dynamic_pool_info_in_details(self):
        """
        Get all dynamic pool information with detailed filtering.
        :return: VspDynamicPoolsInfo
        """
        all_pools = self.get_all_dynamic_pools_info()
        filtered_pools = [
            VspDynamicPoolInfo(
                **self.connection_manager.pegasus_get(
                    Endpoints.SINGLE_DDP_POOL.format(pool.id)
                )
            )
            for pool in all_pools.data
            if any(
                drive.get("parityGroupType") == "DDP"
                for drive in self.connection_manager.pegasus_get(
                    Endpoints.SINGLE_DDP_POOL.format(pool.id)
                ).get("drives", [])
            )
        ]
        all_pools.data = filtered_pools
        return all_pools

    @log_entry_exit
    def create_dynamic_pool(self, pool_spec: VspDynamicPoolSpec):
        """
        Create a dynamic pool.
        :param pool_spec: VspDynamicPoolSpec
        :return: VspDynamicPoolInfo
        """
        payload = {VspDDPConst.name: pool_spec.pool_name, VspDDPConst.drives: []}
        for drive in pool_spec.drives:
            drive_payload = {
                VspDDPConst.driveTypeCode: drive.drive_type_code,
                VspDDPConst.dataDriveCount: drive.data_drive_count,
                VspDDPConst.raidLevel: drive.raid_level,
                VspDDPConst.parityGroupType: drive.parity_group_type,
            }
            payload[VspDDPConst.drives].append(drive_payload)
        if pool_spec.is_encryption_enabled:
            payload[VspDDPConst.isEncryptionEnabled] = pool_spec.is_encryption_enabled
        end_point = Endpoints.POST_DDP_POOL
        logger.writeDebug("Creating dynamic pool.")
        response = self.connection_manager.pegasus_post(end_point, payload)
        return response

    @log_entry_exit
    def change_dynamic_pool_settings(self, pool_spec: VspDynamicPoolSpec):
        """
        Change dynamic pool settings.
        :param pool_id: str
        :param pool_spec: VspDynamicPoolSpec
        """
        payload = {}
        if pool_spec.threshold_depletion:
            payload[VspDDPConst.thresholdDepletion] = pool_spec.threshold_depletion
        if pool_spec.threshold_warning:
            payload[VspDDPConst.thresholdWarning] = pool_spec.threshold_warning
        if pool_spec.pool_name:
            payload[VspDDPConst.name] = pool_spec.pool_name

        if payload:
            end_point = Endpoints.SINGLE_DDP_POOL.format(pool_spec.pool_id)
            logger.writeDebug("Changing dynamic pool settings.")
            unused = self.connection_manager.pegasus_patch(end_point, payload)
        return None

    @log_entry_exit
    def delete_dynamic_pool(self, pool_id: str):
        """
        Delete a dynamic pool.
        :param pool_id: str
        :return: None
        """
        end_point = Endpoints.SINGLE_DDP_POOL.format(pool_id)
        logger.writeDebug("Deleting dynamic pool.")
        self.connection_manager.pegasus_delete(end_point, None)
        return None

    @log_entry_exit
    def expand_dynamic_pool(self, drive_spec: VspDynamicPoolSpec):
        """
        Expand a dynamic pool.
        :param pool_id: str
        :param drive_spec: VspDynamicPoolSpec
        :return: None
        """
        payload = {}
        if drive_spec.drives:
            payload[VspDDPConst.additionalDrives] = []
            for drive in drive_spec.drives:
                drive_payload = {
                    VspDDPConst.driveTypeCode: drive.drive_type_code,
                    VspDDPConst.dataDriveCount: drive.data_drive_count,
                    VspDDPConst.raidLevel: drive.raid_level,
                    VspDDPConst.parityGroupType: drive.parity_group_type,
                }
                payload[VspDDPConst.additionalDrives].append(drive_payload)
            end_point = Endpoints.EXPAND_DDP_POOL.format(drive_spec.pool_id)
            logger.writeDebug("Expanding dynamic pool.")
            return self.connection_manager.pegasus_post(end_point, payload)
        return None

    @log_entry_exit
    def get_recommend_pool_configuration(self, pool_id=None):
        """
        Get recommended drive count.
        :param pool_id: str
        :return: None
        """
        end_point = Endpoints.GET_RECOMMENDED_POOL
        if pool_id:
            end_point = Endpoints.GET_RECOMMENDED_POOL_SINGLE.format(pool_id)
        logger.writeDebug("Getting recommended drive count.")
        response = self.connection_manager.pegasus_get(end_point)
        return PoolConfigurationResponseList().dump_to_object(response)
