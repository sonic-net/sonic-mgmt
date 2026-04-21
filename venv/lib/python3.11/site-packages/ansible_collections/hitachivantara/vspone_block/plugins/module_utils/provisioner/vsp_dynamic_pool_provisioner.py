try:
    from ..gateway.vsp_dynamic_pool_gateway import VspDynamicPoolGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from .vsp_storage_system_provisioner import (
        VSPStorageSystemProvisioner,
    )
    from ..message.vsp_dynamic_pool_msg import DynamicPoolValidationMsg
    from ..model.vsp_dynamic_pool_models import DriveSpec
except ImportError:
    from gateway.vsp_dynamic_pool_gateway import VspDynamicPoolGateway
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from .vsp_storage_system_provisioner import (
        VSPStorageSystemProvisioner,
    )
    from message.vsp_dynamic_pool_msg import DynamicPoolValidationMsg
    from model.vsp_dynamic_pool_models import DriveSpec


logger = Log()

ALLOWED_STORAGE_MODEL = "VSP One"


class VspDynamicPoolProvisioner:
    """
    Class to handle the dynamic pool provisioning for VSP.
    """

    def __init__(self, connection_info):
        self.gateway = VspDynamicPoolGateway(connection_info)
        self.connection_info = connection_info

        self.storage_system_gw = VSPStorageSystemProvisioner(connection_info)
        self.validate_storage_system()

    @log_entry_exit
    def get_all_dynamic_pools(self):
        """
        Get all dynamic pools information.
        :return: List of VspDynamicPoolInfo
        """
        dynamic_pools = self.gateway.get_all_dynamic_pool_info_in_details()
        return dynamic_pools

    @log_entry_exit
    def get_dynamic_pool_by_id(self, object_id):
        """
        Get dynamic pool information by ID.
        :return: VspDynamicPoolInfo
        """
        dynamic_pool = self.gateway.get_dynamic_pool_by_id(object_id)
        return dynamic_pool

    @log_entry_exit
    def create_update_dynamic_pool(self, spec):
        """
        Create or update a dynamic pool.
        :param spec: VspDynamicPoolSpec
        :return: VspDynamicPoolInfo
        """
        dynamic_pool = None
        # Check if the dynamic pool already exists

        if spec.pool_id is not None:
            dynamic_pool = self.gateway.get_dynamic_pool_by_id(spec.pool_id)
        elif spec.pool_name:
            dynamic_pool = self.get_dynamic_pool_using_name_or_id(name=spec.pool_name)
        logger.writeDebug(f"ddp = {dynamic_pool}")
        if not dynamic_pool:
            self.validate_ddp_drives(spec)
            # if spec.drives is None:
            #     raise ValueError(DynamicPoolValidationMsg.DRIVES_REQUIRED.value)
            if spec.pool_name is None:
                raise ValueError(DynamicPoolValidationMsg.POOL_NAME_REQUIRED.value)

            # validate the ddp drives count

            pool_id = self.create_dynamic_pool(spec)
            spec.pool_id = pool_id
            self.connection_info.changed = True
            dynamic_pool = self.gateway.get_dynamic_pool_by_id(spec.pool_id)

        spec.pool_id = dynamic_pool.id
        if (
            dynamic_pool.name != spec.pool_name
            or dynamic_pool.capacityManage.thresholdDepletion
            != spec.threshold_depletion
            or dynamic_pool.capacityManage.thresholdWarning != spec.threshold_warning
        ):
            logger.writeDebug("Updating dynamic pool.")
            self.gateway.change_dynamic_pool_settings(spec)
            dynamic_pool = self.gateway.get_dynamic_pool_by_id(spec.pool_id)
            self.connection_info.changed = True

        return dynamic_pool.camel_to_snake_dict()

    @log_entry_exit
    def create_dynamic_pool(self, spec):
        """
        Create a dynamic pool.
        :param spec: VspDynamicPoolSpec
        :return: VspDynamicPoolInfo
        """
        logger.writeDebug("Creating dynamic pool.")
        pool_id = self.gateway.create_dynamic_pool(spec)
        return pool_id

    @log_entry_exit
    def expand_dynamic_pool(self, spec):
        """
        Expand a dynamic pool.
        :param spec: VspDynamicPoolSpec
        :return: VspDynamicPoolInfo
        """

        logger.writeDebug("Expanding dynamic pool.")
        if spec.pool_id is not None:
            dynamic_pool = self.gateway.get_dynamic_pool_by_id(spec.pool_id)
        elif spec.pool_name:
            dynamic_pool = self.get_dynamic_pool_using_name_or_id(name=spec.pool_name)
        logger.writeDebug("Deleting dynamic pool.")
        if not dynamic_pool:
            logger.writeError("Dynamic pool not found.")
            return DynamicPoolValidationMsg.DYNAMIC_POOL_NOT_FOUND.value

        if spec.drives is None:
            raise ValueError(DynamicPoolValidationMsg.DRIVES_REQUIRED_TO_EXPAND.value)

        spec.pool_id = dynamic_pool.id
        # validate the ddp drives count
        self.validate_ddp_drives(spec)
        response = self.gateway.expand_dynamic_pool(spec)

        if response:
            self.connection_info.changed = True
            dynamic_pool = self.gateway.get_dynamic_pool_by_id(spec.pool_id)
        return dynamic_pool.camel_to_snake_dict()

    @log_entry_exit
    def get_dynamic_pool_using_name_or_id(self, name=None, id=None):
        """
        Get dynamic pool information by name or ID.
        :param object_id: Name or ID of the dynamic pool.
        :return: VspDynamicPoolInfo
        """
        if id is not None:
            return self.gateway.get_dynamic_pool_by_id(id)
        elif name:
            pools = self.gateway.get_all_dynamic_pool_info_in_details()
            for pool in pools.data:
                if pool.name == name:
                    return pool
        return None

    @log_entry_exit
    def dynamic_pool_facts(self, spec=None):
        """
        Get all dynamic pools information.
        :return: List of VspDynamicPoolInfo
        """
        if spec and spec.pool_id or spec and spec.pool_name:
            pool = self.get_dynamic_pool_using_name_or_id(spec.pool_name, spec.pool_id)
            if pool:
                return pool.camel_to_snake_dict()
            else:
                return DynamicPoolValidationMsg.DYNAMIC_POOL_NOT_FOUND.value
        dynamic_pools = self.gateway.get_all_dynamic_pool_info_in_details()
        return dynamic_pools.data_to_snake_case_list()

    @log_entry_exit
    def delete_dynamic_pool(self, spec):
        """
        Delete a dynamic pool.
        :param object_id: ID of the dynamic pool to delete.
        :return: None
        """
        if spec.pool_id is None and spec.pool_name is None:
            return DynamicPoolValidationMsg.POOL_ID_REQUIRED.value

        pool_exists = self.get_dynamic_pool_using_name_or_id(
            spec.pool_name, spec.pool_id
        )
        logger.writeDebug("Deleting dynamic pool.")
        if not pool_exists:
            logger.writeError("Dynamic pool with ID {} not found.".format(spec.pool_id))
            return DynamicPoolValidationMsg.DYNAMIC_POOL_NOT_FOUND_BY_ID.value.format(
                spec.pool_id
            )

        self.gateway.delete_dynamic_pool(pool_exists.id)
        self.connection_info.changed = True
        return DynamicPoolValidationMsg.DYNAMIC_POOL_DELETED.value

    @log_entry_exit
    def validate_storage_system(self):
        """
        Validate the storage system for the dynamic pool.
        :return: Bool
        """
        storage_system = self.storage_system_gw.get_current_storage_system_info()

        if ALLOWED_STORAGE_MODEL not in storage_system.model:
            raise ValueError(DynamicPoolValidationMsg.ALLOWED_STORAGE_MODEL.value)
        return None

    def validate_ddp_drives(self, spec):
        """
        Validate the DDP drives.
        :param drives: List of DDP drives.
        :return: Bool
        """
        try:
            recommend_configs = self.gateway.get_recommend_pool_configuration(
                pool_id=spec.pool_id
            )
        except Exception as e:
            logger.writeError(f"Error validating DDP drives: {e}")
            return
        recommend_configs_dicts = {
            config.driveTypeCode: config
            for config in recommend_configs.data
            if config.parityGroupType == "DDP" and config.raidLevel == "RAID6"
        }
        logger.writeDebug(f"Recommended DDP drives: {recommend_configs_dicts}")
        if spec.drives is not None:
            for drive in spec.drives:
                if drive.drive_type_code is None:
                    raise ValueError(
                        DynamicPoolValidationMsg.DDP_DRIVES_TYPE_CODE_REQUIRED.value
                    )

                if drive.drive_type_code not in recommend_configs_dicts:
                    raise ValueError(
                        DynamicPoolValidationMsg.DDP_DRIVES_NOT_VALID.value.format(
                            drive.drive_type_code
                        )
                    )
                elif drive.data_drive_count and (
                    recommend_configs_dicts[
                        drive.drive_type_code
                    ].numberOfCurrentFreeDrives
                    < drive.data_drive_count
                ):
                    raise ValueError(
                        DynamicPoolValidationMsg.DDP_DRIVES_NOT_VALID_COUNT.value.format(
                            recommend_configs_dicts[
                                drive.drive_type_code
                            ].numberOfCurrentFreeDrives,
                            drive.drive_type_code,
                        )
                    )
                elif (
                    drive.data_drive_count is not None
                    and drive.data_drive_count < 9
                    and spec.pool_id is None
                ):
                    raise ValueError(DynamicPoolValidationMsg.DRIVE_COUNT_RANGE.value)
                else:
                    if drive.data_drive_count is None:
                        drive.data_drive_count = recommend_configs_dicts[
                            drive.drive_type_code
                        ].numberOfRecommendedAddDataDrives
                        drive.drive_type_code = drive.drive_type_code

        else:
            for key, config in recommend_configs_dicts.items():
                if config.numberOfRecommendedAddDataDrives >= 9:
                    spec.drives = [
                        DriveSpec(
                            drive_type_code=config.driveTypeCode,
                            data_drive_count=config.numberOfRecommendedAddDataDrives,
                        )
                    ]
                    return None
            raise ValueError(DynamicPoolValidationMsg.NO_FREE_DRIVES.value)

        return None
