try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.hv_messages import MessageID
    from ..common.ansible_common import log_entry_exit
    from ..message.vsp_copy_group_msgs import (
        VSPCopyGroupsValidateMsg,
    )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.hv_messages import MessageID
    from common.ansible_common import log_entry_exit
    from message.vsp_copy_group_msgs import VSPCopyGroupsValidateMsg

logger = Log()


class VSPLocalCopyGroupProvisioner:

    def __init__(self, connection_info, serial=None):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_LOCAL_COPY_GROUP
        )
        self.connection_info = connection_info

        self.gateway.set_storage_serial_number(serial)
        logger.writeDebug(f"PROV:serial={serial}")

    @log_entry_exit
    def get_storage_serial(self):
        try:
            response = self.gateway.get_storage_serial()
            logger.writeDebug("PROV:get_storage_serial:response={}", response)
            return response
        except Exception as e:
            logger.writeError(MessageID.ERR_GetStorageID)
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def get_local_copy_groups(self, spec):
        try:
            if (
                spec.name is not None
                and spec.primary_volume_device_group_name is not None
                and spec.secondary_volume_device_group_name is not None
            ):
                local_copygroup_id = (
                    spec.name
                    + ","
                    + spec.primary_volume_device_group_name
                    + ","
                    + spec.secondary_volume_device_group_name
                )
                return self.gateway.get_one_copygroup_with_copy_pairs_by_id(
                    local_copygroup_id
                )
            if spec.name is not None and spec.should_include_copy_pairs is True:
                response = self.gateway.get_one_copygroup_info_by_name(spec, True)
                # In case no copy pairs in the copy group return copy group information.
                if response is None:
                    response = self.gateway.get_copy_group_by_name(spec)
            elif spec.name:
                response = self.gateway.get_copy_group_by_name(spec)
            else:
                response = self.gateway.get_local_copy_groups(spec)
            logger.writeDebug("PROV:get_copy_groups:time={}", response)
            return response
        except Exception as e:
            logger.writeError(MessageID.ERR_GetCopyGroups)
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def delete_local_copy_group(self, spec):
        spec.name = spec.copy_group_name
        copy_group_exiting = self.gateway.get_one_copygroup_info_by_name(spec, True)
        if copy_group_exiting is None:
            return VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NOT_FOUND.value.format(
                spec.copy_group_name
            )

        if copy_group_exiting.localCloneCopygroupId is not None:
            pair_elements = copy_group_exiting.localCloneCopygroupId.split(",")
            if (
                spec.primary_volume_device_group_name is not None
                or spec.secondary_volume_device_group_name is not None
            ):
                if spec.primary_volume_device_group_name != pair_elements[1]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_DELETE_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_PVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[1]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                elif spec.secondary_volume_device_group_name != pair_elements[2]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_DELETE_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_SVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[2]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

        self.connection_info.changed = True
        self.gateway.delete_local_copy_group(
            spec, copy_group_exiting.localCloneCopygroupId
        )
        return None

    @log_entry_exit
    def split_local_copy_group(self, spec):
        spec.name = spec.copy_group_name
        found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec, True)
        if found_copy_group is None:
            msg = VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NOT_FOUND.value.format(
                spec.copy_group_name
            )
            logger.writeError(msg)
            raise Exception(msg)
        elif found_copy_group is not None and spec.should_force_split is None:
            if found_copy_group.copyPairs:
                for copy_pair in found_copy_group.copyPairs:
                    pvol_status = copy_pair.pvolStatus
                    svol_status = copy_pair.svolStatus
                    if (
                        pvol_status == "PSUS"
                        and svol_status == "SSUS"
                        # and spec.is_svol_writable is None
                        # and spec.do_pvol_write_protect is None
                        # and spec.do_data_suspend is None
                    ):
                        return found_copy_group

        if found_copy_group.localCloneCopygroupId is not None:
            pair_elements = found_copy_group.localCloneCopygroupId.split(",")
            if (
                spec.primary_volume_device_group_name is not None
                or spec.secondary_volume_device_group_name is not None
            ):
                if spec.primary_volume_device_group_name != pair_elements[1]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_SPLIT_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_PVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[1]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                elif spec.secondary_volume_device_group_name != pair_elements[2]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_SPLIT_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_SVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[2]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

        splitted_copy_group = self.gateway.split_local_copy_group(
            spec, found_copy_group.localCloneCopygroupId
        )
        self.logger.writeDebug(f"splitted_copy_group=  {splitted_copy_group}")
        self.connection_info.changed = True
        return self.gateway.get_one_copygroup_info_by_name(spec, True)

    @log_entry_exit
    def resync_local_copy_group(self, spec):
        spec.name = spec.copy_group_name
        found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec, True)
        if found_copy_group is None:
            msg = VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NOT_FOUND.value.format(
                spec.copy_group_name
            )
            logger.writeError(msg)
            raise Exception(msg)
        elif found_copy_group is not None:
            if found_copy_group.copyPairs:
                for copy_pair in found_copy_group.copyPairs:
                    pvol_status = copy_pair.pvolStatus
                    svol_status = copy_pair.svolStatus
                    if (
                        pvol_status == "PAIR"
                        and svol_status == "PAIR"
                        # and spec.do_failback is None
                        # and spec.is_consistency_group is None
                        # and spec.fence_level is None
                        # and spec.copy_pace is None
                    ):
                        return found_copy_group

            if found_copy_group.localCloneCopygroupId is not None:
                pair_elements = found_copy_group.localCloneCopygroupId.split(",")
                if (
                    spec.primary_volume_device_group_name is not None
                    or spec.secondary_volume_device_group_name is not None
                ):
                    if spec.primary_volume_device_group_name != pair_elements[1]:
                        err_msg = (
                            VSPCopyGroupsValidateMsg.GROUP_RESYNC_FAILED.value
                            + VSPCopyGroupsValidateMsg.NO_PVOL_DEVICE_NAME_FOUND.value.format(
                                spec.copy_group_name, pair_elements[1]
                            )
                        )
                        logger.writeError(err_msg)
                        raise ValueError(err_msg)
                    elif spec.secondary_volume_device_group_name != pair_elements[2]:
                        err_msg = (
                            VSPCopyGroupsValidateMsg.GROUP_RESYNC_FAILED.value
                            + VSPCopyGroupsValidateMsg.NO_SVOL_DEVICE_NAME_FOUND.value.format(
                                spec.copy_group_name, pair_elements[2]
                            )
                        )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

        resync_copy_group = self.gateway.resync_local_copy_group(
            spec, found_copy_group.localCloneCopygroupId
        )
        self.logger.writeDebug(f"resync_copy_group=  {resync_copy_group}")
        self.connection_info.changed = True
        return self.gateway.get_one_copygroup_info_by_name(spec, True)

    @log_entry_exit
    def restore_local_copy_group(self, spec):
        spec.name = spec.copy_group_name
        found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec, True)
        if found_copy_group is None:
            msg = VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NOT_FOUND.value.format(
                spec.copy_group_name
            )
            raise Exception(msg)

        if found_copy_group.localCloneCopygroupId is not None:
            pair_elements = found_copy_group.localCloneCopygroupId.split(",")
            if (
                spec.primary_volume_device_group_name is not None
                or spec.secondary_volume_device_group_name is not None
            ):
                if spec.primary_volume_device_group_name != pair_elements[1]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_RESTORE_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_PVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[1]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                elif spec.secondary_volume_device_group_name != pair_elements[2]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_RESTORE_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_SVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[2]
                        )
                    )
                logger.writeError(err_msg)
                raise ValueError(err_msg)

        restore_local_copy_group = self.gateway.restore_local_copy_group(
            spec, found_copy_group.localCloneCopygroupId
        )
        self.logger.writeDebug(f"restore_local_copy_group=  {restore_local_copy_group}")
        self.connection_info.changed = True
        return self.gateway.get_one_copygroup_info_by_name(spec, True)

    @log_entry_exit
    def migrate_local_copy_group(self, spec):
        spec.name = spec.copy_group_name
        found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec, True)
        if found_copy_group is None:
            msg = VSPCopyGroupsValidateMsg.LOCAL_COPY_GROUP_NOT_FOUND.value.format(
                spec.copy_group_name
            )
            logger.writeError(msg)
            raise Exception(msg)

        if found_copy_group.localCloneCopygroupId is not None:
            pair_elements = found_copy_group.localCloneCopygroupId.split(",")
            if (
                spec.primary_volume_device_group_name is not None
                or spec.secondary_volume_device_group_name is not None
            ):
                if spec.primary_volume_device_group_name != pair_elements[1]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_SPLIT_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_PVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[1]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                elif spec.secondary_volume_device_group_name != pair_elements[2]:
                    err_msg = (
                        VSPCopyGroupsValidateMsg.GROUP_SPLIT_FAILED.value
                        + VSPCopyGroupsValidateMsg.NO_SVOL_DEVICE_NAME_FOUND.value.format(
                            spec.copy_group_name, pair_elements[2]
                        )
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)

        migrated_copy_group = self.gateway.migrate_local_copy_group(
            spec, found_copy_group.localCloneCopygroupId
        )
        self.logger.writeDebug(f"migrated_copy_group=  {migrated_copy_group}")
        self.connection_info.changed = True
        return self.gateway.get_one_copygroup_info_by_name(spec, True)
