try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.hv_messages import MessageID
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import ConnectionTypes
    from ..message.vsp_copy_group_msgs import (
        VSPCopyGroupsValidateMsg,
        CopyGroupFailedMsg,
    )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.hv_messages import MessageID
    from common.ansible_common import log_entry_exit
    from message.vsp_copy_group_msgs import VSPCopyGroupsValidateMsg, CopyGroupFailedMsg

logger = Log()


class VSPCopyGroupsProvisioner:

    def __init__(self, connection_info, serial=None):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_COPY_GROUPS
        )
        self.connection_info = connection_info

        self.gateway.set_storage_serial_number(serial)
        logger.writeDebug(f"PROV:serial={serial}")

    @log_entry_exit
    def get_primary_storage_device_id(self):
        try:
            response = self.gateway.get_primary_storage_device_id()
            logger.writeDebug(
                "PROV:get_primary_storage_device_id:response={}", response
            )
            return response
        except Exception as e:
            logger.writeError(MessageID.ERR_GetStorageID)
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def get_copy_groups(self, spec):
        try:
            if (
                spec.copy_group_name is not None
                and spec.should_include_remote_replication_pairs is True
            ):
                response = self.gateway.get_one_copygroup_info_by_name(spec, True)
                # In case no copy pairs in the copy group return copy group information.
                if response is None:
                    response = self.gateway.get_copy_group_by_name(spec)
            elif spec.copy_group_name:
                response = self.gateway.get_copy_group_by_name(spec)
            else:
                response = self.gateway.get_copy_groups(spec)
            logger.writeDebug("PROV:get_copy_groups:time={}", response)
            return response
        except Exception as e:
            logger.writeError(MessageID.ERR_GetCopyGroups)
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def delete_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            copy_group_exiting = self.gateway.get_copy_group_by_name(spec)
            if copy_group_exiting is None:
                return VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
                    spec.copy_group_name
                )

            self.connection_info.changed = True
            self.gateway.delete_copy_group(spec)
            return None
        else:
            err_msg = CopyGroupFailedMsg.NOT_SUPPORTED_FOR_UAI_GATEWAY.value.format(
                "delete"
            )
            logger.writeError(err_msg)
            raise Exception(err_msg)

    @log_entry_exit
    def split_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec)
            if found_copy_group is None:
                msg = VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
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
                            pvol_status == "PSUS"
                            and svol_status == "SSUS"
                            and spec.is_svol_writable is None
                            and spec.do_pvol_write_protect is None
                            and spec.do_data_suspend is None
                        ):
                            return found_copy_group
            splitted_copy_group = self.gateway.split_copy_group(spec)
            self.logger.writeDebug(f"splitted_copy_group=  {splitted_copy_group}")
            self.connection_info.changed = True
            return self.gateway.get_one_copygroup_info_by_name(spec)
        else:
            err_msg = CopyGroupFailedMsg.NOT_SUPPORTED_FOR_UAI_GATEWAY.value.format(
                "split"
            )
            logger.writeError(err_msg)
            raise Exception(err_msg)

    @log_entry_exit
    def swap_split_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            found_copy_group = self.gateway.get_copy_group_by_name(spec)
            if found_copy_group is None:
                msg = VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
                    spec.copy_group_name
                )
                raise Exception(msg)
            swap_splitted_copy_group = self.gateway.swap_split_copy_group(spec)
            self.logger.writeDebug(
                f"swap_splitted_copy_group=  {swap_splitted_copy_group}"
            )
            self.connection_info.changed = True
            return self.gateway.get_one_copygroup_info_by_name(spec)

    @log_entry_exit
    def resync_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec)
            if found_copy_group is None:
                msg = VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
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
                            and spec.do_failback is None
                            and spec.is_consistency_group is None
                            and spec.fence_level is None
                            and spec.copy_pace is None
                        ):
                            return found_copy_group
            resync_copy_group = self.gateway.resync_copy_group(spec)
            self.logger.writeDebug(f"resync_copy_group=  {resync_copy_group}")
            self.connection_info.changed = True
            return self.gateway.get_one_copygroup_info_by_name(spec)

    @log_entry_exit
    def swap_resync_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            found_copy_group = self.gateway.get_copy_group_by_name(spec)
            if found_copy_group is None:
                msg = VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
                    spec.copy_group_name
                )
                raise Exception(msg)
            swap_resync_copy_group = self.gateway.swap_resync_copy_group(spec)
            self.logger.writeDebug(f"swap_resync_copy_group=  {swap_resync_copy_group}")
            self.connection_info.changed = True
            return self.gateway.get_one_copygroup_info_by_name(spec)

    @log_entry_exit
    def takeover_copy_group(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            if spec.replication_type != "UR" and spec.replication_type is not None:
                err_msg = CopyGroupFailedMsg.NOT_SUPPORTED_FOR_TC_GAD.value.format(
                    "takeover"
                )
                logger.writeError(err_msg)
                raise Exception(err_msg)
            # found_copy_group = self.gateway.get_one_copygroup_info_by_name(spec)
            # if found_copy_group is None:
            #     msg = VSPCopyGroupsValidateMsg.COPY_GROUP_NOT_FOUND.value.format(
            #         spec.copy_group_name
            #     )
            #     logger.writeError(msg)
            #     raise Exception(msg)
            # elif found_copy_group is not None:
            #     if found_copy_group.copyPairs:
            #         for copy_pair in found_copy_group.copyPairs:
            #             pvol_status = copy_pair.pvolStatus
            #             svol_status = copy_pair.svolStatus
            #             if (
            #                 pvol_status == "PSUS"
            #                 and svol_status == "SSUS"
            #                 and spec.is_svol_writable is None
            #                 and spec.do_pvol_write_protect is None
            #                 and spec.do_data_suspend is None
            #             ):
            #                 return found_copy_group
            takenover_copy_group = self.gateway.takeover_copy_group(spec)
            self.logger.writeDebug(f"takenover_copy_group=  {takenover_copy_group}")
            self.connection_info.changed = True
            return takenover_copy_group  # self.gateway.get_one_copygroup_info_by_name(spec)
        else:
            err_msg = CopyGroupFailedMsg.NOT_SUPPORTED_FOR_UAI_GATEWAY.value.format(
                "takeover"
            )
            logger.writeError(err_msg)
            raise Exception(err_msg)
