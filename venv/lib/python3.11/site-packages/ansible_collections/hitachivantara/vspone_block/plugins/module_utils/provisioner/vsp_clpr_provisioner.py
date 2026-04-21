try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..model.vsp_clpr_models import (
        ClprInfoList,
    )
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


class VSPClprProvisioner:

    def __init__(self, connection_info, serial=None):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_CLPR
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
    def get_all_clprs(self, spec):
        try:
            if spec.clpr_id is not None:
                response = self.gateway.get_one_clpr_by_id(spec.clpr_id)
            else:
                response = self.gateway.get_all_clprs(spec)
            logger.writeDebug("PROV:get_all_clprs:time={}", response)
            return response
        except Exception as e:
            # logger.writeError(MessageID.ERR_GetCopyGroups)
            logger.writeDebug(str(e))
            raise (e)

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
    def create_clpr(self, spec):
        """Create a new CLPR"""
        try:
            # First check if CLPR already exists
            all_clprs = self.gateway.get_all_clprs(spec)
            if isinstance(all_clprs, ClprInfoList):
                for clpr in all_clprs.data:
                    if clpr.clprName == spec.clpr_name:
                        logger.writeDebug(f"CLPR {spec.clpr_name} already exists")
                        return clpr

            # Create new CLPR if it doesn't exist
            response = self.gateway.create_clpr(spec)
            if response:
                # Get all CLPRs and filter the one we just created
                all_clprs = self.gateway.get_all_clprs(spec)
                if isinstance(all_clprs, ClprInfoList):
                    for clpr in all_clprs.data:
                        if clpr.clprName == spec.clpr_name:
                            self.connection_info.changed = True
                            return clpr
            return None
        except Exception as e:
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def update_clpr(self, spec):
        """Update CLPR configuration"""
        try:
            if spec.clpr_id is None:
                raise Exception("CLPR ID cannot be None for update operation")

            # First check if CLPR exists
            all_clprs = self.gateway.get_all_clprs(spec)
            existing_clpr = None

            if isinstance(all_clprs, ClprInfoList):
                for clpr in all_clprs.data:
                    if clpr.clprId == spec.clpr_id:
                        existing_clpr = clpr
                        break

            if not existing_clpr:
                raise Exception(f"CLPR with ID {spec.clpr_id} does not exist")

            # Check if update is needed
            update_needed = False
            if spec.clpr_name and spec.clpr_name != existing_clpr.clprName:
                update_needed = True
            if (
                spec.cache_memory_capacity_mb
                and spec.cache_memory_capacity_mb != existing_clpr.cacheMemoryCapacity
            ):
                update_needed = True

            if not update_needed:
                logger.writeDebug("No update needed, returning existing CLPR")
                return existing_clpr

            # Proceed with update if needed
            response = self.gateway.update_clpr(spec)
            if response:
                # Get all CLPRs and filter the one we just created
                all_clprs = self.gateway.get_all_clprs(spec)
                if isinstance(all_clprs, ClprInfoList):
                    for clpr in all_clprs.data:
                        if clpr.clprId == spec.clpr_id:
                            self.connection_info.changed = True
                            return clpr
                self.connection_info.changed = True
            return response
        except Exception as e:
            logger.writeDebug(str(e))
            raise (e)

    @log_entry_exit
    def delete_clpr(self, spec):
        """Delete a CLPR"""
        try:
            if spec.clpr_id is None:
                raise Exception("CLPR ID cannot be None for delete operation")

                # First check if CLPR exists
            all_clprs = self.gateway.get_all_clprs(spec)
            existing_clpr = None

            if isinstance(all_clprs, ClprInfoList):
                for clpr in all_clprs.data:
                    if clpr.clprId == spec.clpr_id:
                        existing_clpr = clpr
                        break

            if not existing_clpr:
                raise Exception(f"CLPR with ID {spec.clpr_id} does not exist")

            response = self.gateway.delete_clpr(spec)
            if response:
                self.connection_info.changed = True
            return None
        except Exception as e:
            logger.writeDebug(str(e))
            raise (e)
