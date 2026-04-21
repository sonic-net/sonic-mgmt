try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import (
        log_entry_exit,
        convert_block_capacity,
        convert_to_mb,
    )
    from ..model.vsp_parity_group_models import VSPParityGroup, VSPParityGroups
    from ..common.hv_constants import ConnectionTypes
    from ..common.hv_log import Log
    from ..message.vsp_parity_group_msgs import VSPParityGroupValidateMsg

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import (
        log_entry_exit,
        convert_block_capacity,
        convert_to_mb,
    )
    from model.vsp_parity_group_models import VSPParityGroup, VSPParityGroups
    from common.hv_constants import ConnectionTypes
    from common.hv_log import Log
    from message.vsp_parity_group_msgs import VSPParityGroupValidateMsg

logger = Log()


class VSPParityGroupProvisioner:

    def __init__(self, connection_info):
        self.logger = Log()
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_PARITY_GROUP
        )
        self.serial = None
        self.resource_id = None
        self.connection_info = connection_info
        self.gateway.resource_id = self.resource_id

    @log_entry_exit
    def format_parity_group(self, parity_group):
        pg_dict = {}
        pg_dict["parityGroupId"] = parity_group.parityGroupId
        if parity_group.availableVolumeCapacity is not None:
            pg_dict["freeCapacity"] = (
                convert_block_capacity(
                    parity_group.availableVolumeCapacity * 1024 * 1024 * 1024, 1
                )
                if parity_group.availableVolumeCapacity != 0
                else "0"
            )
            mb_capacity = convert_to_mb(pg_dict["freeCapacity"])
            pg_dict["freeCapacity_mb"] = mb_capacity
        else:
            None
        if parity_group.physicalCapacity is not None:
            pg_dict["totalCapacity"] = (
                convert_block_capacity(
                    parity_group.physicalCapacity * 1024 * 1024 * 1024, 1
                )
                if parity_group.physicalCapacity != 0
                else "0"
            )
            mb_capacity = convert_to_mb(pg_dict["totalCapacity"])
            pg_dict["totalCapacity_mb"] = mb_capacity
        else:
            if parity_group.totalCapacity is not None:
                pg_dict["totalCapacity"] = (
                    convert_block_capacity(
                        parity_group.totalCapacity * 1024 * 1024 * 1024, 1
                    )
                    if parity_group.totalCapacity != 0
                    else "0"
                )
                mb_capacity = convert_to_mb(pg_dict["totalCapacity"])
                pg_dict["totalCapacity_mb"] = mb_capacity
            else:
                None
        pg_dict["ldevIds"] = []
        count_query = "count={}".format(16384)
        pg_query = "parityGroupId={}".format(parity_group.parityGroupId)
        pg_vol_query = "?" + count_query + "&" + pg_query
        ldevs = self.gateway.get_ldevs(pg_vol_query)
        for ldev in ldevs.data:
            pg_dict["ldevIds"].append(ldev.ldevId)
        pg_dict["raidLevel"] = parity_group.raidLevel
        pg_dict["driveType"] = parity_group.driveTypeName
        pg_dict["copybackMode"] = parity_group.isCopyBackModeEnabled
        pg_dict["isAcceleratedCompression"] = (
            parity_group.isAcceleratedCompressionEnabled
        )
        pg_dict["isEncryptionEnabled"] = parity_group.isEncryptionEnabled
        pg_dict["clprId"] = parity_group.clprId
        return pg_dict

    @log_entry_exit
    def format_external_parity_group(self, external_parity_group):
        pg_dict = {}
        pg_dict["parityGroupId"] = "E" + external_parity_group.externalParityGroupId
        if external_parity_group.availableVolumeCapacity is not None:
            if external_parity_group.availableVolumeCapacity != 0:
                pg_dict["freeCapacity"] = convert_block_capacity(
                    external_parity_group.availableVolumeCapacity * 1024 * 1024 * 1024,
                    1,
                )
                mb_capacity = convert_to_mb(pg_dict["freeCapacity"])
                pg_dict["freeCapacity_mb"] = mb_capacity
            else:
                pg_dict["freeCapacity"] = "0"
                pg_dict["freeCapacity_mb"] = "0"
        else:
            pg_dict["freeCapacity"] = None
        total_capacity = 0
        if external_parity_group.spaces is not None:
            if len(external_parity_group.spaces) > 0:
                for space in external_parity_group.spaces:
                    if space.lbaSize is not None:
                        if space.lbaSize.startswith("0x"):
                            total_capacity += int(space.lbaSize[2:], 16) * 512
                        else:
                            total_capacity += int(space.lbaSize, 16) * 512
                    else:
                        total_capacity = -1
            else:
                total_capacity = 0
        else:
            if external_parity_group.availableVolumeCapacity is not None:
                if (
                    external_parity_group.availableVolumeCapacity != 0
                    and external_parity_group.usedCapacityRate != 100
                ):
                    total_capacity = (
                        external_parity_group.availableVolumeCapacity
                        * 1024
                        * 1024
                        * 1024
                        * 100
                    ) / (100 - external_parity_group.usedCapacityRate)
                else:
                    total_capacity = 0
            else:
                total_capacity = -1
        if total_capacity != 0:
            pg_dict["totalCapacity"] = (
                convert_block_capacity(total_capacity, 1)
                if total_capacity != -1
                else None
            )
            mb_capacity = convert_to_mb(pg_dict["totalCapacity"])
            pg_dict["totalCapacity_mb"] = mb_capacity
        else:
            pg_dict["totalCapacity"] = "0"
            pg_dict["totalCapacity_mb"] = "0"
        return pg_dict

    @log_entry_exit
    def get_all_parity_groups(self):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            tmp_parity_groups = []
            # Get a list of parity groups
            parity_groups = self.gateway.get_all_parity_groups()
            for parity_group in parity_groups.data:
                tmp_parity_groups.append(
                    VSPParityGroup(**self.format_parity_group(parity_group))
                )
            # Get a list of external parity groups
            external_parity_groups = self.gateway.get_all_external_parity_groups()
            for external_parity_group in external_parity_groups.data:
                tmp_parity_groups.append(
                    VSPParityGroup(
                        **self.format_external_parity_group(external_parity_group)
                    )
                )

            return VSPParityGroups(tmp_parity_groups)
        else:
            parity_groups = self.gateway.get_all_parity_groups()
            return VSPParityGroups(
                data=[VSPParityGroup(**pg.to_dict()) for pg in parity_groups.data]
            )

    @log_entry_exit
    def get_parity_group(self, pg_id):
        if pg_id.strip().startswith("E"):
            external_parity_group = self.gateway.get_external_parity_group(pg_id[1:])
            return VSPParityGroup(
                **self.format_external_parity_group(external_parity_group)
            )
        else:
            try:
                parity_group = self.gateway.get_parity_group(pg_id)
                return VSPParityGroup(**self.format_parity_group(parity_group))
            except Exception as e:
                if "Specified object does not exist" in str(e):
                    err_msg = VSPParityGroupValidateMsg.NO_PARITY_GROUP_ID.value.format(
                        pg_id
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    raise (e)

    @log_entry_exit
    def direct_get_parity_group_by_id(self, pg_id):
        parity_groups = self.get_all_parity_groups()
        for parity_group in parity_groups.data:
            if parity_group.parityGroupId == pg_id:
                self.logger.writeDebug(
                    f"PV:parity group exists: parity_group =  {parity_group}"
                )
                return parity_group

    @log_entry_exit
    def create_parity_group(self, spec):
        parity_group_exits = self.direct_get_parity_group_by_id(spec.parity_group_id)
        self.logger.writeDebug(f"PV:parity_group: parity_group =  {parity_group_exits}")
        if parity_group_exits:
            return self.get_parity_group(spec.parity_group_id)
        response = self.gateway.create_parity_group(spec)
        self.logger.writeDebug(f"create_parity_group_direct result: {response}")
        self.connection_info.changed = True
        return self.get_parity_group(spec.parity_group_id)

    @log_entry_exit
    def delete_parity_group(self, spec):
        parity_group_exits = self.direct_get_parity_group_by_id(spec.parity_group_id)
        self.logger.writeDebug(f"PV:parity_group: parity_group =  {parity_group_exits}")
        if parity_group_exits is None:
            return VSPParityGroupValidateMsg.NO_PARITY_GROUP_ID.value.format(
                spec.parity_group_id
            )
        response = self.gateway.delete_parity_group(spec.parity_group_id)
        self.logger.writeDebug(f"delete_parity_group_direct result: {response}")
        self.connection_info.changed = True
        return "Parity Group {} deleted successfully".format(spec.parity_group_id)

    @log_entry_exit
    def update_parity_group(self, spec):
        parity_group_exits = self.get_parity_group(
            spec.parity_group_id
        )  # self.direct_get_parity_group_by_id(spec.parity_group_id)
        self.logger.writeDebug(f"PV:parity_group: parity_group =  {parity_group_exits}")
        if parity_group_exits is not None:
            if (
                parity_group_exits.isAcceleratedCompression
                == spec.is_accelerated_compression_enabled
            ):
                return parity_group_exits
        else:
            return VSPParityGroupValidateMsg.NO_PARITY_GROUP_ID.value.format(
                spec.parity_group_id
            )
        response = self.gateway.update_parity_group(spec)
        self.logger.writeDebug(f"update_parity_group_direct result: {response}")
        self.connection_info.changed = True
        return self.get_parity_group(spec.parity_group_id)

    @log_entry_exit
    def assign_parity_group_to_clpr(self, spec):
        parity_group_exits = self.get_parity_group(
            spec.parity_group_id
        )  # self.direct_get_parity_group_by_id(spec.parity_group_id)
        self.logger.writeDebug(f"PV:parity_group: parity_group =  {parity_group_exits}")
        if parity_group_exits is not None:
            if parity_group_exits.clprId == spec.clpr_id:
                return parity_group_exits
        else:
            return VSPParityGroupValidateMsg.NO_PARITY_GROUP_ID.value.format(
                spec.parity_group_id
            )
        response = self.gateway.assign_parity_group_to_clpr(spec)
        self.logger.writeDebug(f"assign_parity_group_to_clpr result: {response}")
        self.connection_info.changed = True
        return self.get_parity_group(spec.parity_group_id)

    @log_entry_exit
    def get_all_drives(self):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            drives = self.gateway.get_all_drives()
            self.logger.writeDebug(f"get_all_drives result: {drives}")
            for drive in drives["data"]:
                if "totalCapacity" in drive:
                    drive["totalCapacity"] = f"{drive['totalCapacity']} GB"
                    mb_capacity = convert_to_mb(drive["totalCapacity"])
                    drive["totalCapacity_mb"] = mb_capacity
            return drives

    @log_entry_exit
    def get_one_drive(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            try:
                drive = self.gateway.get_one_drive(spec)
                self.logger.writeDebug(f"get_one_drive result: {drive}")
                if "totalCapacity" in drive:
                    drive["totalCapacity"] = f"{drive['totalCapacity']} GB"
                    mb_capacity = convert_to_mb(drive["totalCapacity"])
                    drive["totalCapacity_mb"] = mb_capacity
                return drive
            except Exception as e:
                if "Specified object does not exist" in str(e):
                    err_msg = VSPParityGroupValidateMsg.NO_DISK_DRIVE_ID.value.format(
                        spec.drive_location_id
                    )
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    raise (e)

    @log_entry_exit
    def change_drive_setting(self, spec):
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            drive_exits = self.get_one_drive(spec)
            if drive_exits is None:
                return VSPParityGroupValidateMsg.NO_DISK_DRIVE_ID.value.format(
                    spec.drive_location_id
                )
            try:
                response = self.gateway.change_drive_setting(spec)
                self.logger.writeDebug(f"change_drive_setting result: {response}")
                self.connection_info.changed = True
                drive = self.get_one_drive(spec)
                if "totalCapacity" in drive:
                    drive["totalCapacity"] = f"{drive['totalCapacity']} GB"
                return drive
            except Exception as e:
                if "The API is not supported for the specified storage system" in str(
                    e
                ):
                    err_msg = VSPParityGroupValidateMsg.FEATURE_NOT_SUPPORTED.value
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                else:
                    raise (e)
