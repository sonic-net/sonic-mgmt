try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..model.vsp_storage_system_models import (
        VSPPrimaryAndSecondarySyslogServer,
        VSPStorageSystemInfo,
        TotalCapacitiesPfrest,
    )
    from ..common.ansible_common import log_entry_exit, convert_block_capacity
    from ..model.common_base_models import VSPCommonInfo
    from ..common.vsp_constants import set_basic_storage_details
    from ..common.uaig_constants import UAIGStorageHealthStatus
    from ..message.common_msgs import CommonMessage


except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from model.vsp_storage_system_models import (
        VSPPrimaryAndSecondarySyslogServer,
        VSPStorageSystemInfo,
        TotalCapacitiesPfrest,
    )
    from common.ansible_common import log_entry_exit, convert_block_capacity
    from model.common_base_models import VSPCommonInfo
    from common.vsp_constants import set_basic_storage_details
    from common.uaig_constants import UAIGStorageHealthStatus
    from message.common_msgs import CommonMessage

logger = Log()


class VSPStorageSystemProvisioner:

    def __init__(self, connection_info):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_STORAGE_SYSTEM
        )
        self.connection_info = connection_info
        self.serial = None
        self.resource_id = None

    @log_entry_exit
    def get_syslog_servers(self):
        pfrest_syslog_servers = self.gateway.get_syslog_servers()
        syslog = {}
        syslog_servers = []
        primary_syslog_server = {}
        secondary_syslog_server = {}
        if pfrest_syslog_servers.primarySyslogServer is not None:
            pfrest_primary_syslog_server = VSPPrimaryAndSecondarySyslogServer(
                **pfrest_syslog_servers.primarySyslogServer
            )
            if pfrest_primary_syslog_server.isEnabled:
                primary_syslog_server["id"] = 0
                primary_syslog_server["syslog_server_address"] = (
                    pfrest_primary_syslog_server.ipAddress
                    if pfrest_primary_syslog_server.ipAddress is not None
                    else ""
                )
                primary_syslog_server["syslog_server_port"] = (
                    str(pfrest_primary_syslog_server.port)
                    if pfrest_primary_syslog_server.port is not None
                    else ""
                )
                syslog_servers.append(primary_syslog_server)
        if pfrest_syslog_servers.secondarySyslogServer is not None:
            pfrest_secondary_syslog_server = VSPPrimaryAndSecondarySyslogServer(
                **pfrest_syslog_servers.secondarySyslogServer
            )
            if pfrest_secondary_syslog_server.isEnabled:
                secondary_syslog_server["id"] = 1
                secondary_syslog_server["syslog_server_address"] = (
                    pfrest_secondary_syslog_server.ipAddress
                    if pfrest_primary_syslog_server.ipAddress is not None
                    else ""
                )
                secondary_syslog_server["syslog_server_port"] = (
                    str(pfrest_secondary_syslog_server.port)
                    if pfrest_primary_syslog_server.port is not None
                    else ""
                )
                syslog_servers.append(secondary_syslog_server)
        syslog["syslog_servers"] = syslog_servers
        syslog["detailed"] = pfrest_syslog_servers.isDetailed
        return syslog

    @log_entry_exit
    def get_storage_pools(self):
        pools = self.gateway.get_pools()
        storage_pools = []
        for pool in pools.data:
            tmp_pool = {}
            tmp_pool["pool_id"] = pool.poolId if pool.poolId is not None else -1
            tmp_pool["name"] = pool.poolName if pool.poolName is not None else ""
            tmp_pool["depletion_threshold_rate"] = (
                pool.depletionThreshold if pool.depletionThreshold is not None else -1
            )
            tmp_pool["free_capacity"] = (
                pool.availableVolumeCapacity * 1024 * 1024
                if pool.availableVolumeCapacity is not None
                else -1
            )
            tmp_pool["free_capacity_in_units"] = (
                convert_block_capacity(pool.availableVolumeCapacity * 1024 * 1024, 1)
                if pool.availableVolumeCapacity is not None
                else ""
            )
            if pool.poolStatus == "POLN":
                tmp_pool["status"] = "NORMAL"
            elif pool.poolStatus == "POLF":
                tmp_pool["status"] = "OVER_THRESHOLD"
            elif pool.poolStatus == "POLS":
                tmp_pool["status"] = "SUSPENDED"
            elif pool.poolStatus == "POLE":
                tmp_pool["status"] = "FAILURE"
            else:
                tmp_pool["status"] = "UNKNOWN"

            tmp_pool["subscription_limit_rate"] = (
                pool.virtualVolumeCapacityRate
                if pool.virtualVolumeCapacityRate is not None
                else -1
            )
            tmp_pool["total_capacity"] = (
                pool.totalPoolCapacity * 1024 * 1024
                if pool.totalPoolCapacity is not None
                else -1
            )
            tmp_pool["total_capacity_in_unit"] = (
                convert_block_capacity(pool.totalPoolCapacity * 1024 * 1024, 1)
                if pool.totalPoolCapacity is not None
                else ""
            )
            tmp_pool["type"] = pool.poolType if pool.poolType is not None else ""
            tmp_pool["utilization_rate"] = (
                pool.usedCapacityRate if pool.usedCapacityRate is not None else -1
            )
            if pool.poolType == "HTI":
                tmp_pool["virtual_volume_count"] = (
                    pool.snapshotCount if pool.snapshotCount is not None else -1
                )
            else:
                tmp_pool["virtual_volume_count"] = (
                    pool.locatedVolumeCount
                    if pool.locatedVolumeCount is not None
                    else -1
                )
            tmp_pool["warning_threshold_rate"] = (
                pool.warningThreshold if pool.warningThreshold is not None else -1
            )
            tmp_pool["resource_id"] = ""
            tmp_pool["ldev_ids"] = []
            tmp_pool["dp_volumes"] = []
            tmp_pool["replication_data_released_rate"] = -1
            tmp_pool["replication_depletion_alert_rate"] = -1
            tmp_pool["replication_usage_rate"] = -1
            tmp_pool["resource_group_id"] = -1
            tmp_pool["subscription_rate"] = -1
            tmp_pool["subscription_warning_rate"] = -1
            tmp_pool["deduplication_enabled"] = False

            storage_pools.append(tmp_pool)

        return storage_pools

    @log_entry_exit
    def get_current_storage_system_info(self):
        return self.gateway.get_current_storage_system_info()

    def populate_basic_storage_info(self):
        storage_info = self.get_current_storage_system_info()
        port_info = self.get_ports()
        first_port_wwn = None
        if len(port_info) > 0:
            first_port_wwn = port_info[0]["wwn"]
        basic_details = VSPCommonInfo(
            serialNumber=storage_info.serialNumber,
            model=storage_info.model,
            firstWWN=first_port_wwn,
            deviceID=storage_info.storageDeviceId,
        )
        set_basic_storage_details(basic_details)

    @log_entry_exit
    def get_ports(self):
        ports = self.gateway.get_ports()
        tmp_ports = []
        for port in ports.data:
            tmp_port = {}
            tmp_port["port_id"] = port.portId if port.portId is not None else ""
            tmp_port["type"] = port.portType if port.portType is not None else ""
            if port.portSpeed == "AUT":
                tmp_port["speed"] = "AUTO"
            elif port.portSpeed == "1G":
                tmp_port["speed"] = "1GBPS"
            elif port.portSpeed == "2G":
                tmp_port["speed"] = "2GBPS"
            elif port.portSpeed == "4G":
                tmp_port["speed"] = "4GBPS"
            elif port.portSpeed == "8G":
                tmp_port["speed"] = "8GBPS"
            elif port.portSpeed == "10G":
                tmp_port["speed"] = "10GBPS"
            elif port.portSpeed == "16G":
                tmp_port["speed"] = "16GBPS"
            else:
                tmp_port["speed"] = "UNKNOWN"

            tmp_port["wwn"] = port.wwn if port.wwn is not None else ""
            if port.portConnection == "FCAL":
                tmp_port["connection_type"] = "FC_AL"
            elif port.portConnection == "PtoP":
                tmp_port["connection_type"] = "P_TO_P"
            else:
                tmp_port["connection_type"] = "UNKNOWN"
            tmp_port["fabric_on"] = (
                port.fabricMode if port.fabricMode is not None else False
            )
            if port.portMode == "FC-NVMe":
                tmp_port["mode"] = "NVMe"
            elif port.portMode == "FCP-SCSI":
                tmp_port["mode"] = "SCSI"
            else:
                tmp_port["mode"] = "UNKNOWN"
            tmp_port["is_security_enabled"] = (
                port.lunSecuritySetting
                if port.lunSecuritySetting is not None
                else False
            )
            if len(port.portAttributes) == 1:
                if port.portAttributes[0] == "TAR":
                    tmp_port["attribute"] = "TARGET"
                elif port.portAttributes[0] == "MCU":
                    tmp_port["attribute"] = "INITIATOR"
                elif port.portAttributes[0] == "RCU":
                    tmp_port["attribute"] = "RCU_TARGET"
                elif port.portAttributes[0] == "ELUN":
                    tmp_port["attribute"] = "EXTERNAL"
            elif len(port.portAttributes) > 1:
                tmp_port["attribute"] = "BI_DIRECTIONAL"
            else:
                tmp_port["attribute"] = "UNKNOWN"
            tmp_port["resource_group_id"] = -1
            tmp_port["resource_id"] = ""
            # tmp_port["tags"] = []
            tmp_port["iscsi_port_ip_address"] = ""

            tmp_ports.append(tmp_port)

        return tmp_ports

    @log_entry_exit
    def get_quorum_disks(self):
        pfrest_quorum_disks = self.gateway.get_quorum_disks()
        tmp_quorum_disks = []
        for quorum_disk in pfrest_quorum_disks.data:
            tmp_quorum_disk = {}
            tmp_quorum_disk["device_id"] = (
                quorum_disk.remoteSerialNumber
                if quorum_disk.remoteSerialNumber is not None
                else ""
            )
            tmp_quorum_disk["logical_unit_id"] = (
                quorum_disk.ldevId if quorum_disk.ldevId is not None else -1
            )
            tmp_quorum_disk["quorum_disk_id"] = (
                quorum_disk.quorumDiskId if quorum_disk.quorumDiskId is not None else -1
            )
            tmp_quorum_disk["status"] = (
                quorum_disk.status if quorum_disk.status is not None else ""
            )
            tmp_quorum_disk["timeout"] = (
                quorum_disk.readResponseGuaranteedTime
                if quorum_disk.readResponseGuaranteedTime is not None
                else -1
            )
            tmp_quorum_disk["device_type"] = ""
            tmp_quorum_disk["grid"] = ""

            tmp_quorum_disks.append(tmp_quorum_disk)
        return tmp_quorum_disks

    @log_entry_exit
    def get_journal_pools(self):
        detailed_journal_pools = self.gateway.get_journal_pools("detail")
        basic_journal_pools = self.gateway.get_journal_pools("basic")
        tmp_journal_pools = []
        for detailed_journal in detailed_journal_pools.data:
            for basic_journal in basic_journal_pools.data:
                if detailed_journal.journalId == basic_journal.journalId:
                    tmp_journal_pool = {}

                    tmp_journal_pool["journal_id"] = detailed_journal.journalId
                    tmp_journal_pool["journal_status"] = basic_journal.journalStatus

                    tmp_journal_pool["data_overflow_watch_seconds"] = (
                        detailed_journal.dataOverflowWatchInSeconds
                    )
                    tmp_journal_pool["is_cache_mode_enabled"] = (
                        detailed_journal.isCacheModeEnabled
                    )

                    tmp_journal_pool["is_inflow_control_enabled"] = (
                        detailed_journal.isInflowControlEnabled
                    )
                    tmp_journal_pool["mp_blade_id"] = detailed_journal.mpBladeId
                    tmp_journal_pool["total_capacity"] = int(
                        basic_journal.blockCapacity / 2 * 1024
                    )
                    tmp_journal_pool["mirrorUnitId"] = -1
                    tmp_journal_pool["usageRate"] = -1
                    tmp_journal_pool["logical_unit_ids"] = []
                    tmp_journal_pool["logical_unit_ids_hex_format"] = []
                    tmp_journal_pool["mirror_unit_id"] = -1
                    tmp_journal_pool["timer_type"] = ""
                    tmp_journal_pool["type"] = ""

                    tmp_journal_pools.append(tmp_journal_pool)
                    break
        return tmp_journal_pools

    @log_entry_exit
    def get_free_luns(self):
        pfrest_free_luns = self.gateway.get_free_luns()
        ldevIds = []
        for lun in pfrest_free_luns.data:
            ldevIds.append(lun.ldevId)
        return ldevIds

    @log_entry_exit
    def get_storage_system(self, serial_number, query):
        if serial_number is None:
            current_storage_system = self.gateway.get_current_storage_system_info()
            serial_number = current_storage_system.serialNumber

        # Get a list of storage system
        storage_systems = self.gateway.get_storage_systems()
        tmp_storage_info = {}
        for storage_system in storage_systems.data:
            if storage_system.serialNumber == int(serial_number):
                tmp_storage_info["model"] = (
                    storage_system.model if storage_system.model is not None else ""
                )
                tmp_storage_info["serial_number"] = (
                    str(storage_system.serialNumber)
                    if storage_system.serialNumber is not None
                    else ""
                )
                tmp_storage_info["controller_address"] = (
                    storage_system.svpIp if storage_system.svpIp is not None else ""
                )

                # Get the specified storage system
                specific_storage_system = self.gateway.get_storage_system(
                    storage_system.storageDeviceId
                )
                tmp_storage_info["microcode_version"] = (
                    specific_storage_system.detailDkcMicroVersion
                    if specific_storage_system.detailDkcMicroVersion is not None
                    else ""
                )

                try:
                    storage_capacity = self.gateway.get_storage_capacity()
                    total_storage_capacity = TotalCapacitiesPfrest(
                        **storage_capacity.total
                    )
                    if total_storage_capacity.freeSpace is not None:
                        tmp_storage_info["total_capacity"] = convert_block_capacity(
                            total_storage_capacity.totalCapacity * 1024, 1
                        )
                        tmp_storage_info["total_capacity_in_mb"] = int(
                            total_storage_capacity.totalCapacity / 1024
                        )
                    else:
                        tmp_storage_info["total_capacity"] = ""
                        tmp_storage_info["total_capacity_in_mb"] = -1
                    if total_storage_capacity.freeSpace is not None:
                        tmp_storage_info["free_capacity"] = convert_block_capacity(
                            total_storage_capacity.freeSpace * 1024, 1
                        )
                        tmp_storage_info["free_capacity_in_mb"] = int(
                            total_storage_capacity.freeSpace / 1024
                        )
                    else:
                        tmp_storage_info["free_capacity"] = ""
                        tmp_storage_info["free_capacity_in_mb"] = -1
                except Exception as err:
                    # Some storage models do not support capacity feature.
                    # So set value of total and free capacities to invalid values.
                    API_MSG = (
                        "The API is not supported for the specified storage system"
                    )
                    API_MSG2 = (
                        "The microcode version of the storage system might be incorrect"
                    )
                    if isinstance(err.args[0], str) and (
                        API_MSG in err.args[0] or API_MSG2 in err.args[0]
                    ):
                        tmp_storage_info["total_capacity"] = ""
                        tmp_storage_info["free_capacity"] = ""
                        tmp_storage_info["total_capacity_in_mb"] = -1
                        tmp_storage_info["free_capacity_in_mb"] = -1
                    else:
                        logger.writeException(err)
                        raise  # Retrow the exception
                # Get syslog servers
                tmp_storage_info["syslog_config"] = self.get_syslog_servers()
                tmp_storage_info["total_efficiency"] = (
                    self.gateway.get_total_efficiency_of_storage_system().camel_to_snake_dict()
                )
                date_time = self.gateway.get_storage_systems_date_and_time()
                tmp_storage_info["system_date_time"] = (
                    date_time.camel_to_snake_dict() if date_time else {}
                )

                # Set default values
                tmp_storage_info["management_address"] = ""
                tmp_storage_info["resource_state"] = ""
                tmp_storage_info["health_status"] = ""
                tmp_storage_info["operational_status"] = ""
                tmp_storage_info["free_gad_consistency_group_id"] = -1
                tmp_storage_info["free_local_clone_consistency_group_id"] = -1
                tmp_storage_info["free_remote_clone_consistency_group_id"] = -1

                external_group_number_range = {}
                external_group_number_range["is_valid"] = False
                external_group_number_range["max_value"] = -1
                external_group_number_range["min_value"] = -1
                external_group_sub_number_range = {}
                external_group_sub_number_range["is_valid"] = False
                external_group_sub_number_range["max_value"] = -1
                external_group_sub_number_range["min_value"] = -1
                parity_group_number_range = {}
                parity_group_number_range["is_valid"] = False
                parity_group_number_range["max_value"] = -1
                parity_group_number_range["min_value"] = -1
                parity_group_sub_number_range = {}
                parity_group_sub_number_range["is_valid"] = False
                parity_group_sub_number_range["max_value"] = -1
                parity_group_sub_number_range["min_value"] = -1
                device_limits = {}
                device_limits["external_group_number_range"] = (
                    external_group_number_range
                )
                device_limits["external_group_sub_number_range"] = (
                    external_group_sub_number_range
                )
                device_limits["parity_group_number_range"] = parity_group_number_range
                device_limits["parity_group_sub_number_range"] = (
                    parity_group_sub_number_range
                )
                tmp_storage_info["device_limits"] = device_limits
                tmp_storage_info["health_description"] = ""

                if query:
                    if (
                        "pools" in query
                        or "ports" in query
                        or "quorumdisks" in query
                        or "journalPools" in query
                        or "freeLogicalUnitList" in query
                    ):
                        err_msg = CommonMessage.PORTS_JOURNALS_LUNS.value
                        logger.writeError(err_msg)
                        raise ValueError(err_msg)
                    # if "pools" in query:
                    #     tmp_storage_info["storage_pools"] = self.get_storage_pools()

                    # if "ports" in query:
                    #     tmp_storage_info["ports"] = self.get_ports()

                    # if "quorumdisks" in query:
                    #     tmp_storage_info["quorum_disks"] = self.get_quorum_disks()

                    # if "journalPools" in query:
                    #     tmp_storage_info["journal_pools"] = self.get_journal_pools()

                    # if "freeLogicalUnitList" in query:
                    #     tmp_storage_info["free_logical_unit_list"] = {}
                    #     tmp_ldev_ids = {}
                    #     ldevIds = self.get_free_luns()
                    #     tmp_ldev_ids["ldev_ids"] = ldevIds
                    #     tmp_storage_info["free_logical_unit_list"] = tmp_ldev_ids

                    if "time_zone" in query:
                        time_zones_info = self.gateway.get_storage_systems_time_zone()
                        tmp_storage_info["time_zones_info"] = (
                            time_zones_info.data_to_snake_case_list()
                            if time_zones_info
                            else "Time zone info not available on this storage system."
                        )
                return VSPStorageSystemInfo(**tmp_storage_info)

        err_msg = CommonMessage.SERIAL_NUMBER_NOT_FOUND.value.format(serial_number)
        logger.writeError(err_msg)
        raise ValueError(err_msg)

    def set_storage_system_date_time(self, date_time_spec):
        """
        Set the storage system date and time.
        :param date_time: The date and time to set in ISO 8601 format.
        """
        self.gateway.set_storage_systems_time_zone(date_time_spec)
        self.connection_info.changed = True
        return (
            self.get_storage_system(None, None).camel_to_snake_dict(),
            "Storage system date and time updated successfully.",
        )

    @log_entry_exit
    def get_storage_ucp_system(self, serial):
        systems = self.gateway.get_ucp_systems()
        for system in systems.data:
            for storage in system.storageDevices:
                if storage.serialNumber == serial and (
                    storage.healthStatus == UAIGStorageHealthStatus.NORMAL
                    or storage.healthStatus == UAIGStorageHealthStatus.REFRESHING
                ):
                    return storage
        return None
