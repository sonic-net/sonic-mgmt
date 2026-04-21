try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes, StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        convert_block_capacity,
        convert_to_mb,
    )
    from ..common.hv_constants import ConnectionTypes
    from .vsp_parity_group_provisioner import VSPParityGroupProvisioner
    from ..message.vsp_storage_pool_msgs import (
        VSPStoragePoolValidateMsg,
        StoragePoolInfoMsg,
    )
    from .vsp_volume_prov import VSPVolumeProvisioner
    from ..model.vsp_volume_models import CreateVolumeSpec
    from ..common.vsp_constants import StoragePoolLimits
    from .vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from ..model.vsp_resource_group_models import VSPResourceGroupSpec
    from .vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from ..gateway.vsp_storage_pool_gateway import VSPStoragePoolDirectGateway

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes, StateValue
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        convert_block_capacity,
        convert_to_mb,
    )
    from common.hv_constants import ConnectionTypes
    from .vsp_parity_group_provisioner import VSPParityGroupProvisioner
    from message.vsp_storage_pool_msgs import (
        VSPStoragePoolValidateMsg,
        StoragePoolInfoMsg,
    )
    from .vsp_volume_prov import VSPVolumeProvisioner
    from model.vsp_volume_models import CreateVolumeSpec
    from common.vsp_constants import StoragePoolLimits
    from .vsp_resource_group_provisioner import VSPResourceGroupProvisioner
    from model.vsp_resource_group_models import VSPResourceGroupSpec
    from .vsp_storage_system_provisioner import VSPStorageSystemProvisioner
    from gateway.vsp_storage_pool_gateway import VSPStoragePoolDirectGateway


from enum import Enum
import math

DEDUP_MODELS = [
    "VSP G200",
    "VSP G400",
    "VSP F400",
    "VSP G600",
    "VSP F600",
    "VSP G800",
    "VSP F800",
    "VSP G400 with NAS module",
    "VSP G600 with NAS module",
    "VSP G800 with NAS module",
    "VSP G1000",
    "VSP G1500",
    "VSP F1500",
    "VSP N400",
    "VSP N600",
    "VSP N800",
]


class POOL_STATUS(Enum):
    POOLSTAT_UNKNOWN = 0
    POOLSTAT_NORMAL = 1
    POOLSTAT_OVERTHRESHOLD = 2
    POOLSTAT_SUSPENDED = 3
    POOLSTAT_FAILURE = 4
    POOLSTAT_SHRINKING = 5
    POOLSTAT_REGRESSED = 6
    POOLSTAT_DETACHED = 7


def get_dppool_subscription_rate(volume_used_capacity, total_capacity):
    if total_capacity == 0:
        return -1
    return math.ceil((volume_used_capacity / total_capacity) * 100.0)


logger = Log()


class VSPStoragePoolProvisioner:

    def __init__(self, connection_info):
        self.gateway = VSPStoragePoolDirectGateway(connection_info)
        self.vol_gw = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_VOLUME
        )
        self.connection_info = connection_info
        self.connection_type = connection_info.connection_type
        self.resource_id = None
        self.serial = None
        self.pg_info = None
        self.pg_prov = VSPParityGroupProvisioner(connection_info)
        self.vol_prov = VSPVolumeProvisioner(connection_info)
        if self.connection_type == ConnectionTypes.DIRECT:

            self.resource_group_prov = VSPResourceGroupProvisioner(connection_info)
        self.storage_system_prov = VSPStorageSystemProvisioner(connection_info)

    def format_storage_pool(self, pool):

        storage_pool_dict = {}
        storage_pool_dict["poolId"] = pool.poolId
        storage_pool_dict["name"] = pool.poolName
        storage_pool_dict["type"] = pool.poolType
        if pool.isShrinking:
            storage_pool_dict["status"] = "SHRINKING"
        else:
            if pool.poolStatus == "POLN":
                storage_pool_dict["status"] = "NORMAL"
            elif pool.poolStatus == "POLF":
                storage_pool_dict["status"] = "OVER_THRESHOLD"
            elif pool.poolStatus == "POLS":
                storage_pool_dict["status"] = "SUSPENDED"
            elif pool.poolStatus == "POLE":
                storage_pool_dict["status"] = "FAILURE"
            else:
                storage_pool_dict["status"] = "UNKNOWN"

        storage_pool_dict["utilizationRate"] = pool.usedCapacityRate
        storage_pool_dict["freeCapacity"] = pool.availableVolumeCapacity * 1024 * 1024
        storage_pool_dict["freeCapacityInUnits"] = convert_block_capacity(
            storage_pool_dict.get("freeCapacity", -1), 1
        )

        mb_capacity = convert_to_mb(storage_pool_dict["freeCapacityInUnits"])
        storage_pool_dict["free_capacity_in_mb"] = mb_capacity

        storage_pool_dict["totalCapacity"] = pool.totalPoolCapacity * 1024 * 1024
        storage_pool_dict["totalCapacityInUnit"] = convert_block_capacity(
            storage_pool_dict.get("totalCapacity", -1), 1
        )

        mb_capacity = convert_to_mb(storage_pool_dict["totalCapacityInUnit"])
        storage_pool_dict["total_capacity_in_mb"] = mb_capacity

        storage_pool_dict["warningThresholdRate"] = pool.warningThreshold
        storage_pool_dict["depletionThresholdRate"] = pool.depletionThreshold
        storage_pool_dict["subscriptionLimitRate"] = pool.virtualVolumeCapacityRate
        if pool.poolType == "HTI":
            storage_pool_dict["virtualVolumeCount"] = pool.snapshotCount
        else:
            storage_pool_dict["virtualVolumeCount"] = pool.locatedVolumeCount
        storage_pool_dict["subscriptionRate"] = -1
        if pool.poolType != "HTI":
            storage_pool_dict["subscriptionRate"] = get_dppool_subscription_rate(
                pool.totalLocatedCapacity, pool.totalPoolCapacity
            )

        storage_pool_dict["ldevIds"] = []
        count_query = "count={}".format(16384)
        pool_query = "poolId={}".format(pool.poolId)
        pool_vol_query = "?" + count_query + "&" + pool_query
        ldevs = self.gateway.get_ldevs(pool_vol_query)
        resource_grp_id = 0
        for ldev in ldevs.data:
            storage_pool_dict["ldevIds"].append(ldev.ldevId)
            if ldev.resourceGroupId > 0:
                resource_grp_id = ldev.resourceGroupId
        storage_pool_dict["resourceGroupId"] = resource_grp_id
        storage_pool_dict["dpVolumes"] = []
        count_query = "count={}".format(16384)
        ldev_option_query = "ldevOption=dpVolume"
        pool_query = "poolId={}".format(pool.poolId)
        dpvolume_query = "?" + count_query + "&" + ldev_option_query + "&" + pool_query
        dpvolumes = self.gateway.get_ldevs(dpvolume_query)
        for dpvol in dpvolumes.data:
            tmp_dpvol = {}
            tmp_dpvol["logicalUnitId"] = dpvol.ldevId
            tmp_dpvol["size"] = convert_block_capacity(dpvol.blockCapacity)
            storage_pool_dict["dpVolumes"].append(tmp_dpvol)
        return storage_pool_dict

    @log_entry_exit
    def fetch_dp_volumes(self, pool):
        """
        Fetches the data protection volumes for a given storage pool.
        This method is used to populate the dpVolumes attribute of the storage pool.
        """
        count_query = "count={}".format(16384)
        ldev_option_query = "ldevOption=dpVolume"
        pool_query = "poolId={}".format(pool.poolId)
        dpvolume_query = "?" + count_query + "&" + ldev_option_query + "&" + pool_query
        dpvolumes = self.gateway.get_ldevs(dpvolume_query)
        pool_vols = []
        for dpvol in dpvolumes.data:
            tmp_dpvol = {}
            tmp_dpvol["logicalUnitId"] = dpvol.ldevId
            tmp_dpvol["size"] = convert_block_capacity(dpvol.blockCapacity)
            pool_vols.append(tmp_dpvol)
        return pool_vols

    @log_entry_exit
    def fetch_pool_volumes_lists(self, pool):
        """
        Fetches the data protection volumes for a given storage pool.
        This method is used to populate the dpVolumes attribute of the storage pool.
        """
        # count_query = "count={}".format(16384)
        # ldev_option_query = "ldevOption=dpVolume"
        pool_query = "poolId={}".format(pool.poolId)
        dpvolume_query = f"?{pool_query}"
        dpvolumes = self.gateway.get_ldevs(dpvolume_query)

        return [dpvol.ldevId for dpvol in dpvolumes.data]

    @log_entry_exit
    def get_all_storage_pools(self):
        pools = None
        storage_pools = self.gateway.get_all_storage_pools()
        return storage_pools

    @log_entry_exit
    def get_pool_details_with_more_info(self, pool_id):
        """
        Fetches the storage pool details with more information.
        This method is used to get detailed information about a specific storage pool.
        """
        storage_pools = self.gateway.get_all_storage_pools(True)
        for pool in storage_pools.data:
            if pool.poolId == pool_id:
                # Add encryption info to the pool
                # self.add_encryption_info(pool)
                # Fetch data protection volumes
                # pool.dpVolumes = self.fetch_dp_volumes(pool)
                # Format the storage pool
                return pool
        return None

    @log_entry_exit
    def add_encryption_info(self, pool):
        if not pool.ldevIds or len(pool.ldevIds) < 0:
            return
        first_ldev = pool.ldevIds[0]
        logger.writeDebug(f"189 first_ldev {first_ldev}")

        # sng20241206 add_encryption_info for pool
        # get the volume
        if self.connection_info.connection_type == ConnectionTypes.DIRECT:
            volume = self.vol_gw.get_volume_by_id(first_ldev)
            if len(volume.parityGroupIds) <= 0:
                logger.writeDebug(f"189 volume {volume}")
                return
            pg_info = self.pg_prov.get_parity_group(volume.parityGroupIds[0])
            logger.writeDebug(f"189 pg_info {pg_info.isEncryptionEnabled}")
            pool.isEncrypted = pg_info.isEncryptionEnabled
            return

        else:
            return
        # if self.pg_info is None:
        #     self.pg_info = self.pg_prov.get_all_parity_groups()
        # for pg in self.pg_info.data:
        #     if first_ldev in pg.ldevIds:
        #         ## sng20241206 here pg.isEncryptionEnabled is None, hence this block is not working
        #         pool.isEncrypted = pg.isEncryptionEnabled
        #         break
        # pool.isEncrypted = False

    @log_entry_exit
    def get_storage_pool(self, pool_fact_spec=None):
        if pool_fact_spec and pool_fact_spec.pool_id is not None:
            return self.get_storage_pool_by_id(pool_fact_spec.pool_id)
        elif pool_fact_spec and pool_fact_spec.pool_name is not None:
            return self.get_storage_pool_by_name_or_id(
                pool_name=pool_fact_spec.pool_name
            )
        else:
            return self.get_all_storage_pools()

    @log_entry_exit
    def create_storage_pool(self, pool_spec):
        logger = Log()

        count = 0
        if pool_spec.pool_volumes:
            count = count + 1
        if pool_spec.ldev_ids:
            count = count + 1
        if pool_spec.start_ldev_id or pool_spec.end_ldev_id:
            count = count + 1
        if count != 1:
            raise ValueError(VSPStoragePoolValidateMsg.SPECIFY_ONE.value)

        if pool_spec.name is None or pool_spec.name == "":
            err_msg = VSPStoragePoolValidateMsg.POOL_NAME_REQUIRED.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        if pool_spec.type is None or pool_spec.type == "":
            err_msg = VSPStoragePoolValidateMsg.POOL_TYPE_REQUIRED.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)
        # if pool_spec.pool_volumes is None:
        #     err_msg = VSPStoragePoolValidateMsg.POOL_VOLUME_REQUIRED.value
        #     logger.writeError(err_msg)
        #     raise ValueError(err_msg)
        pool_spec.type = pool_spec.type.upper()

        if pool_spec.should_enable_deduplication:
            storage_system = self.storage_system_prov.get_current_storage_system_info()

            if storage_system.model.strip().upper() not in DEDUP_MODELS:
                err_msg = VSPStoragePoolValidateMsg.DEDUPLICATION_NOT_SUPPORTED.value
                logger.writeError(err_msg)
                raise ValueError(err_msg)
            else:
                dup_ldev = self.vol_prov.get_free_ldev_from_meta()
                if dup_ldev is None:
                    err_msg = VSPStoragePoolValidateMsg.NO_DUP_VOLUMES.value
                    logger.writeError(err_msg)
                    raise ValueError(err_msg)
                pool_spec.duplication_ldev_ids = [dup_ldev]

        if pool_spec.id:
            pool_spec.pool_id = pool_spec.id
        else:
            pool_spec.pool_id = self.get_free_pool_id()

        # handle the case to create a volume in the parity group id
        if pool_spec.pool_volumes:
            pool_spec.ldev_ids = self.create_ldev_for_pool(pool_spec)
        try:
            pool_id = self.gateway.create_storage_pool(pool_spec)
            pool_spec.name = None

        except Exception as e:
            logger.writeException(e)
            try:
                if pool_spec.ldev_ids:
                    for ldev_id in pool_spec.ldev_ids:
                        self.vol_prov.delete_volume(ldev_id, False)
            except Exception as ex:
                logger.writeDebug(f"exception in initializing create_storage_pool {ex}")
            raise e
        self.connection_info.changed = True
        return self.get_storage_pool_by_id(pool_id)

    @log_entry_exit
    def get_free_pool_id(self):
        pools = self.gateway.get_all_storage_pools()
        pool_ids = [pool.poolId for pool in pools.data]
        pool_ids.sort()
        for i in range(1, StoragePoolLimits.MAX_POOL_ID + 1):
            if i not in pool_ids:
                return i
        err_msg = VSPStoragePoolValidateMsg.POOL_ID_EXHAUSTED.value
        logger.writeError(err_msg)
        raise ValueError(err_msg)

    @log_entry_exit
    def create_ldev_for_pool(self, pool_spec):
        volumes_ids = []
        for vol in pool_spec.pool_volumes:
            capacity = vol.capacity.upper()[0:-1]
            vol_spec = CreateVolumeSpec(size=capacity, parity_group=vol.parity_group_id)
            vol_id = self.vol_prov.create_volume(vol_spec)
            volumes_ids.append(vol_id)
        if pool_spec.resource_group_id is not None and pool_spec.resource_group_id > 0:
            rg_spec = VSPResourceGroupSpec(ldevs=volumes_ids)
            unused = self.resource_group_prov.add_resource(
                pool_spec.resource_group_id, rg_spec
            )
        return volumes_ids

    @log_entry_exit
    def get_storage_pool_by_name_or_id(self, pool_name=None, id=None):
        storage_pools = self.get_all_storage_pools()
        for pool in storage_pools.data:
            logger.writeDebug(f"pool check{pool}")
            logger.writeDebug(f"pool check{pool_name} {id}")
            if (
                (pool_name and pool.poolName and pool.poolName == pool_name)
                or (id is not None and pool.poolId == id)
                or (id is not None and pool.resourceId == id)
            ):
                return pool
        return None

    @log_entry_exit
    def get_storage_pool_by_name_or_id_only(self, pool_name=None, id=None):

        if id is not None:
            return self.gateway.get_storage_pool_by_id(id)
        else:
            storage_pools = self.gateway.get_all_storage_pools()
            for pool in storage_pools.data:
                if (pool_name and pool.poolName == pool_name) or (
                    id is not None and pool.poolId == id
                ):
                    # pool.dpVolumes = self.fetch_dp_volumes(pool)
                    return pool
            return None

    @log_entry_exit
    def get_storage_pool_by_id(self, pool_id):
        # if self.connection_type == ConnectionTypes.DIRECT:
        #     # pool = VSPStoragePool(
        #     #     **self.format_storage_pool(self.gateway.get_storage_pool_by_id(pool_id))
        #     # )
        #     pool = self.gateway.get_storage_pool_by_id(pool_id)
        #     # self.add_encryption_info(pool)
        #     # pool = self.fetch_dp_volumes(pool)
        #     return pool
        # else:
        pool = self.gateway.get_storage_pool_by_id(pool_id)
        if pool:
            # pool.dpVolumes = self.fetch_dp_volumes(pool)
            return pool
        return None

    @log_entry_exit
    def get_storage_pool_by_resource_id(self, resource_id):
        storage_pools = self.get_all_storage_pools()
        for pool in storage_pools.data:
            if pool.poolId == resource_id:
                return pool
        return None

    @log_entry_exit
    def update_storage_pool(self, spec, pool):

        if spec.pool_volumes is not None and len(spec.pool_volumes) > 0:
            if self.connection_info.connection_type == ConnectionTypes.DIRECT:
                spec.ldev_ids = self.create_ldev_for_pool(spec)
                self.gateway.update_storage_pool(pool.poolId, spec)
                self.connection_info.changed = True
            self.connection_info.changed = True
        if spec.name is not None and spec.name == pool.poolName:
            spec.name = None
        if spec.type is not None and spec.type == pool.poolType:
            spec.type = None
        if (
            spec.warning_threshold_rate is not None
            and spec.warning_threshold_rate == pool.warningThreshold
        ):
            spec.warning_threshold_rate = None
        if (
            spec.depletion_threshold_rate is not None
            and spec.depletion_threshold_rate == pool.depletionThreshold
        ):
            spec.depletion_threshold_rate = None
        if (
            spec.monitoring_mode is not None
            and pool.monitoringMode is not None
            and spec.monitoring_mode.upper() == pool.monitoringMode.upper()
        ):
            spec.monitoring_mode = None
        if (
            spec.blocking_mode is not None
            and pool.blockingMode is not None
            and spec.blocking_mode.upper() == pool.blockingMode.upper()
        ):
            spec.blocking_mode = None
        if (
            spec.virtual_volume_capacity_rate is not None
            and spec.virtual_volume_capacity_rate == pool.virtualVolumeCapacityRate
        ):
            spec.virtual_volume_capacity_rate = None
        if (
            spec.suspend_snapshot is not None
            and spec.suspend_snapshot == pool.suspendSnapshot
        ):
            spec.suspend_snapshot = None

        update_data = self.gateway.change_storage_pool_settings(pool.poolId, spec)
        if update_data:
            self.connection_info.changed = True

        if self.connection_info.changed:
            pool = self.get_pool_details_with_more_info(pool.poolId)

        return pool

    @log_entry_exit
    def delete_storage_pool(self, spec):
        pool = self.get_storage_pool_by_name_or_id_only(spec.name, spec.id)
        pool_ldevs = []
        if pool is None:
            return None, VSPStoragePoolValidateMsg.POOL_DOES_NOT_EXIST.value
        resource_id = (
            pool.poolId
            if self.connection_type == ConnectionTypes.DIRECT
            else pool.resourceId
        )
        if spec.should_delete_pool_volumes:
            pool_ldevs = self.fetch_pool_volumes_lists(pool)

        unused = self.gateway.delete_storage_pool(resource_id)

        if pool_ldevs:
            for ldev_id in pool_ldevs:
                try:
                    self.vol_prov.delete_volume(ldev_id, False)
                except Exception as e:
                    logger.writeException(
                        f"Failed to delete volume {ldev_id} in pool {pool.poolId}: {e}"
                    )

        self.connection_info.changed = True
        return None, StoragePoolInfoMsg.POOL_DELETED.value

    @log_entry_exit
    def perform_storage_pool_action(self, state, spec):
        msg = ""

        if (
            state in [StateValue.MONITOR, StateValue.RELOCATE]
            and spec.operation_type is None
        ):
            err_msg = VSPStoragePoolValidateMsg.OPERATION_TYPE_REQUIRED.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        pool = self.get_storage_pool_by_name_or_id_only(spec.name, spec.id)
        if not pool:
            err_msg = VSPStoragePoolValidateMsg.POOL_DOES_NOT_EXIST.value
            logger.writeError(err_msg)
            raise ValueError(err_msg)

        if state == StateValue.INIT_CAPACITY:
            self.gateway.initialize_capacity_savings(pool.poolId)
            msg = StoragePoolInfoMsg.CAPACITY_SAVING_INITIATED.value
            self.connection_info.changed = True
        elif state == StateValue.MONITOR:
            if (
                pool.tierOperationStatus in ["MON", "RLM"]
                and spec.operation_type == "start"
            ):
                msg = StoragePoolInfoMsg.PERFORMANCE_MONITORING_IN_PROGRESS.value
            elif (
                pool.tierOperationStatus not in ["MON", "RLM"]
                and spec.operation_type == "stop"
            ):
                msg = StoragePoolInfoMsg.PM_ALREADY_STOPPED.value
            else:
                self.gateway.perform_performance_monitor(
                    pool.poolId, spec.operation_type
                )
                self.connection_info.changed = True
                msg = StoragePoolInfoMsg.PERFORMANCE_MONITOR_UPDATE.value.format(
                    "started" if spec.operation_type != "stop" else "stopped"
                )
        elif state == StateValue.RESTORE:
            self.gateway.restore_storage_pool(pool.poolId)
            self.connection_info.changed = True
            msg = StoragePoolInfoMsg.RESTORE_DONE.value
        elif state == StateValue.RELOCATE:
            if (
                pool.tierOperationStatus in ["RLC", "RLM"]
                and spec.operation_type == "start"
            ):
                msg = StoragePoolInfoMsg.TIER_RELOCATION_IN_PROGRESS.value
            elif (
                pool.tierOperationStatus not in ["MON", "RLM"]
                and spec.operation_type == "stop"
            ):
                msg = StoragePoolInfoMsg.TIER_RELOCATION_ALREADY_STOPPED.value
            else:
                self.gateway.perform_tier_location(pool.poolId, spec.operation_type)
                self.connection_info.changed = True
                msg = StoragePoolInfoMsg.TIER_OPERATION_SUCCESS.value.format(
                    "started" if spec.operation_type != "stop" else "stopped"
                )
        if self.connection_info.changed:
            pool = self.get_pool_details_with_more_info(pool.poolId)

        return pool.camel_to_snake_dict(), msg
