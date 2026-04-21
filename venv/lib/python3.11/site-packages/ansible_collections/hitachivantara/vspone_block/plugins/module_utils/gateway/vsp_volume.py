try:
    from .gateway_manager import VSPConnectionManager
    from ..common.vsp_constants import (
        Endpoints,
        VolumePayloadConst,
        AutomationConstants,
    )
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.vsp_volume_models import (
        VSPVolumesInfo,
        VSPVolumeInfo,
        CreateVolumeSpec,
        VolumeQosParamsOutput,
        VSPUndefinedVolumeInfo,
        VSPUndefinedVolumeInfoList,
    )
    from ..common.hv_log import Log

    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import PEGASUS_MODELS
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.ansible_common import log_entry_exit
    from common.vsp_constants import Endpoints, VolumePayloadConst, AutomationConstants
    from common.ansible_common import dicts_to_dataclass_list
    from model.vsp_volume_models import (
        VSPVolumesInfo,
        VSPVolumeInfo,
        CreateVolumeSpec,
        VolumeQosParamsOutput,
        VSPUndefinedVolumeInfo,
        VSPUndefinedVolumeInfoList,
    )
    from common.hv_log import Log
    from common.vsp_constants import PEGASUS_MODELS
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway


logger = Log()


class VSPVolumeDirectGateway:
    """
    VSPVolumeDirectGateway
    """

    def __init__(self, connection_info):
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.storage_gw = VSPStorageSystemDirectGateway(connection_info)
        self.end_points = Endpoints
        self.is_pegasus = self.get_storage_details()
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial):
        self.serial = serial

    @log_entry_exit
    def get_simple_volumes(
        self, start_ldev=0, ldev_option="defined", count=0
    ) -> VSPVolumesInfo:

        path = VolumePayloadConst.HEAD_LDEV_ID.format(start_ldev)
        path += VolumePayloadConst.LDEV_OPTION.format(ldev_option)
        path += VolumePayloadConst.COUNT.format(
            count if count > 0 else AutomationConstants.LDEV_MAX_NUMBER
        )

        end_point = self.end_points.GET_LDEVS.format(path)
        vol_data = self.rest_api.get(end_point)
        volumes = VSPVolumesInfo(
            dicts_to_dataclass_list(vol_data["data"], VSPVolumeInfo)
        )
        return volumes

    @log_entry_exit
    def get_volumes(
        self,
        start_ldev=0,
        ldev_option="defined",
        count=0,
        pool_id=None,
        resource_group_id=None,
        journal_id=None,
        parity_group_id=None,
    ) -> VSPVolumesInfo:

        if pool_id is None:
            path = VolumePayloadConst.LDEV_OPTION.format(ldev_option)
            path += VolumePayloadConst.HEAD_LDEV_ID_NEXT.format(start_ldev)
        else:
            path = VolumePayloadConst.POOL_ID_PARAM.format(pool_id)

        if resource_group_id:
            path = VolumePayloadConst.RESOURCE_GROUP_ID.format(resource_group_id)
        if journal_id:
            path = VolumePayloadConst.JOURNAL_ID.format(journal_id)
        if parity_group_id:
            path = VolumePayloadConst.PARITY_GROUP_ID.format(parity_group_id)

        path += VolumePayloadConst.COUNT.format(
            count if count > 0 else AutomationConstants.LDEV_MAX_NUMBER
        )

        end_point = self.end_points.GET_LDEVS.format(path)
        vol_data = self.rest_api.get(end_point)
        volumes = VSPVolumesInfo(
            dicts_to_dataclass_list(vol_data["data"], VSPVolumeInfo)
        )

        if self.is_pegasus and len(volumes.data) < 100:
            for volume in volumes.data:
                try:
                    pega_end_point = self.end_points.PEGA_LDEVS_ONE.format(
                        volume.ldevId
                    )
                    add_vol_data = self.rest_api.pegasus_get(pega_end_point)
                    drs_enabled = add_vol_data.get(
                        VolumePayloadConst.IS_DATA_REDUCTION_SHARE_ENABLED, False
                    )
                    volume.isDataReductionShareEnabled = drs_enabled
                except Exception as ex:
                    logger.writeDebug(f"GW: exception in get_volumes {ex}")
        return volumes

    @log_entry_exit
    def get_volumes_by_pool_id(self, pool_id) -> VSPVolumesInfo:

        end_point = self.end_points.GET_LDEVS_BY_POOL_ID.format(pool_id)
        vol_data = self.rest_api.get(end_point)
        return VSPVolumesInfo(dicts_to_dataclass_list(vol_data["data"], VSPVolumeInfo))

    @log_entry_exit
    def get_volume_by_id(self, ldev_id) -> VSPVolumeInfo:

        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        try:
            vol_data = self.rest_api.get(end_point)
        except Exception:
            # try once more
            vol_data = self.rest_api.get(end_point)

        volume_info = VSPVolumeInfo(**vol_data)
        if self.is_pegasus and volume_info.poolId is not None:
            try:
                pega_end_point = self.end_points.PEGA_LDEVS_ONE.format(ldev_id)
                add_vol_data = self.rest_api.pegasus_get(pega_end_point)
                drs_enabled = add_vol_data.get(
                    VolumePayloadConst.IS_DATA_REDUCTION_SHARE_ENABLED, False
                )
                volume_info.isDataReductionShareEnabled = drs_enabled
            except Exception as ex:
                logger.writeDebug(f"GW: exception in get_volume_by_id {ex}")
        return volume_info

    @log_entry_exit
    def get_volume_by_id_external_volume(self, ldev_id) -> VSPVolumeInfo:

        end_point = self.end_points.GET_LDEV_EXT_VOL.format(ldev_id)
        try:
            vol_data = self.rest_api.get(end_point)
        except Exception:
            # try once more
            vol_data = self.rest_api.get(end_point)

        volume_info = VSPVolumeInfo(**vol_data)
        if self.is_pegasus and volume_info.poolId is not None:
            try:
                pega_end_point = self.end_points.PEGA_LDEVS_ONE.format(ldev_id)
                add_vol_data = self.rest_api.pegasus_get(pega_end_point)
                drs_enabled = add_vol_data.get(
                    VolumePayloadConst.IS_DATA_REDUCTION_SHARE_ENABLED, False
                )
                volume_info.isDataReductionShareEnabled = drs_enabled
            except Exception as ex:
                logger.writeDebug(f"GW: exception in get_volume_by_id {ex}")
        return volume_info

    @log_entry_exit
    def map_ext_volume(
        self, ldevId: int, externalParityGroupId: str, externalVolumeCapacity: int
    ):
        payload = {
            "ldevId": ldevId,
            "externalParityGroupId": externalParityGroupId,
            "blockCapacity": externalVolumeCapacity,
        }

        end_point = self.end_points.POST_LDEVS
        logger.writeDebug(f"Payload for map volume: {payload}")

        url = self.rest_api.post(end_point, payload)

        # Split the ldevid from url
        return url.split("/")[-1]

    @log_entry_exit
    def create_volume(self, spec: CreateVolumeSpec):
        payload = {}
        logger.writeDebug(f"spec for creating volume: {spec}")

        # the block_size is added to support decimal values like 1.5 GB etc.
        if spec.block_size:
            payload[VolumePayloadConst.BLOCK_CAPACITY] = spec.block_size
        else:
            payload[VolumePayloadConst.BYTE_CAPACITY] = spec.size
        if isinstance(spec.pool_id, int):
            payload[VolumePayloadConst.POOL_ID] = spec.pool_id
        if spec.ldev_id:
            payload[VolumePayloadConst.LDEV] = spec.ldev_id
        if spec.is_parallel_execution_enabled:
            payload[VolumePayloadConst.IS_PARALLEL_EXECUTION_ENABLED] = (
                spec.is_parallel_execution_enabled
            )
        if spec.capacity_saving:
            payload[VolumePayloadConst.ADR_SETTING] = spec.capacity_saving
            if self.is_pegasus:
                if (
                    spec.capacity_saving.lower() != VolumePayloadConst.DISABLED
                    and spec.pool_id is not None
                ):
                    logger.writeDebug(
                        f"is spec.data_reduction_share : {spec.data_reduction_share}"
                    )
                    is_true = (
                        True
                        if spec.data_reduction_share is None
                        else spec.data_reduction_share
                    )
                    logger.writeDebug(f"is true: {is_true}")

                    if spec.pool_id != -1:
                        payload[
                            VolumePayloadConst.IS_DATA_REDUCTION_SHARED_VOLUME_ENABLED
                        ] = is_true
            else:
                if spec.data_reduction_share is not None:
                    payload[
                        VolumePayloadConst.IS_DATA_REDUCTION_SHARED_VOLUME_ENABLED
                    ] = spec.data_reduction_share
            # if spec.capacity_saving.lower() != VolumePayloadConst.DISABLED:
            #     if spec.is_compression_acceleration_enabled is not None:
            #         payload[VolumePayloadConst.IS_COMPRESSION_ACCELERATION_ENABLED] = (
            #             spec.is_compression_acceleration_enabled
            #         )
        if spec.parity_group:
            payload[VolumePayloadConst.PARITY_GROUP] = spec.parity_group

        if spec.is_parallel_execution_enabled:
            payload[VolumePayloadConst.IS_PARALLEL_EXECUTION_ENABLED] = (
                spec.is_parallel_execution_enabled
            )
        if spec.start_ldev_id:
            payload[VolumePayloadConst.START_LDEV_ID] = spec.start_ldev_id
        if spec.end_ldev_id:
            payload[VolumePayloadConst.END_LDEV_ID] = spec.end_ldev_id
        if spec.external_parity_group:
            payload[VolumePayloadConst.EXTERNAL_PARITY_GROUP_ID] = (
                spec.external_parity_group
            )

        end_point = self.end_points.POST_LDEVS
        logger.writeDebug(f"Payload for creating volume: {payload}")

        url = self.rest_api.post(end_point, payload)

        # Split the ldevid from url
        return url.split("/")[-1]

    @log_entry_exit
    def delete_volume(self, ldev_id, force_execute):
        payload = None
        if force_execute is not None:
            payload = {
                VolumePayloadConst.IS_DATA_REDUCTION_DELETE_FORCE_EXECUTE: force_execute
            }
        end_point = self.end_points.DELETE_LDEVS.format(ldev_id)
        return self.rest_api.delete(end_point, data=payload)

    @log_entry_exit
    def delete_lun_path(self, port):
        end_point = self.end_points.DELETE_LUNS.format(
            port["portId"], port["hostGroupNumber"], port["lun"]
        )
        return self.rest_api.delete(end_point)

    @log_entry_exit
    def get_free_ldev_from_meta(self):
        end_point = self.end_points.GET_FREE_LDEV_FROM_META
        vol_data = self.rest_api.get(end_point)
        return VSPVolumesInfo(dicts_to_dataclass_list(vol_data["data"], VSPVolumeInfo))

    @log_entry_exit
    def get_free_ldevs_from_meta(self, start_ldev=0, resource_group_id=0):

        end_point = self.end_points.GET_FREE_LDEVS_FROM_META_RES.format(
            resource_group_id
        )
        if start_ldev and start_ldev > 0:
            end_point = self.end_points.GET_FREE_LDEVS_FROM_META_HEAD_LDEV.format(
                start_ldev, resource_group_id
            )
        vol_data = self.rest_api.get(end_point)
        return VSPUndefinedVolumeInfoList(
            dicts_to_dataclass_list(vol_data["data"], VSPUndefinedVolumeInfo)
        )

    @log_entry_exit
    def get_free_ldevs_from_meta_chunks(self, start_ldev=0, count=0):

        end_point = self.end_points.GET_FREE_LDEVS_FROM_META_BASIC.format(
            start_ldev, count
        )

        vol_data = self.rest_api.get(end_point)
        return VSPUndefinedVolumeInfoList(
            dicts_to_dataclass_list(vol_data["data"], VSPUndefinedVolumeInfo)
        )

    @log_entry_exit
    def get_free_ldev_matching_svol_range(self, begin_ldev_id, end_ldev_id):
        count = end_ldev_id - begin_ldev_id + 1
        end_point = self.end_points.GET_FREE_LDEV_FROM_META_FOR_SVOL_RANGE.format(
            begin_ldev_id, count
        )
        vol_data = self.rest_api.get(end_point)

        return VSPUndefinedVolumeInfoList(
            dicts_to_dataclass_list(vol_data["data"], VSPUndefinedVolumeInfo)
        )

    @log_entry_exit
    def get_free_ldev_matching_pvol(self, pvol_id):

        found = False
        vol_data = None

        # while not found:
        end_point = self.end_points.GET_FREE_LDEV_MATCHING_PVOL.format(pvol_id)
        vol_data = self.rest_api.get(end_point)
        if vol_data["data"]:
            resource_group_id = vol_data["data"][0]["resourceGroupId"]
            if resource_group_id != 0:
                #     # if resource_group_id is 0, then it is a free ldev in meta
                #     found = True
                # else:
                end_point = self.end_points.GET_FREE_LDEV_FROM_META.format(pvol_id)
                vol_data = self.rest_api.get(end_point)

        return VSPUndefinedVolumeInfoList(
            dicts_to_dataclass_list(vol_data["data"], VSPUndefinedVolumeInfo)
        )

    @log_entry_exit
    def update_volume(self, ldev_id, name=None, adr_setting=None, spec=None):

        payload = {}

        if adr_setting:
            payload[VolumePayloadConst.ADR_SETTING] = adr_setting
        if name:
            payload[VolumePayloadConst.LABEL] = name
        if spec:
            if spec.is_compression_acceleration_enabled is not None:
                payload[VolumePayloadConst.IS_COMPRESSION_ACCELERATION_ENABLED] = (
                    spec.is_compression_acceleration_enabled
                )
            if spec.data_reduction_process_mode is not None:
                payload[VolumePayloadConst.DATA_REDUCTION_PROCESS_MODE] = (
                    spec.data_reduction_process_mode
                )
            if spec.is_relocation_enabled is not None:
                payload[VolumePayloadConst.IS_RELOCATION_ENABLED] = (
                    spec.is_relocation_enabled
                )
            if spec.is_full_allocation_enabled is not None:
                payload[VolumePayloadConst.IS_FULL_ALLOCATION_ENABLED] = (
                    spec.is_full_allocation_enabled
                )
            if spec.is_alua_enabled is not None:
                payload[VolumePayloadConst.IS_ALUA_ENABLED] = spec.is_alua_enabled

        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        return self.rest_api.patch(end_point, payload)

    @log_entry_exit
    def expand_volume(self, ldev_id, additional_capacity, enhanced_expansion):

        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.ADDITIONAL_BLOCK_CAPACITY: round(additional_capacity)
            }
        }
        if enhanced_expansion:
            payload[VolumePayloadConst.PARAMS][
                VolumePayloadConst.ENHANCED_EXPANSION
            ] = True
        end_point = self.end_points.POST_EXPAND_LDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    # sng20241205 unassign_vldev
    @log_entry_exit
    def unassign_vldev(self, ldev_id, vldev_id):
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.VIRTUAL_LDEVID: vldev_id,
            }
        }
        end_point = self.end_points.POST_UNASSIGN_VLDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    @log_entry_exit
    def assign_vldev(self, ldev_id, vldev_id):
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.VIRTUAL_LDEVID: vldev_id,
            }
        }
        end_point = self.end_points.POST_ASSIGN_VLDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    @log_entry_exit
    def format_volume(
        self, ldev_id, force_format: bool, format_type="quick", check_job_status=True
    ):
        operation_type = (
            VolumePayloadConst.QFMT
            if format_type == "quick"
            else VolumePayloadConst.FMT
        )
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.OPERATION_TYPE: operation_type,
                VolumePayloadConst.FORCE_FORMAT: force_format,
            }
        }
        end_point = self.end_points.POST_FORMAT_LDEV.format(ldev_id)
        if check_job_status:
            return self.rest_api.post(end_point, payload)
        else:
            return self.rest_api.post_without_job(end_point, payload)

    @log_entry_exit
    def shredding_volume(self, ldev_id, start=True):

        operation_type = VolumePayloadConst.START if start else VolumePayloadConst.STOP
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.OPERATION_TYPE: operation_type,
            }
        }
        end_point = self.end_points.POST_SHRED_LDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    @log_entry_exit
    def change_qos_settings(self, ldev_id, qos_spec):
        # Define the data
        nested_data = {
            VolumePayloadConst.UPPER_IOPS: qos_spec.upper_iops,
            VolumePayloadConst.LOWER_IOPS: qos_spec.lower_iops,
            VolumePayloadConst.UPPER_TRANSFER_RATE: qos_spec.upper_transfer_rate,
            VolumePayloadConst.LOWER_TRANSFER_RATE: qos_spec.lower_transfer_rate,
            VolumePayloadConst.UPPER_ALERT_ALLOWABLE_TIME: qos_spec.upper_alert_allowable_time,
            VolumePayloadConst.LOWER_ALERT_ALLOWABLE_TIME: qos_spec.lower_alert_allowable_time,
            VolumePayloadConst.RESPONSE_PRIORITY: qos_spec.response_priority,
            VolumePayloadConst.RESPONSE_ALERT_ALLOWABLE_TIME: qos_spec.response_alert_allowable_time,
        }

        # Iterate over each item and send individual requests for non-None values
        for key, value in nested_data.items():
            if value is not None:
                payload = {VolumePayloadConst.PARAMS: {key: value}}
                end_point = self.end_points.POST_QOS_UPDATE.format(ldev_id)
                self.rest_api.post(end_point, payload)

        return "All QoS updates sent successfully."

    @log_entry_exit
    def get_qos_settings(self, ldev_id):
        end_point = self.end_points.GET_QOS_SETTINGS.format(ldev_id)

        qos_data = self.rest_api.get(end_point)
        if len(qos_data.get("data")) > 0 and qos_data.get("data")[0].get("qos"):
            return VolumeQosParamsOutput(**qos_data.get("data")[0].get("qos"))
        return None

    @log_entry_exit
    def change_volume_status(self, ldev_id, is_block=False):

        operation_type = "blk" if is_block else "nml"
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.STATUS: operation_type,
            }
        }
        end_point = self.end_points.POST_CHANGE_STATUS_LDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    @log_entry_exit
    def is_vsp_5000_series(self):
        return self.storage_gw.is_vsp_5000_series()

    @log_entry_exit
    def is_svp_present(self):
        return self.storage_gw.is_svp_present()

    @log_entry_exit
    def fill_cmd_device_info(self, volume):
        logger.writeDebug(
            f"fill_cmd_device_info: is_vsp_5000_series= {self.is_vsp_5000_series()}"
        )
        volume.isCommandDevice = True
        if not self.is_vsp_5000_series() and not self.is_svp_present():
            # VSP One does not support detailInfoType=class
            return volume

        end_point = self.end_points.GET_CMD_DEVICE.format(volume.ldevId)
        vol_data = self.rest_api.get(end_point)
        if vol_data and vol_data.get("data"):
            vol_data = vol_data.get("data")
            command_device = vol_data[0].get("commandDevice")
            if command_device:
                volume.isSecurityEnabled = command_device.get("isSecurityEnabled")
                volume.isUserAuthenticationEnabled = command_device.get(
                    "isUserAuthenticationEnabled"
                )
                volume.isDeviceGroupDefinitionEnabled = command_device.get(
                    "isDeviceGroupDefinitionEnabled"
                )
        logger.writeDebug(f"fill_cmd_device_info: vol_data= {vol_data}")
        return volume

    @log_entry_exit
    def change_volume_settings(self, ldev_id, label=None, isAluaEnabled=None):

        doPatch = False
        payload = {}
        if isAluaEnabled is not None:
            payload["isAluaEnabled"] = isAluaEnabled
            doPatch = True
        if label is not None:
            payload["label"] = label
            doPatch = True

        if not doPatch:
            return

        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        return self.rest_api.patch(end_point, payload)

    @log_entry_exit
    def change_volume_settings_tier_reloc(self, ldev_id, spec=None):

        doPatch = False
        payload = {}
        tier_level_for_new_page_allocation = spec.tier_level_for_new_page_allocation
        if tier_level_for_new_page_allocation:
            tierLevelForNewPageAlloc = "M"
            if tier_level_for_new_page_allocation.lower() == "high":
                tierLevelForNewPageAlloc = "H"
            if tier_level_for_new_page_allocation.lower() == "low":
                tierLevelForNewPageAlloc = "L"
            payload["tierLevelForNewPageAllocation"] = tierLevelForNewPageAlloc
            doPatch = True
        isRelocationEnabled = spec.is_relocation_enabled
        if isRelocationEnabled is not None:
            payload["isRelocationEnabled"] = isRelocationEnabled
            doPatch = True

        if not doPatch:
            return

        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        return self.rest_api.patch(end_point, payload)

    # sng20241202 change_volume_settings_tier_policy
    @log_entry_exit
    def change_volume_settings_tier_policy(self, ldev_id, spec=None):

        if not spec.is_relocation_enabled:
            return

        tiering_policy = spec.tiering_policy
        if tiering_policy is None:
            return

        tieringPolicy = {
            "tierLevel": tiering_policy.get("tier_level", None),
            "tier1AllocationRateMin": tiering_policy.get(
                "tier1_allocation_rate_min", None
            ),
            "tier1AllocationRateMax": tiering_policy.get(
                "tier1_allocation_rate_max", None
            ),
            "tier3AllocationRateMin": tiering_policy.get(
                "tier3_allocation_rate_min", None
            ),
            "tier3AllocationRateMax": tiering_policy.get(
                "tier3_allocation_rate_max", None
            ),
        }

        payload = {"tieringPolicy": tieringPolicy}
        end_point = self.end_points.LDEVS_ONE.format(ldev_id)
        return self.rest_api.patch(end_point, payload)

    @log_entry_exit
    def reclaim_zero_pages(self, ldev_id):

        end_point = self.end_points.RECLAIM_ZERO_PAGES.format(ldev_id)
        return self.rest_api.post(end_point, None)

    @log_entry_exit
    def change_mp_blade(self, ldev_id, mp_blade_id):
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.MP_BLADE_ID: mp_blade_id,
            }
        }
        end_point = self.end_points.CHANGE_MP_BLADE.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    # use all ldev operations above this function
    @log_entry_exit
    def get_storage_details(self):
        storage_info = self.storage_gw.get_current_storage_system_info()
        pegasus_model = any(sub in storage_info.model for sub in PEGASUS_MODELS)
        logger.writeDebug(f"Storage Model: {storage_info.model}")
        return pegasus_model

    @log_entry_exit
    def assign_ldev_to_clpr(self, ldev_id, clpr_id):
        payload = {
            VolumePayloadConst.PARAMS: {
                VolumePayloadConst.CLPR_ID: clpr_id,
            }
        }
        end_point = self.end_points.ASSIGN_LDEV.format(ldev_id)
        return self.rest_api.post(end_point, payload)

    @log_entry_exit
    def get_all_ldevs_using_filter(self, filter_dict):
        """
        Get all LDEVs using filter parameters.
        :param filter_params: Dictionary containing filter parameters.
        :return: VSPVolumesInfo object containing the filtered LDEVs.
        """
        query_params = "&".join(
            f"{key}={value}" for key, value in filter_dict.items() if value is not None
        )
        end_point = self.end_points.GET_LDEVS.format(query_params)
        vol_data = self.rest_api.get(end_point)
        return VSPVolumesInfo(dicts_to_dataclass_list(vol_data["data"], VSPVolumeInfo))
