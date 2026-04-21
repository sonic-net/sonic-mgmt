try:
    from .gateway_manager import VSPConnectionManager
    from ..common.vsp_constants import (
        Endpoints,
        VolumePayloadConst,
    )
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.vsp_volume_models import (
        SalamanderVSPVolumesInfo,
        SalamanderSimpleVolumeInfo,
        SalamanderCreateVolumeRequestSpec,
        SimpleVolumeQosConfig,
        SimpleVolumeQosParamsSpec,
        SalamanderVolumeServerConnectionInfo,
        SalamanderVolumeServerInfo,
        SimpleAPIVolumeFactsSpec,
    )
    from ..common.hv_log import Log

    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import PEGASUS_MODELS
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.ansible_common import log_entry_exit
    from common.vsp_constants import Endpoints, VolumePayloadConst
    from common.ansible_common import dicts_to_dataclass_list
    from model.vsp_volume_models import (
        SalamanderVSPVolumesInfo,
        SalamanderSimpleVolumeInfo,
        SalamanderCreateVolumeRequestSpec,
        SimpleVolumeQosConfig,
        SimpleVolumeQosParamsSpec,
        SalamanderVolumeServerConnectionInfo,
        SalamanderVolumeServerInfo,
        SimpleAPIVolumeFactsSpec,
    )
    from common.hv_log import Log
    from common.vsp_constants import PEGASUS_MODELS
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway


logger = Log()


class VspSimpleApiGateway:
    """
    VspSimpleApiGateway
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

    @log_entry_exit
    def salamander_get_volume_by_id(self, volume_id) -> SalamanderSimpleVolumeInfo:

        end_point = self.end_points.SALAMENDER_GET_LDEVS_ONE.format(volume_id)
        vol_data = None
        try:
            vol_data = self.rest_api.pegasus_get(end_point)
        except Exception:
            # try once more
            return None

        volume_info = SalamanderSimpleVolumeInfo(**vol_data)
        return volume_info

    @log_entry_exit
    def filter_volume_by_specs(self, spec: SimpleAPIVolumeFactsSpec):
        query_params = []
        end_point = self.end_points.SALAMENDER_GET_LDEVS
        if spec:
            if spec.pool_id is not None:
                query_params.append(f"poolId={spec.pool_id}")
            elif spec.pool_name is not None:
                query_params.append(f"poolName={spec.pool_name}")

            if spec.server_id is not None:
                query_params.append(f"serverId={spec.server_id}")
            elif spec.server_nickname is not None:
                query_params.append(f"serverNickname={spec.server_nickname}")
            if spec.nickname is not None:
                query_params.append(f"nickname={spec.nickname}")
            if spec.min_total_capacity is not None:
                query_params.append(f"minTotalCapacity={spec.min_total_capacity}")
            if spec.max_total_capacity is not None:
                query_params.append(f"maxTotalCapacity={spec.max_total_capacity}")
            if spec.min_used_capacity is not None:
                query_params.append(f"minUsedCapacity={spec.min_used_capacity}")
            if spec.max_used_capacity is not None:
                query_params.append(f"maxUsedCapacity={spec.max_used_capacity}")

            if spec.start_volume_id is not None:
                query_params.append(f"startVolumeId={spec.start_volume_id}")
            if spec.count is not None:
                query_params.append(f"count={spec.count}")
            query_string = "&".join(query_params) if query_params else ""
            if query_string:
                query_string = "?" + query_string
                end_point = self.end_points.SALAMENDER_GET_LDEVS_QUERY.format(
                    query_string
                )

        vol_data = self.rest_api.pegasus_get(end_point)

        return SalamanderVSPVolumesInfo().dump_to_object(vol_data)

    @log_entry_exit
    def salamander_get_volume_by_id_with_details(
        self, volume_id
    ) -> SalamanderSimpleVolumeInfo:

        end_point = self.end_points.SALAMENDER_GET_LDEVS_ONE.format(volume_id)
        vol_data = None
        try:
            vol_data = self.rest_api.pegasus_get(end_point)
        except Exception:
            # try once more
            return None
        volume_info = SalamanderSimpleVolumeInfo(**vol_data)

        qos_info = self.get_volume_qos_info(volume_id)
        volume_info.qosSettings = qos_info
        # server_info = self.get_volume_server_connection_info_by_id(volume_id)
        # volume_info.luns = [lun.lunId for lun in server_info.luns] if server_info and server_info.luns else []

        return volume_info

    @log_entry_exit
    def salamander_get_volume_by_name(self, name) -> SalamanderVSPVolumesInfo:
        """
        Get all volumes from the storage system.
        """
        end_point = self.end_points.SALAMENDER_GET_LDEVS_QUERY.format(
            f"nickname={name}"
        )
        vol_data = self.rest_api.pegasus_get(end_point)
        volumes = SalamanderVSPVolumesInfo().dump_to_object(vol_data)
        return volumes

    @log_entry_exit
    def salamander_create_volume(self, spec: SalamanderCreateVolumeRequestSpec):
        payload = {}
        logger.writeDebug(f"spec for creating volume: {spec}")

        # Capacity (in MiB)
        payload[VolumePayloadConst.CAPACITY] = spec.capacity

        # Number of volumes (default 1 if not provided)
        if spec.number_of_volumes:
            payload[VolumePayloadConst.NUMBER] = spec.number_of_volumes

        # Nickname parameters
        if spec.volume_name:
            nickname_payload = {"baseName": spec.volume_name.base_name}
            if spec.volume_name.start_number is not None:
                nickname_payload["startNumber"] = spec.volume_name.start_number
            if spec.volume_name.number_of_digits is not None:
                nickname_payload["numberOfDigits"] = spec.volume_name.number_of_digits

            payload[VolumePayloadConst.NICKNAME_PARAM] = nickname_payload

        # Capacity saving (e.g., COMPRESSION, DEDUPLICATION_AND_COMPRESSION)
        if spec.capacity_saving:
            payload[VolumePayloadConst.SAVING_SETTING] = spec.capacity_saving.upper()

        # Data reduction share flag
        if spec.is_data_reduction_share_enabled is not None:
            payload[VolumePayloadConst.IS_DATA_REDUCTION_SHARE_ENABLED] = (
                spec.is_data_reduction_share_enabled
            )

        # Pool ID
        if spec.pool_id is not None:
            payload[VolumePayloadConst.POOL_ID] = spec.pool_id

        # the block_size is added to support decimal values like 1.5 GB etc.
        end_point = self.end_points.SALAMENDER_GET_LDEVS
        logger.writeDebug(f"Payload for creating volume: {payload}")

        volume_ids = self.rest_api.pegasus_post_multi_resource(end_point, payload)
        logger.writeDebug(f"Created volume IDs: {volume_ids}")
        # Split the ldevid from url
        return volume_ids

    @log_entry_exit
    def salamander_get_volumes(self):

        end_point = self.end_points.SALAMENDER_GET_LDEVS
        vol_data = self.rest_api.pegasus_get(end_point)
        volumes = SalamanderVSPVolumesInfo(
            dicts_to_dataclass_list(vol_data["data"], SalamanderSimpleVolumeInfo)
        )

        return volumes

    @log_entry_exit
    def get_volume_qos_info(self, volume_id):
        end_point = self.end_points.SALAMENDER_GET_QOS_SETTINGS.format(volume_id)

        qos_data = self.rest_api.pegasus_get(end_point)
        return SimpleVolumeQosConfig(**qos_data)

    @log_entry_exit
    def salamander_delete_volume(self, volume_id):
        end_point = self.end_points.SALAMENDER_GET_LDEVS_ONE.format(volume_id)
        return self.rest_api.pegasus_delete(end_point, None)

    @log_entry_exit
    def salamander_update_volume(
        self,
        volume_id,
        nick_name=None,
        saving_setting=None,
        compression_acceleration=None,
    ):

        payload = {}

        if nick_name is not None:
            payload[VolumePayloadConst.NICK_NAME] = nick_name
        if saving_setting is not None:
            payload[VolumePayloadConst.SAVING_SETTING] = saving_setting.upper()
        if compression_acceleration is not None:
            payload[VolumePayloadConst.COMPRESSION_ACCELERATION] = (
                compression_acceleration
            )

        end_point = self.end_points.SALAMENDER_GET_LDEVS_ONE.format(volume_id)
        return self.rest_api.pegasus_patch(end_point, payload)

    @log_entry_exit
    def salamander_update_volume_capacity(self, volume_id, capacity):
        payload = {VolumePayloadConst.CAPACITY: capacity}
        end_point = self.end_points.SIMPLE_API_VOLUME_EXPAND.format(volume_id)
        return self.rest_api.pegasus_post(end_point, payload)

    @log_entry_exit
    def salamander_update_qos_settings(
        self, volume_id, qos_settings: SimpleVolumeQosParamsSpec
    ):
        """
        Update the QoS settings for a volume.
        """
        if qos_settings.alert_setting and qos_settings.threshold:
            return
        payload = {}
        if qos_settings.alert_setting is not None:
            payload = {VolumePayloadConst.alertSetting: {}}
            if qos_settings.alert_setting.is_upper_alert_enabled is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.isUpperAlertEnabled
                ] = qos_settings.alert_setting.is_upper_alert_enabled
            if qos_settings.alert_setting.upper_alert_allowable_time is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.upperAlertAllowableTime
                ] = qos_settings.alert_setting.upper_alert_allowable_time

            if qos_settings.alert_setting.is_lower_alert_enabled is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.isLowerAlertEnabled
                ] = qos_settings.alert_setting.is_lower_alert_enabled
            if qos_settings.alert_setting.lower_alert_allowable_time is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.lowerAlertAllowableTime
                ] = qos_settings.alert_setting.lower_alert_allowable_time

            if qos_settings.alert_setting.is_response_alert_enabled is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.isResponseAlertEnabled
                ] = qos_settings.alert_setting.is_response_alert_enabled
            if qos_settings.alert_setting.response_alert_allowable_time is not None:
                payload[VolumePayloadConst.alertSetting][
                    VolumePayloadConst.responseAlertAllowableTime
                ] = qos_settings.alert_setting.response_alert_allowable_time

        elif qos_settings.threshold is not None:
            threshold = qos_settings.threshold
            payload = {VolumePayloadConst.threshold: {}}
            if qos_settings.threshold.is_lower_iops_enabled is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.isLowerIopsEnabled
                ] = threshold.is_lower_iops_enabled
            if qos_settings.threshold.lower_iops is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.lowerIops
                ] = threshold.lower_iops

            if qos_settings.threshold.is_upper_iops_enabled is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.isUpperIopsEnabled
                ] = threshold.is_upper_iops_enabled
            if qos_settings.threshold.upper_iops is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.upperIops
                ] = threshold.upper_iops

            if qos_settings.threshold.is_upper_transfer_rate_enabled is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.isUpperTransferRateEnabled
                ] = threshold.is_upper_transfer_rate_enabled
            if qos_settings.threshold.upper_transfer_rate is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.upperTransferRate
                ] = threshold.upper_transfer_rate

            if qos_settings.threshold.is_lower_transfer_rate_enabled is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.isLowerTransferRateEnabled
                ] = threshold.is_lower_transfer_rate_enabled
            if qos_settings.threshold.lower_transfer_rate is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.lowerTransferRate
                ] = threshold.lower_transfer_rate

            if qos_settings.threshold.is_response_priority_enabled is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.isResponsePriorityEnabled
                ] = threshold.is_response_priority_enabled
            if qos_settings.threshold.response_priority is not None:
                payload[VolumePayloadConst.threshold][
                    VolumePayloadConst.responsePriority
                ] = threshold.response_priority

        else:
            return None

        end_point = self.end_points.SALAMENDER_UPDATE_QOS_SETTINGS.format(volume_id)
        return self.rest_api.pegasus_patch(end_point, payload)

    @log_entry_exit
    def get_volume_server_connection_info(self):
        """
        Get the server connection information for a volume.
        """
        end_point = self.end_points.SALAMENDER_GET_LDEVS_SERVER_CONNECTION
        connection_info = self.rest_api.pegasus_get(end_point)
        return SalamanderVolumeServerConnectionInfo().dump_to_object(connection_info)

    @log_entry_exit
    def get_volume_server_connection_info_by_id(self, volume_id, server_id):
        """
        Get the server connection information for a specific volume by its volume id and server id.
        """
        end_point = self.end_points.SALAMENDER_GET_LDEV_SERVER_CONNECTION.format(
            f"{volume_id}, {server_id}"
        )
        try:
            connection_info = self.rest_api.pegasus_get(end_point)
            return SalamanderVolumeServerInfo(**connection_info)
        except Exception as e:
            logger.writeError(
                f"Failed to get server connection info for volume {volume_id} and server {server_id}: {e}"
            )
            return None

    @log_entry_exit
    def attach_server_to_volume(self, volume_id, server_ids):
        """
        Attach a server to a volume.
        """
        end_point = self.end_points.ATTACH_SERVER_SIMPLE
        payload = {"volumeIds": [volume_id], "serverIds": server_ids}
        affected_resource, failed_job = self.rest_api.pegasus_post_multi_jobs(
            end_point, payload
        )
        return affected_resource, failed_job

    @log_entry_exit
    def attach_servers_to_volumes(self, volume_ids, server_ids):
        """
        Attach servers to volumes.
        """
        end_point = self.end_points.ATTACH_SERVER_SIMPLE
        payload = {"volumeIds": volume_ids, "serverIds": server_ids}
        affected_resource, failed_job = self.rest_api.pegasus_post_multi_jobs(
            end_point, payload
        )
        return affected_resource, failed_job

    @log_entry_exit
    def detach_server_from_volume(self, volume_id, server_id):
        """
        Detach a server from a volume.
        """
        end_point = self.end_points.DETACH_SERVER_SIMPLE.format(
            f"{volume_id},{server_id}"
        )
        response = self.rest_api.pegasus_delete(end_point, None)
        return response

    @log_entry_exit
    def get_storage_details(self):
        storage_info = self.storage_gw.get_current_storage_system_info()
        pegasus_model = any(sub in storage_info.model for sub in PEGASUS_MODELS)
        logger.writeDebug(f"Storage Model: {storage_info.model}")
        return pegasus_model
