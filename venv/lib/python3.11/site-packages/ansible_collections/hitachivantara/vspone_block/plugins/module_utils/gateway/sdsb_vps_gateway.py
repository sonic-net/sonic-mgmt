try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from ..model.sdsb_vps_models import SDSBVpsListInfo, SDSBVpsInfo, SummaryInformation


except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from model.sdsb_vps_models import SDSBVpsListInfo, SDSBVpsInfo, SummaryInformation


logger = Log()


class SDSBVpsDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_vps(self):
        end_point = SDSBlockEndpoints.GET_VPS
        vps_data = self.connection_manager.get(end_point)
        return SDSBVpsListInfo(
            dicts_to_dataclass_list(vps_data["data"], SDSBVpsInfo),
            SummaryInformation(
                **(
                    vps_data["summaryInformation"]
                    if vps_data.get("summaryInformation", None)
                    else {}
                )
            ),
        )

    @log_entry_exit
    def get_vps_by_id(self, id):
        try:
            end_point = SDSBlockEndpoints.GET_VPS_BY_ID.format(id)
            data = self.connection_manager.get(end_point)
            logger.writeDebug("GW:get_vps_by_id:data={}", data)
            return SDSBVpsInfo(**data)
        except Exception as ex:
            logger.writeDebug("GW:get_vps_by_id:=Exception{}", ex)
            return None

    @log_entry_exit
    def delete_vps_by_id(self, id):
        try:
            end_point = SDSBlockEndpoints.DELETE_VPS.format(id)
            data = self.connection_manager.delete(end_point)
            return data
        except Exception as ex:
            logger.writeDebug("GW:delete_vps_by_id:=Exception{}", ex)
            return None

    @log_entry_exit
    def convert_spec_vol_settings_to_rest_vol_settings_for_create(
        self, spec_vol_settings
    ):

        rest_vol_settings = []

        for x in spec_vol_settings:
            x_dict = x.to_dict()
            r_dict = {}
            r_dict["poolId"] = x_dict["pool_id"]
            r_dict["upperLimitForNumberOfVolumes"] = x_dict[
                "upper_limit_for_number_of_volumes"
            ]
            r_dict["upperLimitForCapacityOfVolumes"] = x_dict[
                "upper_limit_for_capacity_of_volumes_mb"
            ]

            if x_dict.get("upper_limit_for_capacity_of_single_volume_mb", None):
                r_dict["upperLimitForCapacityOfSingleVolume"] = x_dict[
                    "upper_limit_for_capacity_of_single_volume_mb"
                ]

            if x_dict.get("upper_limit_for_iops_of_volume", None):
                r_dict["upperLimitForIopsOfVolume"] = x_dict[
                    "upper_limit_for_iops_of_volume"
                ]

            if x_dict.get("upper_limit_for_transfer_rate_of_volume_mbps", None):
                r_dict["upperLimitForTransferRateOfVolume"] = x_dict[
                    "upper_limit_for_transfer_rate_of_volume_mbps"
                ]

            if x_dict.get("upper_alert_allowable_time_of_volume", None):
                r_dict["upperAlertAllowableTimeOfVolume"] = x_dict[
                    "upper_alert_allowable_time_of_volume"
                ]

            if x_dict.get("capacity_saving", None):
                r_dict["savingSettingOfVolume"] = x_dict["capacity_saving"]

            rest_vol_settings.append(r_dict)

        logger.writeDebug(
            "GW:convert_spec_vol_settings_to_rest_vol_settings_for_create:rest_vol_settings={}",
            rest_vol_settings,
        )
        return rest_vol_settings

    @log_entry_exit
    def create_vps(self, spec):
        end_point = SDSBlockEndpoints.POST_VPS
        payload = {
            "name": spec.name,
            "upperLimitForNumberOfServers": spec.upper_limit_for_number_of_servers,
            "volumeSettings": self.convert_spec_vol_settings_to_rest_vol_settings_for_create(
                spec.volume_settings
            ),
        }
        if spec.upper_limit_for_number_of_user_groups:
            payload["upperLimitForNumberOfUserGroups"] = (
                spec.upper_limit_for_number_of_user_groups
            )
        if spec.upper_limit_for_number_of_users:
            payload["upperLimitForNumberOfUsers"] = spec.upper_limit_for_number_of_users
        if spec.upper_limit_for_number_of_sessions:
            payload["upperLimitForNumberOfSessions"] = (
                spec.upper_limit_for_number_of_sessions
            )

        return self.connection_manager.post(end_point, payload)

    @log_entry_exit
    def update_vps_volume_adr_setting(self, vps_id, adr_setting):
        end_point = SDSBlockEndpoints.UPDATE_VPS.format(vps_id)
        payload = {"savingSettingOfVolume": adr_setting}
        data = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_vps_volume_adr_setting:data={}", data)
        return data

    @log_entry_exit
    def convert_spec_vol_settings_to_rest_vol_settings_for_update(self, spec):
        r_dict = {}
        if spec.name:
            r_dict["name"] = spec.name
        if spec.upper_limit_for_number_of_user_groups:
            r_dict["upperLimitForNumberOfUserGroups"] = (
                spec.upper_limit_for_number_of_user_groups
            )
        if spec.upper_limit_for_number_of_users:
            r_dict["upperLimitForNumberOfUsers"] = spec.upper_limit_for_number_of_users
        if spec.upper_limit_for_number_of_sessions:
            r_dict["upperLimitForNumberOfSessions"] = (
                spec.upper_limit_for_number_of_sessions
            )
        if spec.upper_limit_for_number_of_servers:
            r_dict["upperLimitForNumberOfServers"] = (
                spec.upper_limit_for_number_of_servers
            )
        if spec.upper_limit_for_number_of_volumes:
            r_dict["upperLimitForNumberOfVolumes"] = (
                spec.upper_limit_for_number_of_volumes
            )
        if spec.upper_limit_for_capacity_of_volumes_mb:
            r_dict["upperLimitForCapacityOfVolumes"] = (
                spec.upper_limit_for_capacity_of_volumes_mb
            )
        if spec.upper_limit_for_capacity_of_single_volume_mb:
            r_dict["upperLimitForCapacityOfSingleVolume"] = (
                spec.upper_limit_for_capacity_of_single_volume_mb
            )
        if spec.upper_limit_for_iops_of_volume:
            r_dict["upperLimitForIopsOfVolume"] = spec.upper_limit_for_iops_of_volume
        if spec.upper_limit_for_transfer_rate_of_volume_mbps:
            r_dict["upperLimitForTransferRateOfVolume"] = (
                spec.upper_limit_for_transfer_rate_of_volume_mbps
            )
        if spec.upper_alert_allowable_time_of_volume:
            r_dict["upperLimitForTransferRateOfVolume"] = (
                spec.upper_alert_allowable_time_of_volume
            )
        if spec.capacity_saving:
            r_dict["savingSettingOfVolume"] = spec.capacity_saving
        return r_dict

    @log_entry_exit
    def update_vps(self, vps_id, spec):
        end_point = SDSBlockEndpoints.UPDATE_VPS.format(vps_id)
        payload = self.convert_spec_vol_settings_to_rest_vol_settings_for_update(spec)
        data = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_vps:data={}", data)
        return data
