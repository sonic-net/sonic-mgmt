try:
    from ..provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        camel_to_snake_case,
        log_entry_exit,
        get_default_value,
    )
    from ..message.sdsb_vps_msgs import SDSBVpsValidationMsg
except ImportError:
    from provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import (
        camel_to_snake_case,
        log_entry_exit,
        get_default_value,
    )
    from message.sdsb_vps_msgs import SDSBVpsValidationMsg

logger = Log()


class SDSBVpsReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBVpsProvisioner(self.connection_info)

    @log_entry_exit
    def get_vps_facts(self, spec=None):
        ret_data = self.provisioner.get_vps(spec)
        logger.writeDebug("RC:get_vps:ret_data = {}", ret_data)
        extracted_data = VpsPropertiesExtractor().extract(ret_data)
        logger.writeDebug("RC:get_vps:ret_data = {}", extracted_data)
        return extracted_data

    @log_entry_exit
    def get_vps_by_id(self, id):
        return self.provisioner.get_vps_by_id(id)

    @log_entry_exit
    def get_vps_by_name(self, name):
        return self.provisioner.get_vps_by_name(name)

    @log_entry_exit
    def delete_vps_by_id(self, id):
        self.connection_info.changed = True
        return self.provisioner.delete_vps_by_id(id)

    @log_entry_exit
    def create_sdsb_vps(self, spec):
        if (
            spec.name is None
            or spec.upper_limit_for_number_of_servers is None
            or spec.volume_settings is None
        ):
            raise ValueError(SDSBVpsValidationMsg.CREATE_REQD_FIELDS.value)

        if (
            spec.upper_limit_for_number_of_servers < 0
            or spec.upper_limit_for_number_of_servers > 1024
        ):
            raise ValueError(SDSBVpsValidationMsg.INVALID_NUMBER_OF_SERVERS.value)

        vps_id = self.create_vps(spec)
        if not vps_id:
            raise Exception("Failed to create VPS")

        vps_info = self.get_vps_by_id(vps_id)
        logger.writeDebug("RC:create_sdsb_vps:vps_info = {}", vps_info)
        return VpsPropertiesExtractor().extract_dict(vps_info.to_dict())

    @log_entry_exit
    def create_vps(self, spec):
        self.connection_info.changed = True
        return self.provisioner.create_vps(spec)

    @log_entry_exit
    def update_sdsb_vps(self, vps, spec):
        logger.writeDebug(
            "RC:update_sdsb_vps:spec.capacity_saving = {}", spec.capacity_saving
        )
        logger.writeDebug("RC:update_sdsb_vps:svps = {}", vps)
        if not self.is_updated_required(vps, spec):
            return VpsPropertiesExtractor().extract_dict(vps.to_dict())
        # if spec.capacity_saving:
        #     if vps.volumeSettings.savingSettingOfVolume == spec.capacity_saving:
        #         return VpsPropertiesExtractor().extract_dict(vps.to_dict())

        vps_id = self.update_vps(vps.id, spec)
        if not vps_id:
            raise Exception("Failed to update VPS.")

        vps_info = self.get_vps_by_id(vps_id)
        logger.writeDebug("RC:update_sdsb_vps:vps_info = {}", vps_info)
        return VpsPropertiesExtractor().extract_dict(vps_info.to_dict())

    @log_entry_exit
    def update_vps(self, id, spec):
        self.connection_info.changed = True
        return self.provisioner.update_vps(id, spec)

    @log_entry_exit
    def is_updated_required(self, vps, spec):
        changed = False
        if spec.name and vps.name != spec.name:
            changed = True
        if (
            spec.upper_limit_for_number_of_user_groups
            and vps.upperLimitForNumberOfUserGroups
            != spec.upper_limit_for_number_of_user_groups
        ):
            changed = True
        if (
            spec.upper_limit_for_number_of_users
            and vps.upperLimitForNumberOfUsers != spec.upper_limit_for_number_of_users
        ):
            changed = True
        if (
            spec.upper_limit_for_number_of_sessions
            and vps.upperLimitForNumberOfSessions
            != spec.upper_limit_for_number_of_sessions
        ):
            changed = True
        if (
            spec.upper_limit_for_number_of_servers
            and vps.upperLimitForNumberOfServers
            != spec.upper_limit_for_number_of_servers
        ):
            changed = True
        if (
            spec.upper_limit_for_number_of_volumes
            and vps.volumeSettings.upperLimitForNumberOfVolumes
            != spec.upper_limit_for_number_of_volumes
        ):
            changed = True
        if (
            spec.upper_limit_for_number_of_volumes
            and vps.volumeSettings.upperLimitForNumberOfVolumes
            != spec.upper_limit_for_number_of_volumes
        ):
            changed = True
        if (
            spec.upper_limit_for_capacity_of_volumes_mb
            and vps.volumeSettings.upperLimitForCapacityOfVolumes
            != spec.upper_limit_for_capacity_of_volumes_mb
        ):
            changed = True
        if (
            spec.upper_limit_for_capacity_of_single_volume_mb
            and vps.volumeSettings.upperLimitForCapacityOfSingleVolume
            != spec.upper_limit_for_capacity_of_single_volume_mb
        ):
            changed = True
        if (
            spec.upper_limit_for_iops_of_volume
            and vps.volumeSettings.qosParam.upperLimitForIopsOfVolume
            != spec.upper_limit_for_iops_of_volume
        ):
            changed = True
        if (
            spec.upper_limit_for_transfer_rate_of_volume_mbps
            and vps.volumeSettings.qosParam.upperLimitForTransferRateOfVolume
            != spec.upper_limit_for_transfer_rate_of_volume_mbps
        ):
            changed = True
        if (
            spec.upper_alert_allowable_time_of_volume
            and vps.volumeSettings.qosParam.upperAlertAllowableTimeOfVolume
            != spec.upper_alert_allowable_time_of_volume
        ):
            changed = True
        if (
            spec.capacity_saving
            and vps.volumeSettings.savingSettingOfVolume != spec.capacity_saving
        ):
            changed = True
        return changed

    @log_entry_exit
    def reconcile_vps(self, state, spec):

        if spec is None:
            raise ValueError(SDSBVpsValidationMsg.NO_SPEC.value)

        if state.lower() == StateValue.PRESENT:
            if spec.id is not None:
                logger.writeDebug("RC:=== spec.id is not None ===")
                # user provided an id of the chap user, so this must be an update
                vps = self.get_vps_by_id(spec.id)
                if vps is None:
                    raise ValueError(SDSBVpsValidationMsg.INVALID_VPS_ID.value)
                else:
                    logger.writeDebug("RC:VPS={}", vps)
                    return self.update_sdsb_vps(vps, spec)

            else:
                # this could be a create or an update
                if spec.name is not None:
                    logger.writeDebug("RC:=== spec.name is not None ===")
                    vps = self.get_vps_by_name(spec.name)

                    if vps is not None:
                        # this is an update
                        logger.writeDebug("RC:VPS={}", vps)
                        return self.update_sdsb_vps(vps, spec)
                    else:
                        # this is a create
                        return self.create_sdsb_vps(spec)
                else:
                    raise ValueError(SDSBVpsValidationMsg.NO_NAME_ID.value)

        if state.lower() == StateValue.ABSENT:
            logger.writeDebug("RC:=== Delete VPS ===")
            logger.writeDebug("RC:state = {}", state)
            logger.writeDebug("RC:spec = {}", spec)
            if spec.id is not None:
                # user provided an id of the VPS, so this must be a delete
                vps = self.get_vps_by_id(spec.id)
                if vps is None:
                    raise ValueError(SDSBVpsValidationMsg.INVALID_VPS_ID.value)
                vps_id = spec.id
            elif spec.name is not None:
                # user provided an VPS name, so this must be a delete
                vps = self.get_vps_by_name(spec.name)
                if vps is None:
                    self.connection_info.changed = False
                    raise ValueError(
                        SDSBVpsValidationMsg.VPS_NAME_ABSENT.value.format(spec.name)
                    )
                logger.writeDebug("RC:VPS 2={}", vps)
                vps_id = vps.id
            else:
                raise ValueError(SDSBVpsValidationMsg.NO_NAME_ID.value)

            vps_id = self.delete_vps_by_id(vps_id)
            if vps_id is not None:
                return f"VPS with id {vps_id} is deleted successfully."
            else:
                self.connection_info.changed = False
                return f"Could not delete VPS, ensure VPS ID {vps_id} is valid. "


class VpsPropertiesExtractor:
    def __init__(self):
        self.common_properties = {
            "id": str,
            "name": str,
            "upperLimitForNumberOfUserGroups": int,
            "numberOfUserGroupsCreated": int,
            "upperLimitForNumberOfUsers": int,
            "numberOfUsersCreated": int,
            "upperLimitForNumberOfSessions": int,
            "numberOfSessionsCreated": int,
            "upperLimitForNumberOfServers": int,
            "numberOfServersCreated": int,
            "upperLimitForNumberOfHbas": int,
            "numberOfHbasCreated": int,
            "upperLimitForNumberOfVolumeServerConnections": int,
            "numberOfVolumeServerConnectionsCreated": int,
            "volumeSettings": dict,
        }
        self.summary_properties = {
            "totalCount": int,
            "totalUpperLimitForNumberOfUserGroups": int,
            "totalUpperLimitForNumberOfUsers": int,
            "totalUpperLimitForNumberOfSessions": int,
            "totalUpperLimitForNumberOfVolumes": int,
            "totalUpperLimitForCapacityOfVolumes": int,
            "totalUpperLimitForNumberOfServers": int,
            "totalUpperLimitForNumberOfHbas": int,
            "totalUpperLimitForNumberOfVolumeServerConnections": int,
        }
        self.parameter_mapping = {
            "saving_setting_of_volume": "capacity_saving_of_volume"
        }

    @log_entry_exit
    def change_keys(self, response_key):
        new_dict = {}
        if not response_key:
            return new_dict
        for key, value in response_key.items():
            key = camel_to_snake_case(key)
            if key in self.parameter_mapping.keys():
                new_key = self.parameter_mapping.get(key)
                new_dict[new_key] = value
            else:
                value_type = type(value)
                # logger.writeDebug('RC:extract:change_keys:key={} value_type2 = {}', key, type(value))
                if value_type == dict:
                    value = self.change_keys(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
        return new_dict

    @log_entry_exit
    def extract(self, input_data):
        logger.writeDebug("RC:extract:input_data = {}", input_data)
        new_items = []
        if input_data and input_data.data:
            responses = input_data.data
            for r in responses:
                response = r.to_dict()
                new_dict = {}
                for key, value_type in self.common_properties.items():

                    # Get the corresponding key from the response or its mapped key
                    response_key = response.get(key)
                    logger.writeDebug("r key={} value_type={}", key, value_type)
                    if value_type == dict:
                        response_key = self.change_keys(response_key)

                    # Assign the value based on the response key and its data type
                    key = camel_to_snake_case(key)
                    if response_key is not None:
                        if key in self.parameter_mapping.keys():
                            new_key = self.parameter_mapping.get(key)
                            new_dict[new_key] = value_type(response_key)
                        else:
                            new_dict[key] = value_type(response_key)
                            logger.writeDebug(
                                "RC:extract:value_type(response_key)={}",
                                value_type(response_key),
                            )
                    else:
                        # Handle missing keys by assigning default values
                        default_value = get_default_value(value_type)
                        new_dict[key] = default_value
                new_items.append(new_dict)
        # new_items = camel_array_to_snake_case(new_items)
        summary = input_data.summaryInformation
        new_dict2 = {}
        new_dict2["vsp_info"] = new_items
        new_dict2["vsp_summary_info"] = self.extract_summary(summary.to_dict())
        return new_dict2

    @log_entry_exit
    def extract_summary(self, response):
        new_dict = {}
        for key, value_type in self.summary_properties.items():
            # Get the corresponding key from the response or its mapped key
            response_key = None
            if key in response:
                response_key = response.get(key)

            key = camel_to_snake_case(key)
            if response_key is not None:
                if key in self.parameter_mapping.keys():
                    new_key = self.parameter_mapping.get(key)
                    new_dict[new_key] = value_type(response_key)
                else:
                    new_dict[key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[key] = default_value
        # new_dict = camel_dict_to_snake_case(new_dict)
        return new_dict

    @log_entry_exit
    def extract_dict(self, response):
        new_dict = {}
        for key, value_type in self.common_properties.items():
            # Get the corresponding key from the response or its mapped key
            response_key = None
            if key in response:
                response_key = response.get(key)
                if value_type == dict:
                    response_key = self.change_keys(response_key)
            # Assign the value based on the response key and its data type
            key = camel_to_snake_case(key)
            if response_key is not None:
                if key in self.parameter_mapping.keys():
                    new_key = self.parameter_mapping.get(key)
                    new_dict[new_key] = value_type(response_key)
                else:
                    new_dict[key] = value_type(response_key)
            else:
                # Handle missing keys by assigning default values
                default_value = get_default_value(value_type)
                new_dict[key] = default_value
        # new_dict = camel_dict_to_snake_case(new_dict)
        return new_dict
