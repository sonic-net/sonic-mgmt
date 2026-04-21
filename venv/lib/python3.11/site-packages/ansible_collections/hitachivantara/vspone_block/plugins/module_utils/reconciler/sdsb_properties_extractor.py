from abc import ABC

try:
    from ..common.ansible_common import (
        camel_to_snake_case,
        camel_array_to_snake_case,
        camel_dict_to_snake_case,
        log_entry_exit,
        get_default_value,
    )
    from ..common.hv_log import Log
except ImportError:
    from common.ansible_common import (
        camel_to_snake_case,
        camel_array_to_snake_case,
        camel_dict_to_snake_case,
        log_entry_exit,
        get_default_value,
    )
    from common.hv_log import Log

logger = Log()


class SDSBBasePropertiesExtractor(ABC):
    def __init__(self):
        self.common_properties = {}
        self.parameter_mapping = {}

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
    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():

                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                if value_type == dict:
                    response_key = self.change_keys(response_key)
                # logger.writeDebug('RC:extract:self.size_properties = {}', self.size_properties)
                # logger.writeDebug(
                #     "RC:extract:key = {} response_key={}", key, response_key
                # )
                # logger.writeDebug("RC:extract:value_type={}", value_type)
                # Assign the value based on the response key and its data type
                key = camel_to_snake_case(key)
                if response_key is not None:
                    if key in self.parameter_mapping.keys():
                        new_key = self.parameter_mapping.get(key)
                        new_dict[new_key] = value_type(response_key)
                    else:
                        new_dict[key] = value_type(response_key)
                        # logger.writeDebug(
                        #     "RC:extract:value_type(response_key)={}",
                        #     value_type(response_key),
                        # )
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[key] = default_value
            new_items.append(new_dict)
        new_items = camel_array_to_snake_case(new_items)
        return new_items

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
        new_dict = camel_dict_to_snake_case(new_dict)
        return new_dict


class ComputeNodePropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "id": str,
            "nickname": str,
            "osType": str,
            "totalCapacity": int,
            "usedCapacity": int,
            "numberOfPaths": int,
            "vpsId": str,
            "vpsName": str,
            "numberOfVolumes": int,
            # "lun": int,
            "paths": list,
        }

        self.parameter_mapping = {
            "nickname": "name",
            "total_capacity": "total_capacity_mb",
            "used_capacity": "used_capacity_mb",
        }


class ComputePortPropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "id": str,
            "protocol": str,
            "type": str,
            "name": str,
            "nickname": str,
            "configuredPortSpeed": str,
            "portSpeed": str,
            "portNumber": str,
            "portSpeedDuplex": str,
            "protectionDomainId": str,
            "storageNodeId": str,
            "interfaceName": str,
            "statusSummary": str,
            "status": str,
            "fcInformation": str,
            "nvmeTcpInformation": dict,
            "iscsiInformation": dict,
        }
        self.parameter_mapping = {}


class PortDetailPropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "portInfo": dict,
            "portAuthInfo": dict,
            "chapUsersInfo": list,
        }
        self.parameter_mapping = {}


class VolumeAndComputeNodePropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "volumeInfo": dict,
            "computeNodeInfo": list,
        }
        self.parameter_mapping = {
            "nickname": "name",
            "total_capacity": "total_capacity_mb",
            "used_capacity": "used_capacity_mb",
        }


class ComputeNodeAndVolumePropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "computeNodeInfo": dict,
            "volumeInfo": list,
        }
        self.parameter_mapping = {
            "nickname": "name",
            "total_capacity": "total_capacity_mb",
            "used_capacity": "used_capacity_mb",
        }


class ChapUserPropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        self.common_properties = {
            "id": str,
            "targetChapUserName": str,
            "initiatorChapUserName": str,
        }
        self.parameter_mapping = {}


class VolumePropertiesExtractor(SDSBBasePropertiesExtractor):
    def __init__(self):
        # self.qos_param = {
        #             "upper_alert_allowable_time": int,
        #             "upper_alert_time": str,
        #             "upper_limit_for_iops": int,
        #             "upper_limit_for_transfer_rate": int
        #         }

        self.common_properties = {
            "dataReductionEffects": dict,
            "id": str,
            "name": str,
            "nickname": str,
            "volumeNumber": int,
            "poolId": str,
            "poolName": str,
            "totalCapacity": int,
            "usedCapacity": int,
            "numberOfConnectingServers": int,
            "numberOfSnapshots": int,
            "protectionDomainId": str,
            "fullAllocated": bool,
            "volumeType": str,
            "statusSummary": str,
            "status": str,
            "storageControllerId": str,
            "snapshotAttribute": str,
            "snapshotStatus": str,
            "savingSetting": str,
            "savingMode": str,
            "dataReductionStatus": str,
            "dataReductionProgressRate": str,
            "vpsId": str,
            "vpsName": str,
            "naaId": str,
            "qosParam": dict,
            "computeNodesInfo": list,
        }
        # self.size_properties = ("total_capacity", "used_capacity")
        self.size_properties = ()
        self.parameter_mapping = {
            "total_capacity": "total_capacity_mb",
            "used_capacity": "used_capacity_mb",
            "upper_alert_allowable_time": "upper_alert_allowable_time_in_sec",
            "upper_limit_for_transfer_rate": "upper_limit_for_transfer_rate_mb_per_sec",
            "saving_setting": "capacity_saving",
        }
