try:
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..common.vsp_utils import (
        camel_to_snake_case_dict,
    )
    from ..provisioner.vsp_storage_system_monitor_provisioner import (
        VSPStorageSystemMonitorProvisioner,
    )
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

except ImportError:
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from common.vsp_utils import (
        camel_to_snake_case_dict,
    )
    from provisioner.vsp_storage_system_monitor_provisioner import (
        VSPStorageSystemMonitorProvisioner,
    )
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VSPStorageSystemMonitorReconciler:

    def __init__(self, connection_info, serial=None):
        self.connection_info = connection_info
        if serial is None:
            self.serial = self.get_storage_serial_number()
        self.provisioner = VSPStorageSystemMonitorProvisioner(
            self.connection_info, self.serial
        )

    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def storage_system_monitor_facts(self, spec=None):

        err_msg = "The API is not supported for the specified storage system".lower()
        usr_msg = "This operation is not supported for the specified storage system."

        if spec.query == "channel_boards":
            try:
                rsp = self.provisioner.get_channel_boards()
                if rsp is None:
                    rsp = []
                logger.writeInfo(f"storage_system_monitor_facts={rsp}")
                extracted_data = ChannelBoardInfoExtractor(self.serial).extract(
                    rsp.data_to_list()
                )
                return extracted_data
            except Exception as e:
                logger.writeException(e)
                if err_msg in str(e).lower():
                    raise ValueError(usr_msg)
        if spec.query == "alerts":
            try:
                rsp = self.provisioner.get_alerts(spec)
                if rsp is None:
                    rsp = []
                logger.writeInfo(f"storage_system_monitor_facts={rsp}")
                extracted_data = AlertInfoExtractor(self.serial).extract(
                    rsp.data_to_list()
                )
                return extracted_data
            except Exception as e:
                logger.writeException(e)
                if err_msg in str(e).lower():
                    raise ValueError(usr_msg)
        if spec.query == "hardware_installed":
            rsp = self.provisioner.get_hw_installed(spec)
            if rsp is None:
                rsp = []
            logger.writeInfo(f"storage_system_monitor_facts:hardware_installed={rsp}")
            extracted_data = HardwareInfoExtractor(self.serial).extract(rsp)
            return extracted_data


class AlertInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number
        self.common_properties = {
            "alertIndex": str,
            "alertID": int,
            "occurenceTime": str,
            "referenceCode": int,
            "errorLevel": str,
            "errorSection": str,
            "errorDetail": str,
            "location": str,
            "actionCodes": list,
        }

    def fix_bad_camel_to_snake_conversion(self, key):
        new_key = key.replace("alert_i_d", "alert_id")
        return new_key

    def process_list(self, response_key):
        new_items = []
        if response_key is None:
            return []
        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
                # if value_type == list:
                #     value = self.process_list(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
            new_items.append(new_dict)
        return new_items

    @log_entry_exit
    def extract(self, responses):
        logger.writeDebug(f"storage_system_facts={responses} len = {len(responses)}")
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                if value_type == list:
                    response_key = self.process_list(response_key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if "alert_i_d" in cased_key:
                    cased_key = self.fix_bad_camel_to_snake_conversion(cased_key)
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items


class HardwareInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number

        self.common_properties = {
            "system": dict,
            "ctls": list,
            "cacheMemorySummary": dict,
            "sharedMemorySummary": dict,
            "lanbSummary": dict,
            "bkmfSummary": dict,
            "dkcpsSummary": dict,
            "driveBoxSummary": dict,
            "processorSummary": dict,
            "batterySummary": dict,
            "xPathSummary": dict,
            "dkcs": list,
            "smFunctions": list,
            "driveBoxes": list,
            "hsnbxs": list,
            "xPaths": list,
        }

    def process_list(self, response_key):
        new_items = []
        if response_key is None:
            return []
        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = camel_to_snake_case(key)
                value_type = type(value)
                logger.writeDebug(f"value_type = {value_type}")
                if value_type == list:
                    value = self.process_list(value)
                if value is None:
                    default_value = get_default_value(value_type)
                    value = default_value
                new_dict[key] = value
            new_items.append(new_dict)
        return new_items

    def extract(self, response):
        logger.writeDebug(f"storage_system_facts={response} len = {len(response)}")
        new_dict = {"storage_serial_number": self.storage_serial_number}
        for key, value_type in self.common_properties.items():
            # logger.writeDebug(f"key={key} value_type = {value_type}")
            value = response.get(key)
            if value is None:
                continue
            cased_key = camel_to_snake_case(key)
            if value_type is list:
                new_dict[cased_key] = self.process_list(value)
            elif value_type is dict:
                new_dict[cased_key] = camel_to_snake_case_dict(value)
            else:
                new_dict[cased_key] = value
        return new_dict


class ChannelBoardInfoExtractor:
    def __init__(self, storage_serial_number):
        self.storage_serial_number = storage_serial_number
        self.common_properties = {
            "channelBoardId": int,
            "location": str,
            "clusterNumber": int,
            "channelBoardNumber": int,
            "channelBoardType": str,
            "numOfPorts": str,
            "maxPortSpeed": str,
            "cableMaterial": int,
        }

    @log_entry_exit
    def extract(self, responses):
        logger.writeDebug(f"storage_system_facts={responses} len = {len(responses)}")
        new_items = []
        for response in responses:
            new_dict = {"storage_serial_number": self.storage_serial_number}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
