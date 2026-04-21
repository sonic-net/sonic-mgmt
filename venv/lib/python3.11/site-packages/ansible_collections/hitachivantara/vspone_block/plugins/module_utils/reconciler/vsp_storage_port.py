try:
    from ..common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.vsp_utils import (
        camel_to_snake_case_dict,
        camel_to_snake_case_dict_array,
    )
    from ..provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from ..provisioner.vsp_uvm_provisioner import VSPUvmProvisioner
    from ..model.vsp_storage_port_models import ChangePortSettingSpec
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from common.ansible_common import (
        log_entry_exit,
        camel_to_snake_case,
        get_default_value,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.vsp_utils import (
        camel_to_snake_case_dict,
        camel_to_snake_case_dict_array,
    )
    from provisioner.vsp_storage_port_provisioner import VSPStoragePortProvisioner
    from provisioner.vsp_uvm_provisioner import VSPUvmProvisioner
    from model.vsp_storage_port_models import ChangePortSettingSpec
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway


class VSPStoragePortReconciler:
    def __init__(self, connection_info, serial, state=None):

        self.logger = Log()
        self.connection_info = connection_info
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial_number()
        self.provisioner = VSPStoragePortProvisioner(connection_info)
        self.state = state

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def vsp_storage_port_facts(self, spec) -> dict:
        if spec.query is None:
            if spec.ports is not None:
                port_info = self.provisioner.filter_port_using_port_ids(
                    spec.ports
                ).data_to_list()
                return StoragePortInfoExtractor(self.storage_serial_number).extract(
                    port_info
                )
            else:
                port_info = self.provisioner.get_all_storage_ports().data_to_list()
                return ShortStoragePortInfoExtractor(
                    self.storage_serial_number
                ).extract(port_info)
        else:
            self.validate_query_spec(spec)
            uvm_provisioner = VSPUvmProvisioner(self.connection_info)
            port_info = uvm_provisioner.get_external_port_info(spec)
            self.logger.writeDebug(f"Port info: {port_info}")
            if not port_info:
                return {}
            if "external_storage_ports" in spec.query:
                return ExternalStoragePortInfoExtractor(
                    self.storage_serial_number
                ).extract(port_info.data_to_list())
            elif "external_luns" in spec.query:
                return ExternalLunInfoExtractor(self.storage_serial_number).extract(
                    port_info.data_to_list()
                )
            else:
                return ExternalPortInfoExtractor(
                    self.storage_serial_number, spec
                ).extract(port_info)

    @log_entry_exit
    def validate_query_spec(self, spec):
        valid_query_keys = [
            "external_iscsi_targets",
            "registered_external_iscsi_targets",
            "external_storage_ports",
            "external_luns",
        ]
        lower_case_query = [key.lower() for key in spec.query]
        if not all(key in valid_query_keys for key in lower_case_query):
            self.logger.writeError(
                f"Invalid query keys provided. Valid keys are: {valid_query_keys}"
            )
            raise ValueError(
                f"Invalid query keys provided. Valid keys are: {valid_query_keys}"
            )
        if spec.ports is None:
            self.logger.writeError(
                "Query parameter cannot be used without specifying ports."
            )
            raise ValueError("Query parameter cannot be used without specifying ports.")
        if len(spec.ports) != 1:
            self.logger.writeError(
                "Query parameter can only be used with a single port."
            )
            raise ValueError("Query parameter can only be used with a single port.")
        if (
            "external_iscsi_targets" in lower_case_query
            and spec.external_iscsi_ip_address is None
        ):
            self.logger.writeError(
                "External iSCSI IP address must be provided when using query parameter 'external_iscsi_targets'."
            )
            raise ValueError(
                "External iSCSI IP address must be provided when using query parameter 'external_iscsi_targets'."
            )
        if (
            "external_luns" in lower_case_query
            and (
                spec.external_wwn
                or (spec.external_iscsi_name and spec.external_iscsi_ip_address)
            )
            is None
        ):
            self.logger.writeError(
                "External WWN or external iSCSI IP address and external iSCSI name must be provided when using query parameter 'external_luns'."
            )
            raise ValueError(
                "External WWN orexternal iSCSI IP address and external iSCSI name must be provided when using query parameter 'external_luns'."
            )
        spec.query = lower_case_query

    @log_entry_exit
    def vsp_storage_port_reconcile(self, spec) -> dict:

        if self.state:
            if self.state == StateValue.LOGIN_TEST:
                test_result = self.provisioner.login_test(spec)
                self.logger.writeDebug(f"login_test_result = {test_result} ")
                external_iscsi_target = camel_to_snake_case_dict_array(
                    test_result.get("externalIscsiTargets")
                )
                new_result = camel_to_snake_case_dict(test_result)
                new_result["external_iscsi_targets"] = external_iscsi_target
                return new_result
            elif self.state == StateValue.REGISTER_EXTERNAL_ISCSI_TARGET:
                test_result = self.provisioner.register_external_iscsi_target(spec)
                self.logger.writeDebug(f"register_test_result = {test_result} ")
                self.connection_info.changed = True
                return ExternalPortInfoExtractor(
                    self.storage_serial_number,
                    spec,
                    "registered_external_iscsi_targets",
                ).extract(test_result)
            elif self.state == StateValue.UNREGISTER_EXTERNAL_ISCSI_TARGET:
                test_result = self.provisioner.unregister_external_iscsi_target(spec)
                self.logger.writeDebug(f"unregister_test_result = {test_result} ")
                self.connection_info.changed = True
                return ExternalPortInfoExtractor(
                    self.storage_serial_number,
                    spec,
                    "registered_external_iscsi_targets",
                ).extract(test_result)
        if spec.host_ip_address is not None:
            return self.provisioner.sending_ping_command_to_host(
                spec.port, spec.host_ip_address
            ).camel_to_snake_dict()
        port_info = self.provisioner.change_port_settings(spec)

        # portInfo = self.provisioner.change_port_settings(
        #     spec.port, spec.port_mode, spec.enable_port_security
        # )
        return port_info.camel_to_snake_dict()
        # return StoragePortInfoExtractor(self.storage_serial_number).extract(
        #     [port_info.to_dict()]
        # )


class StoragePortInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "portId": str,
            "portMode": str,
            "portType": str,
            "portSecuritySetting": bool,
            "portAttributes": list,
            "logins": list,
            "portSpeed": str,
            "loopId": str,
            "fabricMode": bool,
            "portConnection": str,
            "wwn": str,
            "iscsiWindowSize": str,
            "keepAliveTimer": int,
            "tcpPort": str,
            "macAddress": str,
            "ipv4Address": str,
            "ipv4Subnetmask": str,
            "ipv4GatewayAddress": str,
        }

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items


class ShortStoragePortInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "portId": str,
            "portType": str,
            "portAttributes": list,
            "portSpeed": str,
            "loopId": str,
            "fabricMode": bool,
            "portConnection": str,
            "portSecuritySetting": bool,
            "wwn": str,
            "portMode": str,
        }

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items


class ExternalPortInfoExtractor:
    def __init__(self, serial, spec, query=None):
        self.storage_serial_number = serial
        self.common_properties = {
            "portId": str,
            "externalIscsiTargets": list,
        }
        self.spec = spec
        self.query = query

    def extract(self, response):
        output = {}
        output["storage_serial_number"] = self.storage_serial_number
        output["port_id"] = response.portId

        iscsi_list = []
        for target in response.externalIscsiTargets:
            target_dict = {}
            for key, value_type in target.items():
                # Get the corresponding key from the response or its mapped key
                response_key = target.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    if response_key == "-":
                        target_dict[cased_key] = ""
                    else:
                        target_dict[cased_key] = response_key
                else:
                    # Handle missing keys by assigning default values
                    default_value = get_default_value(value_type)
                    target_dict[cased_key] = default_value
            iscsi_list.append(target_dict)
        if isinstance(self.spec, ChangePortSettingSpec) and self.query:
            output[self.query] = iscsi_list
        else:
            if "external_iscsi_targets" in self.spec.query:
                output["external_iscsi_targets"] = iscsi_list
            elif "registered_external_iscsi_targets" in self.spec.query:
                output["registered_external_iscsi_targets"] = iscsi_list

        return output


class ExternalLunInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "externalLun": int,
            "portId": str,
            "externalWwn": str,
            "externalVolumeCapacity": int,
            "externalVolumeInfo": str,
            "iscsiIpAddress": str,
            "iscsiName": str,
            "virtualPortId": int,
        }

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            new_dict["storage_serial_number"] = self.storage_serial_number
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                # else:
                #     # Handle missing keys by assigning default values
                #     default_value = get_default_value(value_type)
                #     new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items


class ExternalStoragePortInfoExtractor:
    def __init__(self, serial):
        self.storage_serial_number = serial
        self.common_properties = {
            "portId": str,
            "externalSerialNumber": str,
            "externalStorageInfo": str,
            "externalPathMode": str,
            "externalIsUsed": bool,
            "externalWwn": str,
            "iscsiIpAddress": str,
            "iscsiName": str,
            "virtualPortId": int,
        }

    def extract(self, responses):
        new_items = []
        for response in responses:
            new_dict = {}
            new_dict["storage_serial_number"] = self.storage_serial_number
            for key, value_type in self.common_properties.items():
                # Get the corresponding key from the response or its mapped key
                response_key = response.get(key)
                # Assign the value based on the response key and its data type
                cased_key = camel_to_snake_case(key)
                if response_key is not None:
                    new_dict[cased_key] = value_type(response_key)
                # else:
                #     # Handle missing keys by assigning default values
                #     default_value = get_default_value(value_type)
                #     new_dict[cased_key] = default_value
            new_items.append(new_dict)
        return new_items
