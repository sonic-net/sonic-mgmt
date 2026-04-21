import os
from ..gateway.sdsb_storage_cluster_mgmt_gateway import (
    SDSBStorageClusterManagementGateway,
)
from ..common.ansible_common import log_entry_exit
from ..common.hv_log import Log
from ..model.sdsb_storage_controller_model import (
    SNMPModelSpec,
    SNMPResponseModel,
    SDSBSpareNodeSpec,
    StorageSystemSpec,
    WebServerAccessSettingSpec,
)
from ..message.sdsb_controller_msgs import SDSBControllerValidationMsg
from ..common.ansible_common import is_valid_ip

logger = Log()


class SDSBStorageClusterMgmtProvisioner:

    def __init__(self, connection_info):

        self.gateway = SDSBStorageClusterManagementGateway(connection_info)
        self.connection_info = connection_info

    @log_entry_exit
    def edit_snmp_settings(self, spec: SNMPModelSpec):
        """
        Edit SNMP settings of the storage controller.

        :param spec: SNMPModelSpec object containing the SNMP settings to be updated.
        :return: Response from the API call.
        """
        self.__validate_input_data(spec)
        try:
            unused = self.gateway.edit_snmp_settings(spec)
            self.connection_info.changed = True

        except Exception as e:
            raise Exception(str(e))

        return self.get_snmp_settings().camel_to_snake_dict()

    @log_entry_exit
    def __validate_input_data(self, spec: SNMPModelSpec):
        """
        Validate input data for SNMP settings.

        :param spec: SNMPModelSpec object containing the SNMP settings to be validated.
        :raises Exception: If validation fails.
        """

        ip_addresses = []
        if (
            spec.request_authentication_setting is not None
            and spec.request_authentication_setting.snmpv2c_settings is not None
        ):
            for setting in spec.request_authentication_setting.snmpv2c_settings:
                if setting.requests_permitted is not None:
                    ip_addresses.extend(setting.requests_permitted)

        if (
            spec.sending_trap_setting is not None
            and spec.sending_trap_setting.snmpv2c_settings is not None
        ):
            for setting in spec.sending_trap_setting.snmpv2c_settings:
                if setting.send_trap_to is not None:
                    ip_addresses.extend(setting.send_trap_to)

        if not spec.system_group_information:
            raise Exception(
                SDSBControllerValidationMsg.REQUIRED_SYSTEM_GROUP_INFO.value
            )

    @log_entry_exit
    def get_snmp_settings(self) -> SNMPResponseModel:
        """
        Retrieve SNMP settings of the storage controller.

        :return: SNMPResponseModel object containing the current SNMP settings.
        """
        response = self.gateway.get_snmp_settings()
        return response

    @log_entry_exit
    def get_protection_domains(self, id):
        """
        Retrieve protection domains of the storage controller.

        :return: List of protection domains.
        """
        response = self.gateway.get_protection_domain_settings_by_id(id)

        return response

    @log_entry_exit
    def update_protection_domain(self, spec):
        """
        Update protection domain settings of the storage controller.

        :param domain_id: ID of the protection domain to be updated.
        :param async_processing_resource_usage_rate: New async processing resource usage rate.
        :return: Response from the API call.
        """
        valid_domain = self.gateway.get_protection_domain_settings_by_id(spec.id)
        if not valid_domain:
            raise Exception(
                SDSBControllerValidationMsg.INVALID_PROTECTION_DOMAIN_ID.value.format(
                    spec.id
                )
            )

        response = self.gateway.update_protection_domain_settings(
            spec.id, spec.async_processing_resource_usage_rate
        )
        self.connection_info.changed = True
        spec.comment = "Updated protection domain settings successfully"
        return response

    @log_entry_exit
    def resume_drive_data(self, spec):
        """
        Request resumption of drive data for a protection domain.

        :param spec: Specification for the protection domain.
        :return: Response from the API call.
        """
        valid_domain = self.gateway.get_protection_domain_settings_by_id(spec.id)
        if not valid_domain:
            raise Exception(
                SDSBControllerValidationMsg.INVALID_PROTECTION_DOMAIN_ID.value.format(
                    spec.id
                )
            )

        response = self.gateway.request_resumption_of_drive_data(spec.id)
        self.connection_info.changed = True
        spec.comment = "Requested resumption of drive data successfully"

        return response

    @log_entry_exit
    def suspend_drive_data(self, spec):
        """
        Request suspension of drive data for a protection domain.

        :param spec: Specification for the protection domain.
        :return: Response from the API call.
        """
        valid_domain = self.gateway.get_protection_domain_settings_by_id(spec.id)
        if not valid_domain:
            raise Exception(
                SDSBControllerValidationMsg.INVALID_PROTECTION_DOMAIN_ID.value.format(
                    spec.id
                )
            )

        response = self.gateway.request_suspension_of_drive_data(spec.id)
        self.connection_info.changed = True
        spec.comment = "Requested suspension of drive data successfully"

        return response

    @log_entry_exit
    def register_update_spare_node(self, spec: SDSBSpareNodeSpec):
        """
        Register a spare node to the storage cluster.

        :param spec: Specification for the spare node.
        :return: Response from the API call.
        """

        if spec.control_port_ipv4_address is not None and not is_valid_ip(
            spec.control_port_ipv4_address
        ):
            raise Exception(
                SDSBControllerValidationMsg.INVALID_IP_ADDRESS_IN_CONTROL_PORT.value.format(
                    spec.control_port_ipv4_address
                )
            )

        if spec.id is not None:
            if not self.__is_exists_spare_node(spec):
                return
            self.gateway.edit_spare_node(spec.id, spec)
            self.connection_info.changed = True
            return self.gateway.get_spare_node_by_id(spec.id)

        if spec.fault_domain_id is not None:
            fault_domain = self.gateway.get_fault_domain_using_id(spec.fault_domain_id)
            if not fault_domain:
                raise Exception(
                    SDSBControllerValidationMsg.INVALID_FAULT_DOMAIN_ID.value.format(
                        spec.fault_domain_id
                    )
                )

        response = self.gateway.register_spare_node(spec)
        self.connection_info.changed = True
        spec.id = response

        response = self.gateway.get_spare_node_by_id(spec.id)
        spec.comment = "Registered spare node successfully"
        return response

    @log_entry_exit
    def unregister_spare_node(self, spec):
        """
        Unregister a spare node from the storage cluster.

        :param spec: Specification for the spare node.
        :return: None
        """
        if not self.__is_exists_spare_node(spec):
            return

        self.gateway.delete_spare_node(spec.id)
        self.connection_info.changed = True
        spec.comment = "Unregistered spare node successfully"
        return

    @log_entry_exit
    def edit_storage_system_settings(self, spec: StorageSystemSpec):
        """
        Set write-back mode with cache protection.

        :param enable: True to enable, False to disable.
        :param force: True to force the operation.
        :return: Response from the API call.
        """
        if spec.enable_write_back_mode_with_cache_protection is not None:

            response = self.gateway.set_write_back_mode_with_cache_protection(
                spec.enable_write_back_mode_with_cache_protection,
                spec.force if spec.force else False,
            )
            self.connection_info.changed = True
            spec.comment = "Set write-back mode with cache protection successfully"
        return response

    @log_entry_exit
    def import_root_certificate(self, spec: StorageSystemSpec):
        """
        Import root certificate to the storage controller.

        :param spec: Specification containing the root certificate file path.
        :return: Response from the API call.
        """
        if spec.root_certificate_file_path is None:
            raise Exception(
                SDSBControllerValidationMsg.REQUIRED_ROOT_CERTIFICATE_FILE_PATH.value
            )

        try:
            response = self.gateway.import_root_certificate_of_bmc(
                spec.root_certificate_file_path
            )
            self.connection_info.changed = True
            spec.comment = "Root certificate imported successfully"
            return response

        except Exception as e:
            logger.writeError("GW:import_root_certificate:error={}", e)
            spec.comment = f"Import root certificate failed : {e}"
            return None

    @log_entry_exit
    def delete_root_certificate(self, spec: StorageSystemSpec):
        """
        Delete root certificate from the storage controller.

        :return: Response from the API call.
        """
        try:
            response = self.gateway.delete_root_certificate_of_bmc()
            self.connection_info.changed = True
            spec.comment = "Root certificate deleted successfully"
            return response
        except Exception as e:
            logger.writeError("GW:delete_root_certificate:error={}", e)
            spec.comment = f"Delete root certificate failed : {e}"
            return None

    @log_entry_exit
    def download_root_certificate(self, spec: StorageSystemSpec):
        """
        Download root certificate from the storage controller.

        :param spec: Specification containing the download path.
        :return: Response from the API call.
        """
        try:
            response = self.gateway.get_root_certificate_of_bmc(spec.download_path)
            spec.comment = response
            return response
        except Exception as e:
            logger.writeError("GW:download_root_certificate:error={}", e)
            spec.comment = (
                f"Root certificate file not found to download or failed : {e}"
            )
            return None

    @log_entry_exit
    def update_web_server_access_settings(self, spec: WebServerAccessSettingSpec):
        """
        Update web server access settings.

        :param spec: Specification containing the web access server settings.
        :return: Response from the API call.
        """
        if (
            spec.enable_client_address_allowlist
            and spec.client_address_allowlist is None
        ):
            raise Exception(
                SDSBControllerValidationMsg.REQUIRED_CLIENT_ADDRESS_ALLOWLIST.value
            )

        response = self.gateway.edit_web_server_access_setting(spec)
        self.connection_info.changed = True
        spec.comment = "Updated web server access settings successfully"
        return response

    @log_entry_exit
    def get_web_server_access_settings(self):
        """
        Retrieve web server access settings.

        :return: Web server access settings.
        """
        response = self.gateway.get_web_server_access_setting()
        return response

    @log_entry_exit
    def import_server_certificate(self, spec):
        """
        Import server certificate to the storage controller.

        :param spec: Specification containing the server certificate file path.
        :return: Response from the API call.
        """
        if (
            spec.server_certificate_file_path is None
            and spec.server_certificate_secret_key_file_path is None
        ):
            raise Exception(
                SDSBControllerValidationMsg.REQUIRED_SERVER_CERTIFICATE_FILE_PATH.value
            )

        if os.path.isfile(spec.server_certificate_file_path) is False:
            raise Exception(
                f"Server certificate file '{spec.server_certificate_file_path}' does not exist."
            )

        if os.path.isfile(spec.server_certificate_secret_key_file_path) is False:
            raise Exception(
                f"Secret key file '{spec.server_certificate_secret_key_file_path}' does not exist."
            )

        try:
            response = self.gateway.import_server_certificate(
                spec.server_certificate_file_path,
                spec.server_certificate_secret_key_file_path,
            )
            self.connection_info.changed = True
            spec.comment = "Import server certificate successfully"
            return response

        except Exception as e:
            logger.writeError("GW:import_server_certificate:error={}", e)
            spec.comment = f"Import server certificate failed : {e}"
            return None

    def __is_exists_spare_node(self, spec):
        if spec.id is None:
            raise Exception(SDSBControllerValidationMsg.REQUIRED_SPARE_NODE_ID.value)
        try:
            spare_node = self.gateway.get_spare_node_by_id(spec.id)
            if spare_node is None:
                raise Exception(
                    SDSBControllerValidationMsg.INVALID_SPARE_NODE_ID.value.format(
                        spec.id
                    )
                )
        except Exception as e:
            spec.comment = "Given spare node id does not exist or deleted."
            return
        return spare_node
