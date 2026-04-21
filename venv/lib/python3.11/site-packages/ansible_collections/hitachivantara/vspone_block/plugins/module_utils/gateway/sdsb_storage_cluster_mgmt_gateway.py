from .gateway_manager import SDSBConnectionManager
from ..common.hv_log import Log
from ..common.ansible_common import log_entry_exit
from ..common.sdsb_constants import SDSBlockEndpoints
import os
from ..model.sdsb_storage_controller_model import (
    SNMPModelSpec,
    SNMPResponseModel,
    ProtectionDomainSettingsList,
    ProtectionDomainSettings,
    SDSBStorageSpareNodeModels,
    SDSBStorageSpareNodeModel,
    SDSBSpareNodeSpec,
    SDSBPStorageClusterInfo,
    WebServerAccessSettingResponse,
    WebServerAccessSettingSpec,
)

from ..model.sdsb_storage_system_models import SDSBPfrestPool


logger = Log()


class SDSBStorageClusterManagementGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def edit_snmp_settings(self, spec: SNMPModelSpec):
        """
        Edit SNMP settings of the storage controller.

        :param spec: SNMPResponseModelSpec object containing the SNMP settings to be updated.
        :return: Response from the API call.
        """
        endpoint = SDSBlockEndpoints.SNMP_SETTINGS

        payload = spec.create_snmp_spec()
        response = self.connection_manager.patch(endpoint, payload)
        logger.writeDebug("GW:edit_snmp_settings:response={}", response)
        return response

    @log_entry_exit
    def get_snmp_settings(self):
        """
        Retrieve SNMP settings of the storage controller.

        :return: SNMPResponseModelSpec object containing the current SNMP settings.
        """
        endpoint = SDSBlockEndpoints.SNMP_SETTINGS
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_snmp_settings:response={}", response)
        return SNMPResponseModel(**response)

    @log_entry_exit
    def update_protection_domain_settings(
        self, domain_id, async_processing_resource_usage_rate
    ):

        endpoint = SDSBlockEndpoints.PROTECTION_DOMAIN_SETTINGS_BY_ID.format(domain_id)
        payload = {
            "asyncProcessingResourceUsageRate": async_processing_resource_usage_rate
        }
        response = self.connection_manager.patch(endpoint, payload)
        logger.writeDebug("GW:protection_domain_settings:response={}", response)
        return response

    @log_entry_exit
    def get_protection_domain_settings(self):
        endpoint = SDSBlockEndpoints.PROTECTION_DOMAIN_SETTINGS
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_protection_domain_settings:response={}", response)
        return ProtectionDomainSettingsList().dump_to_object(response)

    @log_entry_exit
    def get_protection_domain_settings_by_id(self, domain_id):
        endpoint = SDSBlockEndpoints.PROTECTION_DOMAIN_SETTINGS_BY_ID.format(domain_id)

        try:
            response = self.connection_manager.get(endpoint)
            logger.writeDebug("GW:get_protection_domain_settings:response={}", response)
            return ProtectionDomainSettings(**response)
        except Exception as e:
            logger.writeError("GW:get_protection_domain_settings:error={}", e)
            return None

    @log_entry_exit
    def request_resumption_of_drive_data(self, domain_id):
        endpoint = SDSBlockEndpoints.RESUME_DRIVE.format(domain_id)
        response = self.connection_manager.post(endpoint, None)
        logger.writeDebug("GW:request_resumption_of_drive_data:response={}", response)
        return response

    @log_entry_exit
    def request_suspension_of_drive_data(self, domain_id):
        endpoint = SDSBlockEndpoints.SUSPEND_DRIVE.format(domain_id)
        response = self.connection_manager.post(endpoint, None)
        logger.writeDebug("GW:request_suspension_of_drive_data:response={}", response)
        return response

    @log_entry_exit
    def delete_root_certificate_of_bmc(self):
        endpoint = SDSBlockEndpoints.DELETE_ROOT_CERTIFICATE
        response = self.connection_manager.post(endpoint, None)
        logger.writeDebug("GW:delete_root_certificate:response={}", response)
        return response

    @log_entry_exit
    def import_root_certificate_of_bmc(self, certificate_file_path):
        """
        Import root certificate of BMC by reading file content and sending as multipart form data.

        :param certificate_file_path: Path to the certificate file to be imported
        :return: Response from the API call
        """
        try:
            # Read the certificate file content (binary-safe)
            with open(certificate_file_path, "rb") as cert_file:
                certificate_content = cert_file.read()

            endpoint = SDSBlockEndpoints.IMPORT_ROOT_CERTIFICATE

            # Generate multipart boundary
            boundary = "------------------------ansibleboundary"
            filename = certificate_file_path.split("/")[-1]

            # Build multipart payload
            # NOTE: keep certificate_content as raw bytes (do NOT decode)
            payload = (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="rootCertificate"; filename="{filename}"\r\n'
                    f"Content-Type: application/x-pem-file\r\n\r\n"
                ).encode("utf-8")
                + certificate_content
                + f"\r\n--{boundary}--\r\n".encode("utf-8")
            )

            # Set headers
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
                "Expect": "",
            }

            # Send request
            response = self.connection_manager.post(
                endpoint, payload, headers_input=headers
            )

            logger.writeDebug("GW:import_root_certificate:response={}", response)
            return response

        except FileNotFoundError:
            logger.writeError("Certificate file not found: {}", certificate_file_path)
            raise
        except Exception as e:
            logger.writeError("Error importing certificate: {}", e)
            raise

    @log_entry_exit
    def get_root_certificate_of_bmc(self, download_path):
        """
        Download root certificate of BMC and save it to the specified path.

        :param download_path: Path where the certificate file should be saved
        :return: Response from the API call
        """
        endpoint = SDSBlockEndpoints.GET_BMC_ROOT_CERTIFICATE

        try:
            # Download the certificate content as binary data
            response = self.connection_manager.download_file(endpoint)

            # Ensure the download directory exists
            os.makedirs(os.path.dirname(download_path), exist_ok=True)
            file_name = "bmc_root_certificate.cer"
            logger.writeInfo(f"Response from BMC: {response}")
            # Save the binary content to the specified download path
            with open(os.path.join(download_path, file_name), "wb") as cert_file:
                if isinstance(response, bytes):
                    cert_file.write(response)
                elif isinstance(response, str):
                    cert_file.write(response.encode("utf-8"))
                else:
                    # Handle other response types by converting to bytes
                    cert_file.write(str(response).encode("utf-8"))
            msg = f"Certificate downloaded and saved to {os.path.join(download_path, file_name)}"
            logger.writeInfo(msg)
            return msg

        except Exception as e:
            logger.writeError("Error downloading and saving certificate: {}", e)
            raise

    @log_entry_exit
    def get_all_spare_nodes(self):
        endpoint = SDSBlockEndpoints.SPARE_NODES
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_all_spare_nodes:response={}", response)
        return SDSBStorageSpareNodeModels().dump_to_object(response)

    @log_entry_exit
    def get_spare_node_by_id(self, node_id):
        endpoint = SDSBlockEndpoints.SPARE_NODES_SINGLE.format(node_id)
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_spare_node:response={}", response)
        return SDSBStorageSpareNodeModel(**response)

    @log_entry_exit
    def register_spare_node(self, spec: SDSBSpareNodeSpec):
        endpoint = SDSBlockEndpoints.SPARE_NODES
        payload = spec.create_spare_node_spec()
        response = self.connection_manager.post(endpoint, payload)
        logger.writeDebug("GW:register_spare_node:response={}", response)
        return response

    @log_entry_exit
    def delete_spare_node(self, node_id):
        endpoint = SDSBlockEndpoints.SPARE_NODES_SINGLE.format(node_id)
        response = self.connection_manager.delete(endpoint)
        logger.writeDebug("GW:delete_spare_node:response={}", response)
        return response

    @log_entry_exit
    def edit_spare_node(self, node_id, spec: SDSBSpareNodeSpec):
        endpoint = SDSBlockEndpoints.SPARE_NODES_SINGLE.format(node_id)
        payload = spec.create_spare_node_spec()
        response = self.connection_manager.patch(endpoint, payload)
        logger.writeDebug("GW:edit_spare_node:response={}", response)
        return response

    @log_entry_exit
    def set_write_back_mode_with_cache_protection(
        self, enable: bool, force: bool = False
    ):
        endpoint = SDSBlockEndpoints.CACHE_PROTECTION
        payload = {"isEnabled": enable}
        if force:
            payload["force"] = force
        response = self.connection_manager.post(endpoint, payload)
        logger.writeDebug(
            "GW:set_write_back_mode_with_cache_protection:response={}", response
        )
        return response

    @log_entry_exit
    def get_storage_system_details(self):
        endpoint = SDSBlockEndpoints.GET_STORAGE_CLUSTER
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_storage_system_details:response={}", response)
        return SDSBPStorageClusterInfo(**response)

    @log_entry_exit
    def get_fault_domain_using_id(self, fault_domain_id):
        endpoint = SDSBlockEndpoints.GET_FAULT_DOMAINS_ID.format(fault_domain_id)
        response = None
        try:
            response = self.connection_manager.get(endpoint)
        except Exception as e:
            logger.writeError("GW:get_fault_domain_using_id:error={}", e)
            return None
        return SDSBPfrestPool(**response)

    @log_entry_exit
    def import_server_certificate(self, certificate_file_path, secret_key_file_path):
        """
        Import server certificate and secret key by reading file contents and sending as multipart form data.

        :param certificate_file_path: Path to the server certificate file to be imported
        :param secret_key_file_path: Path to the secret key file to be imported
        :return: Response from the API call
        """
        try:
            # Read the certificate file content (binary-safe)
            with open(certificate_file_path, "rb") as cert_file:
                certificate_content = cert_file.read()

            # Read the secret key file content (binary-safe)
            with open(secret_key_file_path, "rb") as key_file:
                secret_key_content = key_file.read()

            endpoint = SDSBlockEndpoints.IMPORT_SERVER_CERTIFICATE

            # Generate multipart boundary
            boundary = "------------------------ansibleboundary"
            cert_filename = certificate_file_path.split("/")[-1]
            key_filename = secret_key_file_path.split("/")[-1]

            # Build multipart payload
            payload = (
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="serverCertificate"; filename="{cert_filename}"\r\n'
                    f"Content-Type: application/x-x509-ca-cert\r\n\r\n"
                ).encode("utf-8")
                + certificate_content
                + (
                    f"\r\n--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="secretKey"; filename="{key_filename}"\r\n'
                    f"Content-Type: application/x-pem-file\r\n\r\n"
                ).encode("utf-8")
                + secret_key_content
                + f"\r\n--{boundary}--\r\n".encode("utf-8")
            )

            # Set headers
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
                "Expect": "",
            }

            # Send request
            response = self.connection_manager.post(
                endpoint, payload, headers_input=headers
            )

            logger.writeDebug("GW:import_server_certificate:response={}", response)
            return response

        except FileNotFoundError as e:
            logger.writeError("Certificate or key file not found: {}", e)
            raise
        except Exception as e:
            logger.writeError("Error importing server certificate: {}", e)
            raise

    @log_entry_exit
    def get_web_server_access_setting(self):
        """
        Retrieve server web settings of the storage controller.

        :return: Server web settings object containing the current settings.
        """
        endpoint = SDSBlockEndpoints.WEB_SERVER_ACCESS_SETTING
        response = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_web_server_access_settings:response={}", response)
        return WebServerAccessSettingResponse(**response)

    @log_entry_exit
    def edit_web_server_access_setting(self, spec: WebServerAccessSettingSpec):
        """
        Edit server web settings of the storage controller.

        :param allow_http: Boolean to allow or disallow HTTP access.
        :param allow_https: Boolean to allow or disallow HTTPS access.
        """
        endpoint = SDSBlockEndpoints.WEB_SERVER_ACCESS_SETTING

        payload = {}

        if spec.enable_client_address_allowlist is not None:
            payload["allowlistSetting"] = spec.create_server_allow_settings_spec()

        response = self.connection_manager.patch(endpoint, payload)
        logger.writeDebug("GW:edit_web_server_access_settings:response={}", response)
        return response
