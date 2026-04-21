from enum import Enum


class SDSBControllerValidationMsg(Enum):

    CONTROLLER_NOT_FOUND = "Could not find the storage controller with id {}."
    SNMP_UPDATE_ERR = "Failed to update SNMP settings: {}"
    INVALID_IP_ADDRESS_IN_SNMP = (
        "One or more IP addresses in SNMP settings are invalid: {}"
    )
    REQUIRED_SYSTEM_GROUP_INFO = (
        "system_group_information is required in SNMP settings."
    )
    INVALID_PROTECTION_DOMAIN_ID = "Protection domain with ID '{}' does not exist."
    INVALID_IP_ADDRESS_IN_CONTROL_PORT = (
        "The IP address '{}' in control port settings is invalid."
    )
    INVALID_SPARE_NODE_ID = "Spare node with ID '{}' does not exist."
    REQUIRED_ROOT_CERTIFICATE_FILE_PATH = (
        "root_certificate_file_path is required for importing root certificate."
    )
    REQUIRED_SPARE_NODE_ID = "id is required to unregister a spare node."
    INVALID_FAULT_DOMAIN_ID = "Fault domain with ID '{}' does not exist."
    REQUIRED_SERVER_CERTIFICATE_FILE_PATH = (
        "server_certificate_file_path and "
        "server_certificate_secret_key_file_path are required for importing server certificate."
    )
    REQUIRED_CLIENT_ADDRESS_ALLOWLIST = (
        "client_address_allowlist (list of IP addresses) "
        "is required when enable_client_address_allowlist is set to true."
    )
