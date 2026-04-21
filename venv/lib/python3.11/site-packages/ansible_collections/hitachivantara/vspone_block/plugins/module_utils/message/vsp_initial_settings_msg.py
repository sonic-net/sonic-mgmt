from enum import Enum


class VspInitialMsg(Enum):
    AUDIT_LOG = "Audit log file transfer destination updated successfully."
    CERT_FILE_UPLOAD = "Uploading the files required to set the transfer destination of audit log files successful."
    TRANSFER_DEST = (
        "Specifying the transfer destinations of audit log files done successfully."
    )
    TRANSFER_DEST_TEST_MSG = "Test message sent to transfer destination successfully."
    SNMP_UPDATE = "SNMP configuration created or updated successfully."
    SNMP_TEST_MSG = "Test message sent to SNMP configuration successfully."


class ValidationMsg(Enum):
    INVALID_IP_ADDRESS_DEST = "Invalid IP ipv4/ipv6 address provided in the SNMP v1/v2c trap destination settings."
    INVALID_IP_ADDRESS_DEST_V3 = "Invalid IP ipv4/ipv6 address provided in the SNMP v3 trap destination settings."
    INVALID_IP_ADDRESS_AUTH = "Invalid IP ipv4/ipv6 address provided in the SNMP v1/v2c trap authentication settings."
    INVALID_IP_ADDRESS_AUTH_V3 = "Invalid IP ipv4/ipv6 address provided in the SNMP v3 trap authentication settings."
    INVALID_EMAIL = "Invalid email address provided in the system group information contact settings."
