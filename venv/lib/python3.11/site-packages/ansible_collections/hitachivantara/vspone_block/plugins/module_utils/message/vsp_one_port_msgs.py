from enum import Enum


class VspOnePortMSG(Enum):
    # General messages
    PORT_NOT_FOUND = "Port with ID '{port_id}' not found."
    PORT_ALREADY_EXISTS = "Port with ID '{port_id}' already exists."
    INVALID_PORT_STATE = "Invalid state '{state}' for port with ID '{port_id}'."
    OPERATION_SUCCESSFUL = (
        "Port settings applied successfully on port with ID '{port_id}'."
    )
    OPERATION_FAILED = (
        "Operation '{operation}' failed on port with ID '{port_id}': {error}"
    )

    # Port settings change messages
    ERROR_CHANGING_PORT_SETTINGS = (
        "Error changing port settings for port ID {port_id}: {error}"
    )
    ERROR_CHANGING_PORT_SETTINGS_GENERIC = "Error changing port settings: {error}"

    # Protocol validation messages
    MULTIPLE_SETTINGS_PROVIDED = (
        "Only one of fc_settings, iscsi_settings, or nvme_tcp_settings can be provided."
    )
    FC_SETTINGS_REQUIRED_FOR_FC = "fc_settings must be provided for FC protocol."
    ISCSI_SETTINGS_REQUIRED_FOR_ISCSI = (
        "iscsi_settings must be provided for iSCSI protocol."
    )
    NVME_TCP_SETTINGS_REQUIRED_FOR_NVME_TCP = (
        "nvme_tcp_settings must be provided for NVME_TCP protocol."
    )

    # IP validation messages
    INVALID_IP_ADDRESS = "Invalid IP address: {address}"
    INVALID_SUBNET_MASK = "Invalid subnet mask: {subnet_mask}"
    INVALID_GATEWAY = "Invalid gateway: {gateway}"
