from enum import Enum


class VspNvmValidationMsg(Enum):
    FEATURE_NOT_SUPPORTED = (
        "NVM subsystem feature is not supported on this storage system."
    )
    NVM_ID_OUT_OF_RANGE = (
        "NVM Subsystem id is out of range, specify within the range of 0 to 2047."
    )
    NOT_NVM_ID_OR_NVM_NAME = (
        "Either NVM Subsystem Id or NVM Subsystem Name should be provided."
    )

    CONTRADICT_INFO = "Contradicting information provided in the spec. During create, remove task was specified."
    NAMESPACE_CREATION_FAILED = (
        "The specified LDEV number is already used as a namespace."
    )
    NO_NVM_ID_LEFT = "All NVM Subsystem Ids are already used."
    INVALID_HOST_MODE = "Invalid host mode specified. Valid values are {}."
    FC_PORT_HAS_HOST_GROUPS = "The port {} is not in NVMe mode and has hostgroups attached to it. Can't be used for NVM subsystem."
    CHANGE_PORT_MODE_TO_NVME_FAILED = (
        "Failed to change port mode to NVMe for the port {}."
    )
    NO_NVM_SUBSYSTEM_FOUND = "No NVM Subsystem found on this storage."
    NVM_SUBSYSTEM_NOT_FOUND = "Given NVM Subsystem does not exist."
    NVME_ALREADY_PRESENT = "The NVMe port is already present."
