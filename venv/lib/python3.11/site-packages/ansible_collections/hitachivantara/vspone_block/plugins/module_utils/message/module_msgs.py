from enum import Enum


class ModuleMessage(Enum):
    STORAGE_SYSTEM_ONBOARDING = (
        "The storage system is still onboarding or refreshing, try after sometime."
    )
    OOB_NOT_SUPPORTED = (
        "This functionality is supported with in-band connection mode only."
    )
    NOT_SUPPORTED_FOR_GW = (
        "This functionality is not supported for gateway connection mode."
    )
    HOST_GROUP_NOT_FOUND = "Could not find Host group specified in the spec."
    PARITY_GROUP_NOT_FOUND = "Could not find Parity group specified in the spec."
    STORAGE_PORT_NOT_FOUND = "Could not find Storage port specified in the spec."
    STORAGE_SYSTEM_NOT_FOUND = "Could not find Storage system specified in the spec."
    STORAGE_POOL_NOT_FOUND = "Could not find Storage pool specified in the spec."
    SPM_INFO_NOT_FOUND = "Could not find Server Priority Manager information for the attributes specified in the spec."
    VOLUME_NOT_FOUND = "Volume not found"
