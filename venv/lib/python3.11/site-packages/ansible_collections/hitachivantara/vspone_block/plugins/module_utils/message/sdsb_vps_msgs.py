from enum import Enum


class SDSBChapUserMessage(Enum):
    pass


class SDSBVpsValidationMsg(Enum):

    NO_SPEC = "Specifications for the VPS are not provided."
    INVALID_VPS_ID = "Invalid VPS ID is provided, provide a valid VPS ID."
    NO_NAME_ID = "Either VPS ID or VPS name must be provided."
    VPS_NAME_ABSENT = "Could not find VPS with name {0}."
    VPS_ID_ABSENT = "Could not find VPS with ID {0}."
    CREATE_REQD_FIELDS = "name,  upper_limit_for_number_of_servers and volume_settings are required fields for creating a VPS."
    INVALID_NUMBER_OF_SERVERS = (
        "The value of upper_limit_for_number_of_servers should be between 0 and 1024."
    )

    SAME_SAVING_SETTING = (
        "VPS volume ADR setting is same as the one specified in the spec."
    )
    FEATURE_NOT_SUPPORTED = "{} feature is not supported in this release."
