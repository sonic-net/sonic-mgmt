from enum import Enum


class SDSBPortAuthMessage(Enum):
    pass


class SDSBPortAuthValidationMsg(Enum):

    NO_SPEC = "Specifications for the CHAP user are not provided."
    NOT_SUPPORTED = "Absent state for port authentication is not supported."
    PORT_NAME_ABSENT = "Provide port_name, which is a required field."
    PORT_NOT_FOUND = "Port with port_name {0} not found."
    INVALID_AUTH_MODE = "Invalid authentication_mode {} specified. Valid values are CHAP, CHAP_complying_with_initiator_setting, and None."
    INVALID_SPEC_STATE = "Invalid state provided in the spec. Valid states in the spec are :  {0}, and {1}."
    CHAP_USERS_ABSENT = "All target_chap_users name are not present in the system."
    INVALID_CHAP_USER_LIST = "target_chap_users list is empty. Provide target CHAP users name in the list to add/remove CHAP users."

    CHAP_USER_ID_ABSENT = "Could not find CHAP user with ID {0}."
    NO_NAME_ID = "Either CHAP user ID or target CHAP user name must be provided."
    CREATE_REQD_FIELD = "target_chap_user_name and target_chap_secret are required fields for creating a CHAP user."
    SECRET_LENGTH_ERR = "CHAP user secret should be 12 to 32 characters long."
    UPDATE_REQD_FIELD = "CHAP user ID is required for updating a CHAP user."
    SAME_TARGET_CHAP_NAME = (
        "The target_chap_user_name must be different to update a CHAP user."
    )
