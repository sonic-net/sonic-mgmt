from enum import Enum


class SDSBChapUserMessage(Enum):
    pass


class SDSBChapUserValidationMsg(Enum):

    NO_SPEC = "Specifications for the CHAP user are not provided."
    CHAP_USER_ID_ABSENT = "Could not find CHAP user with ID {0}."
    NO_NAME_ID = "Either CHAP user ID or target CHAP user name must be provided."
    CREATE_REQD_FIELD = "target_chap_user_name and target_chap_secret are required fields for creating a CHAP user."
    SECRET_LENGTH_ERR = "CHAP user secret should be 12 to 32 characters long."
    UPDATE_REQD_FIELD = "CHAP user ID is required for updating a CHAP user."
    SAME_TARGET_CHAP_NAME = (
        "The target_chap_user_name must be different to update a CHAP user."
    )
    INVALID_CHAP_USER_ID = (
        "Invalid CHAP user ID is provided, provide a valid CHAP user ID."
    )
    CHAP_USER_NAME_ABSENT = "Could not find CHAP user with target_chap_user_name {0}."
