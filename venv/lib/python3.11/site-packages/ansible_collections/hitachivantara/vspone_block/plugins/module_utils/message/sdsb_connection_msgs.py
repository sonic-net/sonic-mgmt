from enum import Enum


class SDSBConnectionValidationMsg(Enum):
    DIRECT_API_TOKEN_ERROR = (
        "api_token should not be present when connection type is 'direct'."
    )
    BOTH_API_TOKEN_USER_DETAILS = (
        "either api_token or user credential is required, both can't be provided."
    )
    NOT_API_TOKEN_USER_DETAILS = "api_token is required."
