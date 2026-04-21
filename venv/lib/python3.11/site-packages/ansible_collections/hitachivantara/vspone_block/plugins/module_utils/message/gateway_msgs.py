from enum import Enum


class GatewayValidationMsg(Enum):
    SUBSCRIBER_NAME_MISSING = "Subscriber name is missing."
    QUOTA_LIMIT_MISSING = "Quota Limit is missing."
    SUBSCRIBER_ID_MISSING = "Subscriber ID is missing."
    NAME_LENGTH = "Subscriber name should be between 3-255 characters."
    ID_LENGTH = "Subscriber ID should be less than or equal to 15 characters."
    ID_NUMERIC = "Subscriber ID should be numeric values only."
    SOFT_LIMIT = "Value of soft limit should be between 0 and 99."
    HARD_LIMIT = "Value of hard limit should be between 1 and 100."
    QUOTA_LIMIT = "Minimum value of quota limit should be 1."
    HARD_LIMIT_GREATER = "Hard limit can not be less than or equal to soft limit."

    SUBSCRIBER_ID_FOR_RESOURCE_MISSING = (
        "Subscriber ID is missing. Provide subscriber_id in the connection_info."
    )
    UNSUPPORTED_RESOURCE_TYPE = "This type {} is not supported. Supported types are {}."
    PROVIDE_RESOURCE_VALUE = "Provide a resource value."
