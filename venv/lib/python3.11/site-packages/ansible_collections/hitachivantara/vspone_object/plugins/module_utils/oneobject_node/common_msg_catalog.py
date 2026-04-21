from enum import Enum


class CommonMsgCatalog(Enum):
    ERR_CMN_REASON = "Failed to execute. Error: {}."
    ERR_VALIDATION = "Validation failed. Error: {}."
    AUTH_VALIDATION_ERR = (
        "Authentication failed: Unable to retrieve token. "
        "Ensure your credentials and client ID are correct, then try again."
    )
    HTTP_400_ERR = (
        "Bad HTTP Request."
    )
    HTTP_404_ERR = (
        "The requested resource could not be found."
    )
    HTTP_500_ERR = (
        "500 Internal Server Error: "
        "Please try again later."
    )

    USER_CONSENT_MISSING = (
        "Hitachi Vantara LLC collects usage data such as VSP Object serial number, operation name, status (success or failure),"
        "and duration. This data is collected for product improvement purposes only. It remains confidential and it is not shared with any "
        "third parties. To provide your consent, run the accept_user_consent.yml playbook."
    )
