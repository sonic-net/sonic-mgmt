from enum import Enum


class CommonMessage(Enum):
    STORAGE_SYSTEM_INFO_MISSING = "missing required arguments: storage_system_info"
    REGISTERED_PRODUCT_MISSING = "Ansible product is not registered. Please register the product using the register.yml playbook."
    SERIAL_NUMBER_NOT_FOUND = "Could not find serial number {} in the UAI Gateway. Please try again or provide the correct serial number."
    USER_CONSENT_MISSING = (
        "Hitachi Vantara LLC collects usage data such as storage model, storage serial number, operation name, status (success or failure),"
        "and duration. This data is collected for product improvement purposes only. It remains confidential and it is not shared with any "
        "third parties. To provide your consent, run the accept_user_consent.yml playbook."
    )
    FAILED_CONNECTION = "Failed to establish a connection, please check the Management System address or the credentials."
    PORTS_JOURNALS_LUNS = "Ports, Journals, Pools, Quorum disks and LUNs information are not supported for storage system facts."
