
TARGET_SUB_DIRECTORY = "ansible_collections/hitachivantara/vspone_object"


class Http(object):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    BASE_URL = "/ConfigurationManager/"
    CONTENT_TYPE = "Content-Type"
    APPLICATION_JSON = "application/json"
    RESPONSE_JOB_STATUS = "Response-Job-Status"
    COMPLETED = "Completed"
    HEADERS_JSON = {
        CONTENT_TYPE: APPLICATION_JSON,
        RESPONSE_JOB_STATUS: COMPLETED}
    HTTP = "http://"
    HTTPS = "https://"
    DEFAULT_PORT = 443
    DEFAULT_SSL_PORT = 443
    OPEN_URL_TIMEOUT = 300
    USER_AGENT = "automation-module"
    ERR_400 = 400
    ERR_404 = 404


class StorageClassConstants:
    """
    Enum class for Storage Classes
    """

    NON_MAPI_SPEC_PARAMS = ["queryType", "query_type"]
    DEFAULT_CLASS = "default"
    PRESENT = "present"
    ABSENT = "absent"
    UPDATE = "update"
    SWAP_SPLIT = "swap_split"


class StorageFaultDomainConstants:
    """
    Enum class for Storage Fault domain
    """

    NON_MAPI_SPEC_PARAMS = ["queryType", "query_type"]
    DEFAULT_CLASS = "default"
    PRESENT = "present"
    ABSENT = "absent"
    UPDATE = "update"
    SWAP_SPLIT = "swap_split"


class S3EncryptionConstants:
    """
    Enum class for S3 Encryption Constants
    """
    SUPPORTED_ENCRYPTION_MODE = ["INTERNAL", "EXTERNAL", "DISABLED"]


class StorageComponentConstants:
    """
    Enum class for Storage Components
    """
    DELETE_PATCH_KEYS = ["connectionTtl", "activateNow"]
    CREATE_REQUIRED_FIELDS = ["label", "host", "storageClass",
                              "storageFaultDomain", "port",
                              "bucket", "region", "authType",
                              "accessKey", "secretKey",
                              "managementUser", "managementPassword",
                              "managementProtocol",
                              "managementHost", "activateNow"]
    CREATE_REQUIRED_FIELDS_ARRAY = ["arrayName", "arrayStorageTier", "label",
                                    "storageFaultDomain", "activateNow"]
    CONVERSION_STATE_DECOMMISSION = "DECOMMISSION"
    CONVERSION_STATE_ACTIVE = "ACTIVE"
    CONVERSION_STATE_PAUSED = "PAUSED"
    CONVERSION_STATE_READ_ONLY = "READ_ONLY"
    STORAGE_COMPONENT_STATE_LIST = [
        CONVERSION_STATE_ACTIVE, CONVERSION_STATE_PAUSED, CONVERSION_STATE_READ_ONLY, CONVERSION_STATE_DECOMMISSION]
    DECOMMISSIONED_STATE = "DECOMMISSIONED"
    UNVERIFIED_STATE = "UNVERIFIED"
    INACCESSIBLE_STATE = "INACCESSIBLE"
    NON_EMPTY_FIELDS = ["storageFaultDomain", "region",
                        "bucket", "accessKey", "secretKey", "managementUser",
                        "managementPassword", "managementProtocol",
                        "managementHost"]
    NON_EMPTY_FIELDS_ARRAY = ["storageFaultDomain"]


class KmipConstants:
    """
    Enum class for KMIP Constants
    """
    DEFAULT_HTTPS_CIPHERS = (
        "TLS_RSA_WITH_AES_128_CBC_SHA256,"
        "TLS_RSA_WITH_AES_256_CBC_SHA256,"
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,"
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA,"
        "TLS_AES_256_GCM_SHA384,"
        "TLS_AES_128_GCM_SHA256,"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    )
