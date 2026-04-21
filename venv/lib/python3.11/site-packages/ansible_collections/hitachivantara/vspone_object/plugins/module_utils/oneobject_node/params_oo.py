import re
from .storage_class_msg_catalog import StorageClassMsgCatalog as SCMCA
from .user_buckets_msg_catalog import UserBucketsMsgCatalog as UBMC
from .job_msg_catalog import JobMsgCatalog as JOBMCA
from .serial_number_msg_catalog import SerialNumberMsgCatalog as SERNUMMCA
from .s3_encryption_msg_catalog import S3EncryptionMsgCatalog as S3EMC
from .storage_components_msg_catalog import StorageComponentMsgCatalog as SCOMPMCA
from ..common.hv_constants import StorageClassConstants as SCC
from ..common.hv_constants import StorageComponentConstants as SCOC
from ..common.hv_constants import S3EncryptionConstants as S3EC
from .certificate_msg_catalog import CertificateMsgCatalog as CMCA
from .users_msg_catalog import UsersMsgCatalog as UMC
from .kmip_msg_catalog import KmipMsgCatalog as KMC
from .license_msg_catalog import LicenseMsgCatalog as LMC
from .jobs_msg_catalog import JobsMsgCatalog as JMS


class OOConnectionInfoParam:
    def __init__(self, timeout, retry_times, retry_interval, ssl,
                 cname, region, uname, upasswd, client_id, secret):
        self.http_request_timeout = timeout
        self.http_request_retry_times = retry_times
        self.http_request_retry_interval_seconds = retry_interval
        self.ssl = ssl
        self.cluster_name = cname
        self.region = region
        self.oneobject_node_username = uname
        self.oneobject_node_userpass = upasswd
        self.oneobject_node_client_id = client_id
        self.oneobject_node_client_secret = secret

    def __str__(self):
        return (
            f"OOConnectionInfoParam("
            f"http_request_timeout={self.http_request_timeout}, "
            f"http_request_retry_times={self.http_request_retry_times}, "
            f"http_request_retry_interval_seconds={self.http_request_retry_interval_seconds}, "
            f"ssl={self.ssl}, "
            f"cluster_name={self.cluster_name}, "
            f"region={self.region}, "
            f"oneobject_node_username={self.oneobject_node_username}, "
            f"oneobject_node_userpass=*******, "
            f"oneobject_node_client_id={self.oneobject_node_client_id}, "
            f"oneobject_node_client_secret=*******)")

    def validate(self):
        if self.ssl["validate_certs"] is True:
            if self.ssl["client_cert"] == "":
                raise ValueError("Miss client_cert parameters")
            if self.ssl["client_key"] == "":
                raise ValueError("Miss client_key parameters")
            if self.ssl["ca_path"] == "":
                raise ValueError("Miss ca_path parameters")

        return True


class StorageComponentFactsParam:
    def __init__(self, conn_info, json_spec=None):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"StorageComponents(connection_info={self.connection_info},\
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            storage_component_facts_query = self.json_spec.get(
                "query", None)

            if storage_component_facts_query is not None:
                if storage_component_facts_query != "CAPACITY":
                    raise ValueError(SCOMPMCA.ERR_INVALID_COMPONENT_QUERY_PARAM.value.format(
                        storage_component_facts_query))

            page_size = self.json_spec.get("page_size", None)
            if page_size is not None:
                if page_size <= 0:
                    raise ValueError(SCOMPMCA.ERR_INVALID_PAGE_SIZE.value.format(
                        str(page_size)))
                if isinstance(page_size, bool):
                    raise ValueError(SCOMPMCA.ERR_INVALID_TYPE_PAGE_SIZE.value)
        return True

    def format_bytes(self, size_in_bytes):
        if not isinstance(size_in_bytes, (int, float)):
            try:
                size_in_bytes = float(size_in_bytes)
            except (ValueError, TypeError):
                return str(size_in_bytes)  # Return whole input unchanged
        if size_in_bytes < 0:
            return size_in_bytes

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_in_bytes < 1024:
                return f"{size_in_bytes:.4f} {unit}"
            size_in_bytes /= 1024
        return f"{size_in_bytes:.4f} PB"


class StorageComponentUpdateStateParam:
    def __init__(self, conn_info, json_spec=None):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (
            f"StorageComponentUpdateState(connection_info={self.connection_info},\
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id_value = self.json_spec.get("id", None)
            storage_component_state = self.json_spec.get(
                "storage_component_state", None)

            if id_value is None or storage_component_state is None:
                raise ValueError(SCOMPMCA.ERR_INVALID_SPEC_FIELDS.value)
            if not id_value or id_value.strip() == "":
                raise ValueError(SCOMPMCA.ERR_INVALID_ID.value)
            try:
                int(id_value)
            except ValueError:
                raise ValueError(
                    SCOMPMCA.ERR_INVALID_ID_VALUE.value.format(id_value))
            if storage_component_state == "" or storage_component_state is None:
                raise ValueError(SCOMPMCA.ERR_COMPONENT_STATE_EMPTY.value)
            if isinstance(storage_component_state, bool):
                raise ValueError(
                    SCOMPMCA.ERR_INVALID_COMPONENT_STATE_TYPE.value)
            if storage_component_state not in SCOC.STORAGE_COMPONENT_STATE_LIST:
                raise ValueError(
                    SCOMPMCA.ERR_INVALID_COMPONENT_STATE.value.format(storage_component_state))
        return True


class ActivateStorageComponentParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec
        # self.json_spec = dict()
        # self.json_spec["id"] = json_spec["id"]

    def __str__(self):
        return (
            f"ActivateStorageComponent(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id = self.json_spec.get("id", None)
            if not id or id.strip() == "":
                raise ValueError(SCOMPMCA.ERR_INVALID_UUID.value)
            try:
                int(id)
            except ValueError:
                raise ValueError(
                    SCOMPMCA.ERR_INVALID_ID_VALUE.value.format(id))
            storage_component_config = self.json_spec.get(
                "storage_component_config", None)
            operation = self.json_spec.get("operation", None)
            if storage_component_config is not None and operation is not None:
                raise ValueError(SCOMPMCA.ERR_INVALID_STATE.value)
        else:
            raise ValueError()

        id = self.json_spec.get("id", None)

        self.json_spec = dict()
        self.json_spec["id"] = id

        return True


class Tokens:
    def __init__(self, bearer_token, xsrf_token, vertx_session):
        self.bearer_token = bearer_token
        self.xsrf_token = xsrf_token
        self.vertx_session = vertx_session

    def __str__(self):
        return (f"Tokens(bearer_token={self.bearer_token},\
                xsrf_token={self.xsrf_token},\
                vertx_session={self.vertx_session}")

    def validate(self, state):
        pass


class SystemEventsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"SystemEvents(connection_info={self.connection_info}, \
                json_spec={self.json_spec})")


class GMSEventsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"GMSEvents(connection_info={self.connection_info}, \
                json_spec={self.json_spec})")


class StorageClassParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"StorageClass(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            if self.json_spec["pageSize"] <= 0:
                pageSizeStr = str(self.json_spec["pageSize"])
                raise ValueError("Invalid Page Size: " + pageSizeStr)
        else:
            raise ValueError("Provide Page Size")
        return True


class CreateStorageClassParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"CreateStorageClass(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            name_value = self.json_spec.get("name", None)
            if not name_value or name_value.strip() == "":
                raise ValueError(SCMCA.ERR_INVALID_NAME.value)
            data_count_value = self.json_spec.get("data_count", None)
            if data_count_value is None:
                raise ValueError(SCMCA.ERR_INVALID_DATA_COUNT.value)
            parity_count_value = self.json_spec.get("parity_count", None)
            if parity_count_value is None:
                raise ValueError(SCMCA.ERR_INVALID_PARITY_COUNT.value)
            if len(self.json_spec["name"]) > 63:
                raise ValueError(
                    "Name field length should not exceed 63 characters")
            if not re.match(r'^[a-zA-Z0-9 _-]+$', self.json_spec["name"]):
                raise ValueError(
                    "Invalid value for field name. Allowed characters are Alphanumeric, dash (-), underscore (_) and space")
            if self.json_spec["parity_count"] < 0:
                parity_count_str = str(self.json_spec["parity_count"])
                raise ValueError(
                    f"Parity count must be non-negative, got: {parity_count_str}")
            if self.json_spec["data_count"] < 0:
                data_count_str = str(self.json_spec["data_count"])
                raise ValueError(
                    f"Data count must be non-negative, got: {data_count_str}")
        else:
            raise ValueError("Storage class specification is required")

        return True


class UpdateDefaultStorageClassParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (
            f"UpdateDefaultStorageClass(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id_value = self.json_spec.get("id", None)
            if not id_value or id_value.strip() == "":
                raise ValueError(SCMCA.ERR_INVALID_ID.value)
        else:
            raise ValueError("Storage class specification is required")

        return True


class UpdateStorageClassParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"UpdateStorageClass(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            name_value = self.json_spec.get("name", None)
            if not name_value or name_value.strip() == "":
                raise ValueError(SCMCA.ERR_INVALID_NAME.value)
            if len(self.json_spec["name"]) > 63:
                raise ValueError(
                    "Name field length should not exceed 63 characters")
            if not re.match(r'^[a-zA-Z0-9 _-]+$', self.json_spec["name"]):
                raise ValueError(
                    "Invalid value for field name. Allowed characters are Alphanumeric, dash (-), underscore (_) and space")
            id_value = self.json_spec.get("id", None)
            if not id_value or id_value.strip() == "":
                raise ValueError(SCMCA.ERR_INVALID_ID.value)
        else:
            raise ValueError("Storage class specification is required")

        return True


class StorageClassInfoParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"StorageClass(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id_value = self.json_spec.get("id", None)
            page_size = self.json_spec.get("pageSize", None)

            if (id_value is not None and page_size is not None) or (
                    id_value is None and page_size is None):
                raise ValueError(SCMCA.ERR_INVALID_SPEC_FIELDS.value)
            if id_value is not None:
                if not id_value or id_value.strip() == "":
                    raise ValueError(SCMCA.ERR_INVALID_ID.value)
            if page_size is not None:
                if page_size == "" or page_size is None:
                    raise ValueError(SCMCA.ERR_INVALID_SIZE.value)
                if isinstance(page_size, bool):
                    raise ValueError(SCMCA.ERR_INVALID_TYPE_PAGE_SIZE.value)
                if page_size <= 0:
                    raise ValueError(
                        SCMCA.ERR_INVALID_SIZE.value.format(
                            str(page_size)))
        return True

    def default_query_type(self):
        if self.json_spec is not None:
            query_type = self.json_spec.get("queryType", None)
            if query_type is not None:
                if self.json_spec["queryType"] == SCC.DEFAULT_CLASS:
                    other_params = [k for k in self.json_spec.keys(
                    ) if k != "queryType" and self.json_spec[k] is not None]
                    if len(other_params) > 0:
                        raise ValueError(SCMCA.ERR_INVALID_DEFAULT_SPEC.value)
                    else:
                        return True
                else:
                    return False
        return False


class LicenseParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"LicenseParam(connection_info={self.connection_info})"

    def validate(self):
        return True


class RegionParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"RegionParam(connection_info={self.connection_info})"


class CertificateParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"CertificateParam(connection_info={self.connection_info})"

    def validate_query_one(self):
        if self.json_spec is not None:
            subject_dn_value = self.json_spec.get("subjectDn", None)
            if not subject_dn_value or subject_dn_value.strip() == "":
                raise ValueError(CMCA.ERR_INVALID_SUBJECT_DN.value)
        else:
            raise ValueError("Provide subject_dn parameter")
        return True


class UserParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"UserParam(connection_info={self.connection_info})"

    def validate(self):
        return True


class GenerateS3UserCredentialsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = dict()

    def __str__(self):
        return f"GenerateS3UserCredentials(connection_info={self.connection_info})"

    def validate(self):
        return True


class RevokeS3UserCredentialsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"RevokeS3UserCredentials(connection_info={self.connection_info})"

    def validate(self):
        id = self.json_spec.get("id", None)
        try:
            int(id)
        except Exception:
            raise ValueError(
                UMC.ERR_INVALID_ID_VALUE.value.format(id))
        return True


class SerialNumberParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"SerialNumberParam(connection_info={self.connection_info})"

    def validate(self):
        return True


class SetSerialNumberParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"SetSerialNumber(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            serial_num = self.json_spec.get("serial_number", None)
            if not serial_num or serial_num.strip() == "":
                raise ValueError(SERNUMMCA.ERR_INVALID_SERIAL_NUM.value)
        else:
            raise ValueError("Serial number specification is required")

        return True


class CreateStorageComponentParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (
            f"CreateStorageComponent(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if not self.json_spec:
            raise ValueError(SCOMPMCA.ERR_EMPTY_SPEC.value)
        storage_component_config = self.json_spec.get(
            "storage_component_config", None)
        if not storage_component_config:
            raise ValueError(SCOMPMCA.ERR_EMPTY_COMP_CONF.value)

        operation = self.json_spec.get("operation", "")
        if operation != "":
            if storage_component_config is not None:
                raise ValueError(SCOMPMCA.ERR_INVALID_STATE.value)
        id = self.json_spec.get("id", None)
        if id is not None:
            id = id.strip()
        label = storage_component_config.get("label", None)
        if label is not None:
            label = label.strip()

        if not id and not label:
            raise ValueError(SCOMPMCA.ERR_INVALID_SPEC_ID_LABEL.value)

        return True


class StorageComponentTestParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (
            f"StorageComponentTest(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id = self.json_spec.get("id", None)
            if not id or id.strip() == "":
                raise ValueError(SCOMPMCA.ERR_INVALID_UUID.value)
            try:
                int(id)
            except ValueError:
                raise ValueError(
                    SCOMPMCA.ERR_INVALID_ID_VALUE.value.format(id))
            storage_component_config = self.json_spec.get(
                "storage_component_config", None)
            operation = self.json_spec.get("operation", None)
            if storage_component_config is not None and operation is not None:
                raise ValueError(SCOMPMCA.ERR_INVALID_STATE.value)
        else:
            raise ValueError()

        id = self.json_spec.get("id", None)

        self.json_spec = dict()
        self.json_spec["id"] = id

        return True


class KMIPServerParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"KMIPServerParam(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            name_value = self.json_spec.get("name", None)
            if not name_value or name_value.strip() == "":
                raise ValueError(SCMCA.ERR_INVALID_NAME.value)

        return True


class UserBucketsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"UserBucketsParam(connection_info={self.connection_info})"

    def validate(self):
        if self.json_spec is not None:
            user_id = self.json_spec.get("id", None)
            if not user_id or user_id.strip() == "":
                raise ValueError(UBMC.ERR_ID_NOT_FOUND.value)
        else:
            raise ValueError("User ID is required")
        return True


class CertificateOpParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"CertificateOpParam(connection_info={self.connection_info})"

    def validate(self):
        cert_file_path = self.json_spec.get("cert_file_path", None)
        delete_cert_dn = self.json_spec.get("delete_cert_dn", None)
        state = self.json_spec.pop("state", None)

        if (cert_file_path is None or cert_file_path.strip() == "") and (
                delete_cert_dn is None or delete_cert_dn.strip() == ""):
            raise ValueError(CMCA.ERR_CERT_OP_SPEC.value)
        if cert_file_path and delete_cert_dn:
            raise ValueError(CMCA.ERR_CERT_OP_MUTUAL_EXCLUSIVE.value)
        if state is not None:
            if state == "present":
                if delete_cert_dn is not None and delete_cert_dn.strip() != "":
                    raise ValueError(CMCA.ERR_CERT_OP_STATE.value.format("delete_cert_dn", state))
            elif state == "absent":
                if cert_file_path is not None and cert_file_path.strip() != "":
                    raise ValueError(CMCA.ERR_CERT_OP_STATE.value.format("cert_file_path", state))
        return True


class S3EncryptionParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"S3EncryptionParam(connection_info={self.connection_info})"

    def validate(self):
        return True


class SetS3EncryptionParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"S3EncryptionParam(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            encryption_mode = self.json_spec.get("encryption_mode", None)
            if not encryption_mode or encryption_mode.strip() == "":
                raise ValueError(S3EMC.ERR_INVALID_S3_ENCRYPTION.value)
            if encryption_mode.strip() not in S3EC.SUPPORTED_ENCRYPTION_MODE:
                raise ValueError(
                    S3EMC.ERR_UNSUPPORTED_S3_ENCRYPTION.value.format(encryption_mode))
        else:
            raise ValueError(S3EMC.ERR_INVALID_S3_ENCRYPTION.value)

        return True


class UserIdParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec
        if self.json_spec is not None:
            self.json_spec["id"] = self.json_spec.get("user_uuid", None)

    def __str__(self):
        return f"UserIdParam(connection_info={self.connection_info})"

    def validate(self):
        if self.json_spec is not None:
            user_id = self.json_spec.get("user_uuid", None)
            if not user_id or user_id.strip() == "":
                raise ValueError(UMC.ERR_UUID_EMPTY.value)
            self.json_spec.pop("user_uuid", None)
        else:
            raise ValueError(UMC.ERR_UUID_EMPTY.value)
        return True


class KmipParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec
        if self.json_spec is not None:
            self.json_spec["isTLS12Enabled"] = self.json_spec.get(
                "is_tls12_enabled", None)
            self.json_spec.pop("is_tls12_enabled", None)

    def __str__(self):
        return f"KmipParam(connection_info={self.connection_info})"

    def validate(self):
        if self.json_spec is not None:
            name = self.json_spec.get("name", None)
            if not name or name.strip() == "":
                raise ValueError(KMC.ERR_NAME_EMPTY.value)
            operation = self.json_spec.get("state", None)
            if not operation or operation.strip() == "":
                raise ValueError(KMC.ERR_INVALID_OPERATION.value)

            # ADD operation validation
            if operation == "present" or operation == "modify":
                host = self.json_spec.get("host", None)
                if not host or host.strip() == "":
                    raise ValueError(KMC.ERR_HOST_EMPTY.value)
                port = self.json_spec.get("port", None)
                if not port or port <= 0:
                    raise ValueError(KMC.ERR_PORT_EMPTY.value)
                kmip_protocol = self.json_spec.get("kmip_protocol", None)
                if not kmip_protocol or kmip_protocol.strip() == "":
                    raise ValueError(KMC.ERR_KMIP_PROTOCOL_EMPTY.value)
                https_ciphers = self.json_spec.get("https_ciphers", None)
                if not https_ciphers or https_ciphers.strip() == "":
                    raise ValueError(KMC.ERR_HTTPS_CIPHERS_EMPTY.value)
        else:
            raise ValueError(KMC.ERR_EMPTY_SPEC.value)
        return True


class LicenseOpParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"LicenseOpParam(connection_info={self.connection_info})"

    def validate(self):
        license_file_path = self.json_spec.get("license_file_path", None)

        if (license_file_path is None or license_file_path.strip() == ""):
            raise ValueError(LMC.ERR_LICENSE_ADD_SPEC.value)

        return True


class JobsFactsParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"JobsFactsParam(connection_info={self.connection_info})"

    def validate(self):
        page_size = self.json_spec.get("page_size", None)

        if page_size and page_size <= 0:
            raise ValueError(
                JMS.ERR_INVALID_SPEC.value.format(
                    "page_size", page_size))
        return True


class CreateJobParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"CreateJobParam(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            keys_required = ["job_type", "bucket_name", "job_parameters"]
            for key in keys_required:
                if key not in self.json_spec or not self.json_spec[key]:
                    raise ValueError(JOBMCA.ERR_INVALID_SPEC.value.format(key))
        else:
            raise ValueError(JOBMCA.ERR_EMPTY_SPEC.value)

        return True


class CancelJobParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"CancelJobParam(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            keys_required = ["job_id"]
            for key in keys_required:
                if key not in self.json_spec or not self.json_spec[key]:
                    raise ValueError(JOBMCA.ERR_INVALID_SPEC.value.format(key))
        else:
            raise ValueError(JOBMCA.ERR_EMPTY_SPEC.value)

        return True


class GalaxyInfoParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"GalaxyInfoParam(connection_info={self.connection_info})"

    def validate(self):
        return True


class JobsStatusParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return f"JobsStatusParam(connection_info={self.connection_info})"

    def validate(self):
        job_id = self.json_spec.get("job_id", None)

        if job_id is None:
            raise ValueError(
                JMS.ERR_INVALID_SPEC.value.format(
                    "job_id", job_id))

        return True
