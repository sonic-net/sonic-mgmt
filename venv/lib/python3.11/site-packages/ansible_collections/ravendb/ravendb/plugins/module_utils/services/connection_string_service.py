# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core import files as file


_CS_KIND_MAP = {
    "RAVEN": {"bucket": "RavenConnectionStrings", "attr": "raven_connection_strings"},
    "SQL": {"bucket": "SqlConnectionStrings", "attr": "sql_connection_strings"},
    "OLAP": {"bucket": "OlapConnectionStrings", "attr": "olap_connection_strings"},
    "ELASTIC_SEARCH": {"bucket": "ElasticSearchConnectionStrings", "attr": "elastic_search_connection_strings"},
    "QUEUE": {"bucket": "QueueConnectionStrings", "attr": "queue_connection_strings"},
    "SNOWFLAKE": {"bucket": "SnowflakeConnectionStrings", "attr": "snowflake_connection_strings"},
    "AI": {"bucket": "AiConnectionStrings", "attr": "ai_connection_strings"},
}


def _cs_kind_info(cs_type_upper):
    t = (cs_type_upper or "").upper()
    info = _CS_KIND_MAP.get(t)
    if not info:
        raise ValueError("Unknown connection string type: {}".format(cs_type_upper))
    return info


def _cs_enum(cs_type):
    from ravendb.serverwide.server_operation_executor import ConnectionStringType

    type = (cs_type or "").upper()
    if type == "RAVEN":
        return ConnectionStringType.RAVEN
    if type == "SQL":
        return ConnectionStringType.SQL
    if type == "OLAP":
        return ConnectionStringType.OLAP
    if type == "ELASTIC_SEARCH":
        return ConnectionStringType.ELASTIC_SEARCH
    if type == "QUEUE":
        return ConnectionStringType.QUEUE
    if type == "SNOWFLAKE":
        return ConnectionStringType.SNOWFLAKE
    if type == "AI":
        return ConnectionStringType.AI

    raise ValueError("Unknown connection string type: {}".format(cs_type))


def builder_for(cs_type):
    type = (cs_type or "").upper()
    mapping = {
        "RAVEN": _build_raven,
        "SQL": _build_sql,
        "OLAP": _build_olap,
        "ELASTIC_SEARCH": _build_elastic,
        "QUEUE": _build_queue,
        "SNOWFLAKE": _build_snowflake,
        "AI": _build_ai,
    }

    try:
        return mapping[type]
    except KeyError:
        raise ValueError("Unknown connection string type: {}".format(cs_type))


def _build_raven(name, p):
    from ravendb.documents.operations.etl.configuration import RavenConnectionString
    return RavenConnectionString(
        name=name,
        database=p.get("database"),
        topology_discovery_urls=p.get("topology_discovery_urls") or p.get("urls") or []
    )


def _build_sql(name, p):
    from ravendb.documents.operations.etl.sql import SqlConnectionString
    raw = p.get("connection_string")
    conn = file.read_secret(raw) if raw is not None else None

    return SqlConnectionString(
        name=name,
        connection_string=conn,
        factory_name=p.get("factory_name"),
    )


def _build_olap(name, p):
    from ravendb.documents.operations.etl.olap.connection import OlapConnectionString

    def _script(d):
        if not d:
            return None
        return {
            "Exec": d.get("exec"),
            "Arguments": d.get("arguments"),
            "TimeoutInMs": d.get("timeout_in_ms"),
        }

    def _local(d):
        if not d:
            return None
        out = {
            "Disabled": d.get("disabled"),
            "FolderPath": d.get("folder_path"),
        }
        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    def _s3(d):
        if not d:
            return None

        out = {
            "Disabled": d.get("disabled"),
            "AwsRegionName": d.get("aws_region_name"),
            "RemoteFolderName": d.get("remote_folder_name"),
            "BucketName": d.get("bucket_name"),
            "CustomServerUrl": d.get("custom_server_url"),
            "ForcePathStyle": d.get("force_path_style"),
        }

        r = d.get("aws_access_key")
        if r is not None:
            out["AwsAccessKey"] = file.read_secret(r)
        r = d.get("aws_secret_key")
        if r is not None:
            out["AwsSecretKey"] = file.read_secret(r)
        r = d.get("aws_session_token")
        if r is not None:
            out["AwsSessionToken"] = file.read_secret(r)

        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    def _azure(d):
        if not d:
            return None

        out = {
            "Disabled": d.get("disabled"),
            "StorageContainer": d.get("storage_container"),
            "RemoteFolderName": d.get("remote_folder_name"),
            "AccountName": d.get("account_name"),
        }
        r = d.get("account_key")

        if r is not None:
            out["AccountKey"] = file.read_secret(r)
        r = d.get("sas_token")
        if r is not None:
            out["SasToken"] = file.read_secret(r)

        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    def _glacier(d):
        if not d:
            return None

        out = {
            "Disabled": d.get("disabled"),
            "AwsRegionName": d.get("aws_region_name"),
            "RemoteFolderName": d.get("remote_folder_name"),
            "VaultName": d.get("vault_name"),
        }
        r = d.get("aws_access_key")
        if r is not None:
            out["AwsAccessKey"] = file.read_secret(r)
        r = d.get("aws_secret_key")
        if r is not None:
            out["AwsSecretKey"] = file.read_secret(r)
        r = d.get("aws_session_token")
        if r is not None:
            out["AwsSessionToken"] = file.read_secret(r)

        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    def _gcs(d):
        if not d:
            return None

        out = {
            "Disabled": d.get("disabled"),
            "BucketName": d.get("bucket_name"),
            "RemoteFolderName": d.get("remote_folder_name"),
        }

        r = d.get("google_credentials_json")
        if r is not None:
            out["GoogleCredentialsJson"] = file.read_secret(r)

        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    def _ftp(d):
        if not d:
            return None

        out = {
            "Disabled": d.get("disabled"),
            "Url": d.get("url"),
            "UserName": d.get("user_name"),
        }
        r = d.get("password")
        if r is not None:
            out["Password"] = file.read_secret(r)
        r = d.get("certificate_as_base64")
        if r is not None:
            out["CertificateAsBase64"] = file.read_secret(r)

        s = _script(d.get("overriding_external_script"))
        if s is not None:
            out["GetBackupConfigurationScript"] = s
        return out

    payload = {}
    ls = _local(p.get("local_settings"))
    if ls is not None:
        payload["local_settings"] = ls
    s3 = _s3(p.get("s3_settings"))
    if s3 is not None:
        payload["s3_settings"] = s3
    az = _azure(p.get("azure_settings"))
    if az is not None:
        payload["azure_settings"] = az
    gl = _glacier(p.get("glacier_settings"))
    if gl is not None:
        payload["glacier_settings"] = gl
    gcs = _gcs(p.get("google_cloud_settings"))
    if gcs is not None:
        payload["google_cloud_settings"] = gcs
    ftp = _ftp(p.get("ftp_settings"))
    if ftp is not None:
        payload["ftp_settings"] = ftp

    return OlapConnectionString(name=name, **payload)


def _build_elastic(name, p):
    from ravendb.documents.operations.etl.elastic_search.connection import (
        ElasticSearchConnectionString, Authentication,
        ApiKeyAuthentication, BasicAuthentication, CertificateAuthentication
    )

    auth_dict = p.get("authentication") or {}
    api_key = auth_dict.get("api_key")
    basic = auth_dict.get("basic")
    cert = auth_dict.get("certificate")

    def _secret(val):
        return file.read_secret(val) if val is not None else None

    def _api_key_auth(d):
        if not d:
            return None
        return ApiKeyAuthentication(
            api_key_id=d.get("api_key_id"),
            api_key=_secret(d.get("api_key")),
            encoded_api_key=_secret(d.get("encoded_api_key")),
        )

    def _basic_auth(d):
        if not d:
            return None
        return BasicAuthentication(
            username=d.get("username"),
            password=_secret(d.get("password")),
        )

    def _cert_auth(d):
        if not d:
            return None
        certs = d.get("certificates_base64") or []
        certs = [_secret(x) for x in certs]
        return CertificateAuthentication(certificates_base64=certs)

    auth = None
    if auth_dict:
        auth = Authentication(
            api_key=_api_key_auth(api_key),
            basic=_basic_auth(basic),
            certificate=_cert_auth(cert),
        )

    return ElasticSearchConnectionString(
        name=name,
        nodes=p.get("nodes") or [],
        authentication=auth,
    )


def _build_queue(name, p):
    from ravendb.documents.operations.etl.queue.connection import QueueConnectionString, QueueBrokerType
    from ravendb.documents.operations.etl.queue.kafka_connection_settings import KafkaConnectionSettings
    from ravendb.documents.operations.etl.queue.rabbit_mq_connection_settings import RabbitMqConnectionSettings
    from ravendb.documents.operations.etl.queue.azure_queue_storage_connection_settings import (
        AzureQueueStorageConnectionSettings, EntraId, Passwordless
    )
    from ravendb.documents.operations.etl.queue.amazon_sqs_connection_settings import (
        AmazonSqsConnectionSettings, AmazonSqsCredentials
    )

    broker = (p.get("broker_type") or "").upper()
    broker_enum = QueueBrokerType[broker] if broker else None

    kafka = p.get("kafka_settings") or {}
    rabbit = p.get("rabbit_mq_settings") or {}
    azq = p.get("azure_queue_storage_settings") or {}
    sqs = p.get("amazon_sqs_settings") or {}

    kafka_obj = KafkaConnectionSettings(**kafka) if kafka else None
    rabbit_obj = RabbitMqConnectionSettings(**rabbit) if rabbit else None

    entra = azq.get("entra_id")
    pwl = azq.get("passwordless")
    azq_obj = AzureQueueStorageConnectionSettings(
        entra_id=(
            EntraId(
                storage_account_name=(entra or {}).get("storage_account_name"),
                tenant_id=(entra or {}).get("tenant_id"),
                client_id=(entra or {}).get("client_id"),
                client_secret=(
                    file.read_secret((entra or {}).get("client_secret"))
                    if (entra or {}).get("client_secret") is not None else None
                ),
            ) if entra else None
        ),
        connection_string=(
            file.read_secret(azq.get("connection_string"))
            if azq.get("connection_string") is not None else None
        ),
        passwordless=Passwordless(**pwl) if pwl else None,
    ) if azq else None

    sqs_basic = (sqs.get("basic") or {})
    sqs_basic_obj = None
    if sqs_basic:
        ak = sqs_basic.get("access_key")
        if ak is not None:
            ak = file.read_secret(ak)
        sk = sqs_basic.get("secret_key")
        if sk is not None:
            sk = file.read_secret(sk)
        sqs_basic_obj = AmazonSqsCredentials(
            access_key=ak,
            secret_key=sk,
            region_name=sqs_basic.get("region_name"),
        )
    sqs_obj = AmazonSqsConnectionSettings(
        basic=sqs_basic_obj,
        passwordless=sqs.get("passwordless"),
    ) if sqs else None

    return QueueConnectionString(
        name=name,
        broker_type=broker_enum,
        kafka_settings=kafka_obj,
        rabbit_mq_settings=rabbit_obj,
        azure_queue_storage_settings=azq_obj,
        amazon_sqs_settings=sqs_obj,
    )


def _build_snowflake(name, p):
    from ravendb.documents.operations.etl.snowflake.connection import SnowflakeConnectionString
    raw = p.get("connection_string")
    conn = file.read_secret(raw) if raw is not None else None
    return SnowflakeConnectionString(
        name=name,
        connection_string=conn,
    )


def _build_ai(name, p):
    from ravendb.documents.operations.ai.ai_connection_string import AiConnectionString, AiModelType
    from ravendb.documents.operations.ai.google_settings import GoogleAiVersion
    from ravendb.documents.operations.ai.open_ai_settings import OpenAiSettings
    from ravendb.documents.operations.ai.azure_open_ai_settings import AzureOpenAiSettings
    from ravendb.documents.operations.ai.ollama_settings import OllamaSettings
    from ravendb.documents.operations.ai.embedded_settings import EmbeddedSettings
    from ravendb.documents.operations.ai.google_settings import GoogleSettings
    from ravendb.documents.operations.ai.hugging_face_settings import HuggingFaceSettings
    from ravendb.documents.operations.ai.mistral_ai_settings import MistralAiSettings

    mt = AiModelType[(p.get("model_type") or "CHAT").upper()]

    providers = (
        "openai_settings",
        "azure_openai_settings",
        "ollama_settings",
        "embedded_settings",
        "google_settings",
        "huggingface_settings",
        "mistral_ai_settings",
    )
    present = [k for k in providers if k in (p or {})]
    if len(present) != 1:
        raise ValueError("AI connection string '{}' must contain exactly one provider block".format(name))
    k = present[0]

    if k == "openai_settings":
        d = dict(p[k])
        r = d.get("api_key")
        if r is not None:
            d["api_key"] = file.read_secret(r)
        settings = {"openai_settings": OpenAiSettings(**d)}

    elif k == "azure_openai_settings":
        d = dict(p[k])
        r = d.get("api_key")
        if r is not None:
            d["api_key"] = file.read_secret(r)
        settings = {"azure_openai_settings": AzureOpenAiSettings(**d)}

    elif k == "ollama_settings":
        settings = {"ollama_settings": OllamaSettings(**p[k])}

    elif k == "embedded_settings":
        settings = {"embedded_settings": EmbeddedSettings()}

    elif k == "google_settings":
        gs = dict(p[k])
        if "ai_version" in gs:
            gs["ai_version"] = GoogleAiVersion[gs["ai_version"]]
        r = gs.get("api_key")
        if r is not None:
            gs["api_key"] = file.read_secret(r)
        settings = {"google_settings": GoogleSettings(**gs)}

    elif k == "huggingface_settings":
        hf = dict(p[k])
        r = hf.get("api_key")
        if r is not None:
            hf["api_key"] = file.read_secret(r)
        settings = {"huggingface_settings": HuggingFaceSettings(**hf)}

    elif k == "mistral_ai_settings":
        ms = dict(p[k])
        r = ms.get("api_key")
        if r is not None:
            ms["api_key"] = file.read_secret(r)
        settings = {"mistral_ai_settings": MistralAiSettings(**ms)}

    else:
        raise ValueError("Unsupported provider '{}'".format(k))

    return AiConnectionString(
        name=name,
        identifier=p.get("identifier"),
        model_type=mt,
        **settings
    )


def _requests():
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError("Python 'requests' is required for Connection String operations. Install 'requests'.")


def fetch_connection_string(ctx, cs_type, name, tls=None):

    from ravendb.documents.operations.connection_string.get_connection_string_operation import GetConnectionStringsOperation

    cs_kind = (cs_type or "").upper()
    cs_enum = _cs_enum(cs_type)

    res = ctx.store.maintenance.send(GetConnectionStringsOperation(name, cs_enum))
    attr = _cs_kind_info(cs_kind)["attr"]
    by_name = getattr(res, attr, None) or {}
    return by_name.get(name)


def _get_all_connection_strings_json(ctx, tls):
    base = ctx.store.urls[0].rstrip("/")
    db = ctx.store.database
    url = "{}/databases/{}/admin/connection-strings".format(base.rstrip("/"), db)

    cert = verify = None
    if tls:
        cert, verify = tls.to_requests_tuple()

    resp = _requests().get(url, cert=cert, verify=verify, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _get_server_version(ctx, tls):
    base = ctx.store.urls[0].rstrip("/")
    url = "{}/build/version".format(base)

    cert = verify = None
    if tls:
        cert, verify = tls.to_requests_tuple()

    r = _requests().get(url, cert=cert, verify=verify, timeout=10)
    r.raise_for_status()
    try:
        data = r.json()
        return str(data.get("ProductVersion") or "").strip()
    except Exception:
        return (r.text or "").strip()


def _parse_version(version_string):

    if not version_string:
        return (0, 0, 0)

    base = ""
    for ch in str(version_string):
        if (ch.isdigit() or ch == "."):
            base += ch
        else:
            break
    parts = (base or "0").split(".")
    parts = (parts + ["0", "0"])[:3]

    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return (0, 0, 0)


def require_min_version_for_type(spec, ctx, tls):
    cs_type = (spec.cs_type or "").upper()
    props = spec.properties or {}

    needed = None
    if cs_type == "AI":
        needed = "7.1.0"
    elif cs_type == "SNOWFLAKE":
        needed = "7.1.0"
    elif cs_type == "QUEUE":
        broker = (props.get("broker_type") or "").upper()
        if broker == "AMAZONSQS":
            needed = "7.1.0"
        elif broker == "AZUREQUEUESTORAGE":
            needed = "6.2.0"

    if not needed:
        return

    server_raw = _get_server_version(ctx, tls)
    have = _parse_version(server_raw)
    need = _parse_version(needed)

    if have < need:
        custom_msg = (
            "{} (AmazonSqs)".format(cs_type)
            if cs_type == "QUEUE" and (props.get("broker_type") or "").upper() == "AMAZONSQS"
            else (
                "{} (AzureQueueStorage)".format(cs_type)
                if cs_type == "QUEUE" and (props.get("broker_type") or "").upper() == "AZUREQUEUESTORAGE"
                else "{}".format(cs_type)
            )
        )
        raise RuntimeError(
            "{} connection strings require RavenDB >= {}; server is '{}'.".format(custom_msg, needed, server_raw)
        )


def type_supported_on_server(ctx, cs_type_upper, tls):
    try:
        data = _get_all_connection_strings_json(ctx, tls)
    except Exception:
        return False
    bucket = _cs_kind_info(cs_type_upper)["bucket"]
    return bucket in data


def exists_via_rest(ctx, cs_type_upper, name, tls):
    data = _get_all_connection_strings_json(ctx, tls)
    bucket = _cs_kind_info(cs_type_upper)["bucket"]
    return name in (data.get(bucket) or {})


def put(ctx, cs_obj):
    from ravendb.documents.operations.connection_string.put_connection_string_operation import PutConnectionStringOperation
    ctx.store.maintenance.send(PutConnectionStringOperation(cs_obj))


def remove(ctx, cs_type, name):
    from ravendb.documents.operations.connection_string.remove_connection_string_operation import RemoveConnectionStringOperation
    type = (cs_type or "").upper()

    if type == "AI":
        # try to work around known AI error on deletion by name in the Python client. (bug nr 3)
        # the bugs are listed here: RDBC-954 Python client: fix Connection String R/W Bugs (OLAP + AI)
        # https://issues.hibernatingrhinos.com/issue/RDBC-954/Python-client-fix-Connection-String-R-W-Bugs-OLAP-AI
        # todo:  refactor this when the py client is fixed
        from ravendb.documents.operations.ai.ai_connection_string import AiConnectionString, AiModelType
        from ravendb.documents.operations.ai.embedded_settings import EmbeddedSettings
        cs_obj = AiConnectionString(
            name=name,
            identifier=None,
            model_type=AiModelType.CHAT,
            embedded_settings=EmbeddedSettings()
        )
    else:
        builder = builder_for(cs_type)
        cs_obj = builder(name, {})

    ctx.store.maintenance.send(RemoveConnectionStringOperation(cs_obj))


def exists(ctx, cs_type, name, tls):
    try:
        return exists_via_rest(ctx, (cs_type or "").upper(), name, tls)
    except Exception:
        return fetch_connection_string(ctx, cs_type, name, tls) is not None
