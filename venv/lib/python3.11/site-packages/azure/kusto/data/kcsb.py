import dataclasses
from enum import unique, Enum
from typing import Union, Callable, Coroutine, Optional, Tuple, List, Any, ClassVar
from urllib.parse import urlparse

from ._string_utils import assert_string_is_not_empty
from ._token_providers import DeviceCallbackType
from .client_details import ClientDetails
from .helpers import load_bundled_json


UNSUPPORTED_KEYWORD = "UNSUPPORTED"


@unique
class SupportedKeywords(Enum):
    DATA_SOURCE = "Data Source"
    INITIAL_CATALOG = "Initial Catalog"
    FEDERATED_SECURITY = "AAD Federated Security"
    APPLICATION_CLIENT_ID = "Application Client Id"
    APPLICATION_KEY = "Application Key"
    USER_ID = "User ID"
    PASSWORD = "Password"
    AUTHORITY_ID = "Authority Id"
    APPLICATION_TOKEN = "Application Token"
    USER_TOKEN = "User Token"
    APPLICATION_CERTIFICATE_BLOB = "Application Certificate Blob"
    APPLICATION_CERTIFICATE_X5C = "Application Certificate SendX5c"
    APPLICATION_CERTIFICATE_THUMBPRINT = "Application Certificate Thumbprint"
    TRACE_APP_NAME = "Application Name for Tracing"
    TRACE_USER_NAME = "User Name for Tracing"


@unique
class UnsupportedKeywords(Enum):
    DSTS_FEDERATED_SECURITY = "dSTS Federated Security"
    STREAMING = "Streaming"
    UNCOMPRESSED = "Uncompressed"
    ENFORCE_MFA = "EnforceMfa"
    ACCEPT = "Accept"
    QUERY_CONSISTENCY = "Query Consistency"
    DATA_SOURCE_URI = "Data Source Uri"
    AZURE_REGION = "Azure Region"
    NAMESPACE = "Namespace"
    APPLICATION_CERTIFICATE_ISSUER_DISTINGUISHED_NAME = "Application Certificate Issuer Distinguished Name"
    APPLICATION_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME = "Application Certificate Subject Distinguished Name"


@dataclasses.dataclass(frozen=True)
class Keyword:
    _supported_keywords: ClassVar[List[str]] = [k.value for k in SupportedKeywords]
    _unsupported_keywords: ClassVar[List[str]] = [k.value for k in UnsupportedKeywords]
    _lookup: ClassVar[dict]

    name: SupportedKeywords
    type: str
    secret: bool

    def is_str_type(self) -> bool:
        return self.type == "string"

    def is_bool_type(self) -> bool:
        return self.type == "bool"

    @staticmethod
    def normalize_string(key: str) -> str:
        return key.lower().replace(" ", "")

    @classmethod
    def init_lookup(cls):
        kcsb_json: dict = load_bundled_json("kcsb.json")
        lookup = {}
        for v in kcsb_json["keywords"]:
            name = v["name"]
            if name in cls._supported_keywords:
                keyword = Keyword(SupportedKeywords(name), v["type"], v["secret"])
            elif name in cls._unsupported_keywords:
                keyword = UNSUPPORTED_KEYWORD
            else:
                raise KeyError(f"Unknown keyword: `{name}`")

            lookup[Keyword.normalize_string(name)] = keyword

            for alias in v["aliases"]:
                lookup[Keyword.normalize_string(alias)] = keyword

        cls._lookup = lookup

    @classmethod
    def parse(cls, key: Union[str, SupportedKeywords]) -> "Keyword":
        if isinstance(key, SupportedKeywords):
            key = key.value

        normalized = Keyword.normalize_string(key)

        if normalized not in cls._lookup:
            raise KeyError(f"Unknown keyword: `{key}`")

        if cls._lookup[normalized] == UNSUPPORTED_KEYWORD:
            raise KeyError(f"Keyword `{key}` is not supported by this SDK")

        return cls._lookup[normalized]

    @classmethod
    def lookup(cls, key: Union[str, SupportedKeywords]) -> "Keyword":
        if isinstance(key, SupportedKeywords):
            key = key.value

        return cls._lookup[Keyword.normalize_string(key)]


Keyword.init_lookup()


class KustoConnectionStringBuilder:
    """
    Parses Kusto connection strings.
    For usages, check out the sample at:
        https://github.com/Azure/azure-kusto-python/blob/master/azure-kusto-data/tests/sample.py
    """

    DEFAULT_DATABASE_NAME = "NetDefaultDB"

    interactive_login: bool = False
    az_cli_login: bool = False
    device_login: bool = False
    token_credential_login: bool = False

    device_callback: DeviceCallbackType = None
    msi_authentication: bool = False
    msi_parameters: Optional[dict] = None

    token_provider: Optional[Callable[[], str]] = None
    async_token_provider: Optional[Callable[[], Coroutine[None, None, str]]] = None

    application_for_tracing: Optional[str] = None
    user_name_for_tracing: Optional[str] = None

    azure_credential: Optional[Any] = None
    azure_credential_from_login_endpoint: Optional[Any] = None

    application_public_certificate: Optional[str] = None

    def __init__(self, connection_string: str):
        """
        Creates new KustoConnectionStringBuilder.
        :param str connection_string: Kusto connection string should be of the format:
        https://<clusterName>.kusto.windows.net;AAD User ID="user@microsoft.com";Password=P@ssWord
        For more information please look at:
        https://kusto.azurewebsites.net/docs/concepts/kusto_connection_strings.html
        """
        assert_string_is_not_empty(connection_string)
        self._internal_dict = {}

        if connection_string is not None and "=" not in connection_string.partition(";")[0]:
            connection_string = "Data Source=" + connection_string

        self[SupportedKeywords.AUTHORITY_ID] = "organizations"

        for kvp_string in connection_string.split(";"):
            key, _, value = kvp_string.partition("=")
            keyword = Keyword.parse(key)

            value_stripped = value.strip()
            if keyword.is_str_type():
                if keyword.name == SupportedKeywords.DATA_SOURCE:
                    self[keyword.name] = value_stripped.rstrip("/")
                    self._parse_data_source(self.data_source)
                elif keyword.name == SupportedKeywords.TRACE_USER_NAME:
                    self.user_name_for_tracing = value_stripped
                elif keyword.name == SupportedKeywords.TRACE_APP_NAME:
                    self.application_for_tracing = value_stripped
                else:
                    self[keyword.name] = value_stripped
            elif keyword.is_bool_type():
                if value_stripped in ["True", "true"]:
                    self[keyword.name] = True
                elif value_stripped in ["False", "false"]:
                    self[keyword.name] = False
                else:
                    raise KeyError("Expected aad federated security to be bool. Recieved %s" % value)

        if self.initial_catalog is None:
            self.initial_catalog = self.DEFAULT_DATABASE_NAME

    def __setitem__(self, key: "Union[SupportedKeywords, str]", value: Union[str, bool, dict]):
        keyword = Keyword.parse(key)

        if value is None:
            raise TypeError("Value cannot be None.")

        if keyword.is_str_type():
            self._internal_dict[keyword.name] = value.strip()
        elif keyword.is_bool_type():
            if not isinstance(value, bool):
                raise TypeError("Expected %s to be bool" % key)
            self._internal_dict[keyword.name] = value
        else:
            raise KeyError("KustoConnectionStringBuilder supports only bools and strings.")

    @classmethod
    def with_aad_user_password_authentication(
        cls, connection_string: str, user_id: str, password: str, authority_id: str = "organizations"
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD user name and
        password.
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param str user_id: AAD user ID.
        :param str password: Corresponding password of the AAD user.
        :param str authority_id: optional param. defaults to "organizations"
        """
        assert_string_is_not_empty(user_id)
        assert_string_is_not_empty(password)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.USER_ID] = user_id
        kcsb[SupportedKeywords.AUTHORITY_ID] = authority_id
        kcsb[SupportedKeywords.PASSWORD] = password

        return kcsb

    @classmethod
    def with_aad_user_token_authentication(cls, connection_string: str, user_token: str) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application and
        a certificate credentials.
        :param str connection_string: Kusto connection string should be of the format:
        https://<clusterName>.kusto.windows.net
        :param str user_token: AAD user token.
        """
        assert_string_is_not_empty(user_token)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.USER_TOKEN] = user_token

        return kcsb

    @classmethod
    def with_aad_application_key_authentication(
        cls, connection_string: str, aad_app_id: str, app_key: str, authority_id: str
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application and key.
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param str aad_app_id: AAD application ID.
        :param str app_key: Corresponding key of the AAD application.
        :param str authority_id: Authority id (aka Tenant id) must be provided
        """
        assert_string_is_not_empty(aad_app_id)
        assert_string_is_not_empty(app_key)
        assert_string_is_not_empty(authority_id)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.APPLICATION_CLIENT_ID] = aad_app_id
        kcsb[SupportedKeywords.APPLICATION_KEY] = app_key
        kcsb[SupportedKeywords.AUTHORITY_ID] = authority_id

        return kcsb

    @classmethod
    def with_aad_application_certificate_authentication(
        cls, connection_string: str, aad_app_id: str, certificate: str, thumbprint: str, authority_id: str
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application using
        a certificate.
        :param str connection_string: Kusto connection string should be of the format:
        https://<clusterName>.kusto.windows.net
        :param str aad_app_id: AAD application ID.
        :param str certificate: A PEM encoded certificate private key.
        :param str thumbprint: hex encoded thumbprint of the certificate.
        :param str authority_id: Authority id (aka Tenant id) must be provided
        """
        assert_string_is_not_empty(aad_app_id)
        assert_string_is_not_empty(certificate)
        assert_string_is_not_empty(thumbprint)
        assert_string_is_not_empty(authority_id)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.APPLICATION_CLIENT_ID] = aad_app_id
        kcsb[SupportedKeywords.APPLICATION_CERTIFICATE_BLOB] = certificate
        kcsb[SupportedKeywords.APPLICATION_CERTIFICATE_THUMBPRINT] = thumbprint
        kcsb[SupportedKeywords.AUTHORITY_ID] = authority_id

        return kcsb

    @classmethod
    def with_aad_application_certificate_sni_authentication(
        cls, connection_string: str, aad_app_id: str, private_certificate: str, public_certificate: str, thumbprint: str, authority_id: str
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application using
        a certificate Subject Name and Issuer.
        :param str connection_string: Kusto connection string should be of the format:
        https://<clusterName>.kusto.windows.net
        :param str aad_app_id: AAD application ID.
        :param str private_certificate: A PEM encoded certificate private key.
        :param str public_certificate: A public certificate matching the provided PEM certificate private key.
        :param str thumbprint: hex encoded thumbprint of the certificate.
        :param str authority_id: Authority id (aka Tenant id) must be provided
        """
        assert_string_is_not_empty(aad_app_id)
        assert_string_is_not_empty(private_certificate)
        assert_string_is_not_empty(public_certificate)
        assert_string_is_not_empty(thumbprint)
        assert_string_is_not_empty(authority_id)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.APPLICATION_CLIENT_ID] = aad_app_id
        kcsb[SupportedKeywords.APPLICATION_CERTIFICATE_BLOB] = private_certificate
        kcsb.application_public_certificate = public_certificate
        kcsb[SupportedKeywords.APPLICATION_CERTIFICATE_THUMBPRINT] = thumbprint
        kcsb[SupportedKeywords.AUTHORITY_ID] = authority_id

        return kcsb

    @classmethod
    def with_aad_application_token_authentication(cls, connection_string: str, application_token: str) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application and
        an application token.
        :param str connection_string: Kusto connection string should be of the format:
        https://<clusterName>.kusto.windows.net
        :param str application_token: AAD application token.
        """
        assert_string_is_not_empty(application_token)
        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.APPLICATION_TOKEN] = application_token

        return kcsb

    @classmethod
    def with_aad_device_authentication(
        cls, connection_string: str, authority_id: str = "organizations", callback: DeviceCallbackType = None
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application and
        password.
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param str authority_id: optional param. defaults to "organizations"
        :param DeviceCallbackType callback: options callback function to be called when authentication is required, accepts three parameters:
                - ``verification_uri`` (str) the URL the user must visit
                - ``user_code`` (str) the code the user must enter there
                - ``expires_on`` (datetime.datetime) the UTC time at which the code will expire
        """
        kcsb = cls(connection_string)
        kcsb.device_login = True
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb[SupportedKeywords.AUTHORITY_ID] = authority_id
        kcsb.device_callback = callback

        return kcsb

    @classmethod
    def with_az_cli_authentication(cls, connection_string: str) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will use existing authenticated az cli profile
        password.
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        """
        kcsb = cls(connection_string)
        kcsb.az_cli_login = True
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True

        return kcsb

    @classmethod
    def with_aad_managed_service_identity_authentication(
        cls, connection_string: str, client_id: str = None, object_id: str = None, msi_res_id: str = None, timeout: int = None
    ) -> "KustoConnectionStringBuilder":
        """
        Creates a KustoConnection string builder that will authenticate with AAD application, using
        an application token obtained from a Microsoft Service Identity endpoint. An optional user
        assigned application ID can be added to the token.

        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param client_id: an optional user assigned identity provided as an Azure ID of a client
        :param object_id: an optional user assigned identity provided as an Azure ID of an object
        :param msi_res_id: an optional user assigned identity provided as an Azure ID of an MSI resource
        :param timeout: an optional timeout (seconds) to wait for an MSI Authentication to occur
        """

        kcsb = cls(connection_string)
        params = {}
        exclusive_pcount = 0

        if timeout is not None:
            params["connection_timeout"] = timeout

        if client_id is not None:
            params["client_id"] = client_id
            exclusive_pcount += 1

        if object_id is not None:
            # Until we upgrade azure-identity to version 1.4.1, only client_id is excepted as a hint for user managed service identity
            raise ValueError("User Managed Service Identity with object_id is temporarily not supported by azure identity 1.3.1. Please use client_id instead.")
            # noinspection PyUnreachableCode
            params["object_id"] = object_id
            exclusive_pcount += 1

        if msi_res_id is not None:
            # Until we upgrade azure-identity to version 1.4.1, only client_id is excepted as a hint for user managed service identity
            raise ValueError(
                "User Managed Service Identity with msi_res_id is temporarily not supported by azure identity 1.3.1. Please use client_id instead."
            )
            # noinspection PyUnreachableCode
            params["msi_res_id"] = msi_res_id
            exclusive_pcount += 1

        if exclusive_pcount > 1:
            raise ValueError("the following parameters are mutually exclusive and can not be provided at the same time: client_uid, object_id, msi_res_id")

        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb.msi_authentication = True
        kcsb.msi_parameters = params

        return kcsb

    @classmethod
    def with_token_provider(cls, connection_string: str, token_provider: Callable[[], str]) -> "KustoConnectionStringBuilder":
        """
        Create a KustoConnectionStringBuilder that uses a callback function to obtain a connection token
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param token_provider: a parameterless function that returns a valid bearer token for the relevant kusto resource as a string
        """

        assert callable(token_provider)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb.token_provider = token_provider

        return kcsb

    @classmethod
    def with_async_token_provider(
        cls,
        connection_string: str,
        async_token_provider: Callable[[], Coroutine[None, None, str]],
    ) -> "KustoConnectionStringBuilder":
        """
        Create a KustoConnectionStringBuilder that uses an async callback function to obtain a connection token
        :param str connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param async_token_provider: a parameterless function that after awaiting returns a valid bearer token for the relevant kusto resource as a string
        """

        assert callable(async_token_provider)

        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb.async_token_provider = async_token_provider

        return kcsb

    @classmethod
    def with_interactive_login(
        cls, connection_string: str, user_id_hint: Optional[str] = None, tenant_hint: Optional[str] = None
    ) -> "KustoConnectionStringBuilder":
        kcsb = cls(connection_string)
        kcsb.interactive_login = True
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        if user_id_hint is not None:
            kcsb[SupportedKeywords.USER_ID] = user_id_hint

        if tenant_hint is not None:
            kcsb[SupportedKeywords.AUTHORITY_ID] = tenant_hint

        return kcsb

    @classmethod
    def with_azure_token_credential(
        cls,
        connection_string: str,
        credential: Optional[Any] = None,
        credential_from_login_endpoint: Optional[Callable[[str], Any]] = None,
    ) -> "KustoConnectionStringBuilder":
        """
        Create a KustoConnectionStringBuilder that uses an azure token credential to obtain a connection token.
        :param connection_string: Kusto connection string should be of the format: https://<clusterName>.kusto.windows.net
        :param credential: an optional token credential to use for authentication
        :param credential_from_login_endpoint: an optional function that returns a token credential for the relevant kusto resource
        """
        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = True
        kcsb.token_credential_login = True
        kcsb.azure_credential = credential
        kcsb.azure_credential_from_login_endpoint = credential_from_login_endpoint

        return kcsb

    @classmethod
    def with_no_authentication(cls, connection_string: str) -> "KustoConnectionStringBuilder":
        """
        Create a KustoConnectionStringBuilder that uses no authentication.
        :param connection_string: Kusto's connection string should be of the format: http://<clusterName>.kusto.windows.net
        """
        if not connection_string.startswith("http://"):
            raise ValueError("Connection string must start with http://")
        kcsb = cls(connection_string)
        kcsb[SupportedKeywords.FEDERATED_SECURITY] = False

        return kcsb

    @property
    def data_source(self) -> Optional[str]:
        """The URI specifying the Kusto service endpoint.
        For example, https://kuskus.kusto.windows.net or net.tcp://localhost
        """
        return self._internal_dict.get(SupportedKeywords.DATA_SOURCE)

    @property
    def initial_catalog(self) -> Optional[str]:
        """The default database to be used for requests.
        By default, it is set to 'NetDefaultDB'.
        """
        return self._internal_dict.get(SupportedKeywords.INITIAL_CATALOG)

    @initial_catalog.setter
    def initial_catalog(self, value: str) -> None:
        self._internal_dict[SupportedKeywords.INITIAL_CATALOG] = value

    @property
    def aad_user_id(self) -> Optional[str]:
        """The username to use for AAD Federated AuthN."""
        return self._internal_dict.get(SupportedKeywords.USER_ID)

    @property
    def application_client_id(self) -> Optional[str]:
        """The application client id to use for authentication when federated
        authentication is used.
        """
        return self._internal_dict.get(SupportedKeywords.APPLICATION_CLIENT_ID)

    @property
    def application_key(self) -> Optional[str]:
        """The application key to use for authentication when federated authentication is used"""
        return self._internal_dict.get(SupportedKeywords.APPLICATION_KEY)

    @property
    def application_certificate(self) -> Optional[str]:
        """A PEM encoded certificate private key."""
        return self._internal_dict.get(SupportedKeywords.APPLICATION_CERTIFICATE_BLOB)

    @application_certificate.setter
    def application_certificate(self, value: str):
        self[SupportedKeywords.APPLICATION_CERTIFICATE_BLOB] = value

    @property
    def application_certificate_thumbprint(self) -> Optional[str]:
        """hex encoded thumbprint of the certificate."""
        return self._internal_dict.get(SupportedKeywords.APPLICATION_CERTIFICATE_THUMBPRINT)

    @application_certificate_thumbprint.setter
    def application_certificate_thumbprint(self, value: str):
        self[SupportedKeywords.APPLICATION_CERTIFICATE_THUMBPRINT] = value

    @property
    def authority_id(self) -> Optional[str]:
        """The ID of the AAD tenant where the application is configured.
        (should be supplied only for non-Microsoft tenant)"""
        return self._internal_dict.get(SupportedKeywords.AUTHORITY_ID)

    @authority_id.setter
    def authority_id(self, value: str):
        self[SupportedKeywords.AUTHORITY_ID] = value

    @property
    def aad_federated_security(self) -> Optional[bool]:
        """A Boolean value that instructs the client to perform AAD federated authentication."""
        return self._internal_dict.get(SupportedKeywords.FEDERATED_SECURITY)

    @property
    def user_token(self) -> Optional[str]:
        """User token."""
        return self._internal_dict.get(SupportedKeywords.USER_TOKEN)

    @property
    def application_token(self) -> Optional[str]:
        """Application token."""
        return self._internal_dict.get(SupportedKeywords.APPLICATION_TOKEN)

    @property
    def client_details(self) -> ClientDetails:
        return ClientDetails(self.application_for_tracing, self.user_name_for_tracing)

    @property
    def login_hint(self) -> Optional[str]:
        return self._internal_dict.get(SupportedKeywords.USER_ID)

    @property
    def domain_hint(self) -> Optional[str]:
        return self._internal_dict.get(SupportedKeywords.AUTHORITY_ID)

    @property
    def password(self) -> Optional[str]:
        return self._internal_dict.get(SupportedKeywords.PASSWORD)

    def _set_connector_details(
        self,
        name: str,
        version: str,
        app_name: Optional[str] = None,
        app_version: Optional[str] = None,
        send_user: bool = False,
        override_user: Optional[str] = None,
        additional_fields: Optional[List[Tuple[str, str]]] = None,
    ):
        """
        Sets the connector details for tracing purposes.
        :param name:  The name of the connector
        :param version:  The version of the connector
        :param send_user: Whether to send the user name
        :param override_user: Override the user name ( if send_user is True )
        :param app_name: The name of the containing application
        :param app_version: The version of the containing application
        :param additional_fields: Additional fields to add to the header
        """
        client_details = ClientDetails.set_connector_details(name, version, app_name, app_version, send_user, override_user, additional_fields)

        self.application_for_tracing = client_details.application_for_tracing
        self.user_name_for_tracing = client_details.user_name_for_tracing

    def __str__(self) -> str:
        dict_copy = self._internal_dict.copy()
        for key in dict_copy:
            if Keyword.lookup(key).secret:
                dict_copy[key] = "****"
        return self._build_connection_string(dict_copy)

    def __repr__(self) -> str:
        return self._build_connection_string(self._internal_dict)

    def _build_connection_string(self, kcsb_as_dict: dict) -> str:
        return ";".join(["{0}={1}".format(word.value, kcsb_as_dict[word]) for word in SupportedKeywords if word in kcsb_as_dict])

    def _parse_data_source(self, url: str):
        url = urlparse(url)
        if not url.netloc:
            return
        segments = url.path.lstrip("/").split("/")
        if len(segments) == 1 and segments[0] and not self.initial_catalog:
            self.initial_catalog = segments[0]
            self._internal_dict[SupportedKeywords.DATA_SOURCE] = url._replace(path="").geturl()
