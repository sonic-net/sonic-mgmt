import dataclasses
from threading import Lock
from typing import Optional, Dict
from urllib.parse import urlparse

import requests

from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing import SpanKind

from .env_utils import get_env
from ._telemetry import Span, MonitoredActivity
from .exceptions import KustoServiceError, KustoNetworkError

METADATA_ENDPOINT = "v1/rest/auth/metadata"

DEFAULT_AUTH_ENV_VAR_NAME = "AadAuthorityUri"
DEFAULT_KUSTO_CLIENT_APP_ID = "db662dc1-0cfe-4e1c-a843-19a68e65be58"
DEFAULT_PUBLIC_LOGIN_URL = "https://login.microsoftonline.com"
DEFAULT_REDIRECT_URI = "http://localhost"
DEFAULT_KUSTO_SERVICE_RESOURCE_ID = "https://kusto.kusto.windows.net"
DEFAULT_DEV_KUSTO_SERVICE_RESOURCE_ID = "https://kusto.dev.kusto.windows.net"
DEFAULT_FIRST_PARTY_AUTHORITY_URL = "https://login.microsoftonline.com/f8cdef31-a31e-4b4a-93e4-5f571e91255a"


@dataclasses.dataclass
class CloudInfo:
    """This class holds the data for a specific cloud instance."""

    login_endpoint: str
    login_mfa_required: bool
    kusto_client_app_id: str
    kusto_client_redirect_uri: str
    kusto_service_resource_id: str
    first_party_authority_url: str

    def authority_uri(self, authority_id: Optional[str]):
        return self.login_endpoint + "/" + (authority_id or "organizations")


class CloudSettings:
    """This class holds data for all cloud instances, and returns the specific data instance by parsing the dns suffix from a URL"""

    _cloud_info = None
    _cloud_cache = {}
    _cloud_cache_lock = Lock()

    DEFAULT_CLOUD = CloudInfo(
        login_endpoint=get_env(DEFAULT_AUTH_ENV_VAR_NAME, default=DEFAULT_PUBLIC_LOGIN_URL),
        login_mfa_required=False,
        kusto_client_app_id=DEFAULT_KUSTO_CLIENT_APP_ID,
        kusto_client_redirect_uri=DEFAULT_REDIRECT_URI,
        kusto_service_resource_id=DEFAULT_KUSTO_SERVICE_RESOURCE_ID,
        first_party_authority_url=DEFAULT_FIRST_PARTY_AUTHORITY_URL,
    )

    @classmethod
    @distributed_trace(name_of_span="CloudSettings.get_cloud_info", kind=SpanKind.CLIENT)
    def get_cloud_info_for_cluster(cls, kusto_uri: str, proxies: Optional[Dict[str, str]] = None, session: requests.Session = None) -> CloudInfo:
        normalized_authority = cls._normalize_uri(kusto_uri)

        # tracing attributes for cloud info
        Span.set_cloud_info_attributes(kusto_uri)

        if normalized_authority in cls._cloud_cache:  # Double-checked locking to avoid unnecessary lock access
            return cls._cloud_cache[normalized_authority]

        with cls._cloud_cache_lock:
            if normalized_authority in cls._cloud_cache:
                return cls._cloud_cache[normalized_authority]

            url_parts = urlparse(kusto_uri)
            url = f"{url_parts.scheme}://{url_parts.netloc}/{METADATA_ENDPOINT}"

            try:
                # trace http get call for result
                result = MonitoredActivity.invoke(
                    lambda: (session or requests).get(url, proxies=proxies, allow_redirects=False),
                    name_of_span="CloudSettings.http_get",
                    tracing_attributes=Span.create_http_attributes(url=url, method="GET"),
                )
            except Exception as e:
                raise KustoNetworkError(url) from e

            if result.status_code == 200:
                content = result.json()
                if content is None or content == {}:
                    raise KustoServiceError("Kusto returned an invalid cloud metadata response", result)
                root = content["AzureAD"]
                if root is not None:
                    cls._cloud_cache[normalized_authority] = CloudInfo(
                        login_endpoint=root["LoginEndpoint"],
                        login_mfa_required=root["LoginMfaRequired"],
                        kusto_client_app_id=root["KustoClientAppId"],
                        kusto_client_redirect_uri=root["KustoClientRedirectUri"],
                        kusto_service_resource_id=root["KustoServiceResourceId"],
                        first_party_authority_url=root["FirstPartyAuthorityUrl"],
                    )
                else:
                    cls._cloud_cache[normalized_authority] = cls.DEFAULT_CLOUD
            elif result.status_code == 404:
                # For now as long not all proxies implement the metadata endpoint, if no endpoint exists return public cloud data
                cls._cloud_cache[normalized_authority] = cls.DEFAULT_CLOUD
            else:
                raise KustoServiceError("Kusto returned an invalid cloud metadata response", result)
            return cls._cloud_cache[normalized_authority]

    @classmethod
    def add_to_cache(cls, url: str, cloud_info: CloudInfo):
        with cls._cloud_cache_lock:
            cls._cloud_cache[cls._normalize_uri(url)] = cloud_info

    @classmethod
    def _normalize_uri(cls, kusto_uri):
        """Extracts and returns the authority part of the URI (schema, host, port)"""
        url_parts = urlparse(kusto_uri)
        # Return only the scheme and netloc (which contains host and port if present)
        return f"{url_parts.scheme}://{url_parts.netloc}"
