import abc
import io
import json
import uuid
from datetime import timedelta
from typing import Union, Optional, Any, NoReturn, ClassVar, TYPE_CHECKING
from urllib.parse import urljoin

from requests import Response, Session

from azure.kusto.data._cloud_settings import CloudSettings
from azure.kusto.data._token_providers import CloudInfoTokenProvider
from .client_details import ClientDetails
from .client_request_properties import ClientRequestProperties
from .exceptions import KustoServiceError, KustoThrottlingError, KustoApiError
from .kcsb import KustoConnectionStringBuilder
from .kusto_trusted_endpoints import well_known_kusto_endpoints
from .response import KustoResponseDataSet, KustoResponseDataSetV2, KustoResponseDataSetV1
from .security import _AadHelper

if TYPE_CHECKING:
    import aiohttp


class _KustoClientBase(abc.ABC):
    API_VERSION = "2024-12-12"

    _mgmt_default_timeout: ClassVar[timedelta] = timedelta(hours=1, seconds=30)
    _query_default_timeout: ClassVar[timedelta] = timedelta(minutes=4, seconds=30)
    _streaming_ingest_default_timeout: ClassVar[timedelta] = timedelta(minutes=10)
    _client_server_delta: ClassVar[timedelta] = timedelta(seconds=30)

    _aad_helper: _AadHelper
    client_details: ClientDetails
    _endpoint_validated = False
    _session: Union["aiohttp.ClientSession", "Session"]

    def __init__(self, kcsb: Union[KustoConnectionStringBuilder, str], is_async):
        self._kcsb = kcsb
        self._proxy_url: Optional[str] = None
        if not isinstance(kcsb, KustoConnectionStringBuilder):
            self._kcsb = KustoConnectionStringBuilder(kcsb)
        self._kusto_cluster = self._kcsb.data_source

        # notice that in this context, federated actually just stands for aad auth, not aad federated auth (legacy code)
        self._aad_helper = _AadHelper(self._kcsb, is_async) if self._kcsb.aad_federated_security else None

        if not self._kusto_cluster.endswith("/"):
            self._kusto_cluster += "/"

        # Create a session object for connection pooling
        self._mgmt_endpoint = urljoin(self._kusto_cluster, "v1/rest/mgmt")
        self._query_endpoint = urljoin(self._kusto_cluster, "v2/rest/query")
        self._streaming_ingest_endpoint = urljoin(self._kusto_cluster, "v1/rest/ingest/")
        self._request_headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip,deflate",
            "x-ms-version": self.API_VERSION,
        }

        self.client_details = self._kcsb.client_details
        self._is_closed: bool = False

        self.default_database = self._kcsb.initial_catalog

    def _get_database_or_default(self, database_name: Optional[str]) -> str:
        return database_name or self.default_database

    def close(self):
        self._is_closed = True

    def set_proxy(self, proxy_url: str):
        self._proxy_url = proxy_url
        if self._aad_helper:
            self._aad_helper.token_provider.set_proxy(proxy_url)
            if isinstance(self._session, Session):
                self._aad_helper.token_provider.set_session(self._session)

    def validate_endpoint(self):
        if not self._endpoint_validated and self._aad_helper is not None:
            if isinstance(self._aad_helper.token_provider, CloudInfoTokenProvider):
                endpoint = CloudSettings.get_cloud_info_for_cluster(
                    self._kusto_cluster,
                    self._aad_helper.token_provider._proxy_dict,
                    self._session if isinstance(self._session, Session) else None,
                ).login_endpoint
                well_known_kusto_endpoints.validate_trusted_endpoint(
                    self._kusto_cluster,
                    endpoint,
                )
            self._endpoint_validated = True

    @staticmethod
    def _kusto_parse_by_endpoint(endpoint: str, response_json: Any) -> KustoResponseDataSet:
        if endpoint.endswith("v2/rest/query"):
            return KustoResponseDataSetV2(response_json)
        return KustoResponseDataSetV1(response_json)

    @staticmethod
    def _handle_http_error(
        exception: Exception,
        endpoint: Optional[str],
        payload: Optional[io.IOBase],
        response: "Union[Response, aiohttp.ClientResponse]",
        status: int,
        response_json: Any,
        response_text: Optional[str],
    ) -> NoReturn:
        if status == 404:
            if payload:
                raise KustoServiceError("The ingestion endpoint does not exist. Please enable streaming ingestion on your cluster.", response) from exception

            raise KustoServiceError(f"The requested endpoint '{endpoint}' does not exist.", response) from exception

        if status == 429:
            raise KustoThrottlingError("The request was throttled by the server.", response) from exception

        if status == 401:
            raise KustoServiceError("401. Missing adequate access rights.", response) from exception

        if payload:
            message = f"An error occurred while trying to ingest: Status: {status}, Reason: {response.reason}, Text: {response_text}."
            if response_json:
                raise KustoApiError(response_json, message, response) from exception

            raise KustoServiceError(message, response) from exception

        if response_json:
            raise KustoApiError(response_json, http_response=response) from exception

        if response_text:
            raise KustoServiceError(response_text, response) from exception

        raise KustoServiceError("Server error response contains no data.", response) from exception


class ExecuteRequestParams:
    @staticmethod
    def _from_stream(
        stream: io.IOBase,
        properties: ClientRequestProperties,
        request_headers: Any,
        timeout: timedelta,
        mgmt_default_timeout: timedelta,
        client_server_delta: timedelta,
        client_details: ClientDetails,
    ):
        # Before 3.0 it was KPC.execute_streaming_ingest, but was changed to align with the other SDKs
        client_request_id_prefix = "KPC.executeStreamingIngest;"
        request_headers = request_headers.copy()
        request_headers["Content-Encoding"] = "gzip"
        if properties:
            request_headers.update(json.loads(properties.to_json())["Options"])

        return ExecuteRequestParams(
            stream, None, request_headers, client_request_id_prefix, properties, timeout, mgmt_default_timeout, client_server_delta, client_details
        )

    @staticmethod
    def _from_query(
        query: str,
        database: str,
        properties: ClientRequestProperties,
        request_headers: Any,
        timeout: timedelta,
        mgmt_default_timeout: timedelta,
        client_server_delta: timedelta,
        client_details: ClientDetails,
    ):
        json_payload = {"db": database, "csl": query}
        if properties:
            json_payload["properties"] = properties.to_json()

        client_request_id_prefix = "KPC.execute;"
        request_headers = request_headers.copy()
        request_headers["Content-Type"] = "application/json; charset=utf-8"

        return ExecuteRequestParams(
            None, json_payload, request_headers, client_request_id_prefix, properties, timeout, mgmt_default_timeout, client_server_delta, client_details
        )

    @staticmethod
    def _from_blob_url(
        blob: str,
        properties: ClientRequestProperties,
        request_headers: Any,
        timeout: timedelta,
        mgmt_default_timeout: timedelta,
        client_server_delta: timedelta,
        client_details: ClientDetails,
    ):
        json_payload = {"sourceUri": blob}
        client_request_id_prefix = "KPC.executeStreamingIngestFromBlob;"
        request_headers = request_headers.copy()
        request_headers["Content-Type"] = "application/json; charset=utf-8"
        if properties:
            request_headers.update(json.loads(properties.to_json())["Options"])
        return ExecuteRequestParams(
            None, json_payload, request_headers, client_request_id_prefix, properties, timeout, mgmt_default_timeout, client_server_delta, client_details
        )

    def __init__(
        self,
        payload,
        json_payload,
        request_headers,
        client_request_id_prefix,
        properties: ClientRequestProperties,
        timeout: timedelta,
        mgmt_default_timeout: timedelta,
        client_server_delta: timedelta,
        client_details: ClientDetails,
    ):
        special_headers = [
            {
                "name": "x-ms-client-request-id",
                "value": client_request_id_prefix + str(uuid.uuid4()),
                "property": lambda p: p.client_request_id,
            },
            {
                "name": "x-ms-client-version",
                "value": client_details.version_for_tracing,
                "property": lambda p: None,
            },
            {
                "name": "x-ms-app",
                "value": client_details.application_for_tracing,
                "property": lambda p: p.application,
            },
            {
                "name": "x-ms-user",
                "value": client_details.user_name_for_tracing,
                "property": lambda p: p.user,
            },
        ]

        for header in special_headers:
            value: str
            if properties and header["property"](properties) is not None:
                value = header["property"](properties)
            else:
                value = header["value"]

            if value is not None:
                # Replace any characters that aren't ascii with '?'
                value = value.encode("ascii", "replace").decode("ascii", "strict")
                request_headers[header["name"]] = value

        if properties is not None:
            if properties.get_option(ClientRequestProperties.no_request_timeout_option_name, False):
                timeout = mgmt_default_timeout
            else:
                timeout = properties.get_option(ClientRequestProperties.request_timeout_option_name, timeout)

        timeout = (timeout or mgmt_default_timeout) + client_server_delta

        self.json_payload = json_payload
        self.request_headers = request_headers
        self.timeout = timeout
        self.payload = payload
