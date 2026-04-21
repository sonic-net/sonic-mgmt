# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
import socket
import sys
from datetime import timedelta
from typing import AnyStr, IO, List, Optional, TYPE_CHECKING, Tuple, Union

import requests
import requests.adapters
from requests import Response
from urllib3.connection import HTTPConnection

from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing import SpanKind

from azure.kusto.data._telemetry import Span, MonitoredActivity
from azure.kusto.data.exceptions import KustoServiceError

from .client_base import ExecuteRequestParams, _KustoClientBase
from .client_request_properties import ClientRequestProperties
from .data_format import DataFormat
from .exceptions import KustoClosedError, KustoNetworkError

from .kcsb import KustoConnectionStringBuilder
from .response import KustoResponseDataSet, KustoStreamingResponseDataSet
from .streaming_response import JsonTokenReader, StreamingDataSetEnumerator

if TYPE_CHECKING:
    pass


class HTTPAdapterWithSocketOptions(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.socket_options = kwargs.pop("socket_options", None)
        super(HTTPAdapterWithSocketOptions, self).__init__(*args, **kwargs)

    def __getstate__(self):
        state = super(HTTPAdapterWithSocketOptions, self).__getstate__()
        state["socket_options"] = self.socket_options
        return state

    def init_poolmanager(self, *args, **kwargs):
        if self.socket_options is not None:
            kwargs["socket_options"] = self.socket_options
        super(HTTPAdapterWithSocketOptions, self).init_poolmanager(*args, **kwargs)


class KustoClient(_KustoClientBase):
    """
    Kusto client for Python.
    The client is a wrapper around the Kusto REST API.
    To read more about it, go to https://docs.microsoft.com/en-us/azure/kusto/api/rest/

    The primary methods are:
    `execute_query`:  executes a KQL query against the Kusto service.
    `execute_mgmt`: executes a KQL control command against the Kusto service.
    """

    _mgmt_default_timeout = timedelta(hours=1)
    _query_default_timeout = timedelta(minutes=4)
    _streaming_ingest_default_timeout = timedelta(minutes=10)
    _client_server_delta = timedelta(seconds=30)

    # The maximum amount of connections to be able to operate in parallel
    _max_pool_size = 100

    def __init__(self, kcsb: Union[KustoConnectionStringBuilder, str]):
        """
        Kusto Client constructor.
        :param kcsb: The connection string to initialize KustoClient.
        :type kcsb: azure.kusto.data.KustoConnectionStringBuilder or str
        """
        super().__init__(kcsb, False)

        # Create a session object for connection pooling
        self._session = requests.Session()

        adapter = HTTPAdapterWithSocketOptions(
            socket_options=(HTTPConnection.default_socket_options or []) + self.compose_socket_options(), pool_maxsize=self._max_pool_size
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def close(self):
        if not self._is_closed:
            self._session.close()
            if self._aad_helper:
                self._aad_helper.close()
        super().close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def set_proxy(self, proxy_url: str):
        super().set_proxy(proxy_url)
        self._session.proxies = {"http": proxy_url, "https": proxy_url}

    def set_http_retries(self, max_retries: int):
        """
        Set the number of HTTP retries to attempt
        """
        adapter = HTTPAdapterWithSocketOptions(
            socket_options=(HTTPConnection.default_socket_options or []) + self.compose_socket_options(),
            pool_maxsize=self._max_pool_size,
            max_retries=max_retries,
        )
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    @staticmethod
    def compose_socket_options() -> List[Tuple[int, int, int]]:
        # Sends TCP Keep-Alive after MAX_IDLE_SECONDS seconds of idleness, once every INTERVAL_SECONDS seconds, and closes the connection after MAX_FAILED_KEEPALIVES failed pings (e.g. 20 => 1:00:30)
        MAX_IDLE_SECONDS = 30
        INTERVAL_SECONDS = 180  # Corresponds to Azure Load Balancer Service 4 minute timeout, with 1 minute of slack
        MAX_FAILED_KEEPALIVES = 20

        if (
            sys.platform == "linux"
            and hasattr(socket, "SOL_SOCKET")
            and hasattr(socket, "SO_KEEPALIVE")
            and hasattr(socket, "TCP_KEEPIDLE")
            and hasattr(socket, "TCP_KEEPINTVL")
            and hasattr(socket, "TCP_KEEPCNT")
        ):
            return [
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, MAX_IDLE_SECONDS),
                (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, INTERVAL_SECONDS),
                (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, MAX_FAILED_KEEPALIVES),
            ]
        elif (
            sys.platform == "win32"
            and hasattr(socket, "SOL_SOCKET")
            and hasattr(socket, "SO_KEEPALIVE")
            and hasattr(socket, "TCP_KEEPIDLE")
            and hasattr(socket, "TCP_KEEPCNT")
        ):
            return [
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
                (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, MAX_IDLE_SECONDS),
                (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, MAX_FAILED_KEEPALIVES),
            ]
        elif sys.platform == "darwin" and hasattr(socket, "SOL_SOCKET") and hasattr(socket, "SO_KEEPALIVE") and hasattr(socket, "IPPROTO_TCP"):
            TCP_KEEPALIVE = 0x10
            return [(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), (socket.IPPROTO_TCP, TCP_KEEPALIVE, INTERVAL_SECONDS)]
        else:
            return []

    def execute(self, database: Optional[str], query: str, properties: Optional[ClientRequestProperties] = None) -> KustoResponseDataSet:
        """
        Executes a query or management command.
        :param Optional[str] database: Database against query will be executed. If not provided, will default to the "Initial Catalog" value in the connection string
        :param str query: Query to be executed.
        :param azure.kusto.data.ClientRequestProperties properties: Optional additional properties.
        :return: Kusto response data set.
        :rtype: azure.kusto.data.response.KustoResponseDataSet
        """
        query = query.strip()
        if query.startswith("."):
            return self.execute_mgmt(database, query, properties)
        return self.execute_query(database, query, properties)

    @distributed_trace(name_of_span="KustoClient.query_cmd", kind=SpanKind.CLIENT)
    def execute_query(self, database: Optional[str], query: str, properties: Optional[ClientRequestProperties] = None) -> KustoResponseDataSet:
        """
        Execute a KQL query.
        To learn more about KQL go to https://docs.microsoft.com/en-us/azure/kusto/query/
        :param Optional[str] database: Database against query will be executed. If not provided, will default to the "Initial Catalog" value in the connection string
        :param str query: Query to be executed.
        :param azure.kusto.data.ClientRequestProperties properties: Optional additional properties.
        :return: Kusto response data set.
        :rtype: azure.kusto.data.response.KustoResponseDataSet
        """
        database = self._get_database_or_default(database)
        Span.set_query_attributes(self._kusto_cluster, database, properties)
        request = ExecuteRequestParams._from_query(
            query,
            database,
            properties,
            self._request_headers,
            self._query_default_timeout,
            self._mgmt_default_timeout,
            self._client_server_delta,
            self.client_details,
        )
        return self._execute(self._query_endpoint, request, properties)

    @distributed_trace(name_of_span="KustoClient.control_cmd", kind=SpanKind.CLIENT)
    def execute_mgmt(self, database: Optional[str], query: str, properties: Optional[ClientRequestProperties] = None) -> KustoResponseDataSet:
        """
        Execute a KQL control command.
        To learn more about KQL control commands go to  https://docs.microsoft.com/en-us/azure/kusto/management/
        :param Optional[str] database: Database against query will be executed. If not provided, will default to the "Initial Catalog" value in the connection string
        :param str query: Query to be executed.
        :param azure.kusto.data.ClientRequestProperties properties: Optional additional properties.
        :return: Kusto response data set.
        :rtype: azure.kusto.data.response.KustoResponseDataSet
        """
        database = self._get_database_or_default(database)
        Span.set_query_attributes(self._kusto_cluster, database, properties)
        request = ExecuteRequestParams._from_query(
            query,
            database,
            properties,
            self._request_headers,
            self._mgmt_default_timeout,
            self._mgmt_default_timeout,
            self._client_server_delta,
            self.client_details,
        )
        return self._execute(self._mgmt_endpoint, request, properties)

    @distributed_trace(name_of_span="KustoClient.streaming_ingest", kind=SpanKind.CLIENT)
    def execute_streaming_ingest(
        self,
        database: Optional[str],
        table: str,
        stream: Optional[IO[AnyStr]],
        blob_url: Optional[str],
        stream_format: Union[DataFormat, str],
        properties: Optional[ClientRequestProperties] = None,
        mapping_name: str = None,
    ):
        """
        Execute streaming ingest against this client
        If the Kusto service is not configured to allow streaming ingestion, this may raise an error
        To learn more about streaming ingestion go to:
        https://docs.microsoft.com/en-us/azure/data-explorer/ingest-data-streaming
        :param Optional[str] database: Target database. If not provided, will default to the "Initial Catalog" value in the connection string
        :param str table: Target table.
        :param Optional[IO[AnyStr]] stream: a stream object or which contains the data to ingest.
        :param Optional[str] blob_url: An url to a blob which contains the data to ingest. Provide either this or stream.
        :param DataFormat stream_format: Format of the data in the stream.
        :param ClientRequestProperties properties: additional request properties.
        :param str mapping_name: Pre-defined mapping of the table. Required when stream_format is json/avro.
        """
        database = self._get_database_or_default(database)

        stream_format = stream_format.kusto_value if isinstance(stream_format, DataFormat) else DataFormat[stream_format.upper()].kusto_value
        endpoint = self._streaming_ingest_endpoint + database + "/" + table + "?streamFormat=" + stream_format
        if mapping_name is not None:
            endpoint = endpoint + "&mappingName=" + mapping_name
        if blob_url:
            endpoint += "&sourceKind=uri"
            request = ExecuteRequestParams._from_blob_url(
                blob_url,
                properties,
                self._request_headers,
                self._streaming_ingest_default_timeout,
                self._mgmt_default_timeout,
                self._client_server_delta,
                self.client_details,
            )
        elif stream:
            request = ExecuteRequestParams._from_stream(
                stream,
                properties,
                self._request_headers,
                self._streaming_ingest_default_timeout,
                self._mgmt_default_timeout,
                self._client_server_delta,
                self.client_details,
            )
        else:
            raise Exception("execute_streaming_ingest is expecting either a stream or blob url")

        Span.set_streaming_ingest_attributes(self._kusto_cluster, database, table, properties)
        self._execute(endpoint, request, properties)

    def _execute_streaming_query_parsed(
        self,
        database: Optional[str],
        query: str,
        timeout: timedelta = _KustoClientBase._query_default_timeout,
        properties: Optional[ClientRequestProperties] = None,
    ) -> StreamingDataSetEnumerator:
        request = ExecuteRequestParams._from_query(
            query, database, properties, self._request_headers, timeout, self._mgmt_default_timeout, self._client_server_delta, self.client_details
        )
        response = self._execute(self._query_endpoint, request, properties, stream_response=True)
        response.raw.decode_content = True
        return StreamingDataSetEnumerator(JsonTokenReader(response.raw))

    @distributed_trace(name_of_span="KustoClient.streaming_query", kind=SpanKind.CLIENT)
    def execute_streaming_query(
        self,
        database: Optional[str],
        query: str,
        timeout: timedelta = _KustoClientBase._query_default_timeout,
        properties: Optional[ClientRequestProperties] = None,
    ) -> KustoStreamingResponseDataSet:
        """
        Execute a KQL query without reading it all to memory.
        The resulting KustoStreamingResponseDataSet will stream one table at a time, and the rows can be retrieved sequentially.

        :param Optional[str] database: Database against query will be executed. If not provided, will default to the "Initial Catalog" value in the connection string
        :param str query: Query to be executed.
        :param timedelta timeout: timeout for the query to be executed
        :param azure.kusto.data.ClientRequestProperties properties: Optional additional properties.
        :return KustoStreamingResponseDataSet:
        """
        Span.set_query_attributes(self._kusto_cluster, database, properties)

        return KustoStreamingResponseDataSet(self._execute_streaming_query_parsed(database, query, timeout, properties))

    def _execute(
        self,
        endpoint: str,
        request: ExecuteRequestParams,
        properties: Optional[ClientRequestProperties] = None,
        stream_response: bool = False,
    ) -> Union[KustoResponseDataSet, Response]:
        """Executes given query against this client"""
        if self._is_closed:
            raise KustoClosedError()
        self.validate_endpoint()

        request_headers = request.request_headers
        if self._aad_helper:
            request_headers["Authorization"] = self._aad_helper.acquire_authorization_header()

        # trace http post call for response
        invoker = lambda: self._session.post(
            endpoint,
            headers=request_headers,
            json=request.json_payload,
            data=request.payload,
            timeout=request.timeout.seconds,
            stream=stream_response,
            allow_redirects=False,
        )

        try:
            response = MonitoredActivity.invoke(
                invoker, name_of_span="KustoClient.http_post", tracing_attributes=Span.create_http_attributes("POST", endpoint, request_headers)
            )
        except Exception as e:
            raise KustoNetworkError(endpoint, None if properties is None else properties.client_request_id) from e

        if stream_response:
            try:
                response.raise_for_status()
                if 300 <= response.status_code < 400:
                    raise Exception("Unexpected redirection, got status code: " + str(response.status))
                return response
            except Exception as e:
                raise self._handle_http_error(e, self._query_endpoint, None, response, response.status_code, response.json(), response.text)

        response_json = None
        try:
            if 300 <= response.status_code < 400:
                raise Exception("Unexpected redirection, got status code: " + str(response.status))
            if response.text:
                response_json = response.json()
            else:
                raise KustoServiceError("The content of the response contains no data.", response)
            response.raise_for_status()
        except Exception as e:
            raise self._handle_http_error(e, endpoint, request.payload, response, response.status_code, response_json, response.text)
        # trace response processing
        return MonitoredActivity.invoke(lambda: self._kusto_parse_by_endpoint(endpoint, response_json), name_of_span="KustoClient.processing_response")
