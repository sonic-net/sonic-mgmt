import io
from datetime import timedelta
from typing import Optional, Union

from azure.core.tracing import SpanKind
from azure.core.tracing.decorator_async import distributed_trace_async

from .response import KustoStreamingResponseDataSet
from .._decorators import aio_documented_by, documented_by
from .._telemetry import MonitoredActivity, Span
from ..aio.streaming_response import JsonTokenReader, StreamingDataSetEnumerator
from ..client import KustoClient as KustoClientSync
from ..client_base import ExecuteRequestParams, _KustoClientBase
from ..client_request_properties import ClientRequestProperties
from ..data_format import DataFormat
from ..exceptions import KustoAioSyntaxError, KustoClosedError, KustoNetworkError
from ..kcsb import KustoConnectionStringBuilder
from ..response import KustoResponseDataSet

try:
    from aiohttp import ClientResponse, ClientSession
except ImportError:
    raise KustoAioSyntaxError()


@documented_by(KustoClientSync)
class KustoClient(_KustoClientBase):
    @documented_by(KustoClientSync.__init__)
    def __init__(self, kcsb: Union[KustoConnectionStringBuilder, str]):
        super().__init__(kcsb, True)

        self._session = ClientSession()

    async def __aenter__(self) -> "KustoClient":
        return self

    async def close(self):
        if not self._is_closed:
            await self._session.close()
            if self._aad_helper:
                await self._aad_helper.close_async()
        super().close()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    @aio_documented_by(KustoClientSync.execute)
    async def execute(self, database: Optional[str], query: str, properties: ClientRequestProperties = None) -> KustoResponseDataSet:
        query = query.strip()
        if query.startswith("."):
            return await self.execute_mgmt(database, query, properties)
        return await self.execute_query(database, query, properties)

    @distributed_trace_async(name_of_span="AioKustoClient.query_cmd", kind=SpanKind.CLIENT)
    @aio_documented_by(KustoClientSync.execute_query)
    async def execute_query(self, database: str, query: str, properties: ClientRequestProperties = None) -> KustoResponseDataSet:
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
        return await self._execute(self._query_endpoint, request, properties)

    @distributed_trace_async(name_of_span="AioKustoClient.control_cmd", kind=SpanKind.CLIENT)
    @aio_documented_by(KustoClientSync.execute_mgmt)
    async def execute_mgmt(self, database: str, query: str, properties: ClientRequestProperties = None) -> KustoResponseDataSet:
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
        return await self._execute(self._mgmt_endpoint, request, properties)

    @distributed_trace_async(name_of_span="AioKustoClient.streaming_ingest", kind=SpanKind.CLIENT)
    @aio_documented_by(KustoClientSync.execute_streaming_ingest)
    async def execute_streaming_ingest(
        self,
        database: Optional[str],
        table: str,
        stream: Optional[io.IOBase],
        blob_url: Optional[str],
        stream_format: Union[DataFormat, str],
        properties: ClientRequestProperties = None,
        mapping_name: str = None,
    ):
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
        await self._execute(endpoint, request, properties)

    @aio_documented_by(KustoClientSync._execute_streaming_query_parsed)
    async def _execute_streaming_query_parsed(
        self,
        database: Optional[str],
        query: str,
        timeout: timedelta = _KustoClientBase._query_default_timeout,
        properties: Optional[ClientRequestProperties] = None,
    ) -> StreamingDataSetEnumerator:
        request = ExecuteRequestParams._from_query(
            query, database, properties, self._request_headers, timeout, self._mgmt_default_timeout, self._client_server_delta, self.client_details
        )
        response = await self._execute(self._query_endpoint, request, properties, stream_response=True)
        return StreamingDataSetEnumerator(JsonTokenReader(response.content))

    @distributed_trace_async(name_of_span="AioKustoClient.streaming_query", kind=SpanKind.CLIENT)
    @aio_documented_by(KustoClientSync.execute_streaming_query)
    async def execute_streaming_query(
        self,
        database: Optional[str],
        query: str,
        timeout: timedelta = _KustoClientBase._query_default_timeout,
        properties: Optional[ClientRequestProperties] = None,
    ) -> KustoStreamingResponseDataSet:
        database = self._get_database_or_default(database)
        Span.set_query_attributes(self._kusto_cluster, database, properties)

        response = await self._execute_streaming_query_parsed(database, query, timeout, properties)
        return KustoStreamingResponseDataSet(response)

    @aio_documented_by(KustoClientSync._execute)
    async def _execute(
        self,
        endpoint: str,
        request: ExecuteRequestParams,
        properties: Optional[ClientRequestProperties] = None,
        stream_response: bool = False,
    ) -> Union[KustoResponseDataSet, ClientResponse]:
        """Executes given query against this client"""
        if self._is_closed:
            raise KustoClosedError()
        self.validate_endpoint()

        request_headers = request.request_headers
        timeout = request.timeout
        if self._aad_helper:
            request_headers["Authorization"] = await self._aad_helper.acquire_authorization_header_async()

        invoker = lambda: self._session.post(
            endpoint,
            headers=request_headers,
            json=request.json_payload,
            data=request.payload,
            timeout=timeout.seconds,
            proxy=self._proxy_url,
            allow_redirects=False,
        )

        try:
            response = await MonitoredActivity.invoke_async(
                invoker, name_of_span="AioKustoClient.http_post", tracing_attributes=Span.create_http_attributes("POST", endpoint, request_headers)
            )
        except Exception as e:
            raise KustoNetworkError(endpoint, None if properties is None else properties.client_request_id) from e

        if stream_response:
            try:
                response.raise_for_status()
                if 300 <= response.status < 400:
                    raise Exception("Unexpected redirection, got status code: " + str(response.status))
                return response
            except Exception as e:
                try:
                    response_text = await response.text()
                except Exception:
                    response_text = None
                try:
                    response_json = await response.json()
                except Exception:
                    response_json = None
                raise self._handle_http_error(e, endpoint, request.payload, response, response.status, response_json, response_text)

        async with response:
            response_json = None
            try:
                if 300 <= response.status < 400:
                    raise Exception("Unexpected redirection, got status code: " + str(response.status))
                response_json = await response.json()
                response.raise_for_status()
            except Exception as e:
                try:
                    response_text = await response.text()
                except Exception:
                    response_text = None
                raise self._handle_http_error(e, endpoint, request.payload, response, response.status, response_json, response_text)
            return MonitoredActivity.invoke(lambda: self._kusto_parse_by_endpoint(endpoint, response_json), name_of_span="AioKustoClient.processing_response")
