import uuid
from io import SEEK_SET
from typing import AnyStr, IO, TYPE_CHECKING, Union, Optional

from azure.kusto.ingest.descriptors import DescriptorBase
from tenacity import Retrying, _utils, stop_after_attempt, wait_random_exponential

from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing import SpanKind

from azure.kusto.data import KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoApiError, KustoClosedError, KustoThrottlingError
from azure.kusto.data._telemetry import MonitoredActivity

from . import BlobDescriptor, FileDescriptor, IngestionProperties, StreamDescriptor
from ._ingest_telemetry import IngestTracingAttributes
from ._stream_extensions import chain_streams, read_until_size_or_end
from .base_ingest_client import BaseIngestClient, IngestionResult
from .ingest_client import QueuedIngestClient
from .streaming_ingest_client import KustoStreamingIngestClient

if TYPE_CHECKING:
    pass


class ManagedStreamingIngestClient(BaseIngestClient):
    """
    Managed Streaming Ingestion Client.
    Will try to ingest with streaming, but if it fails, will fall back to queued ingestion.
    Each transient failure will be retried with exponential backoff.

    Managed streaming ingest client will fall back to queued if:
        - Multiple transient errors were encountered when trying to do streaming ingestion
        - The ingestion is too large for streaming ingestion (over 4MB)
        - The ingestion is directly from a blob
    """

    MAX_STREAMING_SIZE_IN_BYTES = 4 * 1024 * 1024

    def __init__(
        self,
        engine_kcsb: Union[KustoConnectionStringBuilder, str],
        dm_kcsb: Union[KustoConnectionStringBuilder, str, None] = None,
        auto_correct_endpoint: bool = True,
    ):
        super().__init__()
        self.queued_client = QueuedIngestClient(dm_kcsb if dm_kcsb is not None else engine_kcsb, auto_correct_endpoint)
        self.streaming_client = KustoStreamingIngestClient(engine_kcsb, auto_correct_endpoint)
        self._set_retry_settings()

    def close(self) -> None:
        if not self._is_closed:
            self.queued_client.close()
            self.streaming_client.close()
        super().close()

    def _set_retry_settings(self, max_seconds_per_retry: float = _utils.MAX_WAIT, num_of_attempts: int = 3):
        self._num_of_attempts = num_of_attempts
        self._max_seconds_per_retry = max_seconds_per_retry

    def set_proxy(self, proxy_url: str):
        self.queued_client.set_proxy(proxy_url)
        self.streaming_client.set_proxy(proxy_url)

    @distributed_trace(kind=SpanKind.CLIENT)
    def ingest_from_file(self, file_descriptor: Union[FileDescriptor, str], ingestion_properties: IngestionProperties) -> IngestionResult:
        file_descriptor = FileDescriptor.get_instance(file_descriptor)
        IngestTracingAttributes.set_ingest_descriptor_attributes(file_descriptor, ingestion_properties)

        super().ingest_from_file(file_descriptor, ingestion_properties)

        stream_descriptor = StreamDescriptor.from_file_descriptor(file_descriptor)

        with stream_descriptor.stream:
            return self.ingest_from_stream(stream_descriptor, ingestion_properties)

    @distributed_trace(kind=SpanKind.CLIENT)
    def ingest_from_stream(self, stream_descriptor: Union[StreamDescriptor, IO[AnyStr]], ingestion_properties: IngestionProperties) -> IngestionResult:
        stream_descriptor = StreamDescriptor.get_instance(stream_descriptor)
        IngestTracingAttributes.set_ingest_descriptor_attributes(stream_descriptor, ingestion_properties)

        super().ingest_from_stream(stream_descriptor, ingestion_properties)

        stream_descriptor = BaseIngestClient._prepare_stream(stream_descriptor, ingestion_properties)
        stream = stream_descriptor.stream

        buffered_stream = read_until_size_or_end(stream, self.MAX_STREAMING_SIZE_IN_BYTES + 1)
        length = len(buffered_stream.getbuffer())

        stream_descriptor.stream = buffered_stream

        try:
            res = self._stream_with_retries(length, stream_descriptor, ingestion_properties)
            if res:
                return res
            stream_descriptor.stream = chain_streams([buffered_stream, stream])
        except KustoApiError as ex:
            error = ex.get_api_error()
            if error.permanent:
                raise
            buffered_stream.seek(0, SEEK_SET)
        except KustoThrottlingError:
            _ = buffered_stream.seek(0, SEEK_SET)

        return self.queued_client.ingest_from_stream(stream_descriptor, ingestion_properties)

    @distributed_trace(kind=SpanKind.CLIENT)
    def ingest_from_blob(self, blob_descriptor: BlobDescriptor, ingestion_properties: IngestionProperties):
        """
        Enqueue an ingest command from azure blobs.

        For ManagedStreamingIngestClient, this method always uses Queued Ingest, since it would be easier and faster to ingest blobs.

        To learn more about ingestion methods go to:
        https://docs.microsoft.com/en-us/azure/data-explorer/ingest-data-overview#ingestion-methods
        :param azure.kusto.ingest.BlobDescriptor blob_descriptor: An object that contains a description of the blob to be ingested.
        :param azure.kusto.ingest.IngestionProperties ingestion_properties: Ingestion properties.
        """
        IngestTracingAttributes.set_ingest_descriptor_attributes(blob_descriptor, ingestion_properties)

        if self._is_closed:
            raise KustoClosedError()
        blob_descriptor.fill_size()
        try:
            res = self._stream_with_retries(blob_descriptor.size, blob_descriptor, ingestion_properties)
            if res:
                return res
        except KustoApiError as ex:
            error = ex.get_api_error()
            if error.permanent:
                raise
        except KustoThrottlingError:
            pass

        return self.queued_client.ingest_from_blob(blob_descriptor, ingestion_properties)

    def _stream_with_retries(
        self,
        length: int,
        descriptor: DescriptorBase,
        props: IngestionProperties,
    ) -> Optional[IngestionResult]:
        from_stream = isinstance(descriptor, StreamDescriptor)
        if length > self.MAX_STREAMING_SIZE_IN_BYTES:
            return None
        for attempt in Retrying(stop=stop_after_attempt(self._num_of_attempts), wait=wait_random_exponential(max=self._max_seconds_per_retry), reraise=True):
            with attempt:
                client_request_id = ManagedStreamingIngestClient._get_request_id(descriptor.source_id, attempt.retry_state.attempt_number - 1)
                # trace attempt to ingest from stream
                if from_stream:
                    descriptor.stream.seek(0, SEEK_SET)
                    invoker = lambda: self.streaming_client._ingest_from_stream_with_client_request_id(descriptor, props, client_request_id)
                else:
                    invoker = lambda: self.streaming_client.ingest_from_blob(descriptor, props, client_request_id)
                return MonitoredActivity.invoke(
                    invoker,
                    name_of_span="ManagedStreamingIngestClient.ingest_from_stream_attempt",
                    tracing_attributes={"attemptNumber": attempt, "sourceIsStream": from_stream},
                )

    @staticmethod
    def _get_request_id(source_id: uuid.UUID, attempt: int):
        return f"KPC.executeManagedStreamingIngest;{source_id};{attempt}"
