# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
from typing import Union, AnyStr, IO, List, Optional, Dict

from azure.storage.blob import BlobServiceClient

from azure.core.tracing.decorator import distributed_trace
from azure.core.tracing import SpanKind
from azure.storage.queue import QueueServiceClient, TextBase64EncodePolicy

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data._telemetry import MonitoredActivity
from azure.kusto.data.exceptions import KustoClosedError

from ._ingest_telemetry import IngestTracingAttributes
from ._resource_manager import _ResourceManager, _ResourceUri
from .base_ingest_client import BaseIngestClient, IngestionResult, IngestionStatus
from .descriptors import BlobDescriptor, FileDescriptor, StreamDescriptor
from .exceptions import KustoQueueError
from azure.kusto.data.exceptions import KustoBlobError
from .ingestion_blob_info import IngestionBlobInfo
from .ingestion_properties import IngestionProperties


class QueuedIngestClient(BaseIngestClient):
    """
    Queued ingest client provides methods to allow queued ingestion into kusto (ADX).
    To learn more about the different types of ingestions and when to use each, visit:
    https://docs.microsoft.com/en-us/azure/data-explorer/ingest-data-overview#ingestion-methods
    """

    _INGEST_PREFIX = "ingest-"
    _SERVICE_CLIENT_TIMEOUT_SECONDS = 10 * 60
    _MAX_RETRIES = 3

    def __init__(self, kcsb: Union[str, KustoConnectionStringBuilder], auto_correct_endpoint: bool = True):
        """Kusto Ingest Client constructor.
        :param kcsb: The connection string to initialize KustoClient.
        """
        super().__init__()
        if not isinstance(kcsb, KustoConnectionStringBuilder):
            kcsb = KustoConnectionStringBuilder(kcsb)

        if auto_correct_endpoint:
            kcsb["Data Source"] = BaseIngestClient.get_ingestion_endpoint(kcsb.data_source)

        self._proxy_dict: Optional[Dict[str, str]] = None
        self._connection_datasource = kcsb.data_source
        self._resource_manager = _ResourceManager(KustoClient(kcsb))
        self._endpoint_service_type = None
        self._suggested_endpoint_uri = None
        self.application_for_tracing = kcsb.client_details.application_for_tracing
        self.client_version_for_tracing = kcsb.client_details.version_for_tracing

    def close(self) -> None:
        self._resource_manager.close()
        super().close()

    def set_proxy(self, proxy_url: str):
        self._resource_manager.set_proxy(proxy_url)
        self._proxy_dict = {"http": proxy_url, "https": proxy_url}

    @distributed_trace(name_of_span="QueuedIngestClient.ingest_from_file", kind=SpanKind.CLIENT)
    def ingest_from_file(self, file_descriptor: Union[FileDescriptor, str], ingestion_properties: IngestionProperties) -> IngestionResult:
        """Enqueue an ingest command from local files.
        To learn more about ingestion methods go to:
        https://docs.microsoft.com/en-us/azure/data-explorer/ingest-data-overview#ingestion-methods
        :param file_descriptor: a FileDescriptor to be ingested.
        :param azure.kusto.ingest.IngestionProperties ingestion_properties: Ingestion properties.
        """
        file_descriptor = FileDescriptor.get_instance(file_descriptor)
        IngestTracingAttributes.set_ingest_descriptor_attributes(file_descriptor, ingestion_properties)

        super().ingest_from_file(file_descriptor, ingestion_properties)

        containers = self._get_containers()

        file_descriptor, should_compress = BaseIngestClient._prepare_file(file_descriptor, ingestion_properties)
        with file_descriptor.open(should_compress) as stream:
            blob_descriptor = self.upload_blob(
                containers,
                file_descriptor,
                ingestion_properties.database,
                ingestion_properties.table,
                stream,
                self._proxy_dict,
                self._SERVICE_CLIENT_TIMEOUT_SECONDS,
                self._MAX_RETRIES,
            )
        return self.ingest_from_blob(blob_descriptor, ingestion_properties=ingestion_properties)

    @distributed_trace(name_of_span="QueuedIngestClient.ingest_from_stream", kind=SpanKind.CLIENT)
    def ingest_from_stream(self, stream_descriptor: Union[StreamDescriptor, IO[AnyStr]], ingestion_properties: IngestionProperties) -> IngestionResult:
        """Ingest from io streams.
        :param stream_descriptor: An object that contains a description of the stream to be ingested.
        :param azure.kusto.ingest.IngestionProperties ingestion_properties: Ingestion properties.
        """
        stream_descriptor = StreamDescriptor.get_instance(stream_descriptor)
        IngestTracingAttributes.set_ingest_descriptor_attributes(stream_descriptor, ingestion_properties)

        super().ingest_from_stream(stream_descriptor, ingestion_properties)

        containers = self._get_containers()

        stream_descriptor = BaseIngestClient._prepare_stream(stream_descriptor, ingestion_properties)
        blob_descriptor = self.upload_blob(
            containers,
            stream_descriptor,
            ingestion_properties.database,
            ingestion_properties.table,
            stream_descriptor.stream,
            self._proxy_dict,
            self._SERVICE_CLIENT_TIMEOUT_SECONDS,
            self._MAX_RETRIES,
        )
        return self.ingest_from_blob(blob_descriptor, ingestion_properties=ingestion_properties)

    @distributed_trace(name_of_span="QueuedIngestClient.ingest_from_blob", kind=SpanKind.CLIENT)
    def ingest_from_blob(self, blob_descriptor: BlobDescriptor, ingestion_properties: IngestionProperties) -> IngestionResult:
        """Enqueue an ingest command from azure blobs.
        To learn more about ingestion methods go to:
        https://docs.microsoft.com/en-us/azure/data-explorer/ingest-data-overview#ingestion-methods
        :param azure.kusto.ingest.BlobDescriptor blob_descriptor: An object that contains a description of the blob to be ingested.
        :param azure.kusto.ingest.IngestionProperties ingestion_properties: Ingestion properties.
        """
        IngestTracingAttributes.set_ingest_descriptor_attributes(blob_descriptor, ingestion_properties)

        if self._is_closed:
            raise KustoClosedError()

        queues = self._resource_manager.get_ingestion_queues()

        authorization_context = self._resource_manager.get_authorization_context()
        ingestion_blob_info = IngestionBlobInfo(
            blob_descriptor,
            ingestion_properties=ingestion_properties,
            auth_context=authorization_context,
            application_for_tracing=self.application_for_tracing,
            client_version_for_tracing=self.client_version_for_tracing,
        )
        ingestion_blob_info_json = ingestion_blob_info.to_json()
        retries_left = min(self._MAX_RETRIES, len(queues))
        for queue in queues:
            try:
                with QueueServiceClient(queue.account_uri, proxies=self._proxy_dict) as queue_service:
                    with queue_service.get_queue_client(queue=queue.object_name, message_encode_policy=TextBase64EncodePolicy()) as queue_client:
                        # trace enqueuing of blob for ingestion
                        invoker = lambda: queue_client.send_message(content=ingestion_blob_info_json, timeout=self._SERVICE_CLIENT_TIMEOUT_SECONDS)
                        enqueue_trace_attributes = IngestTracingAttributes.create_enqueue_request_attributes(queue_client.queue_name, blob_descriptor.source_id)
                        MonitoredActivity.invoke(invoker, name_of_span="QueuedIngestClient.enqueue_request", tracing_attributes=enqueue_trace_attributes)

                self._resource_manager.report_resource_usage_result(queue.storage_account_name, True)
                return IngestionResult(
                    IngestionStatus.QUEUED, ingestion_properties.database, ingestion_properties.table, blob_descriptor.source_id, blob_descriptor.path
                )
            except Exception as e:
                retries_left = retries_left - 1
                # TODO: log the retry once we have a proper logging system
                self._resource_manager.report_resource_usage_result(queue.storage_account_name, False)
                if retries_left == 0:
                    raise KustoQueueError() from e

    def _get_containers(self) -> List[_ResourceUri]:
        return self._resource_manager.get_containers()

    def upload_blob(
        self,
        containers: List[_ResourceUri],
        descriptor: Union[FileDescriptor, "StreamDescriptor"],
        database: str,
        table: str,
        stream: IO[AnyStr],
        proxy_dict: Optional[Dict[str, str]],
        timeout: int,
        max_retries: int,
    ) -> "BlobDescriptor":
        """
        Uploads and transforms FileDescriptor or StreamDescriptor into a BlobDescriptor instance
        :param List[_ResourceUri] containers: blob containers
        :param Union[FileDescriptor, "StreamDescriptor"] descriptor:
        :param string database: database to be ingested to
        :param string table: table to be ingested to
        :param IO[AnyStr] stream: stream to be ingested from
        :param Optional[Dict[str, str]] proxy_dict: proxy urls
        :param int timeout: Azure service call timeout in seconds
        :return new BlobDescriptor instance
        """
        blob_name = "{db}__{table}__{guid}__{file}".format(db=database, table=table, guid=descriptor.source_id, file=descriptor.stream_name)

        retries_left = min(max_retries, len(containers))
        for container in containers:
            try:
                blob_service = BlobServiceClient(container.account_uri, proxies=proxy_dict)
                blob_client = blob_service.get_blob_client(container=container.object_name, blob=blob_name)
                blob_client.upload_blob(data=stream, timeout=timeout)
                self._resource_manager.report_resource_usage_result(container.storage_account_name, True)
                return BlobDescriptor(blob_client.url, descriptor.size, descriptor.source_id)
            except Exception as e:
                retries_left = retries_left - 1
                # TODO: log the retry once we have a proper logging system
                self._resource_manager.report_resource_usage_result(container.storage_account_name, False)
                if retries_left == 0:
                    raise KustoBlobError(e)
