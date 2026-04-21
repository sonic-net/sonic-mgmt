import uuid

from azure.kusto.data._telemetry import Span

from .descriptors import DescriptorBase
from .ingestion_properties import IngestionProperties


class IngestTracingAttributes:
    """
    Additional ADX attributes for telemetry spans
    """

    _BLOB_QUEUE_NAME = "blob_queue_name"
    _SOURCE_ID = "source_id"

    @classmethod
    def set_ingest_descriptor_attributes(cls, descriptor: DescriptorBase, ingestion_properties: IngestionProperties) -> None:
        Span.add_attributes(tracing_attributes={**ingestion_properties.get_tracing_attributes(), **descriptor.get_tracing_attributes()})

    @classmethod
    def create_enqueue_request_attributes(cls, queue_name: str, source_id: uuid.UUID) -> dict:
        enqueue_request_attributes = {cls._BLOB_QUEUE_NAME: queue_name, cls._SOURCE_ID: str(source_id)}
        return enqueue_request_attributes
