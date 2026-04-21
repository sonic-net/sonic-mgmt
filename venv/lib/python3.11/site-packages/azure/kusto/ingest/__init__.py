# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
from ._version import VERSION as __version__
from .base_ingest_client import IngestionResult, IngestionStatus
from .descriptors import BlobDescriptor, FileDescriptor, StreamDescriptor
from .exceptions import KustoMissingMappingError, KustoMappingError, KustoQueueError, KustoDuplicateMappingError, KustoInvalidEndpointError, KustoClientError
from .ingest_client import QueuedIngestClient
from .ingestion_properties import (
    ValidationPolicy,
    ValidationImplications,
    ValidationOptions,
    ReportLevel,
    ReportMethod,
    IngestionProperties,
    IngestionMappingKind,
    ColumnMapping,
    TransformationMethod,
)
from .managed_streaming_ingest_client import ManagedStreamingIngestClient
from .streaming_ingest_client import KustoStreamingIngestClient
from .base_ingest_client import BaseIngestClient

__all__ = [
    "__version__",
    "IngestionResult",
    "IngestionStatus",
    "BlobDescriptor",
    "FileDescriptor",
    "StreamDescriptor",
    "KustoMissingMappingError",
    "KustoMappingError",
    "KustoQueueError",
    "KustoDuplicateMappingError",
    "KustoInvalidEndpointError",
    "KustoClientError",
    "QueuedIngestClient",
    "ValidationPolicy",
    "ValidationImplications",
    "ValidationOptions",
    "ReportLevel",
    "ReportMethod",
    "IngestionProperties",
    "IngestionMappingKind",
    "ColumnMapping",
    "TransformationMethod",
    "ManagedStreamingIngestClient",
    "KustoStreamingIngestClient",
    "BaseIngestClient",
]
