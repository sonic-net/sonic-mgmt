# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
from enum import Enum


class IngestionMappingKind(Enum):
    CSV = "Csv"
    JSON = "Json"
    AVRO = "Avro"
    APACHEAVRO = "ApacheAvro"
    PARQUET = "Parquet"
    SSTREAM = "SStream"
    ORC = "Orc"
    W3CLOGFILE = "W3CLogFile"
    UNKNOWN = "Unknown"


class DataFormat(Enum):
    """All data formats supported by Kusto."""

    CSV = ("csv", IngestionMappingKind.CSV, True)
    TSV = ("tsv", IngestionMappingKind.CSV, True)
    SCSV = ("scsv", IngestionMappingKind.CSV, True)
    SOHSV = ("sohsv", IngestionMappingKind.CSV, True)
    PSV = ("psv", IngestionMappingKind.CSV, True)
    TXT = ("txt", IngestionMappingKind.CSV, True)
    TSVE = ("tsve", IngestionMappingKind.CSV, True)
    JSON = ("json", IngestionMappingKind.JSON, True)
    SINGLEJSON = ("singlejson", IngestionMappingKind.JSON, True)
    MULTIJSON = ("multijson", IngestionMappingKind.JSON, True)
    AVRO = ("avro", IngestionMappingKind.AVRO, False)
    APACHEAVRO = ("apacheavro", IngestionMappingKind.APACHEAVRO, False)
    PARQUET = ("parquet", IngestionMappingKind.PARQUET, False)
    SSTREAM = ("sstream", IngestionMappingKind.SSTREAM, False)
    ORC = ("orc", IngestionMappingKind.ORC, False)
    RAW = ("raw", IngestionMappingKind.CSV, True)
    W3CLOGFILE = ("w3clogfile", IngestionMappingKind.W3CLOGFILE, True)

    def __init__(self, kusto_value: str, ingestion_mapping_kind: IngestionMappingKind, compressible: bool):
        self.kusto_value = kusto_value  # Formatted how Kusto Service expects it
        self.ingestion_mapping_kind = ingestion_mapping_kind
        self.compressible = compressible  # Binary formats should not be compressed
