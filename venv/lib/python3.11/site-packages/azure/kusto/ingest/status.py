# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
import json

from ._status_q import StatusQueue


class StatusMessage:
    OperationId = None
    Database = None
    Table = None
    IngestionSourceId = None
    IngestionSourcePath = None
    RootActivityId = None

    _raw = None

    def __init__(self, s):
        self._raw = s

        o = json.loads(s)
        for key, value in o.items():
            if hasattr(self, key):
                try:
                    setattr(self, key, value)
                except Exception:
                    # TODO: should we set up a logger?
                    pass

    def __str__(self):
        return "{}".format(self._raw)

    def __repr__(self):
        return "{0.__class__.__name__}({0._raw})".format(self)


class SuccessMessage(StatusMessage):
    SucceededOn = None


class FailureMessage(StatusMessage):
    FailedOn = None
    Details = None
    ErrorCode = None
    FailureStatus = None
    OriginatesFromUpdatePolicy = None
    ShouldRetry = None


class KustoIngestStatusQueues:
    """Kusto ingest Status Queue.
    Use this class to get status messages from Kusto status queues.
    Currently there are two queues exposed: `failure` and `success` queues.
    """

    def __init__(self, kusto_ingest_client):
        self.success = StatusQueue(kusto_ingest_client._resource_manager.get_successful_ingestions_queues, message_cls=SuccessMessage)
        self.failure = StatusQueue(kusto_ingest_client._resource_manager.get_failed_ingestions_queues, message_cls=FailureMessage)
