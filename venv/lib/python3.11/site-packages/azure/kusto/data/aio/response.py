from typing import List, AsyncIterator, Union

from azure.kusto.data._models import WellKnownDataSet, KustoResultTable, BaseKustoResultTable
from azure.kusto.data.aio._models import KustoStreamingResultTable
from azure.kusto.data.aio.streaming_response import StreamingDataSetEnumerator
from azure.kusto.data.exceptions import KustoStreamingQueryError
from azure.kusto.data.response import BaseKustoResponseDataSet
from azure.kusto.data.streaming_response import FrameType


class KustoStreamingResponseDataSet(BaseKustoResponseDataSet):
    _status_column = "Payload"
    _error_column = "Level"
    _crid_column = "ClientRequestId"

    def __init__(self, streamed_data: StreamingDataSetEnumerator):
        self._current_table = None
        self._skip_incomplete_tables = False
        self.tables = []
        self.streamed_data = streamed_data
        self.finished = False

    def iter_primary_results(self) -> "PrimaryResultsIterator":
        return PrimaryResultsIterator(self)

    def __aiter__(self) -> AsyncIterator[BaseKustoResultTable]:
        return self

    async def __anext__(self) -> BaseKustoResultTable:
        if self.finished:
            raise StopAsyncIteration()

        if isinstance(self._current_table, KustoStreamingResultTable) and not self._current_table.finished and not self._skip_incomplete_tables:
            raise KustoStreamingQueryError(
                "Tried retrieving a new primary_result table before the old one was finished. To override call `set_skip_incomplete_tables(True)`"
            )

        while True:
            try:
                table = await self.streamed_data.__anext__()
            except StopAsyncIteration:
                self.finished = True
                return
            if table["FrameType"] == FrameType.DataTable:
                break

        if table["TableKind"] == WellKnownDataSet.PrimaryResult.value:
            self._current_table = KustoStreamingResultTable(table)
        else:
            self._current_table = KustoResultTable(table)

        self.tables.append(self._current_table)
        return self._current_table

    def set_skip_incomplete_tables(self, value: bool):
        self._skip_incomplete_tables = value

    @property
    def errors_count(self) -> int:
        if not self.finished:
            raise KustoStreamingQueryError("Unable to get errors count before reading all of the tables.")
        return super().errors_count

    def get_exceptions(self) -> List[str]:
        if not self.finished:
            raise KustoStreamingQueryError("Unable to get errors count before reading all of the tables.")
        return super().get_exceptions()

    def __getitem__(self, key: Union[int, str]) -> KustoResultTable:
        if isinstance(key, int):
            return self.tables[key]
        try:
            return next(t for t in self.tables if t.table_name == key)
        except StopIteration:
            raise LookupError(key)

    def __len__(self) -> int:
        return len(self.tables)


class PrimaryResultsIterator:
    # This class exists because you can't raise exception from an generator and keep working
    def __init__(self, dataset: KustoStreamingResponseDataSet):
        self.dataset = dataset

    def __aiter__(self) -> AsyncIterator[KustoStreamingResultTable]:
        return self

    async def __anext__(self) -> KustoStreamingResultTable:
        while True:
            table = await self.dataset.__anext__()
            if isinstance(table, KustoStreamingResultTable):
                return table
