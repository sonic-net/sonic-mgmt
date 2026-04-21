from typing import AsyncIterator

from azure.kusto.data._models import KustoResultRow, BaseStreamingKustoResultTable


class KustoStreamingResultTable(BaseStreamingKustoResultTable):
    """Async Iterator over a Kusto result table."""

    async def __anext__(self) -> KustoResultRow:
        try:
            row = await self.raw_rows.__anext__()
        except StopAsyncIteration:
            self.finished = True
            raise
        self.row_count += 1
        return KustoResultRow(self.columns, row)

    def __aiter__(self) -> AsyncIterator[KustoResultRow]:
        return self
