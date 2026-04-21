# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json
from abc import ABCMeta, abstractmethod
from decimal import Decimal
from enum import Enum
from typing import Iterator, List, Any, Union, Optional, Dict

from . import _converters
from .exceptions import KustoMultiApiError, KustoStreamingQueryError


class WellKnownDataSet(str, Enum):
    """Categorizes data tables according to the role they play in the data set that a Kusto query returns."""

    PrimaryResult = "PrimaryResult"
    QueryCompletionInformation = "QueryCompletionInformation"
    TableOfContents = "TableOfContents"
    QueryProperties = "QueryProperties"


class KustoResultRow:
    """Iterator over a Kusto result row."""

    conversion_funcs = {"datetime": _converters.to_datetime, "timespan": _converters.to_timedelta, "decimal": Decimal}

    def __init__(self, columns: "List[KustoResultColumn]", row: list):
        self._value_by_name = {}
        self._value_by_index = []

        for i, value in enumerate(row):
            column = columns[i]
            try:
                column_type = column.column_type.lower()
            except AttributeError:
                self._value_by_index.append(value)
                self._value_by_name[columns[i]] = value
                continue

            # If you are here to read this, you probably hit some datetime/timedelta inconsistencies.
            # Azure-Data-Explorer(Kusto) supports 7 decimal digits, while the corresponding python types supports only 6.
            # One example why one might want this precision, is when working with pandas.
            # In that case, use azure.kusto.data.helpers.dataframe_from_result_table which takes into account the original value.
            typed_value = self.get_typed_value(column_type, value)

            self._value_by_index.append(typed_value)
            self._value_by_name[column.column_name] = typed_value

    @staticmethod
    def get_typed_value(column_type: str, value: Any) -> Any:
        return KustoResultRow.conversion_funcs[column_type](value) if value is not None and column_type in KustoResultRow.conversion_funcs else value

    @property
    def columns_count(self) -> int:
        return len(self._value_by_name)

    def __iter__(self) -> Iterator[Any]:
        for i in range(self.columns_count):
            yield self[i]

    def __getitem__(self, key: Union[str, int]) -> Any:
        if isinstance(key, int):
            return self._value_by_index[key]
        return self._value_by_name[key]

    def __len__(self) -> int:
        return self.columns_count

    def to_dict(self) -> Dict[str, Any]:
        return self._value_by_name

    def to_list(self) -> list:
        return self._value_by_index

    def __str__(self) -> str:
        return "['{}']".format("', '".join([str(val) for val in self._value_by_index]))

    def __repr__(self) -> str:
        values = [repr(val) for val in self._value_by_name.values()]
        return "KustoResultRow(['{}'], [{}])".format("', '".join(self._value_by_name), ", ".join(values))

    def __eq__(self, other) -> bool:
        if len(self) != len(other):
            return False
        for value_index, value in enumerate(self):
            if value != other[value_index]:
                return False
        return True


class KustoResultColumn:
    def __init__(self, json_column: Dict[str, Any], ordinal: int):
        self.column_name = json_column["ColumnName"]
        self.column_type = json_column.get("ColumnType") or json_column["DataType"]
        self.ordinal = ordinal

    def __repr__(self) -> str:
        return "KustoResultColumn({},{})".format(json.dumps({"ColumnName": self.column_name, "ColumnType": self.column_type}), self.ordinal)


class BaseKustoResultTable(metaclass=ABCMeta):
    def __init__(self, json_table: Dict[str, Any]):
        self.table_name = json_table.get("TableName")
        self.table_id = json_table.get("TableId")
        self.table_kind = WellKnownDataSet[json_table["TableKind"]] if "TableKind" in json_table else None
        self.columns = [KustoResultColumn(column, index) for index, column in enumerate(json_table["Columns"])]

        self.raw_columns = json_table["Columns"]
        self.raw_rows = json_table["Rows"]
        self.kusto_result_rows = None

    def __bool__(self) -> bool:
        return any(self.columns)

    __nonzero__ = __bool__

    @property
    def columns_count(self) -> int:
        return len(self.columns)

    @abstractmethod
    def __len__(self) -> Optional[int]:
        pass

    @property
    @abstractmethod
    def rows_count(self) -> int:
        pass


class BaseStreamingKustoResultTable(BaseKustoResultTable):
    def __init__(self, json_table: Dict[str, Any]):
        super().__init__(json_table)

        self.finished = False
        self.row_count = 0

    @property
    def rows_count(self) -> int:
        if not self.finished:
            raise KustoStreamingQueryError("Can't retrieve rows count before the iteration is finished")
        return self.row_count

    def __len__(self) -> Optional[int]:
        if not self.finished:
            return None  # We return None here instead of an exception, because otherwise calling list() on the object will throw
        return self.rows_count

    def iter_rows(self) -> "BaseStreamingKustoResultTable":
        return self


class KustoResultTable(BaseKustoResultTable):
    """Iterator over a Kusto result table."""

    def __init__(self, json_table: Dict[str, Any]):
        super().__init__(json_table)
        errors = [row for row in json_table["Rows"] if isinstance(row, dict)]
        if errors:
            raise KustoMultiApiError(errors)

    @property
    def rows(self) -> List[KustoResultRow]:
        if not self.kusto_result_rows:
            self.kusto_result_rows = [KustoResultRow(self.columns, row) for row in self.raw_rows]
        return self.kusto_result_rows

    def to_dict(self) -> Dict[str, Any]:
        """Converts the table to a dict."""
        return {"name": self.table_name, "kind": self.table_kind, "data": [r.to_dict() for r in self]}

    @property
    def rows_count(self) -> int:
        return len(self.raw_rows)

    def __len__(self) -> int:
        return self.rows_count

    def __iter__(self) -> Iterator[KustoResultRow]:
        for row_index, row in enumerate(self.raw_rows):
            if self.kusto_result_rows:
                yield self.kusto_result_rows[row_index]
            else:
                yield KustoResultRow(self.columns, row)

    def __getitem__(self, key: int) -> KustoResultRow:
        return self.rows[key]

    def __str__(self) -> str:
        d = self.to_dict()
        # enum is not serializable, using value instead
        d["kind"] = d["kind"].value
        return json.dumps(d, default=str)


class KustoStreamingResultTable(BaseStreamingKustoResultTable):
    """
    Iterator over a Kusto result table in streaming.
    This class can be iterated only once.
    """

    def __next__(self) -> KustoResultRow:
        try:
            row = next(self.raw_rows)
        except StopIteration:
            self.finished = True
            raise
        self.row_count += 1
        return KustoResultRow(self.columns, row)

    def __iter__(self) -> Iterator[KustoResultRow]:
        return self
