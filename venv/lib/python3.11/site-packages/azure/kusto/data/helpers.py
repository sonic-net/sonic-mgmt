import json
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Union, Callable, Optional

if TYPE_CHECKING:
    import pandas as pd
    from azure.kusto.data._models import KustoResultTable, KustoStreamingResultTable

# Alias for dataframe_from_result_table converter type
Converter = dict[str, Union[str, Callable[[str, "pd.DataFrame"], "pd.Series"]]]


def load_bundled_json(file_name: str) -> dict[Any, Any]:
    filename = Path(__file__).absolute().parent.joinpath(file_name)
    with filename.open("r", encoding="utf-8") as data:
        return json.load(data)


@lru_cache(maxsize=1, typed=False)
def default_dict() -> Converter:
    import pandas as pd

    return {
        "string": lambda col, df: df[col].astype(pd.StringDtype()) if hasattr(pd, "StringDType") else df[col],
        "guid": lambda col, df: df[col],
        "uuid": lambda col, df: df[col],
        "uniqueid": lambda col, df: df[col],
        "dynamic": lambda col, df: df[col],
        "bool": lambda col, df: df[col].astype(bool),
        "boolean": lambda col, df: df[col].astype(bool),
        "int": lambda col, df: df[col].astype(pd.Int32Dtype()),
        "int32": lambda col, df: df[col].astype(pd.Int32Dtype()),
        "int64": lambda col, df: df[col].astype(pd.Int64Dtype()),
        "long": lambda col, df: df[col].astype(pd.Int64Dtype()),
        "real": lambda col, df: parse_float(df, col),
        "double": lambda col, df: parse_float(df, col),
        "decimal": lambda col, df: parse_float(df, col),
        "datetime": lambda col, df: parse_datetime(df, col),
        "date": lambda col, df: parse_datetime(df, col),
        "timespan": lambda col, df: df[col].apply(parse_timedelta),
        "time": lambda col, df: df[col].apply(parse_timedelta),
    }


# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License


def dataframe_from_result_table(
    table: "Union[KustoResultTable, KustoStreamingResultTable]",
    nullable_bools: bool = False,
    converters_by_type: Optional[Converter] = None,
    converters_by_column_name: Optional[Converter] = None,
) -> "pd.DataFrame":
    f"""Converts Kusto tables into pandas DataFrame.
    :param azure.kusto.data._models.KustoResultTable table: Table received from the response.
    :param nullable_bools: When True, converts bools that are 'null' from kusto or 'None' from python to pandas.NA. This will be the default in the future.
    :param converters_by_type: If given, converts specified types to corresponding types, else uses {default_dict()}. The dictionary maps from kusto
    datatype (https://learn.microsoft.com/azure/data-explorer/kusto/query/scalar-data-types/) to a lambda that receives a column name and a dataframe and
    returns the converted column or to a string type name.
    :param converters_by_column_name: If given, converts specified columns to corresponding types, else uses converters_by_type. The dictionary maps from column
     name to a lambda that receives a column name and a dataframe and returns the converted column.
    :return: pandas DataFrame.
    """
    import pandas as pd

    if not table:
        raise ValueError()

    from azure.kusto.data._models import KustoResultTable, KustoStreamingResultTable

    if not isinstance(table, KustoResultTable) and not isinstance(table, KustoStreamingResultTable):
        raise TypeError("Expected KustoResultTable or KustoStreamingResultTable got {}".format(type(table).__name__))

    columns = [col.column_name for col in table.columns]
    frame = pd.DataFrame(table.raw_rows, columns=columns)
    default = default_dict()

    for col in table.columns:
        column_name = col.column_name
        column_type = col.column_type
        if converters_by_column_name and column_name in converters_by_column_name:
            converter = converters_by_column_name.get(column_name)
        elif converters_by_type and column_type in converters_by_type:
            converter = converters_by_type.get(column_type)
        elif nullable_bools and column_type == "bool":
            converter = lambda col, df: df[col].astype(pd.BooleanDtype())
        else:
            converter = default.get(column_type)
        if converter is None:
            raise Exception("Unexpected type " + column_type)
        if isinstance(converter, str):
            frame[column_name] = frame[column_name].astype(converter)
        else:
            frame[column_name] = converter(column_name, frame)

    return frame


def get_string_tail_lower_case(val, length):
    if length <= 0:
        return ""

    if length >= len(val):
        return val.lower()

    return val[len(val) - length :].lower()


# TODO When moving to pandas 2 only - change to the appropriate type
def parse_float(frame, col):
    import numpy as np
    import pandas as pd

    frame[col] = frame[col].infer_objects(copy=False).replace({"NaN": np.nan, "Infinity": np.inf, "-Infinity": -np.inf})
    frame[col] = pd.to_numeric(frame[col], errors="coerce").astype(pd.Float64Dtype())  # pyright: ignore[reportCallIssue,reportArgumentType]

    return frame[col]


def parse_datetime(frame, col) -> "pd.Series":
    import pandas as pd

    frame[col] = pd.to_datetime(frame[col], format="ISO8601", utc=True, errors="coerce")
    return frame[col]


def parse_timedelta(raw_value: Union[int, float, str]) -> "pd.Timedelta":
    """
    Transform a raw python value to a pandas timedelta.
    """
    import pandas as pd

    if isinstance(raw_value, (int, float)):
        # https://docs.microsoft.com/en-us/dotnet/api/system.datetime.ticks
        # Kusto saves up to ticks, 1 tick == 100 nanoseconds
        return pd.to_timedelta(raw_value * 100, unit="ns")
    if isinstance(raw_value, str):
        # The timespan format Kusto returns is 'd.hh:mm:ss.ssssss' or 'hh:mm:ss.ssssss' or 'hh:mm:ss'
        # Pandas expects 'd days hh:mm:ss.ssssss' or 'hh:mm:ss.ssssss' or 'hh:mm:ss'
        parts = raw_value.split(":")
        if "." not in parts[0]:
            return pd.to_timedelta(raw_value)
        else:
            formatted_value = raw_value.replace(".", " days ", 1)
            return pd.to_timedelta(formatted_value)
