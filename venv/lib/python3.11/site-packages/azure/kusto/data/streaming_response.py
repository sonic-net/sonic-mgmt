from enum import Enum
from typing import Optional, Any, Tuple, Dict, AnyStr, IO, List, Iterator

import ijson
from ijson import IncompleteJSONError

from azure.kusto.data._models import WellKnownDataSet
from azure.kusto.data.exceptions import KustoTokenParsingError, KustoUnsupportedApiError, KustoMultiApiError


class JsonTokenType(Enum):
    NULL = 0
    BOOLEAN = 1
    NUMBER = 2
    STRING = 3
    MAP_KEY = 4
    START_MAP = 5
    END_MAP = 6
    START_ARRAY = 7
    END_ARRAY = 8

    @staticmethod
    def start_tokens() -> "List[JsonTokenType]":
        return [JsonTokenType.START_MAP, JsonTokenType.START_ARRAY]

    @staticmethod
    def end_tokens() -> "List[JsonTokenType]":
        return [JsonTokenType.END_MAP, JsonTokenType.END_ARRAY]


class FrameType(Enum):
    DataSetHeader = 0
    TableHeader = 1
    TableFragment = 2
    TableCompletion = 3
    TableProgress = 4
    DataTable = 5
    DataSetCompletion = 6


class JsonToken:
    def __init__(self, token_path: str, token_type: JsonTokenType, token_value: Optional[Any]):
        self.token_path = token_path
        self.token_type = token_type
        self.token_value = token_value


class JsonTokenReader:
    def __init__(self, stream: IO[AnyStr]):
        self.json_iter = ijson.parse(stream, use_float=True)

    def __iter__(self) -> "JsonTokenReader":
        return self

    def __next__(self) -> JsonToken:
        return self.read_next_token_or_throw()

    def read_next_token_or_throw(self) -> JsonToken:
        try:
            next_item = next(self.json_iter)
        except IncompleteJSONError:
            next_item = None
        if next_item is None:
            raise KustoTokenParsingError("Unexpected end of stream")
        (token_path, token_type, token_value) = next_item

        return JsonToken(token_path, JsonTokenType[token_type.upper()], token_value)

    def read_token_of_type(self, *token_types: JsonTokenType) -> JsonToken:
        token = self.read_next_token_or_throw()
        if token.token_type not in token_types:
            raise KustoTokenParsingError(f"Expected one the following types: '{','.join(t.name for t in token_types)}' , got type {token.token_type}")
        return token

    def read_start_object(self) -> JsonToken:
        return self.read_token_of_type(JsonTokenType.START_MAP)

    def read_start_array(self) -> JsonToken:
        return self.read_token_of_type(JsonTokenType.START_ARRAY)

    def read_string(self) -> str:
        return self.read_token_of_type(JsonTokenType.STRING).token_value

    def read_boolean(self) -> bool:
        return self.read_token_of_type(JsonTokenType.BOOLEAN).token_value

    def read_number(self) -> float:
        return self.read_token_of_type(JsonTokenType.NUMBER).token_value

    def skip_children(self, prev_token: JsonToken):
        if prev_token.token_type == JsonTokenType.MAP_KEY:
            prev_token = self.read_next_token_or_throw()

        if prev_token.token_type in JsonTokenType.start_tokens():
            for potential_end_token in self:
                if potential_end_token.token_path == prev_token.token_path and potential_end_token.token_type in JsonTokenType.end_tokens():
                    break

    def skip_until_property_name(self, name: str) -> JsonToken:
        while True:
            token = self.read_token_of_type(JsonTokenType.MAP_KEY)
            if token.token_value == name:
                return token

            self.skip_children(token)

    def skip_until_any_property_name(self, *names: str) -> JsonToken:
        while True:
            token = self.read_token_of_type(JsonTokenType.MAP_KEY)
            if token.token_value in names:
                return token

            self.skip_children(token)

    def skip_until_property_name_or_end_object(self, *names: str) -> JsonToken:
        for token in self:
            if token.token_type == JsonTokenType.END_MAP:
                return token

            if token.token_type == JsonTokenType.MAP_KEY:
                if token.token_value in names:
                    return token

                self.skip_children(token)
                continue

            raise Exception(f"Unexpected token {token}")

    def skip_until_token_with_paths(self, *tokens: (JsonTokenType, str)) -> JsonToken:
        for token in self:
            if any((token.token_type == t_type and token.token_path == t_path) for (t_type, t_path) in tokens):
                return token
            self.skip_children(token)


class StreamingDataSetEnumerator:
    def __init__(self, reader: JsonTokenReader):
        self.reader = reader
        self.done = False
        self.started = False
        self.started_primary_results = False
        self.finished_primary_results = False

    def __iter__(self) -> "StreamingDataSetEnumerator":
        return self

    def __next__(self) -> Dict[str, Any]:
        if self.done:
            raise StopIteration()

        if not self.started:
            self.reader.read_start_array()
            self.started = True

        token = self.reader.skip_until_token_with_paths((JsonTokenType.START_MAP, "item"), (JsonTokenType.END_ARRAY, ""))
        if token == JsonTokenType.END_ARRAY:
            self.done = True
            raise StopIteration()

        frame_type = self.read_frame_type()
        parsed_frame = self.parse_frame(frame_type)
        is_primary_result = parsed_frame["FrameType"] == FrameType.DataTable and parsed_frame["TableKind"] == WellKnownDataSet.PrimaryResult.value
        if is_primary_result:
            self.started_primary_results = True
        elif self.started_primary_results:
            self.finished_primary_results = True

        return parsed_frame

    def parse_frame(self, frame_type: FrameType) -> Dict[str, Any]:
        if frame_type == FrameType.DataSetHeader:
            frame = self.extract_props(frame_type, ("IsProgressive", JsonTokenType.BOOLEAN), ("Version", JsonTokenType.STRING))
            if frame["IsProgressive"]:
                raise KustoUnsupportedApiError.progressive_api_unsupported()
            return frame
        if frame_type in [FrameType.TableHeader, FrameType.TableFragment, FrameType.TableCompletion, FrameType.TableProgress]:
            raise KustoUnsupportedApiError.progressive_api_unsupported()
        if frame_type == FrameType.DataTable:
            props = self.extract_props(
                frame_type,
                ("TableId", JsonTokenType.NUMBER),
                ("TableKind", JsonTokenType.STRING),
                ("TableName", JsonTokenType.STRING),
                ("Columns", JsonTokenType.START_ARRAY),
            )
            self.reader.skip_until_property_name("Rows")
            props["Rows"] = self.row_iterator()
            if props["TableKind"] != WellKnownDataSet.PrimaryResult.value:
                props["Rows"] = list(props["Rows"])
            return props
        if frame_type == FrameType.DataSetCompletion:
            res = self.extract_props(frame_type, ("HasErrors", JsonTokenType.BOOLEAN), ("Cancelled", JsonTokenType.BOOLEAN))
            token = self.reader.skip_until_property_name_or_end_object("OneApiErrors")
            if token.token_type != JsonTokenType.END_MAP:
                res["OneApiErrors"] = self.parse_array(skip_start=False)
            return res

    def row_iterator(self) -> Iterator[list]:
        self.reader.read_token_of_type(JsonTokenType.START_ARRAY)
        while True:
            token = self.reader.read_token_of_type(JsonTokenType.START_ARRAY, JsonTokenType.END_ARRAY, JsonTokenType.START_MAP)
            if token.token_type == JsonTokenType.START_MAP:
                # Todo - this method of error handling may be problematic, since after raising an error the iteration stops.
                #  This means that if there are more data or even more errors, we can't read them
                raise KustoMultiApiError([self.parse_object(skip_start=True)])
            if token.token_type == JsonTokenType.END_ARRAY:
                return
            yield self.parse_array(skip_start=True)

    def parse_array(self, skip_start: bool) -> list:
        if not skip_start:
            self.reader.read_start_array()
        arr = []

        while True:
            token = self.reader.read_token_of_type(
                JsonTokenType.NULL,
                JsonTokenType.BOOLEAN,
                JsonTokenType.NUMBER,
                JsonTokenType.STRING,
                JsonTokenType.START_MAP,
                JsonTokenType.START_ARRAY,
                JsonTokenType.END_ARRAY,
            )

            if token.token_type == JsonTokenType.END_ARRAY:
                return arr

            if token.token_type == JsonTokenType.START_MAP:
                arr.append(self.parse_object(skip_start=True))
            elif token.token_type == JsonTokenType.START_ARRAY:
                arr.append(self.parse_array(skip_start=True))
            else:
                arr.append(token.token_value)

    def parse_object(self, skip_start: bool) -> Dict[str, Any]:
        if not skip_start:
            self.reader.read_start_object()

        obj = {}
        while True:
            token_prop_name = self.reader.read_token_of_type(JsonTokenType.MAP_KEY, JsonTokenType.END_MAP)
            if token_prop_name.token_type == JsonTokenType.END_MAP:
                return obj
            prop_name = token_prop_name.token_value

            token = self.reader.read_token_of_type(
                JsonTokenType.NULL, JsonTokenType.BOOLEAN, JsonTokenType.NUMBER, JsonTokenType.STRING, JsonTokenType.START_MAP, JsonTokenType.START_ARRAY
            )

            if token.token_type == JsonTokenType.START_MAP:
                obj[prop_name] = self.parse_object(skip_start=True)
            elif token.token_type == JsonTokenType.START_ARRAY:
                obj[prop_name] = self.parse_array(skip_start=True)
            else:
                obj[prop_name] = token.token_value

    def extract_props(self, frame_type: FrameType, *props: Tuple[str, JsonTokenType]) -> Dict[str, Any]:
        result = {"FrameType": frame_type}
        props_dict = dict(props)
        while props_dict:
            name = self.reader.skip_until_any_property_name(*props_dict.keys()).token_value
            if props_dict[name] == JsonTokenType.START_ARRAY:
                result[name] = self.parse_array(skip_start=False)
            else:
                result[name] = self.reader.read_token_of_type(props_dict[name]).token_value
            props_dict.pop(name)

        return result

    def read_frame_type(self) -> FrameType:
        self.reader.skip_until_property_name("FrameType")
        return FrameType[self.reader.read_string()]
