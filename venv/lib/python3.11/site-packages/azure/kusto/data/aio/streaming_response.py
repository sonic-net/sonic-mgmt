from typing import Any, Tuple, Dict, Iterator

import aiohttp
import ijson
from ijson import IncompleteJSONError

from azure.kusto.data._models import WellKnownDataSet
from azure.kusto.data.exceptions import KustoTokenParsingError, KustoUnsupportedApiError, KustoMultiApiError
from azure.kusto.data.streaming_response import JsonTokenType, FrameType, JsonToken


class JsonTokenReader:
    def __init__(self, stream: aiohttp.StreamReader):
        self.json_iter = ijson.parse_async(stream, use_float=True)

    def __aiter__(self) -> "JsonTokenReader":
        return self

    def __anext__(self) -> JsonToken:
        return self.read_next_token_or_throw()

    async def read_next_token_or_throw(self) -> JsonToken:
        try:
            next_item = await self.json_iter.__anext__()
        except IncompleteJSONError:
            next_item = None
        if next_item is None:
            raise KustoTokenParsingError("Unexpected end of stream")
        (token_path, token_type, token_value) = next_item

        return JsonToken(token_path, JsonTokenType[token_type.upper()], token_value)

    async def read_token_of_type(self, *token_types: JsonTokenType) -> JsonToken:
        token = await self.read_next_token_or_throw()
        if token.token_type not in token_types:
            raise KustoTokenParsingError(f"Expected one the following types: '{','.join(t.name for t in token_types)}' , got type {token.token_type}")
        return token

    async def read_start_object(self) -> JsonToken:
        return await self.read_token_of_type(JsonTokenType.START_MAP)

    async def read_start_array(self) -> JsonToken:
        return await self.read_token_of_type(JsonTokenType.START_ARRAY)

    async def read_string(self) -> str:
        return (await self.read_token_of_type(JsonTokenType.STRING)).token_value

    async def read_boolean(self) -> bool:
        return (await self.read_token_of_type(JsonTokenType.BOOLEAN)).token_value

    async def read_number(self) -> float:
        return (await self.read_token_of_type(JsonTokenType.NUMBER)).token_value

    async def skip_children(self, prev_token: JsonToken):
        if prev_token.token_type == JsonTokenType.MAP_KEY:
            prev_token = await self.read_next_token_or_throw()
        if prev_token.token_type in JsonTokenType.start_tokens():
            async for potential_end_token in self:
                if potential_end_token.token_path == prev_token.token_path and potential_end_token.token_type in JsonTokenType.end_tokens():
                    break

    async def skip_until_property_name(self, name: str) -> JsonToken:
        while True:
            token = await self.read_token_of_type(JsonTokenType.MAP_KEY)
            if token.token_value == name:
                return token

            await self.skip_children(token)

    async def skip_until_any_property_name(self, *names: str) -> JsonToken:
        while True:
            token = await self.read_token_of_type(JsonTokenType.MAP_KEY)
            if token.token_value in names:
                return token

            await self.skip_children(token)

    async def skip_until_property_name_or_end_object(self, *names: str) -> JsonToken:
        async for token in self:
            if token.token_type == JsonTokenType.END_MAP:
                return token

            if token.token_type == JsonTokenType.MAP_KEY:
                if token.token_value in names:
                    return token

                await self.skip_children(token)
                continue

            raise Exception(f"Unexpected token {token}")

    async def skip_until_token_with_paths(self, *tokens: (JsonTokenType, str)) -> JsonToken:
        async for token in self:
            if any((token.token_type == t_type and token.token_path == t_path) for (t_type, t_path) in tokens):
                return token
            await self.skip_children(token)


class StreamingDataSetEnumerator:
    def __init__(self, reader: JsonTokenReader):
        self.reader = reader
        self.done = False
        self.started = False
        self.started_primary_results = False
        self.finished_primary_results = False

    def __aiter__(self) -> "StreamingDataSetEnumerator":
        return self

    async def __anext__(self) -> Dict[str, Any]:
        if self.done:
            raise StopIteration()

        if not self.started:
            await self.reader.read_start_array()
            self.started = True

        token = await self.reader.skip_until_token_with_paths((JsonTokenType.START_MAP, "item"), (JsonTokenType.END_ARRAY, ""))
        if token == JsonTokenType.END_ARRAY:
            self.done = True
            raise StopIteration()

        frame_type = await self.read_frame_type()
        parsed_frame = await self.parse_frame(frame_type)
        is_primary_result = parsed_frame["FrameType"] == FrameType.DataTable and parsed_frame["TableKind"] == WellKnownDataSet.PrimaryResult.value
        if is_primary_result:
            self.started_primary_results = True
        elif self.started_primary_results:
            self.finished_primary_results = True

        return parsed_frame

    async def parse_frame(self, frame_type: FrameType) -> Dict[str, Any]:
        if frame_type == FrameType.DataSetHeader:
            frame = await self.extract_props(frame_type, ("IsProgressive", JsonTokenType.BOOLEAN), ("Version", JsonTokenType.STRING))
            if frame["IsProgressive"]:
                raise KustoUnsupportedApiError.progressive_api_unsupported()
            return frame
        if frame_type in [FrameType.TableHeader, FrameType.TableFragment, FrameType.TableCompletion, FrameType.TableProgress]:
            raise KustoUnsupportedApiError.progressive_api_unsupported()
        if frame_type == FrameType.DataTable:
            props = await self.extract_props(
                frame_type,
                ("TableId", JsonTokenType.NUMBER),
                ("TableKind", JsonTokenType.STRING),
                ("TableName", JsonTokenType.STRING),
                ("Columns", JsonTokenType.START_ARRAY),
            )
            await self.reader.skip_until_property_name("Rows")
            props["Rows"] = self.row_iterator()
            if props["TableKind"] != WellKnownDataSet.PrimaryResult.value:
                props["Rows"] = [r async for r in props["Rows"]]
            return props
        if frame_type == FrameType.DataSetCompletion:
            res = await self.extract_props(frame_type, ("HasErrors", JsonTokenType.BOOLEAN), ("Cancelled", JsonTokenType.BOOLEAN))
            token = await self.reader.skip_until_property_name_or_end_object("OneApiErrors")
            if token.token_type != JsonTokenType.END_MAP:
                res["OneApiErrors"] = self.parse_array(skip_start=False)
            return res

    async def row_iterator(self) -> Iterator[list]:
        await self.reader.read_token_of_type(JsonTokenType.START_ARRAY)
        while True:
            token = await self.reader.read_token_of_type(JsonTokenType.START_ARRAY, JsonTokenType.END_ARRAY, JsonTokenType.START_MAP)
            if token.token_type == JsonTokenType.START_MAP:
                raise KustoMultiApiError([await self.parse_object(skip_start=True)])
            if token.token_type == JsonTokenType.END_ARRAY:
                return
            yield await self.parse_array(skip_start=True)

    async def parse_array(self, skip_start: bool) -> list:
        if not skip_start:
            await self.reader.read_start_array()
        arr = []

        while True:
            token = await self.reader.read_token_of_type(
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
                arr.append(await self.parse_object(skip_start=True))
            elif token.token_type == JsonTokenType.START_ARRAY:
                arr.append(await self.parse_array(skip_start=True))
            else:
                arr.append(token.token_value)

    async def parse_object(self, skip_start: bool) -> Dict[str, Any]:
        if not skip_start:
            await self.reader.read_start_object()

        obj = {}
        while True:
            token_prop_name = await self.reader.read_token_of_type(JsonTokenType.MAP_KEY, JsonTokenType.END_MAP)
            if token_prop_name.token_type == JsonTokenType.END_MAP:
                return obj
            prop_name = token_prop_name.token_value

            token = await self.reader.read_token_of_type(
                JsonTokenType.NULL, JsonTokenType.BOOLEAN, JsonTokenType.NUMBER, JsonTokenType.STRING, JsonTokenType.START_MAP, JsonTokenType.START_ARRAY
            )

            if token.token_type == JsonTokenType.START_MAP:
                obj[prop_name] = await self.parse_object(skip_start=True)
            elif token.token_type == JsonTokenType.START_ARRAY:
                obj[prop_name] = await self.parse_array(skip_start=True)
            else:
                obj[prop_name] = token.token_value

    async def extract_props(self, frame_type: FrameType, *props: Tuple[str, JsonTokenType]) -> Dict[str, Any]:
        result = {"FrameType": frame_type}
        props_dict = dict(props)
        while props_dict:
            name = (await self.reader.skip_until_any_property_name(*props_dict.keys())).token_value
            if props_dict[name] == JsonTokenType.START_ARRAY:
                result[name] = await self.parse_array(skip_start=False)
            else:
                result[name] = (await self.reader.read_token_of_type(props_dict[name])).token_value
            props_dict.pop(name)

        return result

    async def read_frame_type(self) -> FrameType:
        await self.reader.skip_until_property_name("FrameType")
        return FrameType[await self.reader.read_string()]
