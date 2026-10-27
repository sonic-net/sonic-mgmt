"""Get, Set and bounded Subscribe without a pygnmi dependency.

Each unary call owns its channel. A subscription owns its channel until exhausted
or explicitly closed (use contextlib.closing when breaking out early).
"""

from contextlib import contextmanager
import json
import math
import queue
import re
import threading
import time

import grpc

from .proto import gnmi_pb2 as pb
from .proto import gnmi_pb2_grpc


class GnmiClientError(Exception):
    """Invalid input, malformed response or failed RPC; RPC errors are chained."""


class GnmiClientTimeoutError(GnmiClientError):
    """RPC deadline or required subscription response exceeded its budget."""


def _enum(enum, value):
    # Also accepts the string enums used by the existing test wrapper.
    try:
        return enum.Value(str(value).upper())
    except ValueError as error:
        raise GnmiClientError(f"Invalid {enum.DESCRIPTOR.name}: {value}") from error


def _seconds(value, name, allow_zero=False):
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        raise GnmiClientError(f"{name} must be finite and {'non-negative' if allow_zero else 'positive'}")
    return value


def _split_path(text):
    """Split unescaped slashes outside selectors, retaining escapes for parsing."""
    parts, part, depth, escaped = [], [], 0, False
    for char in text:
        if escaped:
            part.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "/" and not depth:
            if part:
                parts.append("".join(part))
                part = []
        else:
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
            if depth not in (0, 1):
                raise GnmiClientError(f"Invalid path: {text}")
            part.append(char)
    if depth or escaped:
        raise GnmiClientError(f"Invalid path: {text}")
    if part:
        parts.append("".join(part))
    return parts


def _unescape(text):
    return re.sub(r"\\(.)", r"\1", text)


def _path(text, target=None):
    if isinstance(text, pb.Path):
        result = pb.Path()
        result.CopyFrom(text)
    else:
        result = pb.Path()
        text = text.lstrip("/")
        origin = re.match(r"^([A-Za-z_][\w.-]*):", text)
        if origin:
            result.origin = origin[1]
            text = text[origin.end():]
        for part in _split_path(text):
            match = re.fullmatch(r"((?:\\.|[^\[\]])+)((?:\[(?:\\.|[^\[\]])*\])*)", part)
            if not match:
                raise GnmiClientError(f"Invalid path element: {part}")
            element = result.elem.add(name=_unescape(match[1]))
            for selector in re.findall(r"\[((?:\\.|[^\[\]])*)\]", match[2]):
                pair = re.split(r"(?<!\\)=", selector, maxsplit=1)
                if len(pair) != 2 or not pair[0]:
                    raise GnmiClientError(f"Invalid path selector: {selector}")
                element.key[_unescape(pair[0])] = _unescape(pair[1])
    if target is not None:
        result.target = target
    return result


def _path_text(path):
    return "/".join(
        element.name + "".join(f"[{key}={value}]" for key, value in sorted(element.key.items()))
        for element in path.elem
    ) or None


def _paths(paths):
    result = [paths] if isinstance(paths, (str, pb.Path, dict)) else list(paths)
    if not result:
        raise GnmiClientError("At least one path is required")
    return result


def _value(value):
    field = value.WhichOneof("value")
    if field is None:
        raise GnmiClientError("Update has no TypedValue")
    data = getattr(value, field)
    if field in ("json_val", "json_ietf_val"):
        try:
            return json.loads(data)
        except (ValueError, UnicodeDecodeError) as error:
            raise GnmiClientError("Invalid JSON TypedValue") from error
    if field == "leaflist_val":
        return [_value(element) for element in data.element]
    if field in ("decimal_val", "any_val"):
        # Preserve these protobuf values rather than inventing a lossy conversion.
        copy = type(data)()
        copy.CopyFrom(data)
        return copy
    return data


def _notification(notification):
    result = {
        "timestamp": notification.timestamp,
        "prefix": _path_text(notification.prefix),
        "origin": notification.prefix.origin or None,
        "target": notification.prefix.target or None,
        "atomic": notification.atomic,
        "update": [{"path": _path_text(update.path), "val": _value(update.val)}
                   for update in notification.update],
    }
    if notification.delete:
        result["delete"] = [{"path": _path_text(path)} for path in notification.delete]
    return result


def _merge(batch, notification):
    """Coalesce only notifications whose metadata can be represented losslessly."""
    metadata = ("prefix", "origin", "target", "timestamp", "atomic")
    if batch and any(batch[key] != notification[key] for key in metadata):
        raise GnmiClientError("Cannot coalesce notifications with different prefix or metadata")
    for key, value in notification.items():
        if key in ("update", "delete"):
            batch.setdefault(key, []).extend(value)
        else:
            batch[key] = value


class GnmiClient:
    """Minimal test client. Construction is lazy and sends no RPC.

    TLS requires local CA/client certificate/key files. They are read afresh for
    every RPC, so certificate rotation does not retain stale channel credentials.
    timeout bounds each unary RPC and each POLL batch, or the whole ONCE snapshot.
    No automatic retries, Capabilities probe or server configuration are performed.
    """

    def __init__(self, host, port, plaintext=False, ca_cert=None, client_cert=None,
                 client_key=None, timeout=30):
        self.host, self.port, self.plaintext = host, port, plaintext
        self.ca_cert, self.client_cert, self.client_key = ca_cert, client_cert, client_key
        self.timeout = _seconds(timeout, "timeout")
        if not plaintext and not all((ca_cert, client_cert, client_key)):
            raise GnmiClientError("TLS requires ca_cert, client_cert and client_key")

    @contextmanager
    def _stub(self):
        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        target = f"{host}:{self.port}"
        options = (("grpc.enable_retries", 0),)
        if self.plaintext:
            channel = grpc.insecure_channel(target, options=options)
        else:
            certificates = []
            for filename in (self.ca_cert, self.client_key, self.client_cert):
                with open(filename, "rb") as stream:
                    certificates.append(stream.read())
            credentials = grpc.ssl_channel_credentials(*certificates)
            channel = grpc.secure_channel(target, credentials, options=options)
        with channel:
            try:
                yield gnmi_pb2_grpc.gNMIStub(channel)
            except grpc.RpcError as error:
                error_type = (GnmiClientTimeoutError if error.code() == grpc.StatusCode.DEADLINE_EXCEEDED
                              else GnmiClientError)
                raise error_type(f"gNMI {error.code().name}: {error.details()}") from error

    def get(self, paths, datatype="all", encoding="json_ietf", target=None, prefix=""):
        request = pb.GetRequest(
            prefix=_path(prefix, target), path=[_path(path) for path in _paths(paths)],
            type=_enum(pb.GetRequest.DataType, datatype), encoding=_enum(pb.Encoding, encoding),
        )
        with self._stub() as stub:
            response = stub.Get(request, timeout=self.timeout)
        if response.HasField("error"):
            raise GnmiClientError(f"Get error {response.error.code}: {response.error.message}")
        return {"notification": [_notification(item) for item in response.notification]}

    def set(self, update=None, replace=None, delete=None, encoding="json_ietf", target=None, prefix=""):
        if not any((update, replace, delete)):
            raise GnmiClientError("Set requires update, replace or delete")
        encoding = _enum(pb.Encoding, encoding)
        request = pb.SetRequest(prefix=_path(prefix, target), delete=[_path(path) for path in delete or []])
        for operation, items in (("update", update), ("replace", replace)):
            for path, value in items or []:
                entry = getattr(request, operation).add(path=_path(path))
                if isinstance(value, pb.TypedValue):
                    entry.val.CopyFrom(value)
                elif encoding in (pb.JSON, pb.JSON_IETF):
                    # Existing callers pass JSON text, including quoted scalar strings.
                    data = value.encode() if isinstance(value, str) else json.dumps(value).encode()
                    setattr(entry.val, "json_val" if encoding == pb.JSON else "json_ietf_val", data)
                elif encoding in (pb.BYTES, pb.PROTO) and isinstance(value, bytes):
                    setattr(entry.val, "bytes_val" if encoding == pb.BYTES else "proto_bytes", value)
                elif encoding == pb.ASCII and isinstance(value, str):
                    entry.val.ascii_val = value
                else:
                    raise GnmiClientError("Use bytes for bytes/proto, str for ascii, or an explicit TypedValue")
        with self._stub() as stub:
            response = stub.Set(request, timeout=self.timeout)
        if response.HasField("message"):
            raise GnmiClientError(f"Set error {response.message.code}: {response.message.message}")
        return {
            "timestamp": response.timestamp, "prefix": _path_text(response.prefix),
            "target": response.prefix.target or None,
            "response": [{"path": _path_text(item.path), "op": pb.UpdateResult.Operation.Name(item.op)}
                         for item in response.response],
        }

    def subscribe(self, paths, mode="stream", stream_mode="sample", sample_interval=None,
                  heartbeat_interval=None, encoding="json_ietf", target=None,
                  collect_seconds=10, count=None, poll_count=1, poll_interval=1,
                  prefix="", updates_only=False, allow_aggregation=False, qos=None):
        """Yield dict notifications; close the generator when stopping early.

        ONCE yields raw notifications and the final sync marker. POLL yields
        poll_count synchronized batches, INCLUDING the initial snapshot, sending
        a Poll only for subsequent batches. STREAM coalesces its initial snapshot
        to sync, then yields each notification; EVENTS delivers immediately because
        that target has no initial sync. count counts yielded batches/messages,
        not individual update fields. STREAM window expiry is a normal stop.
        Per-path dicts support mode, sample_interval, heartbeat_interval and
        suppress_redundant. Intervals are in seconds. No extension/alias API.
        """
        mode = _enum(pb.SubscriptionList.Mode, mode)
        _seconds(collect_seconds, "collect_seconds")
        _seconds(poll_interval, "poll_interval", allow_zero=True)
        if count is not None and (not isinstance(count, int) or count <= 0):
            raise GnmiClientError("count must be a positive integer")
        if not isinstance(poll_count, int) or poll_count <= 0:
            raise GnmiClientError("poll_count must be a positive integer")
        request = pb.SubscribeRequest(subscribe=pb.SubscriptionList(
            prefix=_path(prefix, target), mode=mode, encoding=_enum(pb.Encoding, encoding),
            updates_only=updates_only, allow_aggregation=allow_aggregation,
        ))
        if qos is not None:
            marking = qos["marking"]
            if not isinstance(marking, int) or not 0 <= marking <= 63:
                raise GnmiClientError("qos marking must be in [0, 63]")
            request.subscribe.qos.marking = marking
        for item in _paths(paths):
            options = item if isinstance(item, dict) else {"path": item}
            subscription = request.subscribe.subscription.add(path=_path(options["path"]))
            if mode == pb.SubscriptionList.STREAM:
                subscription.mode = _enum(pb.SubscriptionMode, options.get("mode", stream_mode))
                subscription.suppress_redundant = options.get("suppress_redundant", False)
                for name, default in (("sample_interval", sample_interval),
                                      ("heartbeat_interval", heartbeat_interval)):
                    interval = options.get(name, default)
                    if interval is not None:
                        setattr(subscription, name, int(_seconds(interval, name, True) * 1_000_000_000))
        return self._subscribe(request, collect_seconds, count, poll_count, poll_interval)

    def _subscribe(self, request, collect_seconds, count, poll_count, poll_interval):
        mode = request.subscribe.mode
        outgoing, incoming = queue.Queue(), queue.Queue(maxsize=256)
        stopped, requests_done = threading.Event(), threading.Event()
        requests_started = threading.Event()

        def requests():
            requests_started.set()
            try:
                yield request
                while True:
                    message = outgoing.get()
                    if message is None:
                        return
                    yield message
            finally:
                requests_done.set()

        def enqueue(message):
            while not stopped.is_set():
                try:
                    incoming.put(message, timeout=0.1)
                    return
                except queue.Full:
                    pass

        # The call deadline is a final guard; per-batch/window bounds below are
        # tighter. It also bounds a consumer that stops requesting new messages.
        duration = (collect_seconds if mode == pb.SubscriptionList.STREAM else
                    poll_count * (self.timeout + poll_interval) if mode == pb.SubscriptionList.POLL else self.timeout)
        with self._stub() as stub:
            call = stub.Subscribe(requests(), timeout=duration + 1)

            def receive():
                try:
                    for response in call:
                        enqueue(response)
                except grpc.RpcError as error:
                    enqueue(error)
                finally:
                    enqueue(None)

            reader = threading.Thread(target=receive, name="gnmi-subscribe-reader")
            reader.start()
            deadline = time.monotonic() + (collect_seconds if mode == pb.SubscriptionList.STREAM else self.timeout)
            batch, produced = {}, 0
            initial_stream = mode == pb.SubscriptionList.STREAM and request.subscribe.prefix.target != "EVENTS"
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    try:
                        if remaining <= 0:
                            raise queue.Empty
                        response = incoming.get(timeout=remaining)
                    except queue.Empty:
                        if mode == pb.SubscriptionList.STREAM:
                            return
                        raise GnmiClientTimeoutError("Subscribe did not synchronize within timeout") from None
                    if isinstance(response, grpc.RpcError):
                        raise response
                    if response is None:
                        raise GnmiClientError("Subscribe ended before the requested collection completed")
                    kind = response.WhichOneof("response")
                    if kind == "error":
                        raise GnmiClientError(f"Subscribe error {response.error.code}: {response.error.message}")
                    if kind == "update":
                        notification = _notification(response.update)
                        if mode == pb.SubscriptionList.POLL or initial_stream:
                            _merge(batch, notification)
                            continue
                        result = {"update": notification}
                    elif kind == "sync_response" and response.sync_response:
                        result = {"sync_response": True}
                        if mode == pb.SubscriptionList.POLL or initial_stream:
                            result["update"] = batch
                            batch = {}
                            initial_stream = False
                    else:
                        raise GnmiClientError("Subscribe returned an empty or invalid response")
                    produced += 1
                    yield result
                    if mode == pb.SubscriptionList.ONCE and kind == "sync_response":
                        return
                    if mode == pb.SubscriptionList.STREAM and count is not None and produced >= count:
                        return
                    if mode == pb.SubscriptionList.POLL:
                        if produced >= poll_count:
                            return
                        time.sleep(poll_interval)
                        deadline = time.monotonic() + self.timeout
                        outgoing.put(pb.SubscribeRequest(poll=pb.Poll()))
            finally:
                stopped.set()
                outgoing.put(None)
                call.cancel()
                reader.join(5)
                if reader.is_alive() or (requests_started.is_set() and not requests_done.wait(5)):
                    raise GnmiClientError("Subscribe workers did not stop after cancellation")
