"""Get, Set and bounded Subscribe, trimmed from pygnmi 0.8.15.

Copyright (c) 2020, karneliuk.com. All rights reserved.
Derived portions are distributed under BSD-3-Clause; see LICENSE.pygnmi and
README.md for the pinned source and the deliberate changes from upstream.

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


def gnmi_path_generator(text, target=None):
    """pygnmi's selector-extraction/path-element algorithm, with escaped slashes.

    Extract selectors before splitting, so slashes inside key values are not
    separators. Unlike upstream, split key/value only once and reject malformed
    selectors rather than silently producing a different path.
    """
    if isinstance(text, pb.Path):
        result = pb.Path()
        result.CopyFrom(text)
    else:
        result = pb.Path()
        keys = []

        def extract_key(match):
            pair = match[1].split("=", 1)
            if len(pair) != 2 or not pair[0]:
                raise GnmiClientError(f"Invalid path selector: {match[0]}")
            keys.append(dict([pair]))
            return f"[{len(keys) - 1}]"

        text = re.sub(r"\[([^\[\]]*)\]", extract_key, text)
        path_elements = [part for part in re.split(r"(?<!\\)/", text) if part]
        if path_elements and ":" in path_elements[0]:
            result.origin, path_elements[0] = path_elements[0].split(":", 1)
            if not path_elements[0]:
                del path_elements[0]
        for part in path_elements:
            match = re.fullmatch(r"([^\[\]]+)((?:\[\d+\])*)", part)
            if not match or part.endswith("\\"):
                raise GnmiClientError(f"Invalid path element: {part}")
            element = result.elem.add(name=match[1].replace(r"\/", "/"))
            for index in re.findall(r"\[(\d+)\]", match[2]):
                element.key.update(keys[int(index)])
    if target is not None:
        result.target = target
    return result


def gnmi_path_degenerator(path):
    """pygnmi's canonical element/key rendering (origin and target stay separate)."""
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
        "prefix": gnmi_path_degenerator(notification.prefix),
        "origin": notification.prefix.origin or None,
        "target": notification.prefix.target or None,
        "atomic": notification.atomic,
        "update": [{"path": gnmi_path_degenerator(update.path), "val": _value(update.val)}
                   for update in notification.update],
    }
    if notification.delete:
        result["delete"] = [{"path": gnmi_path_degenerator(path)} for path in notification.delete]
    return result


def construct_update_message(user_list, encoding):
    """Trimmed pygnmi Set builder: strings are JSON text, not Python scalars."""
    result = []
    fields = {pb.JSON: "json_val", pb.JSON_IETF: "json_ietf_val", pb.BYTES: "bytes_val",
              pb.PROTO: "proto_bytes", pb.ASCII: "ascii_val"}
    for path, value in user_list or []:
        entry = pb.Update(path=gnmi_path_generator(path))
        if isinstance(value, pb.TypedValue):
            entry.val.CopyFrom(value)
        else:
            if encoding in (pb.JSON, pb.JSON_IETF):
                value = value.encode("utf-8") if isinstance(value, str) else json.dumps(value).encode("utf-8")
            elif encoding in (pb.BYTES, pb.PROTO) and not isinstance(value, bytes):
                raise GnmiClientError("Use bytes for bytes/proto, or an explicit TypedValue")
            elif encoding == pb.ASCII and not isinstance(value, str):
                raise GnmiClientError("Use str for ascii, or an explicit TypedValue")
            setattr(entry.val, fields[encoding], value)
        result.append(entry)
    return result


def telemetryParser(response):
    """Trimmed pygnmi response shape; fail visibly on errors or invalid values."""
    kind = response.WhichOneof("response")
    if kind == "update":
        return {"update": _notification(response.update)}
    if kind == "sync_response" and response.sync_response:
        return {"sync_response": True}
    if kind == "error":
        raise GnmiClientError(f"Subscribe error {response.error.code}: {response.error.message}")
    raise GnmiClientError("Subscribe returned an empty or invalid response")


class _Subscriber:
    """pygnmi queue-driven subscriber, reduced to bounded reads and owned close.

    Keep the upstream request queue and receiver model. Queue terminal failures
    as well as messages, retain the RPC for cancel(), and join both workers.
    """

    def __init__(self, stub, request, timeout):
        self._msgs = queue.Queue()
        self._updates = queue.Queue(maxsize=256)
        self._stopped = threading.Event()
        self._requests_started = threading.Event()
        self._requests_done = threading.Event()
        self._first_update_seen = False
        self._mode = request.subscribe.mode
        self._events = request.subscribe.prefix.target == "EVENTS"
        self._call = stub.Subscribe(self._create_client_stream(request), timeout=timeout)
        self._subscribe_thread = threading.Thread(target=self._enqueue_updates, name="gnmi-subscribe-reader")
        self._subscribe_thread.start()

    def _create_client_stream(self, request):
        self._requests_started.set()
        try:
            yield request
            while True:
                message = self._msgs.get()
                if message == "POLL":
                    yield pb.SubscribeRequest(poll=pb.Poll())
                elif message == "STOP":
                    return
        finally:
            self._requests_done.set()

    def _enqueue(self, message):
        while not self._stopped.is_set():
            try:
                self._updates.put(message, timeout=0.1)
                return
            except queue.Full:
                pass

    def _enqueue_updates(self):
        try:
            for update in self._call:
                self._enqueue(update)
        except grpc.RpcError as error:
            self._enqueue(error)
        finally:
            self._enqueue(None)

    def _get_one_update(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise queue.Empty
        response = self._updates.get(timeout=remaining)
        if isinstance(response, grpc.RpcError):
            raise response
        if response is None:
            raise GnmiClientError("Subscribe ended before the requested collection completed")
        return telemetryParser(response)

    def _get_updates_till_sync(self, deadline):
        response = {"update": {}}
        while "sync_response" not in response:
            self._merge_updates(response, self._get_one_update(deadline))
        return response

    @staticmethod
    def _merge_updates(response, new_response):
        if "update" in new_response:
            batch, notification = response["update"], new_response["update"]
            # Upstream overwrites these metadata fields, potentially associating
            # old updates with a different prefix. Reject unrepresentable batches.
            if batch and any(batch[key] != notification[key]
                             for key in ("prefix", "origin", "target", "timestamp", "atomic")):
                raise GnmiClientError("Cannot coalesce notifications with different prefix or metadata")
            for key, value in notification.items():
                if key in ("update", "delete"):
                    batch.setdefault(key, []).extend(value)
                else:
                    batch[key] = value
        if "sync_response" in new_response:
            response["sync_response"] = new_response["sync_response"]

    def get_update(self, timeout):
        deadline = time.monotonic() + timeout
        if self._mode == pb.SubscriptionList.POLL:
            # Consume initial snapshot before requesting another, rather than
            # pygnmi's eager Poll that can leave one unused snapshot queued.
            if self._first_update_seen:
                self._msgs.put("POLL")
            result = self._get_updates_till_sync(deadline)
        elif self._mode == pb.SubscriptionList.STREAM and not self._first_update_seen and not self._events:
            result = self._get_updates_till_sync(deadline)
        else:
            result = self._get_one_update(deadline)
        self._first_update_seen = True
        return result

    def close(self):
        self._stopped.set()
        self._msgs.put("STOP")
        self._call.cancel()
        self._subscribe_thread.join(5)
        if (self._subscribe_thread.is_alive()
                or (self._requests_started.is_set() and not self._requests_done.wait(5))):
            raise GnmiClientError("Subscribe workers did not stop after cancellation")


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
            prefix=gnmi_path_generator(prefix, target), path=[gnmi_path_generator(path) for path in _paths(paths)],
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
        request = pb.SetRequest(
            prefix=gnmi_path_generator(prefix, target),
            delete=[gnmi_path_generator(path) for path in delete or []],
            update=construct_update_message(update, encoding), replace=construct_update_message(replace, encoding),
        )
        with self._stub() as stub:
            response = stub.Set(request, timeout=self.timeout)
        if response.HasField("message"):
            raise GnmiClientError(f"Set error {response.message.code}: {response.message.message}")
        return {
            "timestamp": response.timestamp, "prefix": gnmi_path_degenerator(response.prefix),
            "target": response.prefix.target or None,
            "response": [{"path": gnmi_path_degenerator(item.path), "op": pb.UpdateResult.Operation.Name(item.op)}
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
            prefix=gnmi_path_generator(prefix, target), mode=mode, encoding=_enum(pb.Encoding, encoding),
            updates_only=updates_only, allow_aggregation=allow_aggregation,
        ))
        if qos is not None:
            marking = qos["marking"]
            if not isinstance(marking, int) or not 0 <= marking <= 63:
                raise GnmiClientError("qos marking must be in [0, 63]")
            request.subscribe.qos.marking = marking
        for item in _paths(paths):
            options = item if isinstance(item, dict) else {"path": item}
            subscription = request.subscribe.subscription.add(path=gnmi_path_generator(options["path"]))
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
        duration = (collect_seconds if mode == pb.SubscriptionList.STREAM else
                    poll_count * (self.timeout + poll_interval) if mode == pb.SubscriptionList.POLL else self.timeout)
        with self._stub() as stub:
            subscriber = _Subscriber(stub, request, duration + 1)
            deadline = time.monotonic() + (collect_seconds if mode == pb.SubscriptionList.STREAM else self.timeout)
            produced = 0
            try:
                while True:
                    timeout = self.timeout if mode == pb.SubscriptionList.POLL else deadline - time.monotonic()
                    try:
                        response = subscriber.get_update(timeout)
                    except queue.Empty:
                        if mode == pb.SubscriptionList.STREAM:
                            return
                        raise GnmiClientTimeoutError("Subscribe did not synchronize within timeout") from None
                    produced += 1
                    yield response
                    if mode == pb.SubscriptionList.ONCE and response.get("sync_response"):
                        return
                    if mode == pb.SubscriptionList.STREAM and count is not None and produced >= count:
                        return
                    if mode == pb.SubscriptionList.POLL:
                        if produced >= poll_count:
                            return
                        time.sleep(poll_interval)
            finally:
                subscriber.close()
