"""Lightweight spawn entry; avoid tests.common's parent-only Ansible imports."""

import queue
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import grpc
from pygnmi.client import gNMIclient, telemetryParser
from pygnmi.create_gnmi_path import gnmi_path_generator
from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc


class _IdlePoll:
    """Receive the automatic POLL snapshot without ever generating a Poll."""

    def __init__(self, channel, subscription):
        # Keep this adapter explicit: unsupported options must not be discarded.
        if set(subscription) - {"mode", "encoding", "subscription", "prefix", "updates_only"}:
            raise ValueError("Unsupported idle POLL SubscriptionList option")
        paths = []
        for item in subscription["subscription"]:
            if set(item) - {"path", "mode", "sample_interval"}:
                raise ValueError("Unsupported idle POLL Subscription option")
            paths.append(
                gnmi_pb2.Subscription(
                    path=gnmi_path_generator(item["path"]),
                    mode=gnmi_pb2.SubscriptionMode.Value(item.get("mode", "target_defined").upper()),
                    sample_interval=item.get("sample_interval", 0),
                )
            )
        request = gnmi_pb2.SubscribeRequest(
            subscribe=gnmi_pb2.SubscriptionList(
                mode=gnmi_pb2.SubscriptionList.POLL,
                encoding=gnmi_pb2.Encoding.Value(subscription.get("encoding", "json_ietf").upper()),
                prefix=gnmi_path_generator(subscription.get("prefix", "")),
                updates_only=subscription.get("updates_only", False),
                subscription=paths,
            )
        )
        self._stop = threading.Event()
        self._updates = queue.Queue()
        self.error = None
        self._first = True

        def requests():
            yield request
            self._stop.wait()  # Keep the sending side open; never yield a Poll.

        self._call = gnmi_pb2_grpc.gNMIStub(channel).Subscribe(requests())

        def receive():
            try:
                for response in self._call:
                    self._updates.put(telemetryParser(response))
                if not self._stop.is_set():
                    self.error = RuntimeError("Idle POLL ended without terminal RPC status")
            except grpc.RpcError as error:
                if not self._stop.is_set():
                    self.error = error
            except Exception as error:
                self.error = error

        self._receiver = threading.Thread(target=receive)
        self._receiver.start()

    def get_update(self, timeout):
        """Initial snapshot returns only coalesced update entries and sync, not notification metadata."""
        deadline = time.monotonic() + timeout
        result = {"update": {"update": []}}
        try:
            while True:
                response = self._updates.get(timeout=max(0, deadline - time.monotonic()))
                if not self._first:
                    return response
                result["update"]["update"].extend(response.get("update", {}).get("update", []))
                if response.get("sync_response"):
                    self._first = False
                    result["sync_response"] = True
                    return result
                if time.monotonic() >= deadline:
                    raise TimeoutError("Idle POLL initial snapshot timed out")
        except queue.Empty as error:
            raise TimeoutError("Idle POLL update timed out") from error

    def peek(self):
        return not self._updates.empty()

    def close(self):
        self._stop.set()
        self._call.cancel()
        self._receiver.join(5)
        if self._receiver.is_alive():
            raise RuntimeError("Idle POLL receiver did not stop")


@contextmanager
def _subscriber(options, subscription):
    if subscription.get("mode", "stream").lower() != "poll":
        with gNMIclient(**options) as client:
            subscriber = client.subscribe2(subscribe=subscription)
            try:
                yield subscriber
            finally:
                try:
                    client.close()
                finally:
                    subscriber.close()
        return
    host, port = options["target"]
    target = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
    if options.get("insecure"):
        channel = grpc.insecure_channel(target, options=options.get("grpc_options"))
    else:
        credentials = grpc.ssl_channel_credentials(
            root_certificates=Path(options["path_root"]).read_bytes(),
            private_key=Path(options["path_key"]).read_bytes(),
            certificate_chain=Path(options["path_cert"]).read_bytes(),
        )
        channel = grpc.secure_channel(target, credentials, options=options.get("grpc_options"))
    try:
        grpc.channel_ready_future(channel).result(timeout=options["gnmi_timeout"])
        subscriber = _IdlePoll(channel, subscription)
        try:
            yield subscriber
        finally:
            subscriber.close()
    finally:
        channel.close()


def isolated_subscribe(options, subscription, pipe):
    """Serve public subscribe2 (STREAM/ONCE) or zero-Poll generated-stub POLL."""
    try:
        with _subscriber(options, subscription) as subscriber:
            pipe.send(None)
            while True:
                command, timeout = pipe.recv()
                if command == "close":
                    return
                try:
                    if command == "update":
                        result = subscriber.get_update(timeout=timeout)
                    elif command == "peek":
                        result = subscriber.peek()
                    elif command == "status":
                        error = subscriber.error
                        if error is not None and not isinstance(error, grpc.RpcError):
                            raise RuntimeError("Subscription failed outside gRPC")
                        result = error.code().name if error is not None else None
                    else:
                        raise ValueError("Unknown subscription command")
                except TimeoutError:
                    pipe.send(("timeout", None))
                else:
                    pipe.send(("result", result))
    finally:
        pipe.close()  # Unexpected errors escape; the context checks exitcode.
