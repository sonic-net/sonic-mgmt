"""
Native gNMI client for docker-sonic-mgmt, built on pygnmi.

This client runs in-process in the sonic-mgmt orchestrator and talks gRPC to
the DUT's gNMI server via pygnmi.

capabilities()/get()/set() return pygnmi's native dict shapes. subscribe() adds
the only things pygnmi does not: connection/cert binding and bounded collection
(STREAM count/timeout, POLL count, ONCE sync_response). Every other subscribe
option is forwarded to pygnmi verbatim, so the client never caps pygnmi's
request surface.
"""
import logging
import os
import sys
import time
from collections.abc import Iterable, Iterator
from enum import StrEnum

import grpc
from pygnmi.client import gNMIclient, gNMIException

logger = logging.getLogger(__name__)


class SubscribeMode(StrEnum):
    STREAM = "stream"
    POLL = "poll"
    ONCE = "once"


class StreamMode(StrEnum):
    SAMPLE = "sample"
    ON_CHANGE = "on_change"
    TARGET_DEFINED = "target_defined"


class GetDataType(StrEnum):
    ALL = "all"
    CONFIG = "config"
    STATE = "state"
    OPERATIONAL = "operational"


class Encoding(StrEnum):
    JSON = "json"
    BYTES = "bytes"
    PROTO = "proto"
    ASCII = "ascii"
    JSON_IETF = "json_ietf"


class PygnmiClientError(Exception):
    """Base exception for PygnmiClient operations."""


class PygnmiClientConnectionError(PygnmiClientError):
    """Connection-related errors (target unreachable, mTLS handshake failures)."""


class PygnmiClientTimeoutError(PygnmiClientError):
    """Operation timeout errors (per-call deadline or collection window exceeded)."""


class PygnmiClientCallError(PygnmiClientError):
    """Validation or RPC execution errors (bad args, server-side failures)."""


def _normalize_paths(paths: str | dict | Iterable) -> list:
    """
    Coerce a path argument into a list of path entries.

    Args:
        paths: A single path string, a single per-path dict, or an iterable of
            either.

    Returns:
        A list of path entries. A lone string or dict is wrapped in a
        single-element list; any other iterable is materialized as a list.
    """
    if isinstance(paths, (str, dict)):
        return [paths]
    return list(paths)


def _seconds_to_nanos(seconds: int | float) -> int:
    """
    Convert a sample/heartbeat interval expressed in seconds to nanoseconds.

    Args:
        seconds: Interval in seconds (int or float).

    Returns:
        The interval in integer nanoseconds (gNMI's native unit).
    """
    return int(float(seconds) * 1_000_000_000)


class PygnmiClient:
    """
    Native pygnmi gNMI client running in docker-sonic-mgmt.

    This class talks gRPC directly to the DUT's gNMI server via pygnmi, running
    in-process in the sonic-mgmt orchestrator and unlocking POLL/ONCE
    subscriptions. Each call opens a gNMIclient channel and closes it before
    returning: gRPC's C-core threads are not fork-safe and sonic-mgmt helpers
    fork the test process between calls (e.g. loganalyzer's parallel_run), so
    no channel may outlive a call.

    Usage:
        client = PygnmiClient(host, port, ca_cert=ca, client_cert=crt,
                              client_key=key)
        client.capabilities()
        client.get(paths)
    """

    def __init__(self, host: str, port: int, plaintext: bool = False,
                 ca_cert: str = None, client_cert: str = None,
                 client_key: str = None, timeout: int = 30,
                 connect: bool = True):
        """
        Initialize PygnmiClient.

        Args:
            host: Target host (IPv4/IPv6 literal or name); IPv6 is bracketed by
                pygnmi as needed.
            port: Target gNMI port.
            plaintext: If True, connect insecurely instead of using mTLS certs.
            ca_cert: Path to the CA certificate (required unless plaintext).
            client_cert: Path to the client certificate (required unless plaintext).
            client_key: Path to the client private key (required unless plaintext).
            timeout: Per-call gRPC deadline in seconds, also used as the default
                per-update wait for POLL/ONCE collection.
            connect: If True (default), open and close a probe channel now so
                bad target/cert data fails fast. Set False to construct without
                connecting (e.g. for request-building/validation only).

        Raises:
            PygnmiClientCallError: If mTLS mode is requested but cert paths are
                missing or do not exist on disk.
            PygnmiClientConnectionError: If connect is True and the initial
                connection or mTLS handshake fails.
        """
        self._host = host
        self._port = port
        self._plaintext = plaintext
        self._ca_cert = ca_cert
        self._client_cert = client_cert
        self._client_key = client_key
        self.timeout = timeout
        self._client = None
        if not self._plaintext:
            self._validate_cert_paths()
        logger.info("Initialized PygnmiClient: host=%s, port=%s, plaintext=%s",
                    self._host, self._port, self._plaintext)
        if connect:
            self._ensure_client()
            self.close()

    def _validate_cert_paths(self) -> None:
        """
        Validate that mTLS certificate paths are provided and exist on disk.

        Raises:
            PygnmiClientCallError: If any cert path is missing or not a file.
        """
        certs = (("ca_cert", self._ca_cert), ("client_cert", self._client_cert),
                 ("client_key", self._client_key))
        missing = [name for name, path in certs if not path]
        if missing:
            raise PygnmiClientCallError(
                f"mTLS mode requires cert paths; missing: {', '.join(missing)}")
        for name, path in certs:
            if not os.path.isfile(path):
                raise PygnmiClientCallError(f"{name} file not found: {path}")

    def _build_client(self) -> gNMIclient:
        """
        Build a pygnmi client bound to this instance's target and credentials.

        Returns:
            An unconnected ``gNMIclient`` configured for either an insecure
            (plaintext) channel or mutual TLS using the configured cert paths.
        """
        kwargs = {"target": (self._host, self._port), "gnmi_timeout": self.timeout}
        if self._plaintext:
            kwargs["insecure"] = True
        else:
            kwargs["path_root"] = self._ca_cert
            kwargs["path_cert"] = self._client_cert
            kwargs["path_key"] = self._client_key
        return gNMIclient(**kwargs)

    def _ensure_client(self) -> gNMIclient:
        """
        Lazily open and cache the gNMIclient channel, reusing it across calls.

        Returns:
            The connected ``gNMIclient`` for this instance.
        """
        if self._client is None:
            client = self._build_client()
            client.connect()
            self._client = client
        return self._client

    def close(self) -> None:
        """Close the reused gNMIclient channel if one is open."""
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    def __enter__(self) -> "PygnmiClient":
        """Open the channel and return the client for context-manager use."""
        self._ensure_client()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Close the channel on context-manager exit."""
        self.close()

    def _map_error(self, exc: Exception, op: str) -> PygnmiClientError:
        """
        Translate a low-level exception into a typed PygnmiClient error.

        Args:
            exc: The exception raised by pygnmi/grpc (or an already-typed
                PygnmiClientError, which is passed through unchanged).
            op: Name of the gNMI operation in progress (e.g. "get",
                "subscribe"), used to build the error message.

        Returns:
            A PygnmiClientError subclass: PygnmiClientTimeoutError for deadline
            exceedances, PygnmiClientConnectionError for unreachable/
            unauthenticated targets, and PygnmiClientCallError otherwise.
        """
        if isinstance(exc, PygnmiClientError):
            return exc
        if isinstance(exc, TimeoutError):
            return PygnmiClientTimeoutError(f"gnmi {op} timed out after {self.timeout}s: {exc}")
        if isinstance(exc, grpc.FutureTimeoutError):
            return PygnmiClientConnectionError(f"gnmi {op} connection timed out: {exc}")
        if isinstance(exc, grpc.RpcError):
            code = exc.code()
            if code == grpc.StatusCode.DEADLINE_EXCEEDED:
                return PygnmiClientTimeoutError(f"gnmi {op} timed out: {exc}")
            if code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.UNAUTHENTICATED):
                return PygnmiClientConnectionError(f"gnmi {op} connection failed: {exc}")
            return PygnmiClientCallError(f"gnmi {op} failed ({code}): {exc}")
        if isinstance(exc, gNMIException):
            return PygnmiClientCallError(f"gnmi {op} failed: {exc}")
        return PygnmiClientCallError(f"gnmi {op} failed: {exc}")

    # --- unary passthroughs (native pygnmi shapes) ---------------------------

    def capabilities(self) -> dict:
        """
        Query gNMI capabilities from the target device.

        Returns:
            pygnmi's native capabilities dict (gnmi_version, supported_models,
            supported_encodings).

        Raises:
            PygnmiClientConnectionError: If the target is unreachable or mTLS fails.
            PygnmiClientTimeoutError: If the RPC exceeds the configured deadline.
            PygnmiClientCallError: If the server returns an error.
        """
        try:
            return self._ensure_client().capabilities()
        except (grpc.RpcError, grpc.FutureTimeoutError, gNMIException,
                TimeoutError, PygnmiClientError) as exc:
            raise self._map_error(exc, "capabilities") from exc
        finally:
            self.close()

    def get(self, paths: str | dict | Iterable,
            datatype: GetDataType = GetDataType.ALL,
            encoding: Encoding = Encoding.JSON_IETF,
            target: str | None = None, prefix: str = "") -> dict:
        """
        Issue a gNMI Get RPC against the target device.

        Args:
            paths: A single gNMI path string or an iterable of path strings.
            datatype: gNMI data type filter (GetDataType member). Defaults to
                GetDataType.ALL.
            encoding: Encoding to request (Encoding member). Defaults to
                Encoding.JSON_IETF.
            target: Optional gNMI target used to route non-OpenConfig paths
                (e.g. "COUNTERS_DB", "OTHERS").
            prefix: Optional gNMI prefix applied to all paths.

        Returns:
            pygnmi's native get dict of the form
            {"notification": [{"timestamp", "prefix", "update": [{"path", "val"}]}]}.

        Raises:
            PygnmiClientCallError: If no path is provided or the server returns
                an error.
            PygnmiClientConnectionError: If the target is unreachable or mTLS fails.
            PygnmiClientTimeoutError: If the RPC exceeds the configured deadline.
        """
        paths = _normalize_paths(paths)
        if not paths:
            raise PygnmiClientCallError("get requires at least one path")
        try:
            gc = self._ensure_client()
            return gc.get(path=paths, prefix=prefix, datatype=str(datatype),
                          encoding=str(encoding), target=target)
        except (grpc.RpcError, grpc.FutureTimeoutError, gNMIException,
                TimeoutError, PygnmiClientError) as exc:
            raise self._map_error(exc, "get") from exc
        finally:
            self.close()

    def set(self, update: list | None = None, replace: list | None = None,
            delete: list | None = None,
            encoding: Encoding = Encoding.JSON_IETF,
            target: str | None = None, prefix: str = "") -> dict:
        """
        Issue a gNMI Set RPC against the target device.

        Args:
            update: Optional list of (path, value) tuples to update.
            replace: Optional list of (path, value) tuples to replace.
            delete: Optional list of path strings to delete.
            encoding: Encoding to request (Encoding member). Defaults to
                Encoding.JSON_IETF.
            target: Optional gNMI target used to route the request.
            prefix: Optional gNMI prefix applied to all paths.

        Returns:
            pygnmi's native set response dict (timestamp plus per-operation
            results).

        Raises:
            PygnmiClientCallError: If none of update/replace/delete is provided
                or the server returns an error.
            PygnmiClientConnectionError: If the target is unreachable or mTLS fails.
            PygnmiClientTimeoutError: If the RPC exceeds the configured deadline.
        """
        if not any([update, replace, delete]):
            raise PygnmiClientCallError("set requires at least one of update, replace, delete")
        try:
            gc = self._ensure_client()
            return gc.set(update=update, replace=replace, delete=delete,
                          prefix=prefix, encoding=str(encoding), target=target)
        except (grpc.RpcError, grpc.FutureTimeoutError, gNMIException,
                TimeoutError, PygnmiClientError) as exc:
            raise self._map_error(exc, "set") from exc
        finally:
            self.close()

    # --- subscribe (connection binding + bounded collection) -----------------

    def _build_subscribe_request(self, paths, mode, stream_mode, sample_interval,
                                 heartbeat_interval, encoding, extra=None) -> dict:
        """
        Build pygnmi's subscribe dict.

        Each entry in `paths` is either a path string (uniform stream settings)
        or a dict with per-path overrides (path, mode, sample_interval,
        heartbeat_interval, suppress_redundant). `extra` (prefix, updates_only,
        allow_aggregation, use_aliases, qos, ...) is merged in verbatim.

        Args:
            paths: Normalized list of path strings and/or per-path dicts.
            mode: The resolved SubscribeMode for the whole subscription.
            stream_mode: Default STREAM sub-mode applied to plain-string paths.
            sample_interval: Default sample interval in seconds for plain-string
                STREAM paths; ignored otherwise.
            heartbeat_interval: Default heartbeat interval in seconds for
                plain-string STREAM paths; ignored otherwise.
            encoding: Encoding string recorded on the request.
            extra: Additional SubscriptionList fields merged verbatim.

        Returns:
            A pygnmi subscribe request dict with "subscription", "mode" and
            "encoding" keys, plus any merged `extra` fields. STREAM intervals
            are converted to nanoseconds; non-STREAM modes drop per-path stream
            settings.

        Raises:
            PygnmiClientCallError: If a dict entry lacks a "path" key.
        """
        subs = []
        for item in paths:
            if isinstance(item, dict):
                entry = dict(item)
                if "path" not in entry:
                    raise PygnmiClientCallError("subscription dict requires a 'path' key")
                if mode == SubscribeMode.STREAM:
                    entry["mode"] = str(entry.get("mode", stream_mode))
                    for key in ("sample_interval", "heartbeat_interval"):
                        if entry.get(key) is not None:
                            entry[key] = _seconds_to_nanos(entry[key])
                else:
                    for key in ("mode", "sample_interval", "heartbeat_interval"):
                        entry.pop(key, None)
            else:
                entry = {"path": item}
                if mode == SubscribeMode.STREAM:
                    entry["mode"] = str(stream_mode)
                    if sample_interval is not None:
                        entry["sample_interval"] = _seconds_to_nanos(sample_interval)
                    if heartbeat_interval is not None:
                        entry["heartbeat_interval"] = _seconds_to_nanos(heartbeat_interval)
            subs.append(entry)

        request = dict(extra or {})
        request["subscription"] = subs
        request["mode"] = str(mode)
        request["encoding"] = str(encoding)
        return request

    def subscribe(self, paths: str | dict | Iterable,
                  mode: SubscribeMode = SubscribeMode.STREAM,
                  stream_mode: StreamMode = StreamMode.SAMPLE,
                  sample_interval: int | float | None = None,
                  heartbeat_interval: int | float | None = None,
                  encoding: Encoding = Encoding.JSON_IETF,
                  target: str | None = None, extension: list | None = None,
                  collect_seconds: int | float = 10, count: int | None = None,
                  poll_count: int = 1, poll_interval: int | float = 1.0,
                  **sub_options) -> Iterator[dict]:
        """
        Run a bounded gNMI Subscribe, yielding each notification as it arrives.

        Arguments are validated eagerly (so bad input fails fast at the call
        site), then a generator is returned. gNMI subscriptions are open-ended,
        so the generator adds the bounding that pygnmi does not: STREAM yields
        until ``count`` notifications are produced or ``collect_seconds``
        elapses, whichever comes first; POLL sends ``poll_count`` triggers; ONCE
        drains until the server's sync_response. Yielding lets the caller process
        notifications one at a time instead of waiting for the full batch; the
        subscription is closed when the generator is exhausted or closed early.
        Wrap the call in ``list(...)`` to collect every notification.

        Args:
            paths: A single gNMI path, an iterable of paths, or per-path dicts.
                A dict entry must carry a "path" key and may override "mode",
                "sample_interval", "heartbeat_interval", "suppress_redundant".
            mode: Subscription mode: ``SubscribeMode.STREAM`` (default),
                ``POLL`` or ``ONCE``.
            stream_mode: STREAM sub-mode applied to plain-string paths:
                ``StreamMode.SAMPLE`` (default), ``ON_CHANGE`` or
                ``TARGET_DEFINED``.
            sample_interval: Sampling interval in seconds for STREAM+SAMPLE.
                None (default) omits the field, which per the gNMI spec is
                equivalent to sample_interval=0: the target samples at the
                lowest interval it supports.
            heartbeat_interval: Optional heartbeat interval in seconds applied to
                plain-string paths.
            encoding: Encoding to request (Encoding member). Defaults to
                Encoding.JSON_IETF.
            target: Optional gNMI target used to route non-OpenConfig paths
                (e.g. "COUNTERS_DB", "OTHERS").
            extension: Optional list of gNMI extensions forwarded to pygnmi.
            collect_seconds: STREAM wall-clock collection window, in seconds.
            count: STREAM cap on the number of notifications to yield; None
                yields for the full window.
            poll_count: POLL number of Poll() triggers to send.
            poll_interval: POLL delay between triggers, in seconds.
            **sub_options: Any additional pygnmi SubscriptionList field
                (e.g. prefix, updates_only, allow_aggregation, use_aliases,
                qos), forwarded verbatim.

        Returns:
            A generator yielding pygnmi notification dicts in receive order.
            STREAM/POLL entries are shaped
            {"update": {"update": [{"path", "val"}], ...}}; ONCE additionally
            yields the trailing {"sync_response": True}.

        Raises:
            PygnmiClientCallError: If no path is provided, required arguments are
                missing/invalid, or the server returns an error.
            PygnmiClientConnectionError: If the target is unreachable or mTLS fails.
            PygnmiClientTimeoutError: If a per-call deadline fires or ONCE never
                sends sync_response.
        """
        paths = _normalize_paths(paths)
        if not paths:
            raise PygnmiClientCallError("subscribe requires at least one path")

        request = self._build_subscribe_request(
            paths, mode, stream_mode, sample_interval, heartbeat_interval,
            encoding, extra=sub_options)

        return self._run_subscription(
            mode, request, target, extension, collect_seconds, count,
            poll_count, poll_interval)

    def _run_subscription(self, mode, request, target, extension,
                          collect_seconds, count, poll_count, poll_interval):
        """
        Drive the pygnmi subscriber, yielding notifications until the bound.

        Split out from ``subscribe`` so argument validation runs eagerly at the
        call site while the streaming itself stays lazy. See ``subscribe`` for
        the semantics of each mode.

        Yields:
            pygnmi notification dicts in receive order.

        Raises:
            PygnmiClientCallError: If the server returns an error.
            PygnmiClientConnectionError: If the target is unreachable or mTLS fails.
            PygnmiClientTimeoutError: If a per-call deadline fires or ONCE never
                sends sync_response.
        """
        subscriber = None
        close_subscriber = None
        try:
            gc = self._ensure_client()
            subscriber = gc.subscribe2(subscribe=request, target=target,
                                       extension=extension)
            close_subscriber = self._prepare_subscription_shutdown(subscriber)
            if mode == SubscribeMode.ONCE:
                yield from self._iter_once(subscriber)
            elif mode == SubscribeMode.POLL:
                yield from self._iter_poll(subscriber, poll_count, poll_interval)
            else:
                yield from self._iter_stream(subscriber, collect_seconds, count)
        except (grpc.RpcError, grpc.FutureTimeoutError, gNMIException,
                TimeoutError, PygnmiClientError) as exc:
            raise self._map_error(exc, "subscribe") from exc
        finally:
            if close_subscriber is not None:
                close_subscriber()
            else:
                self.close()

    def _prepare_subscription_shutdown(self, subscriber):
        """Return a closer that drains pygnmi's receiver thread without noise.

        pygnmi 0.8.15 cannot cancel its internal Subscribe call directly. Its
        subscriber closes only the request iterator, leaving the receive thread
        blocked until the channel closes. Marking that wrapper-owned shutdown
        lets us ignore only its expected terminal RPC error and join the thread
        before returning to the test.
        """
        thread = getattr(subscriber, "_subscribe_thread", None)
        closing = [False]

        if thread is not None and hasattr(thread, "_invoke_excepthook"):
            invoke_excepthook = thread._invoke_excepthook

            def invoke_subscription_excepthook(thread):
                error = sys.exc_info()[1]
                if closing[0] and self._is_expected_subscription_shutdown(error):
                    logger.debug("Ignoring expected gNMI subscription shutdown: %s", error)
                    return
                invoke_excepthook(thread)

            thread._invoke_excepthook = invoke_subscription_excepthook

        def close_subscriber():
            closing[0] = True
            try:
                subscriber.close()
            finally:
                self.close()
                if thread is not None:
                    thread.join(self.timeout)
                    if thread.is_alive():
                        raise PygnmiClientTimeoutError(
                            "gNMI subscription receiver did not stop after channel close")

        return close_subscriber

    @staticmethod
    def _is_expected_subscription_shutdown(error):
        """Return whether an RPC error is caused by wrapper-owned shutdown."""
        if not isinstance(error, grpc.RpcError):
            return False
        code = error.code()
        details = (error.details() or "").lower()
        channel_closed = (code == grpc.StatusCode.CANCELLED
                          and details == "channel closed!")
        queue_disposed = (code == grpc.StatusCode.INVALID_ARGUMENT
                          and details == "queue: disposed")
        return channel_closed or queue_disposed

    def _iter_stream(self, subscriber, collect_seconds, count=None):
        """
        STREAM: yield until `count` notifications or `collect_seconds`, first hit.

        A short collection due to the timeout is a normal stop, not an error.

        Args:
            subscriber: The pygnmi subscriber yielded by ``subscribe2``.
            collect_seconds: Wall-clock collection window, in seconds. The
                remaining window is used as the per-update timeout.
            count: Optional cap on the number of notifications; None yields for
                the full window.

        Yields:
            pygnmi notification dicts gathered before the count or window bound
            was reached.

        Raises:
            PygnmiClientCallError: If collect_seconds <= 0 or count is non-positive.
        """
        if collect_seconds <= 0:
            raise PygnmiClientCallError("collect_seconds must be > 0")
        if count is not None and count <= 0:
            raise PygnmiClientCallError("count must be > 0")
        collected = 0
        deadline = time.monotonic() + collect_seconds
        while True:
            if count is not None and collected >= count:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                notif = subscriber.get_update(timeout=remaining)
            except TimeoutError:
                break  # window elapsed before reaching count: normal stop
            yield notif
            collected += 1

    def _iter_poll(self, subscriber, poll_count, poll_interval):
        """
        POLL: each get_update() sends one Poll() and coalesces to sync.

        Args:
            subscriber: The pygnmi subscriber yielded by ``subscribe2``.
            poll_count: Number of Poll() triggers to send.
            poll_interval: Delay between triggers, in seconds.

        Yields:
            One pygnmi notification dict per Poll() trigger.

        Raises:
            PygnmiClientCallError: If poll_count is non-positive.
        """
        if poll_count <= 0:
            raise PygnmiClientCallError("poll_count must be > 0")
        for i in range(poll_count):
            yield subscriber.get_update(timeout=self.timeout)
            if poll_interval and i < poll_count - 1:
                time.sleep(poll_interval)

    def _iter_once(self, subscriber):
        """
        ONCE: yield via bounded get_update() until the server's sync_response.

        Uses a per-update timeout (like STREAM/POLL) so a server that stalls
        before sending sync_response cannot hang the call.

        Args:
            subscriber: The pygnmi subscriber yielded by ``subscribe2``.

        Yields:
            pygnmi notification dicts, including the trailing sync_response
            notification.

        Raises:
            PygnmiClientTimeoutError: If the server never sends sync_response
                within the configured timeout.
        """
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PygnmiClientTimeoutError("ONCE subscription never sent sync_response")
            try:
                notif = subscriber.get_update(timeout=remaining)
            except TimeoutError as exc:
                raise PygnmiClientTimeoutError(
                    "ONCE subscription never sent sync_response") from exc
            yield notif
            if isinstance(notif, dict) and notif.get("sync_response"):
                break

    def __str__(self) -> str:
        """Return a summary without exposing connection configuration."""
        return "PygnmiClient()"

    def __repr__(self) -> str:
        """Return the same representation as ``__str__``."""
        return self.__str__()
