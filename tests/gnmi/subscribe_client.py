"""Spawn entry for revocation tests; deliberately excludes Ansible/pytest imports."""

import time

import grpc
from pygnmi.client import gNMIclient


def subscribe(endpoint, certificates, mode, pipe):
    """Use one public subscribe2 session and report readiness and its outcome."""
    try:
        with gNMIclient(
            target=endpoint,
            path_root=certificates[0],
            path_cert=certificates[1],
            path_key=certificates[2],
            grpc_options=[("grpc.enable_retries", 0)],
            gnmi_timeout=30,
        ) as client:
            subscription = client.subscribe2(
                subscribe={
                    "mode": mode,
                    "encoding": "json_ietf",
                    "subscription": [
                        {
                            "path": "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost",
                            "mode": "sample",
                            "sample_interval": 1000000000,
                        }
                    ],
                }
            )
            try:
                # The public POLL get_update requests an initial poll.
                initial = subscription.get_update(timeout=30)
                assert initial.get("sync_response"), "No initial sync"
                assert initial.get("update", {}).get("update"), "No initial data"
                assert subscription.error is None, "Subscribe failed before revocation"
                pipe.send(("ready", None))
                while True:
                    if subscription.error is not None:
                        assert isinstance(subscription.error, grpc.RpcError), "Subscribe failed outside gRPC"
                        pipe.send(("error", subscription.error.code().name))
                        return
                    if not pipe.poll(0.1):
                        continue
                    command, seconds = pipe.recv()
                    if command == "stop":
                        return
                    assert command == "observe", "Unknown subscription command"
                    until = time.monotonic() + seconds
                    while time.monotonic() < until:
                        assert subscription.error is None, "Readonly subscription failed"
                        update = subscription.get_update(timeout=15)
                        assert update.get("update", {}).get("update"), "Readonly subscription returned no data"
                    # Queue drain proves a new enqueue, not DUT generation time.
                    deadline = time.monotonic() + 15
                    while subscription.peek():
                        assert time.monotonic() < deadline, "Unable to drain queued updates"
                        subscription.get_update(timeout=1)
                    update = subscription.get_update(timeout=15)
                    assert update.get("update", {}).get("update"), "No data after observation"
                    assert subscription.error is None, "Readonly subscription failed"
                    break
            finally:
                try:
                    client.close()
                finally:
                    subscription.close()
        pipe.send(("observed", None))  # Success is reported only after cleanup.
    finally:
        pipe.close()  # Unexpected errors escape: the parent checks exitcode.
