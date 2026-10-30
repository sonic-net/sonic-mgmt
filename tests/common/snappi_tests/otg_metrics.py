"""Poll OTG flow/port metrics over HTTP (dpdk-tgen REST).

Avoids snappi JSON typing issues on fields such as ``loss`` when values are
integers. Same protocol as dpdk-tgen ``tests/otg_metrics.py``.
"""

import json
import urllib.request

_FLOAT_KEYS = (
    "loss",
    "frames_tx_rate",
    "frames_rx_rate",
    "bytes_tx_rate",
    "bytes_rx_rate",
)


class FlowMetric(object):
    __slots__ = ("_d",)

    def __init__(self, doc):
        self._d = doc

    def __getattr__(self, name):
        if name in self._d:
            return self._d[name]
        raise AttributeError(name)


class PortMetric(object):
    __slots__ = ("_d",)

    def __init__(self, doc):
        self._d = doc

    def __getattr__(self, name):
        if name in self._d:
            return self._d[name]
        raise AttributeError(name)


def _coerce_flow_metric(doc):
    out = dict(doc)
    for key in _FLOAT_KEYS:
        if key in out and out[key] is not None:
            out[key] = float(out[key])
    return FlowMetric(out)


def poll_flow_metric(api_base, flow_name, timeout=30.0):
    url = api_base.rstrip("/") + "/monitor/metrics"
    body = json.dumps(
        {"choice": "flow", "flow": {"flow_names": [flow_name]}}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    metrics = payload.get("flow_metrics") or []
    if not metrics:
        raise RuntimeError("no flow_metrics in response: %s" % payload)
    return _coerce_flow_metric(metrics[0])


def poll_port_metrics(api_base, port_names=None, timeout=30.0):
    url = api_base.rstrip("/") + "/monitor/metrics"
    body = {"choice": "port", "port": {"port_names": list(port_names or [])}}
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    return [PortMetric(doc) for doc in (payload.get("port_metrics") or [])]
