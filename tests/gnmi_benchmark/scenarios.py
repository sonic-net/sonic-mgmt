"""Request construction and sequential gNMI operations, independent of load timing."""

import hashlib
import json
import re
import time
from dataclasses import dataclass

import grpc
from google.protobuf import json_format
from pygnmi.spec.v080 import gnmi_pb2


@dataclass(frozen=True)
class Step:
    name: str
    method: str
    requests: tuple
    metadata: tuple = ()


def set_response_has_error(response):
    return response.message.code != 0 or any(item.message.code != 0 for item in response.response)


def build_request(operation, workload):
    if operation == "get":
        return gnmi_pb2.GetRequest()
    request = gnmi_pb2.SetRequest()
    update = request.update.add()
    update.path.origin = "sonic-db"
    path = (("CONFIG_DB", workload["instance"], "VNET_ROUTE_TUNNEL") if "payload" in workload else
            ("CONFIG_DB", workload["instance"], "PORT", workload["port"], "description"))
    for name in path:
        update.path.elem.add(name=name)
    update.val.json_ietf_val = (
        json.dumps(workload["payload"], sort_keys=True, separators=(",", ":")).encode()
        if "payload" in workload else b'"gnmi-benchmark"')
    return request


def builtin_steps(operation, workload, bypass_requested=False):
    metadata = (("x-sonic-ss-bypass-validation", "true"),) if bypass_requested else ()
    if operation == "get":
        return (Step("get", "get", (build_request("get", None),)),)
    write = Step("set", "set", (build_request("set", workload),), metadata)
    return (Step("get", "get", (build_request("get", None),)), write) if operation == "get-set" else (write,)


def load_scenario(filename):
    """Load explicit protobuf-JSON request variants; never execute configuration code."""
    with open(filename, encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or set(data) != {"name", "steps"}:
        raise ValueError("scenario requires only name and steps")
    if not isinstance(data["name"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", data["name"]):
        raise ValueError("scenario name must be a nonempty identifier")
    if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= 20:
        raise ValueError("scenario requires 1..20 sequential steps")
    steps, names = [], set()
    for spec in data["steps"]:
        if not isinstance(spec, dict) or set(spec) - {"name", "method", "requests", "metadata"}:
            raise ValueError("unknown scenario step fields")
        name, method, variants = spec.get("name"), spec.get("method"), spec.get("requests")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name) or name in names:
            raise ValueError("step names must be unique nonempty identifiers")
        if method not in ("get", "set"):
            raise ValueError("scenario step method must be get or set")
        if not isinstance(variants, list) or not variants or any(not isinstance(v, dict) for v in variants):
            raise ValueError("step requests must be a nonempty list of protobuf-JSON objects")
        metadata = spec.get("metadata", {})
        if not isinstance(metadata, dict) or any(
                not isinstance(k, str) or not re.fullmatch(r"[a-z0-9_.-]+", k) or k.endswith("-bin")
                or not isinstance(v, str) or any(ord(c) < 32 or ord(c) > 126 for c in v)
                for k, v in metadata.items()):
            raise ValueError("step metadata must contain lowercase text keys and printable ASCII values")
        message = gnmi_pb2.GetRequest if method == "get" else gnmi_pb2.SetRequest
        requests = tuple(json_format.ParseDict(v, message()) for v in variants)
        if method == "set" and any(not (r.update or r.replace or r.delete) for r in requests):
            raise ValueError("scenario Set requests must contain an operation")
        steps.append(Step(name, method, requests, tuple(metadata.items())))
        names.add(name)
    # Do not put request contents or metadata values in reports. The digest covers
    # request definitions, not metadata values (which may contain credentials).
    identity = [{"name": s.name, "method": s.method,
                 "requests": [r.SerializeToString(deterministic=True).hex() for r in s.requests]} for s in steps]
    descriptor = {
        "name": data["name"],
        "request_sha256": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
        "steps": [{"name": s.name, "method": s.method, "request_variants": len(s.requests),
                   "metadata_keys": [k for k, _ in s.metadata]} for s in steps],
        "selection": "scheduled_iteration_index_modulo_variant_count",
    }
    return tuple(steps), descriptor


class RpcExecutor:
    """Execute a scenario iteration; stop later steps after the first error."""

    def __init__(self, stub, steps, timeout_seconds, response_check=set_response_has_error):
        self.stub = stub
        self.steps = steps
        self.timeout_seconds = timeout_seconds
        self.response_check = response_check

    def execute(self, stats, index):
        for step in self.steps:
            item = stats[step.name]
            request = step.requests[index % len(step.requests)]
            started = time.perf_counter_ns()
            try:
                call = self.stub.Get if step.method == "get" else self.stub.Set
                kwargs = {"timeout": self.timeout_seconds}
                if step.metadata or step.method == "set":
                    kwargs["metadata"] = step.metadata
                response = call(request, **kwargs)
                finished = time.perf_counter_ns()
            except grpc.RpcError as error:
                finished = time.perf_counter_ns()
                status = error.code().name if error.code() is not None else "UNKNOWN"
                item.statuses[status] += 1
                return False, status, finished
            item.statuses["OK"] += 1
            if step.method == "set" and self.response_check(response):
                item.response_errors += 1
                return False, "OK", finished
            item.latencies.append((finished - started) / 1_000_000)
        return True, "OK", finished
