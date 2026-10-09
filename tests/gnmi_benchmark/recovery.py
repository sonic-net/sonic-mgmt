"""Out-of-band Redis subscriber recovery for an exclusively reserved benchmark DUT."""

import json
from pathlib import Path
import re
import time


OMEM_LIMIT_BYTES = 10 * 1024 * 1024


def redis_output_buffers(host):
    """Match sanity_check's per-instance sum; retain only diagnostic client fields."""
    instances = []
    for asic in host.asics:
        response = asic.run_redis_cli_cmd("client list")
        if response.get("rc", 0) != 0:
            raise RuntimeError("Cannot inspect Redis client output buffers")
        lines = response.get("stdout_lines", [])
        if not lines:
            raise RuntimeError("Redis CLIENT LIST returned no clients")
        clients = []
        for line in lines:
            fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
            omem = int(fields["omem"])
            if omem:
                clients.append({**{key: fields.get(key, "") for key in
                                   ("id", "db", "flags", "cmd", "psub", "sub", "age", "oll")},
                                "omem": omem})
        instances.append({"namespace": asic.namespace or "", "total_omem": sum(c["omem"] for c in clients),
                          "clients": clients})
    if not instances:
        raise RuntimeError("No Redis instances found")
    return instances


def buffers_drained(instances):
    return all(instance["total_omem"] <= OMEM_LIMIT_BYTES for instance in instances)


class ConsumerRecovery:
    """Never infer consumer ownership from a Redis client ID or subscription type."""

    def __init__(self, host, output_dir, cid, consumer_service=None, timeout_seconds=60):
        if timeout_seconds < 0:
            raise ValueError("Recovery timeout must be non-negative")
        if consumer_service is not None:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", consumer_service):
                raise ValueError("consumer_service must be one systemd unit name")
            if consumer_service.removesuffix(".service") in ("redis", "redis-server", "database", "gnmi"):
                raise ValueError("Restart only the identified consumer, not Redis/database/gNMI")
        self.host = host
        self.path = Path(output_dir) / (cid + "-cleanup.json")
        self.consumer_service = consumer_service
        self.timeout_seconds = timeout_seconds
        self.baseline_config = None
        self.receipt = {"cid": cid, "host": host.hostname, "limit_bytes": OMEM_LIMIT_BYTES,
                        "consumer_service": consumer_service, "restart_attempted": False,
                        "status": "pending", "samples": []}

    def _sample(self, phase):
        instances = redis_output_buffers(self.host)
        self.receipt["samples"].append({"phase": phase, "instances": instances})
        return instances

    def _write(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.receipt, indent=2) + "\n", encoding="utf-8")

    def prepare(self):
        """Run before TLS setup or route creation; never hide pre-existing backlog."""
        try:
            if not buffers_drained(self._sample("before_test")):
                raise RuntimeError("Pre-existing Redis output backlog exceeds 10 MiB; DUT needs recovery")
            self.baseline_config = self.host.get_running_config_facts()
            if self.consumer_service:
                self.host.command("systemctl is-active " + self.consumer_service)
            self.receipt["status"] = "prepared"
        except Exception as error:
            self.receipt.update(status="precheck_failed", error=str(error))
            raise
        finally:
            self._write()

    def finish(self):
        """Called AFTER gnmi_tls rollback; neither polling nor restart enters RPC timers."""
        started = time.monotonic()
        try:
            if self.host.get_running_config_facts() != self.baseline_config:
                raise RuntimeError("Running configuration did not return to the pre-test baseline")
            instances = self._sample("after_rollback")
            if not buffers_drained(instances) and self.consumer_service:
                # Opt-in only after identifying the service and verifying its restart resync contract.
                # Do not kill unnamed Pub/Sub clients: they may belong to unrelated services.
                self.receipt["restart_attempted"] = True
                self._write()
                self.host.command("sudo systemctl restart " + self.consumer_service)
            deadline = time.monotonic() + self.timeout_seconds
            while not buffers_drained(instances):
                instances = self._sample("recovery")
                if buffers_drained(instances):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Redis output buffers remain above 10 MiB after recovery deadline")
                time.sleep(min(2, max(0, deadline - time.monotonic())))
            if self.consumer_service:
                self.host.command("systemctl is-active " + self.consumer_service)
            if self.host.get_running_config_facts() != self.baseline_config:
                raise RuntimeError("Consumer recovery changed the restored configuration")
            self.receipt["status"] = "recovered_with_restart" if self.receipt["restart_attempted"] else "drained"
        except Exception as error:
            self.receipt.update(status="failed", error=str(error))
            raise
        finally:
            self.receipt["elapsed_seconds"] = time.monotonic() - started
            self._write()
