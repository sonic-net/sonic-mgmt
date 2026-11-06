"""Preserve the exact RIF COUNTERS DB fields overwritten by the SNMP test."""

from contextlib import contextmanager


class CounterCommandError(RuntimeError):
    """A counter read or write failed or returned an unexpected reply."""


class SnmpCounterFieldRestorer:
    """Snapshot fields once while their counter poller is paused."""

    def __init__(self, duthost):
        self._duthost = duthost
        self._snapshots = {}

    def _command(self, operation, interface_oid, counter_name, *values):
        args = ["sudo", "redis-cli", "-e", "--raw", "-n", "2", operation,
                f"COUNTERS:{interface_oid}", counter_name]
        args.extend(str(value) for value in values)
        result = self._duthost.command(
            argv=args, strip_empty_ends=False, module_ignore_errors=True)
        if (result.get("rc") != 0 or result.get("failed")
                or result.get("unreachable")):
            raise CounterCommandError(
                f"{operation} {interface_oid}.{counter_name} failed: "
                f"{result.get('stderr', '')} {result.get('stdout', '')}")
        reply = result.get("stdout")
        if not isinstance(reply, str):
            raise CounterCommandError(
                f"Missing Redis reply for {operation} "
                f"{interface_oid}.{counter_name}")
        if operation == "HGET":
            return reply[:-1] if reply.endswith("\n") else reply
        reply = reply.strip()
        if reply not in {"0", "1"}:
            raise CounterCommandError(
                f"Unexpected Redis reply for {operation} "
                f"{interface_oid}.{counter_name}: {reply!r}")
        return reply

    def _read_counter_field(self, interface_oid, counter_name):
        exists = self._command("HEXISTS", interface_oid, counter_name) == "1"
        if not exists:
            return False, None
        return True, self._command("HGET", interface_oid, counter_name)

    def set_counter_value(self, interface_oid, counter_name, counter_value):
        key = interface_oid, counter_name
        if key not in self._snapshots:
            self._snapshots[key] = self._read_counter_field(
                interface_oid, counter_name)
        self._command("HSET", interface_oid, counter_name, counter_value)

    def restore(self):
        """Attempt all recorded restorations and report any failure."""
        restore_errors = []
        for (interface_oid, counter_name), (exists, value) in list(
                self._snapshots.items()):
            try:
                if exists:
                    self._command("HSET", interface_oid, counter_name, value)
                else:
                    self._command("HDEL", interface_oid, counter_name)
                if self._read_counter_field(
                        interface_oid, counter_name) != (exists, value):
                    raise CounterCommandError(
                        "Restored field does not match its snapshot")
                del self._snapshots[(interface_oid, counter_name)]
            except CounterCommandError as exc:
                restore_errors.append(
                    f"{interface_oid}.{counter_name}: {exc}")
        if restore_errors:
            raise CounterCommandError(
                "Failed to restore injected SNMP RIF counter fields: "
                "{}".format("; ".join(restore_errors)))


@contextmanager
def preserve_injected_snmp_rif_counter_fields(duthost):
    """Restore injected RIF fields before resuming their counterpolls."""
    counter_field_restorer = SnmpCounterFieldRestorer(duthost)
    try:
        yield counter_field_restorer
    finally:
        counter_field_restorer.restore()
