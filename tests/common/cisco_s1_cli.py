"""Helper wrapper for driving Cisco-only serviceability functionality.

The :class:`S1Cli` class provides a small, reusable abstraction over the
``s1-cli-sonic`` command so that Cisco-specific test helpers can be written
cleanly without repeating command-construction and output-parsing boilerplate.
"""
import json


class S1CliError(RuntimeError):
    """Raised when an s1-cli-sonic operation fails or returns no usable data."""


class CiscoS1Cli(object):
    """Thin wrapper around the ``s1-cli-sonic`` serviceability CLI.

    Construction validates that the target DUT/ASIC can run the CLI and raises
    :class:`S1CliError` otherwise, so a successfully constructed instance can be
    treated as ready to use.

    Args:
        duthost: The DUT host handle.
        asic_index (int, optional): ASIC index for multi-ASIC platforms. Ignored
            on single-ASIC platforms.
    """

    def __init__(self, duthost, asic_index=None):
        if duthost.facts["asic_type"] != "cisco-8000":
            raise S1CliError("s1-cli-sonic is only available on cisco-8000 platforms.")
        self._duthost = duthost
        self._asic_arg = ""
        if asic_index is not None and duthost.is_multi_asic:
            self._asic_arg = " --asic-num {}".format(asic_index)
        self._cache = {}
        probe = duthost.shell("which s1-cli-sonic", module_ignore_errors=True)
        if probe["rc"] != 0:
            raise S1CliError("s1-cli-sonic is not available on {}.".format(duthost.hostname))

    def _run(self, command):
        """Run an s1-cli-sonic command and return its parsed JSON payload.

        Results are cached per instance keyed on the command, so repeated
        lookups (e.g. resolving OIDs for many ports in a loop) do not re-invoke
        the CLI. The queried data is static topology/hardware state.
        """
        if command in self._cache:
            return self._cache[command]
        cmd = 's1-cli-sonic{} -c "{}" -j'.format(self._asic_arg, command)
        result = self._duthost.shell(cmd, module_ignore_errors=True)
        if result["rc"] != 0 or result["stderr"]:
            raise S1CliError("Command failed: {} ({})".format(cmd, result["stderr"]))
        try:
            payload = json.loads(result["stdout"])
        except ValueError as exc:
            raise S1CliError("Could not parse JSON output of: {} ({})".format(cmd, exc))
        self._cache[command] = payload
        return payload

    @staticmethod
    def _to_oid(decimal_oid):
        """Convert a decimal OID (as returned in JSON) to the CLI hex form."""
        return hex(int(decimal_oid))

    def get_port_oid(self, interface):
        """Return the SAI port OID (hex string) for a front-panel interface name."""
        gid = None
        for entry in self._run("show ports counters")["result"]:
            if entry["sysport"]["sysport-cookie"] == interface:
                gid = int(entry["sysport"]["sysport-gid"])
                break
        if gid is None:
            raise S1CliError("Interface {} not found in port counters.".format(interface))

        for entry in self._run("show sai ports status")["result"]:
            if int(entry["gid"]) == gid:
                return self._to_oid(entry["oid"])
        raise S1CliError("No SAI port OID found for interface {}.".format(interface))

    def get_queue_oid(self, port_oid, traffic_class):
        """Return the SAI queue OID (hex string) for a port OID and queue index."""
        for entry in self._run("show sai queue list port-oid {}".format(port_oid))["result"]:
            if entry["index"] == traffic_class:
                return self._to_oid(entry["queueOid"])
        raise S1CliError(
            "No queue OID found for port {} traffic class {}.".format(port_oid, traffic_class))

    def get_queue_watermark_thresholds(self, queue_oid):
        """Return the queue watermark thresholds (bytes), ordered lowest to highest."""
        data = self._run("show sai queue watermark-thresholds queue-oid {}".format(queue_oid))
        levels = sorted(data["result"], key=lambda item: item["congLevel"])
        return [int(item["thresholdBytes"]) for item in levels]
