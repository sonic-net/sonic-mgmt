"""Exercise installed CLI error handling using process-local synthetic endpoints.

Initialization, topology lookup and every EEPROM/control endpoint are replaced
inside this process. No platform object is constructed and no hardware is written.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch


def simulate(request, cli_module=None):
    output, errors = io.StringIO(), io.StringIO()
    counters = {"reads": 0, "writes": 0, "controls": 0}
    with redirect_stdout(output), redirect_stderr(errors):
        if cli_module is None:
            import cpoutil.main as cli_module
        operation, target, failure = request["operation"], request["target"], request["failure"]

        def fail():
            if failure == "unsupported":
                raise NotImplementedError("synthetic failure")
            if failure == "attribute":
                raise AttributeError("synthetic failure")
            if failure == "oserror":
                raise OSError("synthetic failure")
            if failure == "timeout":
                raise TimeoutError("synthetic timeout")
            return False

        def read(offset, size):
            counters["reads"] += 1
            if failure == "none":
                return None
            if failure == "short":
                return bytearray(max(0, size - 1))
            return fail()

        def write(*args):
            counters["writes"] += 1
            return fail()

        def control(*args):
            counters["controls"] += 1
            if failure == "partial" and counters["controls"] == 1:
                return True
            return fail()

        endpoint = SimpleNamespace(read_eeprom=read, write_eeprom=write, set_lpmode=control, reset=control)
        cpo = SimpleNamespace(oe=endpoint, elsfp=endpoint, tx_disable=control)
        topology = SimpleNamespace(ports_for_resource=lambda *args: ["TEST-PORT"])
        replacements = {
            "initialize_command_platform": lambda: None,
            "get_resource_cpo_objects": lambda kind, selector=None: [(kind + "0", cpo)],
            "_interface_eeprom_target": lambda port, kind, page=None: (0, 0),
            "_validate_eeprom_page": lambda *args: None,
            "_eeprom_linear_offset": lambda *args: 0,
            "_get_eeprom_device": lambda *args: endpoint,
            "_get_els_eeprom": lambda *args: SimpleNamespace(reader=read),
            "cpo_mapping": topology,
            "get_vmodule_targets": lambda *args: [
                ("TEST-TARGET-{}".format(index), cpo, ["TEST-PORT-{}".format(index)])
                for index in range(2 if failure == "partial" else 1)],
        }
        if target.startswith("interface-"):
            selector = ["interface", "-p", "TEST-PORT", "--" + target.split("-")[1]]
        elif target == "interface":
            selector = ["interface", "tx-disable", "-p", "TEST-PORT", "true"]
        else:
            selector = [target, "-i", "0"]
        if operation in ("read-eeprom", "write-eeprom"):
            arguments = [operation] + selector + ["-n", "0", "-o", "0"] + (
                ["-s", "2"] if operation == "read-eeprom" else ["-d", "55aa"])
        else:
            arguments = ["config"] + (selector if target == "interface" else [target, operation, "0"] + (
                ["low"] if operation == "lpmode" else []))
        with ExitStack() as stack:
            for name, value in replacements.items():
                stack.enter_context(patch.object(cli_module, name, value))
            stack.enter_context(patch.object(sys, "argv", ["cpoutil"] + arguments))
            try:
                # setup.py installs cpoutil.main:cli, which lets Click choose
                # process exit codes. The module's main() wrapper differs.
                cli_module.cli()
                rc = 0
            except SystemExit as error:
                rc = error.code
            except Exception:
                rc = -1
                errors.write(" traceback ")
    text = (output.getvalue() + errors.getvalue()).lower()
    return {"rc": rc, **counters, "traceback": "traceback" in text,
            "unsupported": "not implemented" in text, "failed": "failed" in text,
            "partial": "already applied" in text}


def main():
    try:
        result = simulate(json.loads(sys.argv[1]))
    except Exception:
        result = {"rc": -1, "traceback": True}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
