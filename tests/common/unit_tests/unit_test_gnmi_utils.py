import ast
from pathlib import Path
from unittest.mock import MagicMock


MODULE_PATH = Path(__file__).resolve().parents[1] / "helpers" / "gnmi_utils.py"


def _load_dump_gnmi_log():
    tree = ast.parse(MODULE_PATH.read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "dump_gnmi_log":
            logger = MagicMock()
            namespace = {"logger": logger}
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         str(MODULE_PATH), "exec"), namespace)
            return namespace["dump_gnmi_log"], logger
    raise LookupError("dump_gnmi_log")


def test_dump_gnmi_log_reads_bounded_host_log():
    duthost = MagicMock()
    duthost.shell.return_value = {"stdout": "current gnmi log\n"}
    dump_gnmi_log, logger = _load_dump_gnmi_log()

    assert dump_gnmi_log(duthost) == "current gnmi log\n"
    duthost.shell.assert_called_once_with(
        "sudo tail -n 500 /var/log/gnmi.log",
        module_ignore_errors=True,
    )
    logger.info.assert_called_once_with("GNMI log: current gnmi log\n")
