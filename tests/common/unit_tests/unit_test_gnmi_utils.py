import importlib.util
import os
from unittest.mock import Mock


_HELPER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "helpers",
    "gnmi_utils.py",
)
_SPEC = importlib.util.spec_from_file_location("gnmi_utils_under_test", _HELPER_PATH)
_GNMI_UTILS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GNMI_UTILS)

GNMIEnvironment = _GNMI_UTILS.GNMIEnvironment
cleanup_gnmi_insecure_mode = _GNMI_UTILS.cleanup_gnmi_insecure_mode
ensure_gnmi_insecure_mode = _GNMI_UTILS.ensure_gnmi_insecure_mode


def _result(stdout=""):
    return {"stdout": stdout}


_TEST_GNMI_CONFIG = {
    "port": "8080",
    "client_auth": "false",
    "user_auth": "none",
}


def _duthost_with_gnmi_config(config):
    duthost = Mock()

    def shell(command, module_ignore_errors):
        for field, value in config.items():
            if command == f'sonic-db-cli CONFIG_DB hexists "GNMI|gnmi" "{field}"':
                return _result("1")
            if command == f'sonic-db-cli CONFIG_DB hget "GNMI|gnmi" "{field}"':
                return _result(value)
        if command.startswith('sonic-db-cli CONFIG_DB hexists "GNMI|gnmi"'):
            return _result("0")
        return _result()

    duthost.shell.side_effect = shell
    return duthost


def test_insecure_mode_configures_explicit_test_auth_and_restores_absent_fields():
    duthost = _duthost_with_gnmi_config({})

    original = ensure_gnmi_insecure_mode(
        duthost,
        mode=GNMIEnvironment.GNMI_MODE,
        gnmi_config=_TEST_GNMI_CONFIG
    )
    cleanup_gnmi_insecure_mode(
        duthost,
        mode=GNMIEnvironment.GNMI_MODE,
        original_gnmi_config=original
    )

    assert original == {"port": None, "client_auth": None, "user_auth": None}
    commands = [call.args[0] for call in duthost.shell.call_args_list]
    assert (
        'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" '
        '"port" 8080 "client_auth" false "user_auth" none'
    ) in commands
    assert 'sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" "port"' in commands
    assert 'sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" "client_auth"' in commands
    assert 'sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" "user_auth"' in commands


def test_insecure_mode_restores_existing_auth_fields():
    duthost = _duthost_with_gnmi_config({
        "port": "50051",
        "client_auth": "true",
        "user_auth": "cert",
    })

    original = ensure_gnmi_insecure_mode(
        duthost,
        mode=GNMIEnvironment.GNMI_MODE,
        gnmi_config=_TEST_GNMI_CONFIG
    )
    cleanup_gnmi_insecure_mode(
        duthost,
        mode=GNMIEnvironment.GNMI_MODE,
        original_gnmi_config=original
    )

    assert original == {"port": "50051", "client_auth": "true", "user_auth": "cert"}
    commands = [call.args[0] for call in duthost.shell.call_args_list]
    assert 'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "port" 50051' in commands
    assert 'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "client_auth" true' in commands
    assert 'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" "user_auth" cert' in commands
