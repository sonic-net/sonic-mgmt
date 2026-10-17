"""Local and remote host command execution without credential-bearing test parameters."""
import json
import re
import shlex
import subprocess


_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*")
_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
# ssh splits these options on whitespace and expands % and ~, so paths stay plain.
_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]+")
_DUT_OS_VALUES = ("sonic", "none")
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|token|secret|private[_-]?key|key[_-]?(?:file|path))",
    re.IGNORECASE,
)
_SHELL_CONTROLS = frozenset(";&|`$<>\n\r\x00\\'\"(){}[]*?!")
_CONTAINER_PARAMS = (
    "host_control_container",
    "vsonic_saiserver_container",
    "asic_container",
)
_DEFAULT_TIMEOUT_S = 30
_MAX_TIMEOUT_S = 3600
_REMOTE_EXEC_CODE = (
    "import json,os,sys;"
    "argv=json.load(sys.stdin);"
    "os.execvp(argv[0],argv)"
)
_REMOTE_EXEC_COMMAND = "python3 -c {}".format(shlex.quote(_REMOTE_EXEC_CODE))


def _reject_sensitive_params(params):
    for key in params:
        if not isinstance(key, str):
            raise ValueError("PTF test parameter names must be strings")
        if _SENSITIVE_KEY_RE.search(key):
            raise ValueError("credential-bearing PTF test parameters are rejected")


def _validated_text(value, description, pattern=None):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("{} must be a non-empty string".format(description))
    if any(character in _SHELL_CONTROLS or ord(character) < 32
           for character in value):
        raise ValueError("{} contains shell control characters".format(description))
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ValueError("invalid {}".format(description))
    return value


def _validated_timeout(value, description):
    if isinstance(value, bool):
        raise ValueError("{} must be a positive number".format(description))
    try:
        timeout = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("{} must be a positive number".format(description)) from error
    if timeout <= 0 or timeout > _MAX_TIMEOUT_S:
        raise ValueError("{} must be between 0 and {} seconds".format(
            description, _MAX_TIMEOUT_S))
    return timeout


def _validated_argv(argv):
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("command argv must be a non-empty list or tuple")
    result = []
    for argument in argv:
        if not isinstance(argument, str) or "\x00" in argument or any(
                ord(character) < 32 and character not in "\t\n\r"
                for character in argument):
            raise ValueError("command arguments must be strings without control bytes")
        result.append(argument)
    if not result[0]:
        raise ValueError("command executable must be non-empty")
    return result


def run_local(argv, timeout_s=_DEFAULT_TIMEOUT_S, check=True):
    """Run one local command with a literal argument vector."""
    return subprocess.run(
        _validated_argv(argv),
        shell=False,
        check=check,
        capture_output=True,
        text=True,
        timeout=_validated_timeout(timeout_s, "local timeout"),
    )


class RuntimeControl:
    """Execute host operations over noninteractive key-based SSH."""

    def __init__(self, test_params):
        if not isinstance(test_params, dict):
            raise ValueError("PTF test parameters must be a dictionary")
        _reject_sensitive_params(test_params)

        host = test_params.get("host_control_host",
                               test_params.get("thrift_server"))
        self.host = _validated_text(host, "host", _HOST_RE)

        user = test_params.get("host_control_user")
        self.user = None if user is None else _validated_text(
            user, "user", _USER_RE)
        identity = test_params.get("host_control_identity_file")
        known_hosts = test_params.get("host_control_known_hosts")
        if (identity is None) != (known_hosts is None):
            raise ValueError("host control identity and known hosts files are set together")
        self.identity_file = None if identity is None else _validated_text(
            identity, "identity file", _PATH_RE)
        self.known_hosts = None if known_hosts is None else _validated_text(
            known_hosts, "known hosts file", _PATH_RE)
        self.dut_os = test_params.get("dut_os", "sonic")
        if self.dut_os not in _DUT_OS_VALUES:
            raise ValueError("unknown dut_os")
        self.timeout_s = _validated_timeout(
            test_params.get("host_control_timeout_s", _DEFAULT_TIMEOUT_S),
            "remote timeout")

        self._containers = {}
        for parameter in _CONTAINER_PARAMS:
            value = test_params.get(parameter)
            if value is not None:
                self._containers[parameter] = _validated_text(
                    value, "container", _CONTAINER_RE)

    def container(self, parameter="host_control_container"):
        try:
            return self._containers[parameter]
        except KeyError as error:
            raise RuntimeError(
                "PTF test parameter '{}' is required".format(parameter)) from error

    def run_local(self, argv, timeout_s=None, check=True):
        return run_local(argv, self.timeout_s if timeout_s is None else timeout_s,
                         check=check)

    def run_remote(self, argv, timeout_s=None, check=True):
        command = _validated_argv(argv)
        timeout = self.timeout_s if timeout_s is None else _validated_timeout(
            timeout_s, "remote timeout")
        destination = self.host if self.user is None else "{}@{}".format(
            self.user, self.host)
        ssh_argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "NumberOfPasswordPrompts=0",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout={}".format(max(1, int(timeout))),
        ]
        if self.identity_file is not None:
            ssh_argv.extend([
                "-i", self.identity_file,
                "-o", "IdentitiesOnly=yes",
                "-o", "UserKnownHostsFile={}".format(self.known_hosts),
            ])
        ssh_argv.extend(["--", destination, _REMOTE_EXEC_COMMAND])
        return subprocess.run(
            ssh_argv,
            shell=False,
            check=check,
            capture_output=True,
            text=True,
            input=json.dumps(command, separators=(",", ":")),
            timeout=timeout,
        )

    def run_container(self, argv, container_parameter="host_control_container",
                      timeout_s=None, check=True):
        command = ["docker", "exec", self.container(container_parameter)]
        command.extend(_validated_argv(argv))
        return self.run_remote(command, timeout_s=timeout_s, check=check)
