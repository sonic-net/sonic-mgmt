"""Check deploy-mg TACACS ordering without requiring a testbed."""

from pathlib import Path
import shlex
import subprocess

import pytest
import yaml

from unit_test_ptf_tacacs_provisioning import ENV


PLAYBOOK = Path(__file__).resolve().parents[4] / "ansible" / "config_sonic_basedon_testbed.yml"
ENV.filters["bool"] = lambda value: (
    value if isinstance(value, bool) else str(value).strip().lower() in ("1", "true", "yes", "on")
)
ENV.filters["quote"] = shlex.quote


def _find_task(tasks, name):
    for task in tasks:
        if task.get("name") == name:
            return task
        for section in ("block", "rescue", "always"):
            match = _find_task(task.get(section, []), name)
            if match:
                return match
    return None


def _render_shell(use_ptf_tacacs_server, topo, tacacs_passkey="test-key"):
    playbook = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))
    task = _find_task(playbook[0]["tasks"], "Configure TACACS")
    return task, ENV.from_string(task["shell"]).render(
        tacacs_passkey=tacacs_passkey,
        use_ptf_tacacs_server=use_ptf_tacacs_server,
        topo=topo,
    )


def _run_tacacs_shell(
        use_ptf_tacacs_server,
        topo,
        fail_command="",
        sonic_release="master",
        sonic_build_version="master.0",
        tacacs_passkey="test-key",
):
    task, command = _render_shell(use_ptf_tacacs_server, topo, tacacs_passkey)
    harness = r'''
AUTHENTICATION=tacacs+
AUTHORIZATION=previous
ACCOUNTING=previous
AUTH_TYPE=chap
PASSKEY=old-key
PASSKEY_ARG_COUNTS=
COMMAND_LOG=

config() {
    command="config $*"
    COMMAND_LOG="${COMMAND_LOG}${command}|"
    if [[ "$1 $2" == "tacacs passkey" ]]; then
        PASSKEY_ARG_COUNTS="${PASSKEY_ARG_COUNTS}$#|"
    fi
    if [[ "$command" == "$FAIL_COMMAND" ]]; then
        return 42
    fi

    case "$command" in
        "config aaa authentication login "*) AUTHENTICATION="${command##* }" ;;
        "config aaa authorization "*) AUTHORIZATION="${command#config aaa authorization }" ;;
        "config aaa accounting "*) ACCOUNTING="${command#config aaa accounting }" ;;
        "config tacacs authtype "*) AUTH_TYPE="${command#config tacacs authtype }" ;;
        "config tacacs passkey "*) PASSKEY="${command#config tacacs passkey }" ;;
        *) return 2 ;;
    esac
}

sonic-cfggen() {
    case "${*: -1}" in
        release) echo "$SONIC_RELEASE" ;;
        build_version) echo "$SONIC_BUILD_VERSION" ;;
        *) return 3 ;;
    esac
}

dump_state() {
    rc=$?
    printf 'RESULT_RC=%s\n' "$rc"
    printf 'STATE=%s|%s|%s|%s|%s\n' \
        "$AUTHENTICATION" "$AUTHORIZATION" "$ACCOUNTING" "$AUTH_TYPE" "$PASSKEY"
    printf 'LOG=%s\n' "$COMMAND_LOG"
    printf 'PASSKEY_ARG_COUNTS=%s\n' "$PASSKEY_ARG_COUNTS"
    printf 'RESOLVED_RELEASE=%s\n' "$resolved_release"
    printf 'PTF_TACACS=%s\n' "$ptf_tacacs"
}
trap dump_state EXIT
'''
    result = subprocess.run(
        ["/bin/bash", "-c", harness + "\n" + command],
        capture_output=True,
        text=True,
        env={
            "FAIL_COMMAND": fail_command,
            "SONIC_RELEASE": sonic_release,
            "SONIC_BUILD_VERSION": sonic_build_version,
        },
        check=False,
    )
    output = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    output["commands"] = [item for item in output["LOG"].split("|") if item]
    output["state"] = output["STATE"].split("|")
    output["passkey_arg_counts"] = [
        int(count) for count in output["PASSKEY_ARG_COUNTS"].split("|") if count
    ]
    return task, result, output


@pytest.mark.parametrize(
    "use_ptf_tacacs_server,topo,expected_state,expected_commands",
    [
        pytest.param(
            True,
            "t0",
            ["tacacs+", "tacacs+", "tacacs+ local", "login", "test-key"],
            [
                "config aaa authentication login local",
                "config aaa authorization local",
                "config aaa accounting disable",
                "config tacacs passkey test-key",
                "config tacacs authtype login",
                "config aaa authorization tacacs+",
                "config aaa accounting tacacs+ local",
                "config aaa authentication login tacacs+",
            ],
            id="ptf-t0",
        ),
        pytest.param(
            True,
            "mx",
            ["tacacs+", "tacacs+ local", "tacacs+ local", "login", "test-key"],
            [
                "config aaa authentication login local",
                "config aaa authorization local",
                "config aaa accounting disable",
                "config tacacs passkey test-key",
                "config tacacs authtype login",
                "config aaa authorization tacacs+ local",
                "config aaa accounting tacacs+ local",
                "config aaa authentication login tacacs+",
            ],
            id="ptf-mx",
        ),
        pytest.param(
            False,
            "t0",
            ["tacacs+", "local", "tacacs+ local", "pap", "test-key"],
            [
                "config aaa authentication login local",
                "config aaa authorization local",
                "config aaa accounting disable",
                "config tacacs passkey test-key",
                "config tacacs authtype pap",
                "config aaa accounting tacacs+ local",
                "config aaa authentication login tacacs+",
            ],
            id="lab-pap-local-authorization-common-accounting",
        ),
    ],
)
def test_deploy_tacacs_success_order(
        use_ptf_tacacs_server, topo, expected_state, expected_commands):
    task, result, output = _run_tacacs_shell(use_ptf_tacacs_server, topo)

    assert result.returncode == 0
    assert output["state"] == expected_state
    assert output["commands"] == expected_commands
    assert output["PTF_TACACS"] == str(use_ptf_tacacs_server).lower()
    assert task["args"]["executable"] == "/bin/bash"
    assert "ignore_errors" not in task
    assert "trap " not in task["shell"]
    assert "original_" not in task["shell"]


@pytest.mark.parametrize(
    "sonic_release,sonic_build_version,expected_release,expected_authz,expected_accounting",
    [
        ("master", "master.1-202012", "master", True, True),
        ("202605", "202106.42", "202605", True, True),
        ("none", "internal-master.1", "master", True, True),
        ("none", "201811.30", "201811", False, False),
        ("none", "201911.42", "201911", False, False),
        ("", "20201231.99", "202012", False, True),
        ("none", "202106.42", "202106", False, False),
        ("none", "internal-202012.1", "unknown", True, True),
    ],
)
def test_deploy_tacacs_release_capability_gates(
        sonic_release, sonic_build_version, expected_release, expected_authz, expected_accounting):
    _, result, output = _run_tacacs_shell(
        True,
        "t0",
        sonic_release=sonic_release,
        sonic_build_version=sonic_build_version,
    )

    assert result.returncode == 0
    assert output["RESOLVED_RELEASE"] == expected_release
    assert ("config aaa authorization local" in output["commands"]) is expected_authz
    assert ("config aaa accounting disable" in output["commands"]) is expected_accounting
    assert ("config aaa authorization tacacs+" in output["commands"]) is expected_authz
    assert ("config aaa accounting tacacs+ local" in output["commands"]) is expected_accounting
    assert output["commands"][-1] == "config aaa authentication login tacacs+"


def test_deploy_tacacs_quotes_passkey_as_one_literal_argument():
    passkey = "key{a,b} with spaces;$(printf injected) '$HOME'"

    _, result, output = _run_tacacs_shell(True, "t0", tacacs_passkey=passkey)

    assert result.returncode == 0
    assert output["state"][-1] == passkey
    assert output["passkey_arg_counts"] == [3]


@pytest.mark.parametrize(
    "use_ptf_tacacs_server,topo,fail_command",
    [
        (True, "t0", "config tacacs passkey test-key"),
        (True, "t0", "config tacacs authtype login"),
        (True, "t0", "config aaa authorization tacacs+"),
        (True, "mx", "config aaa accounting tacacs+ local"),
        (True, "t0", "config aaa authentication login tacacs+"),
        (False, "t0", "config tacacs authtype pap"),
        (False, "t0", "config aaa accounting tacacs+ local"),
        (False, "t0", "config aaa authentication login tacacs+"),
    ],
)
def test_deploy_tacacs_failure_stops_with_local_authentication(
        use_ptf_tacacs_server, topo, fail_command):
    _, result, output = _run_tacacs_shell(
        use_ptf_tacacs_server,
        topo,
        fail_command=fail_command,
    )

    assert result.returncode == 42
    assert output["state"][0] == "local"
    failure_index = output["commands"].index(fail_command)
    assert output["commands"][failure_index:] == [fail_command]
    assert "config aaa authentication login tacacs+" not in output["commands"][failure_index + 1:]
