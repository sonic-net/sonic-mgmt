import json
import re
import shlex


def pytest_assert(condition, message):
    assert condition, message


TPM_DEVICE_PATH = re.compile(r"(?:^|/)tpm(?:rm)?[0-9]+$")
FORBIDDEN_DATABASE_CAPABILITIES = {
    "SYS_MODULE": 16,
    "SYS_RAWIO": 17,
    "SYS_PTRACE": 19,
    "SYS_ADMIN": 21,
    "SYS_BOOT": 22,
}


def is_tpm_or_dev_path(path):
    if not isinstance(path, str):
        return False
    normalized = path.rstrip("/")
    return normalized == "/dev" or bool(TPM_DEVICE_PATH.search(normalized))


def database_tpm_mappings(host_config, mounts):
    paths = []
    for device in host_config.get("Devices") or []:
        paths.extend([device.get("PathOnHost"), device.get("PathInContainer")])
    for bind in host_config.get("Binds") or []:
        paths.extend(bind.split(":")[:2])
    for mount in mounts or []:
        paths.extend([mount.get("Source"), mount.get("Destination")])
    return [path for path in paths if is_tpm_or_dev_path(path)]


def namespace_ids(output):
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def capabilities_added(host_config):
    return {capability.upper().removeprefix("CAP_") for capability in host_config.get("CapAdd") or []}


def test_database_container_isolation(duthosts, tbinfo):
    """Verify database containers do not expose host TPM devices or broad privileges."""
    namespace_command = "for ns in pid ipc mnt; do printf '%s=' \"$ns\"; readlink \"/proc/1/ns/$ns\"; done"
    capability_allowlist = tbinfo.get("database_capability_allowlist") or {}

    for duthost in duthosts.nodes:
        running_containers = duthost.shell(
            r"docker ps -f 'status=running' --format \{\{.Names\}\}"
        )["stdout_lines"]
        database_containers = [name for name in running_containers if name.lower().startswith("database")]
        pytest_assert(database_containers, "No running database containers found on {}".format(duthost.hostname))

        for container_name in database_containers:
            inspect_result = duthost.shell("docker inspect {}".format(shlex.quote(container_name)))
            container_info = json.loads(inspect_result["stdout"])[0]
            host_config = container_info["HostConfig"]
            mounts = container_info.get("Mounts", [])

            pytest_assert(not host_config.get("Privileged"), "{} is running privileged".format(container_name))
            pytest_assert(
                not database_tpm_mappings(host_config, mounts),
                "{} has a host /dev or TPM device mapping".format(container_name),
            )

            container_policy = capability_allowlist.get(container_name, {})
            expected_capabilities = {
                capability.upper().removeprefix("CAP_")
                for capability in container_policy.get("capabilities", [])
            }
            added_capabilities = capabilities_added(host_config)
            pytest_assert(
                added_capabilities.issubset(expected_capabilities),
                "{} has unexpected added capabilities: {}".format(
                    container_name, sorted(added_capabilities - expected_capabilities)
                ),
            )
            if added_capabilities:
                pytest_assert(
                    bool(container_policy.get("reason")),
                    "{} has added capabilities without a documented testbed policy".format(container_name),
                )

            for namespace in ("PidMode", "IpcMode", "UsernsMode"):
                pytest_assert(
                    host_config.get(namespace) != "host",
                    "{} shares the host {} namespace".format(container_name, namespace),
                )

            namespace_result = duthost.shell(
                "docker exec {} sh -c {}".format(shlex.quote(container_name), shlex.quote(namespace_command)),
                module_ignore_errors=True,
            )
            host_namespace_result = duthost.shell(namespace_command)
            pytest_assert(namespace_result["rc"] == 0, "Could not inspect namespaces in {}".format(container_name))
            container_namespaces = namespace_ids(namespace_result["stdout"])
            host_namespaces = namespace_ids(host_namespace_result["stdout"])
            for namespace in ("pid", "ipc", "mnt"):
                pytest_assert(
                    namespace in container_namespaces and namespace in host_namespaces,
                    "Could not resolve the {} namespace for {}".format(namespace, container_name),
                )
                pytest_assert(
                    container_namespaces[namespace] != host_namespaces[namespace],
                    "{} shares the host {} namespace".format(container_name, namespace),
                )

            capability_result = duthost.shell(
                "docker exec {} cat /proc/1/status".format(shlex.quote(container_name)),
                module_ignore_errors=True,
            )
            pytest_assert(capability_result["rc"] == 0, "Could not inspect capabilities in {}".format(container_name))
            effective_line = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", capability_result["stdout"], re.MULTILINE)
            pytest_assert(effective_line, "Could not read effective capabilities in {}".format(container_name))
            effective_capabilities = int(effective_line.group(1), 16)
            forbidden_capabilities = [
                name for name, bit in FORBIDDEN_DATABASE_CAPABILITIES.items()
                if effective_capabilities & (1 << bit)
            ]
            pytest_assert(
                not forbidden_capabilities,
                "{} has forbidden effective capabilities: {}".format(container_name, forbidden_capabilities),
            )
            if effective_capabilities & (1 << 12):
                pytest_assert(
                    "NET_ADMIN" in expected_capabilities and bool(container_policy.get("reason")),
                    "{} has effective NET_ADMIN without a documented testbed policy".format(container_name),
                )

            device_probe = (
                "for path in /dev/tpm[0-9]* /dev/tpmrm[0-9]*; "
                'do [ ! -e "$path" ] || echo "$path"; done; true'
            )
            device_result = duthost.shell(
                "docker exec {} sh -c {}".format(shlex.quote(container_name), shlex.quote(device_probe))
            )
            pytest_assert(
                not device_result["stdout"].strip(),
                "{} can see TPM devices: {}".format(container_name, device_result["stdout"].strip()),
            )

            redis_result = duthost.shell(
                "docker exec {} redis-cli PING".format(shlex.quote(container_name)),
                module_ignore_errors=True,
            )
            pytest_assert(
                redis_result["rc"] == 0 and redis_result["stdout"].strip() == "PONG",
                "Redis is not responding in {}".format(container_name),
            )


def test_database_device_path_detection():
    assert is_tpm_or_dev_path("/dev")
    assert is_tpm_or_dev_path("/dev/tpm0")
    assert is_tpm_or_dev_path("/dev/tpmrm12")
    assert not is_tpm_or_dev_path("/dev/sda")
    assert not is_tpm_or_dev_path("/tmp/device/virtual0")
    assert not is_tpm_or_dev_path(None)


def test_database_mapping_detection():
    config = {
        "Devices": [{"PathOnHost": "/dev/tpm0", "PathInContainer": "/dev/tpm0"}],
        "Binds": ["/dev:/dev:rw", "/var/run/docker.sock:/var/run/docker.sock"],
    }
    assert database_tpm_mappings(config, []) == ["/dev/tpm0", "/dev/tpm0", "/dev", "/dev"]
    assert not database_tpm_mappings({"Devices": [], "Binds": []}, [])
