import os
import pytest
import logging
import json

from container_upgrade_helper import (
    parse_containers, create_testcase_mapping, create_parameters_mapping,
    create_image_list, os_upgrade, pull_run_dockers, store_results,
)
from tests.common.system_utils.docker import load_docker_registry_info

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)

# Build image server. <majorversion> = first 6 digits of the OS version
# (e.g. 202511), <osversion> = the full version (e.g. 20251110.28).
IMAGE_URL_TEMPLATE = ("https://sonic.packages.trafficmanager.net/pipelines/"
                      "Networking-acs-buildimage-Official/vs/internal-<majorversion>/"
                      "tagged/sonic-vs-<osversion>.bin")


def verify_container_string(runner, registry, container_string):
    """Verify every 'name:tag' in the bundle exists in the registry.

    container_string is a pipe-separated bundle, e.g.
    'docker-acms:tag1|docker-acms-watchdog:tag2'.
    """
    for pair in container_string.split("|"):
        docker_image_name, _, tag = pair.partition(":")
        image_ref = f"{registry.host}/{docker_image_name}:{tag}"
        result = runner.shell(f"docker manifest inspect {image_ref}",
                              module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail(f"Image '{image_ref}' does not exist in registry "
                        f"(rc={result['rc']})")
        logger.info(f"Verified {image_ref} exists in registry")


class NightlyContainerUpgradeEnvironment:
    """Minimal env compatible with pull_run_dockers() and store_results()."""

    def __init__(self, container_string, testcase_file, parameters_file, optional_parameters=""):
        self.container_string = container_string
        self.containers, self.container_versions, self.container_names = \
            parse_containers(container_string)
        self.testcases = create_testcase_mapping(testcase_file)
        self.parameters = create_parameters_mapping(container_string, parameters_file)
        self.optional_parameters = optional_parameters


# Map of full container image name -> supervisord program name for the main
# service. Output capture only runs for containers in this map; sidecars,
# watchdogs, and anything else not listed here is implicitly skipped.
# Add an entry here when a new nightly config for another main service container
# is introduced.
CONTAINER_TO_PROGRAM = {
    "docker-sonic-telemetry": "telemetry",
    "docker-sonic-gnmi":       "gnmi",
    "docker-acms":             "acms",
    "docker-auditd":           "auditd",
    "docker-restapi":          "restapi",
}

OUTPUT_CAPTURE_TEMPLATE_PATH = os.path.join(
    os.path.dirname(__file__), "output_capture_supervisord.conf.template")


def setup_output_capture(duthost, program):
    """Render the output_capture supervisord template for `program` and place
    the host-side artifacts on the DUT. Returns the two `-v` bind-mount strings
    to append to that container's parameters in env.parameters so
    migrate_container_systemd sed-injects them into the docker create line.

    Both stdout and stderr are routed to the file *and* to syslog so the host's
    /var/log/{program}.log keeps working unchanged while the file path captures
    every byte supervisord receives - including a Go panic+stack burst that
    syslog drops.
    """
    out_dir = f"/var/log/{program}-output"
    conf_path = f"/etc/sonic/{program}-output-supervisord.conf"

    with open(OUTPUT_CAPTURE_TEMPLATE_PATH) as f:
        rendered = f.read().replace("{program}", program)

    duthost.shell(f"mkdir -p {out_dir}")
    duthost.copy(content=rendered, dest=conf_path)

    return [
        f"-v {out_dir}:{out_dir}:rw",
        f"-v {conf_path}:/etc/supervisor/conf.d/supervisord.conf:ro",
    ]


def test_container_upgrade_nightly(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                                   creds, request):
    """Nightly container upgrade test (KVM).

    One job tests one OS version: upgrade the DUT to the target OS version,
    then pull/run the containers and execute the testcases. No multi-hop -
    the pipeline schedules one job per (container x OS version x topology).
    (The physical test_container_upgrade.py still does multi-hop; this is the
    KVM-nightly-specific variant.)
    """
    nightly_config = request.config.getoption("nightly_config")
    if not nightly_config:
        pytest.skip("Nightly test missing --nightly_config parameter")

    os_version = request.config.getoption("os_versions")
    if not os_version:
        pytest.skip("Nightly test missing --os_versions parameter")

    with open(nightly_config, 'r') as f:
        config = json.load(f)

    testcase_file = config["testcase_file"]
    parameters_file = config["parameters_file"]

    duthost = duthosts[rand_one_dut_hostname]

    # KVM DUT is network-isolated - run network ops from localhost and transfer to DUT.
    # Physical DUTs have internet access and run everything directly.
    is_kvm = duthost.facts.get("asic_type") == "vs"
    registry = load_docker_registry_info(duthost, creds)
    runner = localhost if is_kvm else duthost
    logger.info(f"Running in {'KVM' if is_kvm else 'physical'} mode - "
                f"network ops run on {'localhost' if is_kvm else 'DUT'}")

    # docker login on the runner so `docker manifest inspect` and `docker pull` work
    runner.shell(f"docker login {registry.host} -u {registry.username} "
                 f"-p {registry.password}")

    # Step 1: Determine the container bundle (name:tag|name:tag|...).
    # Pipeline-time override via `--containers=name:tag1,name:tag2`. Commas because
    # bash interprets `|` when SPECIFIC_PARAM is expanded; we map commas back to
    # pipes here. If empty, use the bundle from the config file.
    containers_override = request.config.getoption("containers")
    if containers_override:
        container_string = containers_override.replace(",", "|")
        logger.info(f"Using --containers override: {container_string}")
    else:
        container_string = config["containers"]
        logger.info(f"Using containers from config: {container_string}")
    verify_container_string(runner, registry, container_string)

    # Step 2: Build test environment
    optional_parameters = (request.config.getoption("optional_parameters")
                           or config.get("optional_parameters", ""))
    env = NightlyContainerUpgradeEnvironment(
        container_string, testcase_file, parameters_file, optional_parameters
    )

    tb_name = tbinfo["conf-name"]
    tb_file = request.config.option.testbed_file
    inventory = ",".join(request.config.option.ansible_inventory)
    hostname = duthost.hostname
    test_results = {}

    # Step 3: Upgrade the DUT to the target OS version (single hop).
    # On KVM the DUT is network-isolated, so localhost downloads the image and
    # copies it over; on physical the DUT downloads directly.
    if os_version not in duthost.os_version:
        image_url = create_image_list([os_version], IMAGE_URL_TEMPLATE)[0]
        logger.info(f"Upgrading DUT to {os_version} from {image_url}")
        os_upgrade(duthost, localhost, tbinfo, image_url,
                   network_runner=runner if is_kvm else None)
    else:
        logger.info(f"DUT already on {os_version}, skipping OS upgrade")

    # Step 4: Pull containers and run testcases
    # KVM only: render the supervisord output-capture override per main service
    # container in the bundle, drop it on the DUT, and inject the bind mounts
    # into env.parameters so migrate_container_systemd picks them up and routes
    # each program's stdout/stderr to a host-mounted file (in addition to syslog)
    # on every container create. Captures Go panic+stack bursts that syslog
    # drops. Skipped on physical testbeds.
    if is_kvm:
        for container_name in env.containers:
            program = CONTAINER_TO_PROGRAM.get(container_name)
            if program is None:
                continue
            mounts = setup_output_capture(duthost, program)
            env.parameters[container_name] = (
                env.parameters[container_name] + " " + " ".join(mounts))
    pull_run_dockers(duthost, creds, env, network_runner=runner)

    for testcase in env.testcases.keys():
        logger.info(f"Testing {testcase} on os_version={os_version}")
        os_version_key = os_version.replace('.', '_')
        testcase_key = testcase.replace(".py", "").replace('/', '_').replace('.', '_')
        log_file = f"logs/container_upgrade_nightly/{testcase_key}_{os_version_key}.log"
        log_xml = f"logs/container_upgrade_nightly/{testcase_key}_{os_version_key}.xml"
        command = (
            f"python3 -m pytest {testcase} --inventory={inventory} "
            f"--testbed={tb_name} --testbed_file={tb_file} "
            f"--host-pattern={hostname} --log-cli-level=warning "
            f"--log-file-level=debug --kube_master=unset --showlocals "
            f"--assert=plain --show-capture=no -rav --allow_recover "
            f"--skip_sanity --disable_loganalyzer --disable_memory_utilization "
            f"--container_test=true "
            f"--log-file={log_file} --junit-xml={log_xml}"
        )

        output = localhost.shell(command, module_ignore_errors=True)
        passed = not output['failed']

        if not passed:
            logger.warning(f"Test {testcase} output start =====================")
            logger.warning(f"{output}".replace('\\n', '\n'))
            logger.warning(f"Test {testcase} output end   =====================")
            # Dump `docker logs` for each container under test - this is the
            # container's own stdout/stderr, which the host syslog does not have.
            for cname in env.container_names:
                dlogs = duthost.shell(f"docker logs --timestamps {cname}",
                                      module_ignore_errors=True)
                logger.warning(f"docker logs {cname} start ====================")
                logger.warning(f"stdout:\n{dlogs.get('stdout', '')}")
                logger.warning(f"stderr:\n{dlogs.get('stderr', '')}")
                logger.warning(f"docker logs {cname} end   ====================")
            # Snapshot the entire DUT /var/log into the pipeline artifact tree.
            tar_name = f"{testcase_key}_{os_version_key}_var_log.tar.gz"
            extract_dir = f"logs/container_upgrade_nightly/{testcase_key}_{os_version_key}_var_log"
            duthost.shell(f"tar -czf /tmp/{tar_name} -C /var/log .",
                          module_ignore_errors=True)
            fetch_result = duthost.fetch(
                src=f"/tmp/{tar_name}",
                dest=f"logs/container_upgrade_nightly/{tar_name}",
                flat=True, fail_on_missing=False)
            duthost.shell(f"rm -f /tmp/{tar_name}", module_ignore_errors=True)
            localhost.shell(
                f"mkdir -p {extract_dir} && "
                f"tar -xzf logs/container_upgrade_nightly/{tar_name} -C {extract_dir}",
                module_ignore_errors=True)
            logger.warning(f"Captured /var/log -> {extract_dir}/ "
                           f"(fetch_failed={fetch_result.get('failed', False)})")

        test_results.setdefault(os_version, {})[testcase] = passed

    # Bundle every core dump on the DUT into a single base64-encoded artifact.
    # The base64 output is ASCII so it survives elastictest's artifact pipeline
    # (binary uploads get UTF-8-mangled). SONiC's coredump-compress has already
    # gzipped each file in /var/core in place.
    # Decode locally with:  base64 -d cores.tar.gz.b64 | tar -xzf -
    duthost.shell(
        "[ \"$(ls -A /var/core/ 2>/dev/null)\" ] && "
        "tar -czf - -C /var/core . | base64 > /tmp/cores.tar.gz.b64 || true",
        module_ignore_errors=True)
    duthost.fetch(src="/tmp/cores.tar.gz.b64",
                  dest="logs/container_upgrade_nightly/cores.tar.gz.b64",
                  flat=True, fail_on_missing=False)
    duthost.shell("rm -f /tmp/cores.tar.gz.b64", module_ignore_errors=True)

    # KVM only: pull each main-service container's full output capture (every
    # line supervisord forwarded to the bind-mounted file across all restarts -
    # syslog-independent, survives container recreate).
    if is_kvm:
        for container_name in env.containers:
            program = CONTAINER_TO_PROGRAM.get(container_name)
            if program is None:
                continue
            duthost.fetch(
                src=f"/var/log/{program}-output/{program}.output.log",
                dest=f"logs/container_upgrade_nightly/{program}.output.log",
                flat=True, fail_on_missing=False)

    # Step 5: Store results and assert all passed
    # Attach attributes store_results expects
    env.osversions = [os_version]
    env.image_urls = []
    env.version_pointer = len(env.osversions)
    store_results(request, test_results, env)

    failed_tests = []
    for os_ver, results in test_results.items():
        for testcase, passed in results.items():
            if not passed:
                failed_tests.append(f"{testcase} (os_version={os_ver})")

    if failed_tests:
        pytest.fail(f"The following tests failed: {', '.join(failed_tests)}")
