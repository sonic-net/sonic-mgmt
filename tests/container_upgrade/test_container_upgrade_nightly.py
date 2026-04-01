import pytest
import logging
import json

from container_upgrade_helper import (
    parse_containers, parse_os_versions, create_image_list,
    create_testcase_mapping, create_parameters_mapping,
    os_upgrade, pull_run_dockers, store_results,
    container_name_mapping
)
from tests.common.system_utils.docker import load_docker_registry_info

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)

# Reverse mapping: short name (e.g. "telemetry") -> full docker image name (e.g. "docker-sonic-telemetry")
DOCKER_SHORT_NAME_MAP = {v: k for k, v in container_name_mapping.items()}


def discover_latest_tag(duthost, registry, docker_image_name, tag_prefix):
    """Query the docker registry for tags and find the latest matching the prefix.

    For tag_prefix="internal-kubesonic", matches tags like
    "internal-kubesonic.2321asd3fe21321" but NOT "internal-202411.abc123".

    Args:
        duthost: DUT host to run commands on.
        registry: DockerRegistryInfo with host, username, password.
        docker_image_name: Full docker image name (e.g. "docker-sonic-telemetry").
        tag_prefix: Tag prefix to match (e.g. "internal-kubesonic").

    Returns:
        str: The latest matching tag, or None if no match found.
    """
    registry_url = f"https://{registry.host}/v2/{docker_image_name}/tags/list"
    cmd = f'curl -s -k -u "{registry.username}:{registry.password}" "{registry_url}"'
    result = duthost.shell(cmd, module_ignore_errors=True)

    if result['rc'] != 0:
        logger.warning(f"Failed to query registry API for {docker_image_name}: "
                       f"{result.get('stderr', '')}")
        return None

    try:
        tag_data = json.loads(result['stdout'])
        tags = tag_data.get('tags', [])
    except (json.JSONDecodeError, KeyError):
        logger.error(f"Failed to parse registry response for {docker_image_name}: "
                     f"{result['stdout']}")
        return None

    matching_tags = [t for t in tags if t.startswith(f"{tag_prefix}.")]

    if not matching_tags:
        logger.warning(f"No tags matching prefix '{tag_prefix}.' found for "
                       f"{docker_image_name}")
        logger.info(f"Available tags (first 20): {tags[:20]}")
        return None

    matching_tags.sort()
    latest = matching_tags[-1]
    logger.info(f"Discovered latest tag for {docker_image_name}: {latest} "
                f"(matched {len(matching_tags)} tags with prefix '{tag_prefix}')")
    return latest


def discover_container_string(duthost, creds, dockers, branches):
    """Discover latest docker tags and build the container string.

    Args:
        duthost: DUT host.
        creds: Credentials dict.
        dockers: Pipe-separated short docker names (e.g. "telemetry|restapi").
        branches: Pipe-separated tag prefixes (e.g. "internal-kubesonic").

    Returns:
        str: Container string like "docker-sonic-telemetry:tag|docker-sonic-restapi:tag".
    """
    registry = load_docker_registry_info(duthost, creds)
    docker_short_names = dockers.split("|")
    branch_list = branches.split("|")

    container_pairs = []
    for docker_short in docker_short_names:
        full_name = DOCKER_SHORT_NAME_MAP.get(docker_short)
        if full_name is None:
            pytest.fail(f"Unknown docker short name: '{docker_short}'. "
                        f"Valid names: {list(DOCKER_SHORT_NAME_MAP.keys())}")

        discovered_tag = None
        for branch in branch_list:
            discovered_tag = discover_latest_tag(duthost, registry, full_name, branch)
            if discovered_tag:
                break

        if discovered_tag is None:
            pytest.fail(f"Could not discover any tag for {full_name} "
                        f"with prefixes: {branch_list}")

        container_pairs.append(f"{full_name}:{discovered_tag}")

    container_string = "|".join(container_pairs)
    logger.info(f"Discovered container string: {container_string}")
    return container_string


class NightlyContainerUpgradeEnvironment:
    """Test environment that discovers docker tags at runtime.

    Exposes the same attributes as ContainerUpgradeTestEnvironment so it is
    compatible with pull_run_dockers() and store_results().
    """

    def __init__(self, container_string, os_versions, image_url_template,
                 testcase_file, parameters_file):
        self.container_string = container_string
        self.containers, self.container_versions, self.container_names = \
            parse_containers(container_string)
        self.osversions = parse_os_versions(os_versions)
        self.image_urls = create_image_list(self.osversions, image_url_template)
        self.testcases = create_testcase_mapping(testcase_file)
        self.parameters = create_parameters_mapping(container_string, parameters_file)
        self.optional_parameters = ""
        self.version_pointer = 0


def test_container_upgrade_nightly(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                                   creds, request):
    """Nightly container upgrade test that auto-discovers the latest docker tags.

    1. Discovers latest docker image tags from the registry.
    2. Builds a ContainerUpgradeTestEnvironment-compatible env.
    3. Pulls/runs containers and executes each testcase once (no retries).
    4. Stores results and asserts ALL tests passed.
    """
    dockers = request.config.getoption("dockers")
    branches = request.config.getoption("branches")
    os_versions = request.config.getoption("os_versions")
    image_url_template = request.config.getoption("image_url_template")
    testcase_file = request.config.getoption("testcase_file")
    parameters_file = request.config.getoption("parameters_file")

    if any(v is None or v == "" for v in [
            dockers, branches, os_versions,
            image_url_template, testcase_file, parameters_file]):
        pytest.skip("Nightly test missing required parameters")

    duthost = duthosts[rand_one_dut_hostname]

    # Step 1: Discover latest docker tags from registry
    container_string = discover_container_string(duthost, creds, dockers, branches)

    # Step 2: Build test environment with discovered tags
    env = NightlyContainerUpgradeEnvironment(
        container_string, os_versions, image_url_template,
        testcase_file, parameters_file
    )

    tb_name = tbinfo["conf-name"]
    tb_file = request.config.option.testbed_file
    inventory = ",".join(request.config.option.ansible_inventory)
    hostname = duthost.hostname
    test_results = {}

    # Step 3: For each OS version, upgrade OS, pull containers, and run testcases once
    while env.version_pointer < len(env.osversions):
        expected_os_version = env.osversions[env.version_pointer]
        if expected_os_version not in duthost.os_version:
            os_upgrade(duthost, localhost, tbinfo, env.image_urls[env.version_pointer])
        pull_run_dockers(duthost, creds, env)

        for testcase in env.testcases.keys():
            logger.info(f"Testing {testcase} for {expected_os_version}")
            os_version_key = expected_os_version.replace('.', '_')
            testcase_key = testcase.replace(".py", "").replace('/', '_').replace('.', '_')
            log_file = f"logs/container_upgrade_nightly/{testcase_key}_{os_version_key}.log"
            log_xml = f"logs/container_upgrade_nightly/{testcase_key}_{os_version_key}.xml"
            command = (
                f"python3 -m pytest {testcase} --inventory={inventory} "
                f"--testbed={tb_name} --testbed_file={tb_file} "
                f"--host-pattern={hostname} --log-cli-level=warning "
                f"--log-file-level=debug --kube_master=unset --showlocals "
                f"--assert=plain --show-capture=no -rav --allow_recover "
                f"--skip_sanity --disable_loganalyzer --container_test=true "
                f"--log-file={log_file} --junit-xml={log_xml}"
            )

            output = localhost.shell(command, module_ignore_errors=True)
            passed = not output['failed']

            if not passed:
                logger.warning(f"Test {testcase} output start =====================")
                logger.warning(f"{output}".replace('\\n', '\n'))
                logger.warning(f"Test {testcase} output end   =====================")

            test_results.setdefault(expected_os_version, {})[testcase] = passed
        env.version_pointer += 1

    # Step 4: Store results and assert all passed
    store_results(request, test_results, env)

    failed_tests = []
    for os_ver, results in test_results.items():
        for testcase, passed in results.items():
            if not passed:
                failed_tests.append(f"{testcase} (os_version={os_ver})")

    if failed_tests:
        pytest.fail(f"The following tests failed: {', '.join(failed_tests)}")
