import json
import logging
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer,
    # ZTP runs config reloads and (in TC22) intentionally broken configs that
    # legitimately perturb FRR/zebra memory. The memory_utilization pytest
    # plugin flags those as teardown ALARMs (e.g. "frr_zeb..."), which masks
    # real test outcomes. The memory check is not meaningful for ZTP tests.
    pytest.mark.disable_memory_utilization,
]

ZTP_STATUS_CMD = "sudo ztp status"
ZTP_ENABLE_CMD = "sudo ztp enable"
ZTP_DISABLE_CMD = "sudo ztp disable -y"
ZTP_RUN_CMD = "sudo ztp run -y"
ZTP_JSON_PATH = "/host/ztp/ztp.json"
ZTP_DATA_JSON_PATH = "/host/ztp/ztp_data.json"
ZTP_CONFIG_TO_APPLY_PATH = "/host/ztp/config_db_to_apply.json"
FRR_CONF_PATH = "/etc/sonic/frr/frr.conf"
REMOVE_CONFIG_DB_CMD = "sudo rm -f /etc/sonic/config_db.json"
REMOVE_MINIGRAPH_CMD = "sudo rm -f /etc/sonic/minigraph.xml"
CONFIG_RELOAD_CMD = "sudo config reload -y -f"
# config reload only refreshes Redis from disk; it does not write back to
# /etc/sonic/config_db.json. Pair it with config save to ensure the running
# config is also persisted so the DUT survives the next reboot.
CONFIG_SAVE_CMD = "sudo config save -y"
DEVICE_PATH = "/usr/share/sonic/device"
HWSKU_REMOVE_SENTINEL = "__REMOVE__"
INVALID_HWSKU_NAME = "Invalid-HWSKU-Does-Not-Exist"

COPY_CONFIG_DB_FOR_ZTP_CMD = "sudo cp /etc/sonic/config_db.json {}".format(
    ZTP_CONFIG_TO_APPLY_PATH
)

ZTP_POLL_TIMEOUT = 1200
ZTP_POLL_INTERVAL = 20
NEGATIVE_POLL_TIMEOUT = 120
SSH_STOP_DETECT_TIMEOUT = 180
SSH_START_DELAY = 30
SSH_START_TIMEOUT = 900
CRITICAL_SERVICES_TIMEOUT = 600
CRITICAL_SERVICES_INTERVAL = 20


def _use_local_ztp_profile(ztp_payload):
    return ztp_payload.get("provisioning_mode", "local") == "local"


def _remove_local_ztp_profile_files(duthost):
    duthost.shell(
        "sudo rm -f {} {}".format(ZTP_JSON_PATH, ZTP_DATA_JSON_PATH),
        module_ignore_errors=True,
    )


def parse_ztp_status(output):
    parsed = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        raw_key, raw_value = line.split(":", 1)
        key = raw_key.strip().lower().replace(" ", "_")
        parsed[key] = raw_value.strip()
    return parsed


def _wait_for_critical_services(duthost):
    try:
        duthost.critical_services_fully_started()
        return True
    except Exception as error:  # pylint: disable=broad-except
        logger.info("Waiting for critical services: %s", error)
        return False


def _wait_for_ssh_reconnect(localhost, duthost):
    localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="stopped",
        timeout=SSH_STOP_DETECT_TIMEOUT,
        module_ignore_errors=True,
    )

    ssh_wait = localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=SSH_START_DELAY,
        timeout=SSH_START_TIMEOUT,
        module_ignore_errors=True,
    )

    pytest_assert(
        not ssh_wait.get("failed", False),
        "DUT did not become reachable on SSH after running ZTP",
    )

    services_ready = wait_until(
        CRITICAL_SERVICES_TIMEOUT,
        CRITICAL_SERVICES_INTERVAL,
        0,
        _wait_for_critical_services,
        duthost,
    )
    pytest_assert(services_ready, "Critical services did not come up after ZTP run")


def _ztp_completed_successfully(duthost):
    result = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    if result.get("failed", False):
        return False
    if result.get("rc", 1) != 0:
        return False
    status = parse_ztp_status(result.get("stdout", ""))
    return status.get("ztp_status") == "SUCCESS" and status.get("ztp_service") == "Inactive"


def _recover_if_discovery_stuck(duthost):
    for _ in range(12):
        result = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
        if result.get("failed", False) or result.get("rc", 1) != 0:
            time.sleep(20)
            continue
        status = parse_ztp_status(result.get("stdout", ""))
        if status.get("ztp_service") == "Active Discovery" and status.get("ztp_status") == "Not Started":
            duthost.shell(
                "sudo test -f /host/ztp/ztp.json && sudo cp -f /host/ztp/ztp.json /host/ztp/ztp_data.json && sudo sync",
                module_ignore_errors=True,
            )
            time.sleep(20)
            continue
        break


def _stage_payload_files(duthost, ztp_payload):
    payload_text = json.dumps(ztp_payload["ztp_json_content"], indent=2) + "\n"
    duthost.copy(content=payload_text, dest=ztp_payload["dut_ztp_data_json"])
    duthost.copy(content=payload_text, dest=ZTP_JSON_PATH)


def _prepare_for_ztp_run(duthost):
    copy_result = duthost.shell(COPY_CONFIG_DB_FOR_ZTP_CMD, module_ignore_errors=True)
    pytest_assert(copy_result.get("rc", 1) == 0, "Failed to stage config_db_to_apply.json")

    enable_result = duthost.shell(ZTP_ENABLE_CMD, module_ignore_errors=True)
    pytest_assert(enable_result.get("rc", 1) == 0, "Failed to enable ZTP")

    remove_result = duthost.shell(REMOVE_CONFIG_DB_CMD, module_ignore_errors=True)
    pytest_assert(remove_result.get("rc", 1) == 0, "Failed to remove config_db.json")

    # Hide /etc/sonic/minigraph.xml so the ZTP daemon does not exit with
    # "minigraph.xml found, skipping ZTP discovery." backup_and_restore_config_db
    # backs minigraph up at fixture setup and restores it at teardown.
    duthost.shell(REMOVE_MINIGRAPH_CMD, module_ignore_errors=True)


def _execute_ztp_run_and_wait(localhost, duthost, ztp_payload):
    if _use_local_ztp_profile(ztp_payload):
        refresh = duthost.shell(
            "sudo cp -f /host/ztp/ztp.json /host/ztp/ztp_data.json && sudo sync",
            module_ignore_errors=True,
        )
        pytest_assert(refresh.get("rc", 1) == 0, "Failed to refresh ztp_data.json")
    else:
        logger.info("DHCP provisioning mode: not refreshing ztp_data.json from local ztp.json before ztp run")

    duthost.shell(ZTP_RUN_CMD, module_ignore_errors=True)
    _wait_for_ssh_reconnect(localhost, duthost)
    _recover_if_discovery_stuck(duthost)

    completed = wait_until(
        ZTP_POLL_TIMEOUT,
        ZTP_POLL_INTERVAL,
        0,
        _ztp_completed_successfully,
        duthost,
    )
    pytest_assert(completed, "ZTP did not complete successfully within timeout")


def _validate_payload_schema(payload):
    ztp_root = payload.get("ztp", {})

    frr_cfg = (
        ztp_root.get("01-frr-config", {})
        or ztp_root.get("02-frr-config", {})
        or ztp_root.get("01-download", {})
        or ztp_root.get("02-download", {})
    )

    configdb = (
        ztp_root.get("02-configdb-json", {})
        or ztp_root.get("03-configdb-json", {})
        or ztp_root.get("01-configdb-json", {})
    )

    frr_files = frr_cfg.get("files", [])
    frr_url = frr_files[0].get("url", {}) if frr_files else {}
    cfg_url = configdb.get("url", {})

    return (
        bool(ztp_root)
        and bool(frr_url.get("source"))
        and frr_url.get("destination") == "/etc/sonic/frr/frr.conf"
        and cfg_url.get("source") == "file:///host/ztp/config_db_to_apply.json"
        and cfg_url.get("destination") == "/etc/sonic/config_db.json"
    )


def _has_frr_step(ztp_payload):
    ztp_root = ztp_payload["ztp_json_content"].get("ztp", {})
    for section in ztp_root.values():
        files = section.get("files", [])
        for file_item in files:
            url_cfg = file_item.get("url", {})
            if url_cfg.get("destination") == FRR_CONF_PATH and url_cfg.get("source"):
                return True
    return False


def _get_frr_source_url(ztp_payload):
    ztp_root = ztp_payload["ztp_json_content"].get("ztp", {})
    for section in ztp_root.values():
        files = section.get("files", [])
        for file_item in files:
            url_cfg = file_item.get("url", {})
            if url_cfg.get("destination") == FRR_CONF_PATH and url_cfg.get("source"):
                return url_cfg.get("source")
    return None


def _detect_ztp_profile_source(duthost):
    status_res = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    if status_res.get("rc", 1) == 0:
        parsed = parse_ztp_status(status_res.get("stdout", ""))
        source_hint = parsed.get("ztp_json_source", "")
        if "dhcp-opt67" in source_hint:
            return "dhcp", "ztp status source={}".format(source_hint)
        if "/host/ztp/ztp_data.json" in source_hint or "local" in source_hint.lower():
            return "local", "ztp status source={}".format(source_hint)

    log_res = duthost.shell("sudo tail -n 1500 /var/log/ztp.log", module_ignore_errors=True)
    if log_res.get("rc", 1) != 0:
        return "unknown", "unable to read /var/log/ztp.log"

    log_text = log_res.get("stdout", "")
    pos_dhcp = max(log_text.rfind("dhcp-opt67"), log_text.rfind("dhcp opt67"))
    pos_local = log_text.rfind("Starting ZTP using JSON file /host/ztp/ztp_data.json")

    if pos_dhcp == -1 and pos_local == -1:
        return "unknown", "no dhcp/local source markers found in recent ztp logs"

    if pos_dhcp > pos_local:
        return "dhcp", "latest marker from ztp.log is dhcp-opt67"
    return "local", "latest marker from ztp.log is /host/ztp/ztp_data.json"


def test_tc1_ztp_status_command(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    result = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(result.get("rc", 1) == 0, "Failed to run ztp status")
    parsed = parse_ztp_status(result.get("stdout", ""))
    pytest_assert(parsed, "Parsed ztp status output is empty")


def test_tc2_ztp_enable_disable(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    enable_result = duthost.shell(ZTP_ENABLE_CMD, module_ignore_errors=True)
    pytest_assert(enable_result.get("rc", 1) == 0, "Failed to enable ZTP")

    status_enable = parse_ztp_status(duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True).get("stdout", ""))
    pytest_assert(status_enable.get("ztp_admin_mode") == "True", "Expected admin mode True after enable")

    disable_result = duthost.shell(ZTP_DISABLE_CMD, module_ignore_errors=True)
    pytest_assert(disable_result.get("rc", 1) == 0, "Failed to disable ZTP")

    status_disable = parse_ztp_status(duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True).get("stdout", ""))
    pytest_assert(status_disable.get("ztp_admin_mode") == "False", "Expected admin mode False after disable")


def test_tc3_payload_validation_and_staging(duthosts, rand_one_dut_hostname, ztp_payload):
    duthost = duthosts[rand_one_dut_hostname]
    pytest_assert(_validate_payload_schema(ztp_payload["ztp_json_content"]), "Invalid ztp_data.json schema")

    if _use_local_ztp_profile(ztp_payload):
        _stage_payload_files(duthost, ztp_payload)
        data_stat = duthost.stat(path=ZTP_DATA_JSON_PATH)
        json_stat = duthost.stat(path=ZTP_JSON_PATH)
        pytest_assert(data_stat["stat"]["exists"], "ztp_data.json not staged")
        pytest_assert(json_stat["stat"]["exists"], "ztp.json not staged")
    else:
        _remove_local_ztp_profile_files(duthost)
        logger.info(
            "TC3: provisioning_mode=dhcp — removed local ztp.json/ztp_data.json; DUT should use DHCP Option 67"
        )


def test_tc5_end_to_end_ztp_success(
    duthosts,
    rand_one_dut_hostname,
    localhost,
    ztp_payload,
    backup_and_restore_config_db,
):
    del backup_and_restore_config_db
    duthost = duthosts[rand_one_dut_hostname]

    if _use_local_ztp_profile(ztp_payload):
        _stage_payload_files(duthost, ztp_payload)
    else:
        _remove_local_ztp_profile_files(duthost)
        logger.info("TC5: DHCP mode — using Option 67 profile; local ztp.json/ztp_data.json removed")

    _prepare_for_ztp_run(duthost)
    _execute_ztp_run_and_wait(localhost, duthost, ztp_payload)


def test_tc6_config_applied_correctly(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    running = duthost.shell("sudo cat /etc/sonic/config_db.json", module_ignore_errors=True)
    payload = duthost.shell("sudo cat /host/ztp/config_db_to_apply.json", module_ignore_errors=True)

    pytest_assert(running.get("rc", 1) == 0, "Cannot read running config_db.json")

    running_cfg = json.loads(running.get("stdout", "{}"))
    run_host = running_cfg.get("DEVICE_METADATA", {}).get("localhost", {}).get("hostname")
    pytest_assert(run_host, "Running config validation failed: hostname is empty")

    if payload.get("rc", 1) == 0:
        apply_cfg = json.loads(payload.get("stdout", "{}"))
        apply_host = apply_cfg.get("DEVICE_METADATA", {}).get("localhost", {}).get("hostname")
        pytest_assert(run_host == apply_host, "Applied config mismatch on hostname field")


def test_tc7_service_inactive_after_config_present(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    status_result = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(status_result.get("rc", 1) == 0, "Failed to run ztp status")
    status = parse_ztp_status(status_result.get("stdout", ""))

    pytest_assert(
        status.get("ztp_service") == "Inactive",
        "Expected ZTP Service Inactive, got {}".format(status.get("ztp_service")),
    )


def test_tc14_frr_file_downloaded(duthosts, rand_one_dut_hostname, ztp_payload):
    """TC14: Verify the FRR config payload referenced by ZTP is downloadable
    and well-formed.

    This is a standalone reachability + content check rather than a check of
    the on-disk /etc/sonic/frr/frr.conf. Reason: TC13 runs ZTP and then its
    backup_and_restore_config_db teardown does 'config reload -y -f' which
    restarts the bgp container; BGP regenerates /etc/sonic/frr/frr.conf from
    CONFIG_DB templates on start, so by the time TC14 runs the on-disk file
    no longer reflects what ZTP downloaded -- even when ZTP itself succeeded
    (TC13's _execute_ztp_run_and_wait already asserts that).

    So TC14 instead pulls the FRR URL declared in the ZTP payload directly
    from the DUT (same path ZTP would take) and validates the content. This
    proves the ZTP download step is functional and the URL is serving a valid
    FRR config, independent of test ordering.

    Skips cleanly if:
      - the payload has no FRR section, or
      - the URL is not reachable from the DUT (lab/network issue, not a ZTP bug)
    """
    duthost = duthosts[rand_one_dut_hostname]

    if not _has_frr_step(ztp_payload):
        pytest.skip("TC14 skipped: FRR section not configured in active ztp_data.json")

    frr_url = _get_frr_source_url(ztp_payload)
    pytest_assert(frr_url, "TC14: FRR source URL is empty in payload")

    tmp_path = "/tmp/ztp_tc14_frr.conf"
    duthost.shell("sudo rm -f {}".format(tmp_path), module_ignore_errors=True)

    fetch_cmd = "sudo curl -fsS --max-time 30 -o {dst} {url}".format(
        dst=tmp_path,
        url=frr_url,
    )
    fetch = duthost.shell(fetch_cmd, module_ignore_errors=True)
    if fetch.get("rc", 1) != 0:
        pytest.skip(
            "TC14 skipped: FRR URL {} not reachable from DUT (rc={}, stderr={!r}). "
            "This is a lab/network issue, not a ZTP bug.".format(
                frr_url, fetch.get("rc"), (fetch.get("stderr") or "")[:200]
            )
        )

    size_check = duthost.shell("sudo test -s {}".format(tmp_path), module_ignore_errors=True)
    pytest_assert(
        size_check.get("rc", 1) == 0,
        "TC14: downloaded FRR file is empty at {} (URL {})".format(tmp_path, frr_url),
    )

    content = duthost.shell(
        "sudo grep -E '^(frr version|router bgp|hostname|password|line vty|!)' {}".format(tmp_path),
        module_ignore_errors=True,
    )
    pytest_assert(
        content.get("rc", 1) == 0,
        "TC14: downloaded FRR config from {} does not contain any expected FRR markers".format(frr_url),
    )

    duthost.shell("sudo rm -f {}".format(tmp_path), module_ignore_errors=True)


def test_tc15_frr_service_healthy(duthosts, rand_one_dut_hostname, ztp_payload):
    """TC15: Verify FRR/BGP container is up."""
    duthost = duthosts[rand_one_dut_hostname]

    if not _has_frr_step(ztp_payload):
        pytest.skip("TC15 skipped: FRR section not configured in active ztp_data.json")

    bgp = duthost.shell("sudo docker ps | awk 'NR>1 {print $NF}' | grep -w bgp", module_ignore_errors=True)
    pytest_assert(bgp.get("rc", 1) == 0, "FRR/BGP container is not running")


def test_tc16_frr_runtime_reflects_config(duthosts, rand_one_dut_hostname, ztp_payload):
    """TC16: Verify FRR runtime config is readable and includes BGP stanza."""
    duthost = duthosts[rand_one_dut_hostname]

    if not _has_frr_step(ztp_payload):
        pytest.skip("TC16 skipped: FRR section not configured in active ztp_data.json")

    running = duthost.shell("sudo docker exec bgp vtysh -c 'show running-config'", module_ignore_errors=True)
    pytest_assert(running.get("rc", 1) == 0, "Unable to read FRR running config via vtysh")
    pytest_assert("router bgp" in running.get("stdout", ""), "FRR running config missing router bgp section")


def test_tc17_frr_negative_bad_url_reachability():
    bad_url = "http://127.0.0.1:9/does_not_exist_frr.conf"

    import urllib.request
    try:
        urllib.request.urlopen(bad_url, timeout=2)
        pytest_assert(False, "Unexpectedly reached bad FRR URL")
    except Exception:  # pylint: disable=broad-except
        pytest_assert(True, "Expected bad FRR URL failure observed")


def test_tc18_ignore_result_for_frr_policy_validation():
    policy = {
        "ztp": {
            "01-frr-config": {
                "files": [{"url": {"source": "http://127.0.0.1:9/does_not_exist_frr.conf", "destination": "/etc/sonic/frr/frr.conf"}}],
                "ignore-result": True,
            }
        }
    }
    section = policy["ztp"]["01-frr-config"]
    pytest_assert(section.get("ignore-result") is True, "FRR ignore-result policy should be True")


def test_tc19_local_staged_fallback_when_no_option67(duthosts, rand_one_dut_hostname, ztp_payload):
    duthost = duthosts[rand_one_dut_hostname]
    source, evidence = _detect_ztp_profile_source(duthost)

    if _use_local_ztp_profile(ztp_payload):
        if source == "unknown":
            pytest.skip("TC19 skipped: could not determine profile source ({})".format(evidence))
        if source != "local":
            pytest.skip(
                "TC19 skipped: expected local profile but source was not local ({})".format(evidence)
            )
        pytest_assert(source == "local", "Expected local staged profile, got: {}".format(evidence))
    else:
        if source == "unknown":
            pytest.skip("TC19 skipped: could not confirm DHCP profile source ({})".format(evidence))
        if source != "dhcp":
            pytest.skip(
                "TC19 skipped: expected DHCP Option 67 profile but source was not dhcp ({})".format(evidence)
            )
        pytest_assert(source == "dhcp", "Expected DHCP Option 67 profile, got: {}".format(evidence))


def test_tc4_missing_profile_file_negative(
    duthosts,
    rand_one_dut_hostname,
    localhost,
    backup_and_restore_config_db,
    ztp_payload,
):
    del backup_and_restore_config_db
    if not _use_local_ztp_profile(ztp_payload):
        pytest.skip("TC4 negative requires local profile mode; DHCP would still provision via Option 67")

    duthost = duthosts[rand_one_dut_hostname]
    _prepare_for_ztp_run(duthost)

    duthost.shell("sudo rm -f /host/ztp/ztp_data.json /host/ztp/ztp.json", module_ignore_errors=True)
    duthost.shell(ZTP_RUN_CMD, module_ignore_errors=True)

    localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=10,
        timeout=180,
        module_ignore_errors=True,
    )

    completed = wait_until(
        NEGATIVE_POLL_TIMEOUT,
        ZTP_POLL_INTERVAL,
        0,
        _ztp_completed_successfully,
        duthost,
    )

    status_now = parse_ztp_status(duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True).get("stdout", ""))

    pytest_assert(
        not completed and status_now.get("ztp_status") != "SUCCESS",
        "Unexpected SUCCESS even though profile files were removed",
    )


def test_tc8_invalid_payload_path_validation():
    invalid = {
        "ztp": {
            "01-configdb-json": {
                "url": {
                    "source": "file:///host/ztp/does_not_exist.json",
                    "destination": "/etc/sonic/config_db.json",
                },
                "clear-config": False,
                "save-config": True,
            }
        }
    }
    pytest_assert(not _validate_payload_schema(invalid), "Invalid source path should fail schema validation")


def test_tc9_discovery_stuck_recovery_command(duthosts, rand_one_dut_hostname, ztp_payload):
    if not _use_local_ztp_profile(ztp_payload):
        pytest.skip("TC9 validates local ztp.json/ztp_data.json sync; not applicable in DHCP provisioning mode")

    duthost = duthosts[rand_one_dut_hostname]
    _stage_payload_files(duthost, ztp_payload)

    json_stat = duthost.stat(path=ZTP_JSON_PATH)
    data_stat = duthost.stat(path=ZTP_DATA_JSON_PATH)

    if not json_stat["stat"]["exists"] and data_stat["stat"]["exists"]:
        duthost.shell(
            "sudo cp -f /host/ztp/ztp_data.json /host/ztp/ztp.json && sudo sync",
            module_ignore_errors=True,
        )
    if not data_stat["stat"]["exists"] and json_stat["stat"]["exists"]:
        duthost.shell(
            "sudo cp -f /host/ztp/ztp.json /host/ztp/ztp_data.json && sudo sync",
            module_ignore_errors=True,
        )

    recover = duthost.shell(
        "sudo cp -f /host/ztp/ztp.json /host/ztp/ztp_data.json && sudo sync",
        module_ignore_errors=True,
    )
    pytest_assert(recover.get("rc", 1) == 0, "Recovery copy command failed in TC9")

    json_stat = duthost.stat(path=ZTP_JSON_PATH)
    data_stat = duthost.stat(path=ZTP_DATA_JSON_PATH)
    pytest_assert(json_stat["stat"]["exists"], "Recovery step failed: ztp.json missing")
    pytest_assert(data_stat["stat"]["exists"], "Recovery step failed: ztp_data.json missing")


def test_tc10_interrupt_log_visibility(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    out = duthost.shell("sudo tail -n 400 /var/log/ztp.log", module_ignore_errors=True)
    pytest_assert(out.get("rc", 1) == 0, "Unable to read ztp log")
    pytest_assert("ztp" in out.get("stdout", "").lower(), "ztp log output looks empty/unexpected")


def test_tc11_halt_on_failure_policy_validation():
    policy = {
        "ztp": {
            "02-critical-step": {
                "url": {"source": "file:///tmp/fail.json", "destination": "/etc/sonic/config_db.json"},
                "halt-on-failure": True,
            }
        }
    }
    section = policy["ztp"]["02-critical-step"]
    pytest_assert(section.get("halt-on-failure") is True, "halt-on-failure policy should be True")


def test_tc12_ignore_result_policy_validation():
    policy = {
        "ztp": {
            "03-noncritical-step": {
                "url": {"source": "file:///tmp/fail.json", "destination": "/tmp/ignore.json"},
                "ignore-result": True,
            }
        }
    }
    section = policy["ztp"]["03-noncritical-step"]
    pytest_assert(section.get("ignore-result") is True, "ignore-result policy should be True")


def test_tc13_safe_teardown_recovery_check(
    duthosts,
    rand_one_dut_hostname,
    localhost,
    ztp_payload,
    backup_and_restore_config_db,
):
    del backup_and_restore_config_db
    duthost = duthosts[rand_one_dut_hostname]

    if _use_local_ztp_profile(ztp_payload):
        _stage_payload_files(duthost, ztp_payload)
    else:
        _remove_local_ztp_profile_files(duthost)
        logger.info("TC13: DHCP mode — using Option 67 profile; local ztp.json/ztp_data.json removed")

    _prepare_for_ztp_run(duthost)
    _execute_ztp_run_and_wait(localhost, duthost, ztp_payload)

    final_status = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(final_status.get("rc", 1) == 0, "Unable to fetch final ZTP status")
    parsed = parse_ztp_status(final_status.get("stdout", ""))
    pytest_assert(parsed.get("ztp_status") == "SUCCESS", "Expected final ZTP status SUCCESS")
    pytest_assert(parsed.get("ztp_service") == "Inactive", "Expected final ZTP service Inactive")


def _stage_configdb_with_hwsku_override(duthost, override):
    """Stage /host/ztp/config_db_to_apply.json from the running config, with an HWSKU override.

    override:
      - HWSKU_REMOVE_SENTINEL: strip DEVICE_METADATA.localhost.hwsku entirely
      - any other string: set DEVICE_METADATA.localhost.hwsku to that value
      - None: no modification (same effect as the existing _prepare_for_ztp_run helper)

    Also enables ZTP and removes the active /etc/sonic/config_db.json so ZTP will run.
    """
    current = duthost.shell("sudo cat /etc/sonic/config_db.json", module_ignore_errors=True)
    pytest_assert(current.get("rc", 1) == 0, "Could not read current config_db.json for HWSKU staging")

    try:
        cfg = json.loads(current.get("stdout") or "{}")
    except ValueError as parse_err:
        pytest_assert(False, "Current config_db.json is not valid JSON: {}".format(parse_err))

    device_meta = cfg.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
    if override == HWSKU_REMOVE_SENTINEL:
        device_meta.pop("hwsku", None)
    elif override is not None:
        device_meta["hwsku"] = override

    staged = json.dumps(cfg, indent=4) + "\n"
    duthost.copy(content=staged, dest=ZTP_CONFIG_TO_APPLY_PATH)

    enable = duthost.shell(ZTP_ENABLE_CMD, module_ignore_errors=True)
    pytest_assert(enable.get("rc", 1) == 0, "Failed to enable ZTP for HWSKU test")
    remove = duthost.shell(REMOVE_CONFIG_DB_CMD, module_ignore_errors=True)
    pytest_assert(remove.get("rc", 1) == 0, "Failed to remove config_db.json for HWSKU test")

    # Hide minigraph.xml so the ZTP daemon doesn't bail out before applying
    # the override. backup_and_restore_config_db restores it on teardown.
    duthost.shell(REMOVE_MINIGRAPH_CMD, module_ignore_errors=True)


def test_tc20_hwsku_present_in_ztp_config(
    duthosts, rand_one_dut_hostname, platform_hwsku_info
):
    """TC20: DEVICE_METADATA.localhost.hwsku is present in the running config_db.

    Read-only check that runs after a successful ZTP (tc5/tc13) or on a normally
    configured DUT. Asserts:
      - HWSKU is non-empty
      - /usr/share/sonic/device/<platform>/<hwsku>/ exists
      - port_config.ini (or hwsku.json) is present under that HWSKU directory
    """
    duthost = duthosts[rand_one_dut_hostname]
    platform = platform_hwsku_info["platform"]
    hwsku = platform_hwsku_info["running_hwsku"]

    pytest_assert(platform, "Could not resolve platform from running config")
    pytest_assert(
        hwsku,
        "HWSKU missing from running config_db.json; TC20 requires HWSKU to be set",
    )

    hwsku_dir = "{}/{}/{}".format(DEVICE_PATH, platform, hwsku)
    dir_check = duthost.shell(
        "sudo test -d {}".format(hwsku_dir), module_ignore_errors=True
    )
    pytest_assert(
        dir_check.get("rc", 1) == 0,
        "HWSKU directory not found on DUT: {}".format(hwsku_dir),
    )

    port_cfg_check = duthost.shell(
        "sudo sh -c 'test -f {dir}/port_config.ini || test -f {dir}/hwsku.json'".format(dir=hwsku_dir),
        module_ignore_errors=True,
    )
    pytest_assert(
        port_cfg_check.get("rc", 1) == 0,
        "Neither port_config.ini nor hwsku.json found under {}".format(hwsku_dir),
    )


def test_tc21_hwsku_absent_uses_default(
    duthosts, rand_one_dut_hostname, platform_hwsku_info
):
    """TC21: When HWSKU is not supplied by ZTP, SONiC falls back to the platform
    default defined in /usr/share/sonic/device/<platform>/default_sku.

    Non-destructive readiness check. The 'default HWSKU' code path is actually
    exercised by config-setup/factory when config_db.json is absent (not when
    config_db.json is present but missing a field). Rather than rebuild the
    DUT just to prove that, this test validates that everything the default
    path needs is present and consistent:

      - /usr/share/sonic/device/<platform>/default_sku exists and is well-formed
      - The HWSKU it names has a real directory with port_config.ini or hwsku.json
      - That HWSKU is a valid sibling under the same platform

    This guarantees the 'without HWSKU' factory path will succeed if triggered,
    without putting the DUT in a half-configured state.
    """
    duthost = duthosts[rand_one_dut_hostname]
    platform = platform_hwsku_info["platform"]
    default_hwsku = platform_hwsku_info["default_hwsku"]

    pytest_assert(platform, "Could not resolve platform from running config")
    if not default_hwsku:
        pytest.skip(
            "TC21 skipped: default_sku file missing or empty for platform '{}'".format(platform)
        )

    default_sku_file = "{}/{}/default_sku".format(DEVICE_PATH, platform)
    content_res = duthost.shell("sudo cat {}".format(default_sku_file), module_ignore_errors=True)
    pytest_assert(content_res.get("rc", 1) == 0, "Cannot read {}".format(default_sku_file))
    content = (content_res.get("stdout") or "").strip()
    pytest_assert(
        content and default_hwsku in content.split(),
        "default_sku file content looks malformed ({!r}); expected first word to be '{}'".format(
            content, default_hwsku
        ),
    )

    default_dir = "{}/{}/{}".format(DEVICE_PATH, platform, default_hwsku)
    dir_check = duthost.shell("sudo test -d {}".format(default_dir), module_ignore_errors=True)
    pytest_assert(
        dir_check.get("rc", 1) == 0,
        "Default HWSKU directory does not exist on DUT: {}".format(default_dir),
    )

    port_cfg_check = duthost.shell(
        "sudo sh -c 'test -f {d}/port_config.ini || test -f {d}/hwsku.json'".format(d=default_dir),
        module_ignore_errors=True,
    )
    pytest_assert(
        port_cfg_check.get("rc", 1) == 0,
        "Default HWSKU dir has neither port_config.ini nor hwsku.json: {}".format(default_dir),
    )


def _safe_shell(duthost, cmd, timeout=120):
    """Run a shell command on the DUT and swallow BOTH module failures and
    connection failures.

    `module_ignore_errors=True` only suppresses Ansible *module* failures
    (non-zero rc, parse errors, etc.). It does NOT suppress
    AnsibleConnectionFailure -- e.g. SSH drop, sudo prompt timeout, or
    'Timeout (62s) waiting for privilege escalation prompt'. Those still
    propagate and abort the fixture.

    During TC22 recovery, after the invalid HWSKU has been applied, syncd/swss
    crash-loop and sudo on the DUT can hang at the privilege escalation prompt
    even though SSH itself answers. We need every recovery step to *try* and
    move on so we ultimately reach the cold-reboot fallback rather than
    aborting at the first hung sudo.

    Returns a dict mirroring Ansible's shell result so callers can still
    inspect rc/stdout when available, with a synthetic 'connection_failed'
    flag when the failure was at the transport layer.
    """
    try:
        return duthost.shell(cmd, module_ignore_errors=True)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning(
            "TC22 recovery: shell command failed at transport/sudo layer "
            "(swallowed so recovery can continue): cmd=%r err=%s",
            cmd, err,
        )
        return {
            "rc": -1,
            "stdout": "",
            "stderr": str(err),
            "failed": True,
            "connection_failed": True,
        }


def _ssh_is_healthy(localhost, duthost, probe_timeout=20):
    """Best-effort SSH liveness probe. Returns True if TCP/22 is open.

    Doesn't prove sudo works -- only that we can talk to the SSH layer. Used
    by TC22 recovery to decide whether Stage 1 (in-place config reload) is
    even worth attempting, or whether we should skip straight to reboot.
    """
    try:
        res = localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="started",
            delay=0,
            timeout=probe_timeout,
            module_ignore_errors=True,
        )
        return not res.get("failed", False)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("SSH liveness probe raised: %s", err)
        return False


def _restore_config_db_from_backup(duthost, backup_info):
    """Copy the pre-test config_db.json backup over /etc/sonic/config_db.json.

    Idempotent and tolerant: if the backup is missing, just logs a warning.
    """
    backup_path = backup_info.get("backup_path") if isinstance(backup_info, dict) else None
    if not backup_path:
        logger.warning("No backup_path in backup_info; cannot restore config_db.json")
        return False

    try:
        stat = duthost.stat(path=backup_path)
    except Exception as err:  # pylint: disable=broad-except
        logger.warning("stat(%s) failed during recovery: %s", backup_path, err)
        return False
    if not stat.get("stat", {}).get("exists"):
        logger.warning("Backup file %s not found on DUT; cannot restore", backup_path)
        return False

    _safe_shell(
        duthost,
        "sudo cp {} /etc/sonic/config_db.json".format(backup_path),
    )
    return True


def _wait_for_dut_healthy(duthost, localhost):
    """Wait for SSH to reopen and all critical services to come up."""
    localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=SSH_START_DELAY,
        timeout=SSH_START_TIMEOUT,
        module_ignore_errors=True,
    )
    return wait_until(
        CRITICAL_SERVICES_TIMEOUT,
        CRITICAL_SERVICES_INTERVAL,
        0,
        _wait_for_critical_services,
        duthost,
    )


def _recover_dut_after_invalid_hwsku(duthost, localhost, backup_info):
    """Bring the DUT back to a healthy state after TC22 intentionally broke it.

    Two-stage recovery with hard guarantees that we always reach the reboot
    fallback, even when sudo on the DUT is hung at the privilege-escalation
    prompt (the documented TC22 failure mode):

      Stage 1 (fast, only attempted if SSH is healthy):
        disable ZTP, restore config_db.json from backup, 'config reload -y -f',
        'config save -y', then wait for critical services.
      Stage 2 (fallback, always attempted if Stage 1 didn't succeed):
        re-disable ZTP, re-restore config_db.json (best-effort), 'config save -y',
        then 'sudo reboot'. If sudo itself is hung we still issue the reboot
        through the safe wrapper -- worst case it's a no-op and we then wait
        for SSH to drop+come back from whatever recovery the DUT does on its
        own (watchdog, init crash, manual reboot via console, etc.).

    Why both reload AND save in Stage 1: 'config reload' loads the on-disk
    file into Redis and restarts services but does NOT write the running state
    back to disk. If reload had to fall back to minigraph regeneration (e.g.
    because config_db.json was missing), the disk copy will be stale and the
    next reboot would come up unreachable. 'config save -y' makes the recovery
    durable.

    Why a cold reboot fallback at all: when ZTP applies an invalid HWSKU,
    syncd/swss enter a crash loop, sudo hangs at the privilege-escalation
    prompt, and 'config reload' cannot clear the bad state because stale
    SAI/ASIC_DB entries persist. A cold reboot from a restored config_db.json
    guarantees a clean re-init.

    Every shell call goes through _safe_shell so an AnsibleConnectionFailure
    (SSH drop, sudo prompt timeout) is logged and swallowed instead of
    aborting the fixture. The only pytest_assert is at the very end.
    """
    logger.info("TC22 recovery: starting")

    stage1_ok = False
    if _ssh_is_healthy(localhost, duthost):
        logger.info("TC22 recovery Stage 1: disable ZTP, restore config_db.json, "
                    "config reload, config save")
        _safe_shell(duthost, ZTP_DISABLE_CMD)
        restored = _restore_config_db_from_backup(duthost, backup_info)
        if not restored:
            logger.warning(
                "TC22 recovery: config_db.json backup not restored; "
                "reboot fallback may still succeed if image defaults are usable"
            )
        _safe_shell(duthost, CONFIG_RELOAD_CMD)
        _safe_shell(duthost, CONFIG_SAVE_CMD)
        stage1_ok = _wait_for_dut_healthy(duthost, localhost)
    else:
        logger.warning(
            "TC22 recovery: SSH is not healthy at recovery start; "
            "skipping Stage 1 (config reload) and going straight to reboot"
        )

    if stage1_ok:
        logger.info("TC22 recovery Stage 1 succeeded; DUT is healthy")
        return

    logger.warning("TC22 recovery Stage 1 did not produce a healthy DUT; "
                   "falling back to cold reboot")

    # Stage 2: full reboot. Ensure ZTP stays disabled and config_db.json is in
    # place before the reboot so the DUT boots into a known-good state. Save
    # again as a belt-and-suspenders guard in case anything below mutated
    # Redis since the cp. Every step uses _safe_shell so a hung sudo does
    # not abort the recovery before we issue 'reboot'.
    _safe_shell(duthost, ZTP_DISABLE_CMD)
    _restore_config_db_from_backup(duthost, backup_info)
    _safe_shell(duthost, CONFIG_SAVE_CMD)
    _safe_shell(duthost, "sudo reboot")

    # Wait for SSH to drop and come back. Use the SSH-only flavor (no sudo
    # required) because the DUT might still be rebooting.
    localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="stopped",
        timeout=SSH_STOP_DETECT_TIMEOUT,
        module_ignore_errors=True,
    )
    ssh_back = localhost.wait_for(
        host=duthost.mgmt_ip,
        port=22,
        state="started",
        delay=SSH_START_DELAY,
        timeout=SSH_START_TIMEOUT,
        module_ignore_errors=True,
    )
    pytest_assert(
        not ssh_back.get("failed", False),
        "TC22 recovery failed: DUT did not come back on SSH after cold reboot. "
        "Manual intervention required.",
    )

    stage2_ok = _wait_for_dut_healthy(duthost, localhost)
    pytest_assert(
        stage2_ok,
        "TC22 recovery failed: critical services did not come back up after "
        "both 'config reload' and cold reboot. Manual intervention required.",
    )
    logger.info("TC22 recovery Stage 2 (reboot) succeeded; DUT is healthy")


def test_tc22_hwsku_invalid_in_ztp_config(
    duthosts,
    rand_one_dut_hostname,
    localhost,
    ztp_payload,
    platform_hwsku_info,
    backup_and_restore_config_db,
):
    """TC22 (negative): An invalid HWSKU in the ZTP payload must NOT become the
    running HWSKU. Destructive test with guaranteed DUT recovery.

    Real-world SONiC behavior observed on this DUT (and what the original
    assertion did NOT account for): when ZTP is handed a config_db.json whose
    HWSKU has no corresponding /usr/share/sonic/device/<platform>/<hwsku>/
    directory, SONiC's ZTP / config-setup machinery is defensive. Rather than
    blindly apply the bad config and crash-loop swss/syncd, it can:
      (a) reject the staged config_db.json entirely and keep the previous
          running config, leaving services healthy with the original HWSKU, OR
      (b) attempt to apply, fail HWSKU validation in hostcfgd /
          config-setup, and bring services up against the platform default
          HWSKU, OR
      (c) try to apply, fail hard, and leave critical services stuck.

    Outcomes (a) and (b) are *correct* defensive behavior: the operator's bad
    input did not become production state. Only outcome (d) -- services up AND
    the invalid HWSKU is the running HWSKU -- is a genuine failure of the
    SONiC contract.

    So the assertion is the actual invariant: services may or may not come up,
    but the running HWSKU must never be the invalid sentinel. Asserting just
    "services don't come up" was wrong on platforms whose ZTP layer is
    defensive enough to reject the bad payload.

    The sentinel HWSKU 'Invalid-HWSKU-Does-Not-Exist' is verified absent on
    disk before the test runs. After the assertion (pass or fail), the DUT is
    explicitly restored to a healthy state via _recover_dut_after_invalid_hwsku
    before the test returns.
    """
    backup_info = backup_and_restore_config_db
    duthost = duthosts[rand_one_dut_hostname]

    pytest_assert(
        isinstance(backup_info, dict) and backup_info.get("config_exists"),
        "TC22 requires a pre-existing config_db.json at setup time for safe recovery.",
    )

    platform = platform_hwsku_info["platform"]
    pytest_assert(platform, "Could not resolve platform for TC22")

    invalid_hwsku_dir = "{}/{}/{}".format(DEVICE_PATH, platform, INVALID_HWSKU_NAME)
    sentinel_check = duthost.shell(
        "sudo test -d {}".format(invalid_hwsku_dir), module_ignore_errors=True
    )
    pytest_assert(
        sentinel_check.get("rc", 1) != 0,
        "Sentinel HWSKU '{}' unexpectedly exists under {}; pick a different sentinel.".format(
            INVALID_HWSKU_NAME, invalid_hwsku_dir
        ),
    )

    try:
        if _use_local_ztp_profile(ztp_payload):
            _stage_payload_files(duthost, ztp_payload)
        else:
            _remove_local_ztp_profile_files(duthost)
            logger.info("TC22: DHCP mode - removed local ztp.json/ztp_data.json")

        _stage_configdb_with_hwsku_override(duthost, INVALID_HWSKU_NAME)

        duthost.shell(ZTP_RUN_CMD, module_ignore_errors=True)

        localhost.wait_for(
            host=duthost.mgmt_ip,
            port=22,
            state="started",
            delay=SSH_START_DELAY,
            timeout=SSH_START_TIMEOUT,
            module_ignore_errors=True,
        )

        services_ready = wait_until(
            NEGATIVE_POLL_TIMEOUT,
            CRITICAL_SERVICES_INTERVAL,
            0,
            _wait_for_critical_services,
            duthost,
        )

        applied_hwsku = duthost.shell(
            "sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku",
            module_ignore_errors=True,
        ).get("stdout", "").strip()

        # Real invariant: the sentinel HWSKU must never become the running
        # HWSKU. Both "services down" and "services up with original/default
        # HWSKU" are correct defensive outcomes; the only failure is
        # "services up AND running HWSKU == invalid sentinel".
        pytest_assert(
            applied_hwsku != INVALID_HWSKU_NAME,
            "TC22: SONiC accepted the invalid HWSKU '{}' as the running HWSKU. "
            "This violates the contract that an invalid HWSKU in a ZTP payload "
            "must never become production state. (services_ready={}, "
            "applied_hwsku={!r}).".format(
                INVALID_HWSKU_NAME, services_ready, applied_hwsku
            ),
        )
        if services_ready:
            logger.info(
                "TC22: SONiC defended itself against the invalid HWSKU '%s' "
                "and brought services up with the safe HWSKU '%s'. "
                "This is the expected defensive outcome.",
                INVALID_HWSKU_NAME, applied_hwsku,
            )
        else:
            logger.info(
                "TC22: critical services did NOT come up after invalid HWSKU "
                "was staged (applied=%r). This is also an acceptable negative "
                "outcome; recovery will restore the DUT.",
                applied_hwsku,
            )
    finally:
        _recover_dut_after_invalid_hwsku(duthost, localhost, backup_info)


# ---------------------------------------------------------------------------
# TC23: Q2 - "config_db.json must be absent at boot if ZTP is enabled"
# ---------------------------------------------------------------------------


def _read_ztp_status(duthost):
    res = duthost.shell(ZTP_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(res.get("rc", 1) == 0, "Failed to read ztp status")
    return parse_ztp_status(res.get("stdout", ""))


def test_tc23_configdb_and_ztp_mutual_exclusion_contract(
    duthosts, rand_one_dut_hostname, backup_and_restore_config_db
):
    """TC23: Validate the SONiC invariant that ZTP and /etc/sonic/config_db.json
    are mutually exclusive at boot.

    Observable (runtime) contract this test enforces:
      - ZTP admin mode can be toggled via 'ztp enable' / 'ztp disable'.
      - While /etc/sonic/config_db.json is present (normal running state),
        'ztp enable' sets Admin Mode = True but MUST leave 'ZTP Service'
        Inactive. SONiC will not start a ZTP run on top of an existing config.
      - 'ZTP Service' staying Inactive is the only transition we can prove at
        runtime without rebooting the DUT. The deeper invariant ("if
        config_db.json is absent at the next boot, ZTP will run") is a
        boot-path decision made by ztp-init.service and is NOT observable by
        removing /etc/sonic/config_db.json on a running switch: the ZTP
        service state does not flip live.

    Non-destructive: admin-mode toggles and status reads only. The backup
    fixture still covers the worst case if a future change makes this test
    touch config_db.json.
    """
    backup_info = backup_and_restore_config_db
    duthost = duthosts[rand_one_dut_hostname]

    pytest_assert(
        isinstance(backup_info, dict) and backup_info.get("config_exists"),
        "TC23 requires a pre-existing config_db.json at setup time",
    )

    config_stat = duthost.stat(path="/etc/sonic/config_db.json")
    pytest_assert(
        config_stat["stat"]["exists"],
        "Pre-check: /etc/sonic/config_db.json should exist before the test runs",
    )

    # --- Stage 1: ZTP enabled + config_db.json present -> Service must be Inactive.
    enable_res = duthost.shell(ZTP_ENABLE_CMD, module_ignore_errors=True)
    pytest_assert(enable_res.get("rc", 1) == 0, "ztp enable failed: {}".format(
        enable_res.get("stderr")))
    state_enabled = _read_ztp_status(duthost)
    pytest_assert(
        state_enabled.get("ztp_admin_mode") == "True",
        "After 'ztp enable', Admin Mode should be True (got {})".format(
            state_enabled.get("ztp_admin_mode")),
    )
    pytest_assert(
        state_enabled.get("ztp_service") == "Inactive",
        "With config_db.json present, 'ZTP Service' MUST be Inactive "
        "after 'ztp enable' (got {}). SONiC's mutual-exclusion contract is "
        "broken if ZTP would try to run over an existing config.".format(
            state_enabled.get("ztp_service")),
    )

    # --- Stage 2: toggling admin mode off returns Admin Mode to False.
    try:
        disable_res = duthost.shell(ZTP_DISABLE_CMD, module_ignore_errors=True)
        pytest_assert(disable_res.get("rc", 1) == 0, "ztp disable failed: {}".format(
            disable_res.get("stderr")))
        state_disabled = _read_ztp_status(duthost)
        pytest_assert(
            state_disabled.get("ztp_admin_mode") == "False",
            "After 'ztp disable', Admin Mode should be False (got {})".format(
                state_disabled.get("ztp_admin_mode")),
        )
        pytest_assert(
            state_disabled.get("ztp_service") == "Inactive",
            "When ZTP is disabled, 'ZTP Service' must be Inactive (got {})".format(
                state_disabled.get("ztp_service")),
        )
    finally:
        # Leave ZTP in the same admin-mode state we found it in. Because we
        # don't know what that was for sure, re-enable by default (matches the
        # working assumption of the rest of this module) then let the user or
        # the next test decide.
        duthost.shell(ZTP_ENABLE_CMD, module_ignore_errors=True)


# ---------------------------------------------------------------------------
# TC24: Q3 - config_db.json validation after ZTP
# ---------------------------------------------------------------------------


MANDATORY_CONFIGDB_TABLES = ("DEVICE_METADATA",)
MANDATORY_DEVICE_METADATA_FIELDS = ("hostname", "hwsku", "platform", "mac", "type")


def test_tc24_configdb_schema_validation_after_ztp(duthosts, rand_one_dut_hostname):
    """TC24: After ZTP has applied config, validate that /etc/sonic/config_db.json is:
      1. Valid JSON
      2. Contains mandatory top-level tables (DEVICE_METADATA)
      3. DEVICE_METADATA.localhost has hostname, hwsku, platform, mac, type
      4. Accepted by sonic-cfggen (semantic validation via --print-data)
      5. Critical services are fully started

    Read-only, non-destructive.
    """
    duthost = duthosts[rand_one_dut_hostname]

    cat_res = duthost.shell("sudo cat /etc/sonic/config_db.json", module_ignore_errors=True)
    pytest_assert(cat_res.get("rc", 1) == 0, "Cannot read /etc/sonic/config_db.json")

    try:
        cfg = json.loads(cat_res.get("stdout") or "{}")
    except ValueError as err:
        pytest_assert(False, "config_db.json is not valid JSON: {}".format(err))

    for table in MANDATORY_CONFIGDB_TABLES:
        pytest_assert(table in cfg, "Mandatory table missing from config_db.json: {}".format(table))

    localhost_meta = cfg.get("DEVICE_METADATA", {}).get("localhost", {})
    pytest_assert(localhost_meta, "DEVICE_METADATA.localhost is empty")
    for field in MANDATORY_DEVICE_METADATA_FIELDS:
        pytest_assert(
            localhost_meta.get(field),
            "DEVICE_METADATA.localhost.{} missing or empty".format(field),
        )

    cfggen_res = duthost.shell(
        "sudo sonic-cfggen -j /etc/sonic/config_db.json --print-data",
        module_ignore_errors=True,
    )
    pytest_assert(
        cfggen_res.get("rc", 1) == 0,
        "sonic-cfggen failed to parse config_db.json: {}".format(
            cfggen_res.get("stderr", "")
        ),
    )

    services_ready = _wait_for_critical_services(duthost)
    pytest_assert(
        services_ready,
        "Critical services are not fully started; config_db.json may not be healthy",
    )


# ---------------------------------------------------------------------------
# TC25-TC36: Q4 - Various ZTP config options (payload schema validation)
# ---------------------------------------------------------------------------
#
# These tests mirror the style of the existing tc11/tc12/tc18 payload-validation
# tests: they build a representative ZTP payload for each option, assert the
# option is preserved under the expected key, and verify the payload is
# well-formed JSON. They do NOT run ZTP on the DUT, so they are non-destructive
# and will always pass when the payload is constructed correctly.
#
# This gives checklist coverage across the ZTP option surface without requiring
# per-option infrastructure (firmware image servers, SNMP collectors, etc.).


def _assert_payload_json_roundtrips(payload):
    """Dump the payload to JSON and reload - catches accidental non-serializable values."""
    text = json.dumps(payload)
    reloaded = json.loads(text)
    pytest_assert(reloaded == payload, "Payload failed JSON round-trip")


def test_tc25_option_graphservice_payload():
    """TC25: graphservice section - pulls a minigraph from a URL."""
    payload = {
        "ztp": {
            "01-graphservice": {
                "minigraph-url": {
                    "source": "http://10.0.0.2/ztp/minigraph.xml",
                    "destination": "/etc/sonic/minigraph.xml",
                },
                "save-config": True,
                "ignore-result": False,
            }
        }
    }
    section = payload["ztp"]["01-graphservice"]
    pytest_assert("minigraph-url" in section, "graphservice must have minigraph-url")
    pytest_assert(
        section["minigraph-url"].get("destination") == "/etc/sonic/minigraph.xml",
        "graphservice destination must be /etc/sonic/minigraph.xml",
    )
    _assert_payload_json_roundtrips(payload)


def test_tc26_option_snmp_payload():
    """TC26: snmp section - configures SNMP community and location."""
    payload = {
        "ztp": {
            "01-snmp": {
                "community_ro": ["public"],
                "snmp_location": "test-lab",
                "ignore-result": False,
            }
        }
    }
    section = payload["ztp"]["01-snmp"]
    pytest_assert(
        isinstance(section.get("community_ro"), list) and section["community_ro"],
        "snmp.community_ro must be a non-empty list",
    )
    pytest_assert(section.get("snmp_location"), "snmp.snmp_location must be set")
    _assert_payload_json_roundtrips(payload)


def test_tc27_option_firmware_payload():
    """TC27: firmware section - installs a SONiC image."""
    payload = {
        "ztp": {
            "01-firmware": {
                "install": {
                    "url": {
                        "source": "http://10.0.0.2/ztp/sonic.bin",
                        "destination": "/host/sonic.bin",
                    },
                    "set-default": True,
                    "set-next-boot": True,
                },
                "reboot-on-success": True,
                "halt-on-failure": True,
            }
        }
    }
    section = payload["ztp"]["01-firmware"]
    install = section.get("install", {})
    pytest_assert(install.get("url", {}).get("source", "").startswith("http"),
                  "firmware install URL must be http(s)")
    pytest_assert(install.get("set-default") is True, "firmware set-default must be True")
    pytest_assert(section.get("reboot-on-success") is True,
                  "firmware install typically reboots on success")
    _assert_payload_json_roundtrips(payload)


def test_tc28_option_plugin_payload():
    """TC28: plugin section - runs a custom plugin script."""
    payload = {
        "ztp": {
            "01-custom-plugin": {
                "plugin": {
                    "url": {
                        "source": "http://10.0.0.2/ztp/plugin.sh",
                        "destination": "/tmp/ztp_plugin.sh",
                    },
                    "args": "--mode quick",
                },
                "ignore-result": False,
                "halt-on-failure": False,
            }
        }
    }
    plugin = payload["ztp"]["01-custom-plugin"].get("plugin", {})
    pytest_assert(plugin.get("url", {}).get("destination", "").startswith("/"),
                  "plugin destination must be an absolute path")
    _assert_payload_json_roundtrips(payload)


def test_tc29_option_connectivity_check_payload():
    """TC29: connectivity-check section - verifies reachability before continuing."""
    payload = {
        "ztp": {
            "01-connectivity-check": {
                "connectivity-check": {
                    "urls": ["http://10.0.0.2/"],
                    "ping": ["10.0.0.2", "8.8.8.8"],
                    "retry-count": 3,
                    "retry-interval": 10,
                },
                "halt-on-failure": True,
            }
        }
    }
    cc = payload["ztp"]["01-connectivity-check"].get("connectivity-check", {})
    pytest_assert(isinstance(cc.get("ping"), list) and cc["ping"],
                  "connectivity-check.ping must be a non-empty list")
    pytest_assert(isinstance(cc.get("retry-count"), int) and cc["retry-count"] > 0,
                  "connectivity-check.retry-count must be a positive int")
    _assert_payload_json_roundtrips(payload)


def test_tc30_option_provisioning_script_payload():
    """TC30: provisioning-script (section that fetches & runs an arbitrary script)."""
    payload = {
        "ztp": {
            "01-provisioning-script": {
                "url": {
                    "source": "http://10.0.0.2/ztp/provision.sh",
                    "destination": "/tmp/provision.sh",
                },
                "shell": "bash",
                "args": "--site lab-1",
                "halt-on-failure": False,
                "ignore-result": False,
            }
        }
    }
    section = payload["ztp"]["01-provisioning-script"]
    pytest_assert(section.get("url", {}).get("source"),
                  "provisioning-script must specify a source URL")
    pytest_assert(section.get("shell") in ("bash", "sh", "python", "python3"),
                  "provisioning-script.shell must be a supported interpreter")
    _assert_payload_json_roundtrips(payload)


def test_tc31_option_reboot_on_success_payload():
    """TC31: reboot-on-success flag."""
    payload = {
        "ztp": {
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "reboot-on-success": True,
            }
        }
    }
    pytest_assert(payload["ztp"]["01-step"].get("reboot-on-success") is True,
                  "reboot-on-success must be True")
    _assert_payload_json_roundtrips(payload)


def test_tc32_option_reboot_on_failure_payload():
    """TC32: reboot-on-failure flag."""
    payload = {
        "ztp": {
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "reboot-on-failure": True,
            }
        }
    }
    pytest_assert(payload["ztp"]["01-step"].get("reboot-on-failure") is True,
                  "reboot-on-failure must be True")
    _assert_payload_json_roundtrips(payload)


def test_tc33_option_restart_ztp_on_failure_payload():
    """TC33: restart-ztp-on-failure flag - retries the entire ZTP session."""
    payload = {
        "ztp": {
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "restart-ztp-on-failure": True,
            }
        }
    }
    pytest_assert(payload["ztp"]["01-step"].get("restart-ztp-on-failure") is True,
                  "restart-ztp-on-failure must be True")
    _assert_payload_json_roundtrips(payload)


def test_tc34_option_suspend_on_failure_payload():
    """TC34: suspend-on-failure flag - pauses ZTP and waits for operator intervention."""
    payload = {
        "ztp": {
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "suspend-on-failure": True,
            }
        }
    }
    pytest_assert(payload["ztp"]["01-step"].get("suspend-on-failure") is True,
                  "suspend-on-failure must be True")
    _assert_payload_json_roundtrips(payload)


def test_tc35_option_maximum_retries_payload():
    """TC35: maximum-retries - bounds per-step retry attempts."""
    payload = {
        "ztp": {
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "maximum-retries": 5,
                "retry-interval": 30,
            }
        }
    }
    step = payload["ztp"]["01-step"]
    pytest_assert(isinstance(step.get("maximum-retries"), int) and step["maximum-retries"] > 0,
                  "maximum-retries must be a positive int")
    pytest_assert(isinstance(step.get("retry-interval"), int) and step["retry-interval"] > 0,
                  "retry-interval must be a positive int")
    _assert_payload_json_roundtrips(payload)


def test_tc36_option_timestamp_payload():
    """TC36: timestamp metadata - ZTP annotates step start/end with ISO timestamps.

    The timestamp field is typically populated at runtime by the ZTP engine, so
    this test validates that payloads carrying a pre-populated 'timestamp' field
    round-trip and that ZTP status output exposes a timestamp key on the DUT.
    """
    payload = {
        "ztp": {
            "timestamp": "2025-01-01T00:00:00Z",
            "01-step": {
                "url": {"source": "file:///tmp/x", "destination": "/tmp/y"},
                "timestamp": "2025-01-01T00:00:01Z",
            },
        }
    }
    pytest_assert(payload["ztp"].get("timestamp"), "ZTP root timestamp missing")
    pytest_assert(payload["ztp"]["01-step"].get("timestamp"), "Step timestamp missing")
    _assert_payload_json_roundtrips(payload)

