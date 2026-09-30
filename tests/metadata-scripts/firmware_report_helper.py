import json
import logging
import os
import shlex

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

ERROR_REPORT_GUID = "44444444-5555-4666-8777-888888888888"
ERROR_REPORT_HARNESS_SOURCE = os.path.join(os.path.dirname(__file__), "unmapped_failure_report_harness.sh")
EXPECTED_SOURCE_TEXT = 'NGS_DEVICE_TYPE=$(redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "type")'


def find_metadata_actions_dir():
    """Locate the metadata checkout used by direct CI or Elastictest."""
    for relative_path in (
        "../../../sonic-metadata/scripts/update_firmware_actions_data",
        "../../sonic-metadata/scripts/update_firmware_actions_data",
    ):
        path = os.path.abspath(os.path.join(os.path.dirname(__file__), relative_path))
        if os.path.isdir(path):
            return path
    return None


def verify_unmapped_update_firmware_failure_report(duthost, metadata_actions_dir):
    """Exercise the real firmware entry in isolation and retain its failure report."""
    pytest_assert(metadata_actions_dir is not None, "SONiC metadata checkout is required for report validation")
    required_files = (
        "sonic-error-report.py",
        "sonic-report-functions.sh",
        "update-firmware-error-codes.sh",
        "reboot-error-codes.sh",
        "platforms.sh",
        "flag.sh",
    )
    firmware_source = os.path.join(os.path.dirname(metadata_actions_dir), "update_firmware")
    with open(firmware_source) as source:
        source_line = source.read().splitlines().index(EXPECTED_SOURCE_TEXT) + 1

    for filename in required_files:
        source = os.path.join(metadata_actions_dir, filename)
        pytest_assert(os.path.isfile(source), "Required metadata script not found: {}".format(source))
    pytest_assert(os.path.isfile(ERROR_REPORT_HARNESS_SOURCE), "Error report harness not found")

    artifact_dir = "logs/metadata-scripts/unmapped-failure-report/{}/".format(duthost.hostname)
    test_dir = None
    try:
        test_dir = duthost.command(
            "mktemp -d /tmp/update-firmware-error-report-test.XXXXXX"
        )["stdout"].strip()
        pytest_assert(test_dir, "Failed to create DUT error-report test directory")
        report_path = os.path.join(
            test_dir, "root/host/sonic-upgrade-reports",
            "update_firmware.{}.json".format(ERROR_REPORT_GUID),
        )
        harness_path = os.path.join(test_dir, "unmapped-failure.sh")
        actions_path = os.path.join(test_dir, "update_firmware_actions_data")
        duthost.file(path=actions_path, state="directory")
        for filename in required_files:
            duthost.copy(src=os.path.join(metadata_actions_dir, filename), dest=os.path.join(actions_path, filename))
        duthost.copy(src=firmware_source, dest=os.path.join(test_dir, "update_firmware"))
        duthost.copy(src=ERROR_REPORT_HARNESS_SOURCE, dest=harness_path)

        result = duthost.command(
            "/usr/bin/sudo timeout 60 /bin/bash {} {} {}".format(
                shlex.quote(harness_path), shlex.quote(test_dir), shlex.quote(ERROR_REPORT_GUID),
            ),
            module_ignore_errors=True,
        )
        pytest_assert(
            result.get("rc") == 1,
            "Expected native exit code 1, got rc={} stderr={}".format(result.get("rc"), result.get("stderr")),
        )
        report_result = duthost.command("cat {}".format(shlex.quote(report_path)))
        logger.info("update_firmware error report JSON from %s (%s):\n%s",
                    duthost.hostname, report_path, report_result["stdout"])
        duthost.fetch(src=report_path, dest=artifact_dir, flat=True)
        report = json.loads(report_result["stdout"])
        summary = report["sonic_upgrade_summary"]
        errors = report["sonic_upgrade_report"]["errors"]

        pytest_assert(summary["fault_code"] == "9", "Unexpected summary: {}".format(summary))
        expected_reason = (
            "SONiC update_firmware unmapped error (fault code 9, native exit code 1); "
            "unhandled failure at update_firmware:{} in main; source line: {}"
        ).format(source_line, EXPECTED_SOURCE_TEXT)
        pytest_assert(summary["fault_reason"] == expected_reason,
                      "Unexpected fault reason: {}".format(summary["fault_reason"]))
        pytest_assert(len(errors) == 1, "Expected one report error, got: {}".format(errors))
        pytest_assert(errors[0]["name"] == "EXIT_CODE_9", "Unexpected report error: {}".format(errors[0]))
        pytest_assert(errors[0]["message"] == summary["fault_reason"],
                      "Report error does not match summary: {}".format(errors[0]))
    finally:
        if test_dir:
            duthost.file(path=test_dir, state="absent")

    logger.info("UNMAPPED_FIRMWARE_REPORT_VERIFIED dut=%s expected_exit=1 actual_exit=%s "
                "expected_fault_code=9 actual_fault_code=%s source=update_firmware:%s artifact=%s cleanup=complete",
                duthost.hostname, result["rc"], summary["fault_code"], source_line,
                os.path.join(artifact_dir, os.path.basename(report_path)))
