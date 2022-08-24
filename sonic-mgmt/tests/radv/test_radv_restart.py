from datetime import datetime
import pytest

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any')
]


# For this Test gap "Restarting radv causes swss service to restart"
# see details at
# https://github.com/sonic-net/sonic-mgmt/issues/6042
def test_radv_swss(duthost):
    """swss does not restart while radv restarting

    Args:
        duthost: AnsiblecHost instance for DUT
    """

    # 1. check status of swss.service
    swss_stdout_lines = duthost.shell("systemctl show -p ActiveState -p ActiveEnterTimestamp swss.service")[
        "stdout_lines"]
    swss_status_dict_before = parse_service_status(swss_stdout_lines)

    # make sure swss is running
    assert swss_status_dict_before is not None and swss_status_dict_before.get(
        "ActiveState") == "active", "service swss is not running"

    # 2. restart radv.service
    duthost.shell("sudo systemctl restart radv.service")

    # 3. check status of radv.service
    radv_stdout_lines = duthost.shell("systemctl show -p ActiveState -p ActiveEnterTimestamp radv.service")[
        "stdout_lines"]
    radv_status_dict = parse_service_status(radv_stdout_lines)

    # make sure radv run successfully
    assert radv_status_dict is not None and radv_status_dict.get(
        "ActiveState") == "active", "service radv is not running"

    # 4. check status of swss.service
    swss_stdout_lines = duthost.shell("systemctl show -p ActiveState -p ActiveEnterTimestamp swss.service")[
        "stdout_lines"]
    swss_status_dict = parse_service_status(swss_stdout_lines)
    # make sure the ActiveSate is active
    assert swss_status_dict is not None and swss_status_dict.get(
        "ActiveState") == "active", "service swss is not running after restart radv.service"

    # 5. verify "Restarting radv causes swss service to restart" or not
    # compare ActiveEnterTimestamp of swss.service with radv.service, and compare ActiveEnterTimestamp of swss.service
    # before and after radv.service restarts.
    date_format = "%a %Y-%m-%d %H:%M:%S %Z"
    datetime_swss_before = datetime.strptime(swss_status_dict_before.get("ActiveEnterTimestamp"), date_format)
    datetime_swss = datetime.strptime(swss_status_dict.get("ActiveEnterTimestamp"), date_format)
    datetime_radv = datetime.strptime(radv_status_dict.get("ActiveEnterTimestamp"), date_format)
    assert datetime_swss < datetime_radv and datetime_swss == datetime_swss_before, "service swss also restarted while radv restarting"


def parse_service_status(service_status_stdout_lines):
    """parse the service status from array format into dictionary format

    Args:
        service_status_stdout_lines: "stdout_lines" field for the result of duthost.shell(). Type is array, each element is a string. For example:

        ["ActiveState=active",
        "ActiveEnterTimestamp=Tue 2022-08-09 10:30:58 UTC"]

    Returns:
        A dictionary which holds the service status. For example:

        {"ActiveState": "active",
         "ActiveEnterTimestamp": "Tue 2022-08-09 10:30:58 UTC"}
    """

    # check empty
    if not service_status_stdout_lines:
        return None

    service_status_dict = {}
    # parsing
    for line in service_status_stdout_lines:
        fields = line.split("=")
        if len(fields) == 2:
            service_status_dict[fields[0]] = fields[1]

    return service_status_dict
