from __future__ import print_function

import argparse
import json
import os
import sys
import time

import requests

DEFAULT_LOCK_HOURS = 36


def _get_token(tenant_id, client_id, client_secret):
    token_url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenant_id)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "api://sonic-testbed-tools-prod/.default"
    }
    try:
        resp = requests.post(token_url, headers=headers, data=payload, timeout=10).json()
        return resp["access_token"]
    except Exception as e:
        print("Get token failed with exception: {}".format(repr(e)))
    return None


def _create_test_plan(testbed_tools_url, name, token, test_type):
    url = "{}/test_plan".format(testbed_tools_url)

    payload = json.dumps({
        "name": name,
        "testbed": {
            "platform": "kvm",
            "hwsku": "any|<specific_hwsku regex>",
            "topology": test_type,
            "image_url": "<http_url>|",
            "min": 1,
            "max": 2
        },
        "test_option": {
            "stop_on_failure": True,
            "retry_times": 2,
            "test_cases": {
                "features": [],
                "scripts": get_test_cases(test_type),
                "features_exclude": [],
                "scripts_exclude": []
            },
            "common_params": [
            ],
            "specified_params": {
            }
        },
        "extra_params":{
            "pull_request_id": os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
        },
        "priority": 10,
        "requester": "pull request"
    })
    headers = {
        "Authorization": "Bearer {}".format(token),
        "scheduler-site": "PRTest",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=10).json()
        if not resp["success"]:
            print("Create test plan failed with error: {}".format(resp["errmsg"]))
            return None
        return resp["data"]
    except Exception as e:
        print("Create test plan failed with exception: {}".format(repr(e)))


def _cancel_test_plan(testbed_tools_url, test_plan_id, token):
    url = "{}/test_plan/{}/cancel".format(testbed_tools_url, test_plan_id)

    payload = json.dumps({})
    headers = {
        "Authorization": "Bearer {}".format(token),
        "scheduler-site": "PRTest",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(url, headers=headers, data=payload, timeout=10).json()
        if not resp["success"]:
            print("Cancel test plan failed with error: {}".format(resp["errmsg"]))
            return None
        return resp["data"]
    except Exception as e:
        print("Cancel test plan failed with exception: {}".format(repr(e)))


def get_test_cases(test_type):
    if test_type == "t0":
        # ["bgp/test_bgp_fact.py"]
        return ["arp/test_arp_dualtor.py",
                "arp/test_neighbor_mac.py",
                "arp/test_neighbor_mac_noptf.py",
                "bgp/test_bgp_fact.py",
                "bgp/test_bgp_gr_helper.py::test_bgp_gr_helper_routes_perserved",
                "bgp/test_bgp_speaker.py",
                "bgp/test_bgpmon.py",
                "bgp/test_bgp_update_timer.py",
                "container_checker/test_container_checker.py",
                "cacl/test_cacl_application.py",
                "cacl/test_cacl_function.py",
                "cacl/test_ebtables_application.py",
                "dhcp_relay/test_dhcp_relay.py",
                "dhcp_relay/test_dhcpv6_relay.py",
                "iface_namingmode/test_iface_namingmode.py",
                "lldp/test_lldp.py",
                "monit/test_monit_status.py",
                "ntp/test_ntp.py",
                "pc/test_po_cleanup.py",
                "pc/test_po_update.py",
                "platform_tests/test_advanced_reboot.py::test_warm_reboot",
                "platform_tests/test_cpu_memory_usage.py",
                "route/test_default_route.py",
                "route/test_static_route.py",
                "snmp/test_snmp_cpu.py",
                "snmp/test_snmp_default_route.py",
                "snmp/test_snmp_interfaces.py",
                "snmp/test_snmp_lldp.py",
                "snmp/test_snmp_loopback.py",
                "snmp/test_snmp_pfc_counters.py",
                "snmp/test_snmp_queue.py",
                "ssh/test_ssh_ciphers.py",
                "ssh/test_ssh_limit.py",
                "syslog/test_syslog.py",
                "tacacs/test_accounting.py",
                "tacacs/test_authorization.py",
                "tacacs/test_jit_user.py",
                "tacacs/test_ro_disk.py",
                "tacacs/test_ro_user.py",
                "tacacs/test_rw_user.py",
                "telemetry/test_telemetry.py",
                "test_features.py",
                "test_interfaces.py",
                "test_procdockerstatsd.py",
                "generic_config_updater/test_aaa.py",
                "generic_config_updater/test_bgpl.py",
                "generic_config_updater/test_bgp_prefix.py",
                "generic_config_updater/test_bgp_speaker.py",
                "generic_config_updater/test_cacl.py",
                "generic_config_updater/test_dhcp_relay.py",
                "generic_config_updater/test_eth_interface.py",
                "generic_config_updater/test_ipv6.py",
                "generic_config_updater/test_lo_interface.py",
                "generic_config_updater/test_monitor_config.py",
                "generic_config_updater/test_portchannel_interface.py",
                "generic_config_updater/test_syslog.py",
                "generic_config_updater/test_vlan_interface.py",
                "process_monitoring/test_critical_process_monitoring.py",
                "show_techsupport/test_techsupport_no_secret.py",
                "system_health/test_system_status.py",
                ]
    if test_type == "t1-lag":
        # ["bgp/test_bgp_fact.py"]
        return ["bgp/test_bgp_allow_list.py",
                "bgp/test_bgp_bbr.py",
                "bgp/test_bgp_bounce.py",
                "bgp/test_bgp_fact.py",
                "bgp/test_bgp_multipath_relax.py",
                "bgp/test_bgp_update_timer.py",
                "bgp/test_bgpmon.py",
                "bgp/test_traffic_shift.py",
                "configlet/test_add_rack.py",
                "container_checker/test_container_checker.py",
                "http/test_http_copy.py",
                "ipfwd/test_mtu.py",
                "lldp/test_lldp.py",
                "monit/test_monit_status.py",
                "pc/test_lag_2.py",
                "platform_tests/test_cpu_memory_usage.py",
                "process_monitoring/test_critical_process_monitoring.py",
                "route/test_default_route.py",
                "scp/test_scp_copy.py",
                "test_interfaces.py",
                ]


def create_test_plan(tenant_id, client_id, client_secret, test_type, testbed_tools_url):
    if not client_id or not client_secret or not tenant_id or not test_type:
        print("Need environment variables: TENANT_ID, CLIENT_ID, CLIENT_SECRET, TEST_TYPE")
        sys.exit(1)

    token = _get_token(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
    if not token:
        sys.exit(2)

    name = "{BUILD_REPOSITORY_PROVIDER}_{BUILD_REASON}_PR_{PULL_REQUEST_NUMBER}_BUILD_{BUILD_ID}_JOB_{JOB_NAME}".format(
        BUILD_REPOSITORY_PROVIDER=os.environ.get("BUILD_REPOSITORY_PROVIDER"),
        BUILD_REASON=os.environ.get("BUILD_REASON"),
        PULL_REQUEST_NUMBER=os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER"),
        BUILD_ID=os.environ.get("BUILD_BUILDID"),
        JOB_NAME=os.environ.get("SYSTEM_JOBDISPLAYNAME")
    )
    test_plan_id = _create_test_plan(testbed_tools_url=testbed_tools_url, name=name, token=token, test_type=test_type)
    print(test_plan_id)
    if not test_plan_id:
        sys.exit(2)


def cancel_test_plan(tenant_id, client_id, client_secret, testbed_tools_url, test_plan_id):
    if not client_id or not client_secret or not tenant_id:
        print("Need environment variables: TENANT_ID, CLIENT_ID, CLIENT_SECRET")
        sys.exit(1)

    token = _get_token(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
    if not token:
        sys.exit(2)

    result = _cancel_test_plan(testbed_tools_url=testbed_tools_url, test_plan_id=test_plan_id, token=token)
    print(result)
    if not result:
        sys.exit(2)


def poll_test_plan(test_plan_id, testbed_tools_url):
    print("Polling Test plan {}, detailed progress in https://www.testbed-tools.org/scheduler/testplan/{}".format(
        test_plan_id, test_plan_id))
    url = "{}/test_plan/{}".format(testbed_tools_url, test_plan_id)
    headers = {
        "Content-Type": "application/json"
    }
    try:
        while True:
            resp = requests.get(url, headers=headers, timeout=10).json()
            if not resp["success"]:
                print("Query test plan failed with error: {}".format(resp["errmsg"]))
                sys.exit(2)
            if resp["data"]["status"] in ["FINISHED", "CANCELLED"]:
                if resp["data"]["result"] == "SUCCESS":
                    sys.exit(0)
                else:
                    print("Test plan result is {}".format(resp["data"]["result"]))
                    sys.exit(2)
            print("Test plan {}'s status is {}, progress is {}%".format(test_plan_id, resp["data"]["status"], resp["data"]["progress"] * 100))
            time.sleep(10)

    except Exception as e:
        print("Query test plan failed with exception: {}".format(repr(e)))
        sys.exit(2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Lock/release a testbed")

    parser.add_argument("-a", "--action",
                        type=str,
                        dest="action",
                        choices=["create_test_plan", "poll_test_plan", "cancel_test_plan"],
                        required=True,
                        help="Action.")

    parser.add_argument("-t", "--test_plan_id",
                        type=int,
                        dest="test_plan_id",
                        required=False,
                        help="Test plan id.")

    args = parser.parse_args()

    tenant_id = os.environ.get("TENANT_ID")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")
    test_type = os.environ.get("TEST_TYPE")
    testbed_tools_url = os.environ.get("TESTBED_TOOLS_URL")
    test_plan_id = args.test_plan_id

    if args.action == "create_test_plan":
        create_test_plan(tenant_id, client_id, client_secret, test_type, testbed_tools_url)
    elif args.action == "poll_test_plan":
        poll_test_plan(test_plan_id, testbed_tools_url)
    elif args.action == "cancel_test_plan":
        cancel_test_plan(tenant_id, client_id, client_secret, testbed_tools_url, test_plan_id)
