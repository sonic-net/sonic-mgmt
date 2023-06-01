import os
import sys
import requests
import json
import argparse
import yaml
import logging
from datetime import datetime
from collections import defaultdict

_self_dir = os.path.dirname(os.path.abspath(__file__))
base_path = os.path.realpath(os.path.join(_self_dir, ".."))
if base_path not in sys.path:
    sys.path.append(base_path)
from nightly.templates.lock_release import get_token_from_testbedV2

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

server_host_map = {}

TESTBED_FILE = "../../ansible/testbed.yaml"
INVENTORY_POOL = ["../../ansible/str", 
                  "../../ansible/str2", 
                  "../../ansible/str3", 
                  "../../ansible/strsvc", 
                  "../../ansible/bjw"]


def get_testbeds_list():
    testbed_list = []
    with open(TESTBED_FILE) as fd:
        testbed_yml = yaml.load(fd, Loader=yaml.FullLoader)
    for item in range(len(testbed_yml)):
        testbed_list.append(testbed_yml[item]['conf-name'])
    return testbed_list


def get_testbed_hwsku(testbed_utilization):
    dut_hwsku_pair = {}
    for inventory_file in INVENTORY_POOL:
        with open(inventory_file) as fd:
            inv_yml = yaml.load(fd, Loader=yaml.FullLoader)
            for sonic_host in inv_yml:
                if "vars" in inv_yml[sonic_host] and "hwsku" in inv_yml[sonic_host]["vars"]:
                    hwsku = inv_yml[sonic_host]["vars"]["hwsku"]
                    duts = inv_yml[sonic_host]["hosts"]
                    for dut in duts:
                        dut_hwsku_pair[dut] = hwsku
                elif "hosts" in inv_yml[sonic_host]:
                    for dut in inv_yml[sonic_host]["hosts"]:
                        if inv_yml[sonic_host]["hosts"][dut] is not None \
                                and "hwsku" in inv_yml[sonic_host]["hosts"][dut]:
                            dut_hwsku_pair[dut] = inv_yml[sonic_host]["hosts"][dut]["hwsku"]
                        else:
                            dut_hwsku_pair[dut] = ""

    for item in range(len(testbed_utilization)):
        dut_name = testbed_utilization[item]["DutName"]
        if ";" in dut_name:
            hwskus = []
            duts = dut_name.split(";")
            for dut in duts:
                if dut in dut_hwsku_pair:
                   hwskus.append(dut_hwsku_pair[dut])
            hwsku = ";".join(hwskus)
            testbed_utilization[item]["HwSKU"] = hwsku
        elif dut_name in dut_hwsku_pair:
            testbed_utilization[item]["HwSKU"] = dut_hwsku_pair[dut_name]
    return testbed_utilization


def get_tbshare_resp(token, proxies):
    url = 'https://sonic-elastictest-prod-management-webapp.azurewebsites.net/api/v1/testbeds/query_by_keyword?keyword=&testbed_type=PHYSICAL&page=1&page_size=2000'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    result = {}
    try:
        result = requests.get(url, headers=headers, proxies=proxies, timeout=10).json()
        if result["failed"]:
            retry_times = 2
            while(retry_times > 0 and result["failed"]):
                result = requests.get(url, headers=headers, proxies=proxies, timeout=10).json()
                retry_times -= 1
        result["timestamp"] = str(datetime.utcnow())
    except Exception:
        result["failed"] = True

    result["timestamp"] = str(datetime.utcnow())
    return result


def parse_testbed_status_result(tbshare_resp, skip_testbeds):
    testbed_utilization = []
    if "data" not in tbshare_resp:
        return testbed_utilization
    upload_info = {}
    for testbed_info in tbshare_resp["data"]:
        upload_info = {}
        if testbed_info["name"] not in skip_testbeds:
            upload_info["TestbedName"] = testbed_info["name"]
            duts = []
            for dut in testbed_info["dut"]:
                duts.append(dut)
            upload_info["DutName"] = ";".join(duts)
            if testbed_info["locked_by"] is not None:
                upload_info["LockedBy"] = testbed_info["locked_by"]
                if testbed_info["lock_reason"]:
                    upload_info["LockReason"] = testbed_info["lock_reason"]
                upload_info["LockTime"] = testbed_info["lock_time"]
                upload_info["ReleaseTime"] = testbed_info["release_time"]
            upload_info["Timestamp"] = str(datetime.utcnow())
            testbed_utilization.append(upload_info)

    testbed_utilization = get_testbed_hwsku(testbed_utilization)
    return testbed_utilization


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get testbed occupy status.')
    # skip-testbeds is seperated by ","
    parser.add_argument('--skip-testbeds', default='', type=str, required=False, help='testbeds to skip')
    args = parser.parse_args()
    skip_testbeds = args.skip_testbeds
    if skip_testbeds or skip_testbeds != '':
        skip_testbeds = skip_testbeds.split(',')

    proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('http_proxy')
    }

    token = get_token_from_testbedV2()
    tbshare_resp = defaultdict(list)
    tbshare_resp = get_tbshare_resp(token, proxies)
    testbed_utilization = parse_testbed_status_result(tbshare_resp, skip_testbeds)

    if len(testbed_utilization) > 0:
        with open("testbed_utilization.json", "w") as f:
            json.dump(testbed_utilization, f)
