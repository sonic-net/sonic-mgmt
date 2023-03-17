import os
import sys
import requests
import json
import argparse
import yaml
import logging
from datetime import datetime
from collections import defaultdict

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)

server_host_map = {}


def get_token(client_id, client_secret, proxies):
    token_url = 'https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'resource': 'https://tbshare.azurewebsites.net',
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    try:
        resp = requests.post(token_url, headers=headers, data=payload, proxies=proxies, timeout=10).json()
        return resp['access_token']
    except Exception as e:
        print('Get token failed with exception: {}'.format(repr(e)))
    return None


def get_testbeds_list():
    testbed_list = []
    with open("../../ansible/testbed.yaml") as fd:
        testbed_yml = yaml.load(fd, Loader=yaml.FullLoader)
    for item in range(len(testbed_yml)):
        testbed_list.append(testbed_yml[item]['conf-name'])
    return testbed_list


def get_testbed_status(testbed, token, proxies):
    url = 'https://tbshare.azurewebsites.net/api/testbed/{}'.format(testbed)
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


def parse_testbed_status_result(testbed_status):
    """
    Parse poll results of tbshare.
    The data looks like this:
    {
        "testbed-bjw-can-7215-1": {
            "failed": false,
            "testbed": {
                "topo": "m0",
                "lock_time": "2023-03-07T01:42:42.040050+00:00",
                "lock_reason": "NightlyTest",
                "Timestamp": "Tue, 07 Mar 2023 01:42:42 GMT",
                "duts": "bjw-can-7215-1",
                "locked_by": "testbed-bjw-can-7215-1.202205_229718",
                "absolute_lock": true,
                "nightly": false,
                "PartitionKey": "switch",
                "etag": "W/\"datetime'2023-03-07T01%3A42%3A42.1181954Z'\"",
                "RowKey": "testbed-bjw-can-7215-1",
                "release_time": "2023-03-08T13:42:42.040050+00:00"
            }
        }
    }
    """
    testbed_utilization = []
    for testbed_name in testbed_status:
        upload_info = {}
        upload_info["TestbedName"] = testbed_name
        if "testbed" in testbed_status[testbed_name]:
            testbed_info = testbed_status[testbed_name]["testbed"]
        else:
            testbed_info = {}
        if not testbed_status[testbed_name]["failed"]:
            upload_info["DutName"] = testbed_info["duts"]
            if testbed_info["locked_by"]:
                upload_info["LockedBy"] = testbed_info["locked_by"]
                if testbed_info["lock_reason"]:
                    upload_info["LockReason"] = testbed_info["lock_reason"]
                upload_info["LockTime"] = testbed_info["lock_time"]
                upload_info["ReleaseTime"] = testbed_info["release_time"]
        else:
            if "duts" in testbed_info:
                upload_info["DutName"] = testbed_info["duts"]
            upload_info["LockedBy"] = "unknown"
        upload_info["Timestamp"] = testbed_status[testbed_name]["timestamp"]
        testbed_utilization.append(upload_info)

    return testbed_utilization


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get testbed occupy status.')
    # skip-testbeds is seperated by ","
    parser.add_argument('--skip-testbeds', default='', type=str, required=False, help='testbeds to skip')
    args = parser.parse_args()
    skip_testbeds = args.skip_testbeds
    if skip_testbeds or skip_testbeds != '':
        skip_testbeds = skip_testbeds.split(',')

    client_id = os.environ.get('TBSHARE_AAD_CLIENT_ID')
    client_secret = os.environ.get('TBSHARE_AAD_CLIENT_SECRET')

    if not client_id or not client_secret:
        print('Need environment variables: TBSHARE_AAD_CLIENT_ID, TBSHARE_AAD_CLIENT_SECRET')
        sys.exit(1)

    proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('http_proxy')
    }

    token = get_token(client_id, client_secret, proxies)

    testbed_list = get_testbeds_list()
    testbed_status = defaultdict(list)
    for testbed in testbed_list:
        if testbed not in skip_testbeds:
            testbed_status[testbed] = get_testbed_status(testbed, token, proxies)
    testbed_utilization = parse_testbed_status_result(testbed_status)

    with open("testbed_utilization.json", "w") as f:
        json.dump(testbed_utilization, f)
