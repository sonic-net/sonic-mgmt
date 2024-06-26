from __future__ import print_function
import argparse
import os
import requests
import sys

DEFAULT_LOCK_HOURS = 36
ENDPOINT_TESTBED = "https://sonic-elastictest-prod-management-webapp.azurewebsites.net/api/v1/testbed"
ENDPOINT_TESTBEDS = "https://sonic-elastictest-prod-management-webapp.azurewebsites.net/api/v1/testbeds"


def get_token():

    access_token = os.environ.get('ACCESS_TOKEN', None)
    if access_token:
        print("Got ACCESS_TOKEN from environment variable.")
        return access_token

    print("No ACCESS_TOKEN in environment variable, try to get token using client secrets.")

    token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(
        os.environ.get('ELASTICTEST_MSAL_TENANT'))
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'grant_type': 'client_credentials',
        'client_id': os.environ.get('ELASTICTEST_MSAL_CLIENT_ID'),
        'client_secret': os.environ.get('ELASTICTEST_MSAL_SECRET_VALUE'),
        'scope': os.environ.get('ELASTICTEST_MSAL_SCOPE')
    }

    try:
        resp = requests.post(token_url, headers=headers, data=payload, timeout=10).json()
        return resp['access_token']
    except Exception as e:
        print('Get token failed with exception: {}'.format(repr(e)))
    return None


def get_testbed(testbed_name, endpoint_testbeds):
    """
    Get testbed info by search testbed name.
    """
    try:
        # Use the same API as testbed mgmt page
        url = '{}/query_by_keyword?keyword={}&testbed_type=PHYSICAL&page=1&page_size=1'.format(
            endpoint_testbeds,
            testbed_name
        )
        headers = {
            'Authorization': 'Bearer {}'.format(get_token())
        }

        response = requests.get(url, headers=headers, timeout=10).json()

        # If the response is successful, the returned content will be like:
        # { "success": True, "errmsg": "", "data": [{testbed1}, {testbed2}, ...]

        if not response['success']:
            print('Get testbed {} failed . {}'.format(testbed_name, response['errmsg']))

        return response['data'][0]

    except Exception as e:
        print('Get testbed {} failed with exception: {}'.format(testbed_name, e))
        return {}


def lock_release(testbed, action, hours, user, reason, force, absolute, ignore_status, endpoint_testbed):
    """
    Lock or release a testbed.

    Args:
        testbed: testbed name. str.
        action: lock/release. str.
        hours: lock hours. int.
        user: request user. str.
        reason: lock reason. str.
        force: force lock/release. bool.
        absolute: absolute lock. bool.
    """
    try:
        lock_tb_num = 1
        data = {
            "testbed_requirement": {
                'platform': 'PHYSICAL',
                'name': [testbed],
                'min': lock_tb_num,
                'max': lock_tb_num
            },
            "hours": hours,
            "requester_id": user,
            'lock_reason': reason,
            'absolute_lock': absolute,
            'force_lock': force,
            'ignore_status': ignore_status,
        }
        if action == 'release':
            data = {
                'testbed_names': [testbed],
                'force_release': force,
                "requester_id": user,
            }

        headers = {
            'Authorization': 'Bearer {}'.format(get_token())
        }
        resp = requests.post(
            "{}/{}".format(endpoint_testbed, action),
            json=data,
            headers=headers
        ).json()

        if 'failed' in resp and resp['failed']:
            print('[Elastictest] {} {} testbed {} failed'.format(user, action, testbed))
            if 'msg' in resp:
                print(resp['msg'])
            return 2
        else:
            if not resp['success']:
                print('[Elastictest] {} {} testbeds failed with error: {}'.format(user, action, resp['errmsg']))
                return 2
            if resp['data'] is None or (len(resp['data']) < lock_tb_num):
                print("[Elastictest] {} {} testbed failed. {}".format(user, action, resp['errmsg']))
                return 2
            print('[Elastictest] {} {} testbed {} succeeded'.format(user, action, testbed))
            return 0

    except Exception as e:
        print('[Elastictest] {} {} testbed {} failed with exception: {}'.format(user, action, testbed, repr(e)))
        return 3


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Lock/release a testbed")

    parser.add_argument('-a', '--action',
        type=str,
        dest='action',
        choices=['lock', 'release'],
        required=True,
        help='Action lock or release.')

    parser.add_argument('-t', '--testbed',
        type=str,
        dest='testbed',
        required=True,
        help='Testbed name')

    parser.add_argument('-u', '--user',
        type=str,
        dest='user',
        required=False,
        default='',
        help='Lock user')

    parser.add_argument('-o', '--hours',
        type=int,
        dest='hours',
        required=False,
        default=DEFAULT_LOCK_HOURS,
        help='Lock hours')

    parser.add_argument('-r', '--lock-reason',
        type=str,
        dest='reason',
        required=False,
        default='NightlyTest',
        help='Lock reason')

    parser.add_argument('-f', '--force',
        type=str,
        dest='force',
        required=False,
        default="yes",
        help='Force lock/release. Valid values: true, yes, t, y, false, no, f, n. Case insensitive')

    parser.add_argument('-b', '--absolute',
        type=str,
        dest='absolute',
        required=False,
        default="yes",
        help='Absolute lock. Valid values: true, yes, t, y, false, no, f, n. Case insensitive')

    parser.add_argument('-i', '--ignore-status',
        type=str,
        dest='ignore_status',
        required=False,
        default='true',
        help='Ignore status. Valid values: True, False. Case insensitive. Default is True.')

    parser.add_argument('-R',
        action='store_true',
        dest='brutal_release',
        required=False,
        help='Brutal force release flag.')

    parser.add_argument('--endpoint-testbed',
        type=str,
        dest='endpoint_testbed',
        required=False,
        default=ENDPOINT_TESTBED,
        help='Endpoint for the testbed API')

    parser.add_argument('--endpoint-testbeds',
        type=str,
        dest='endpoint_testbeds',
        required=False,
        default=ENDPOINT_TESTBEDS,
        help='Endpoint for the testbeds API')

    args = parser.parse_args()

    if args.user == '':
        build_name = os.environ.get('BUILD_DEFINITIONNAME')
        build_id = os.environ.get('BUILD_BUILDID')
        user = '{}_{}'.format(build_name, build_id)
        args.user = user

    proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('http_proxy')
    }

    print('Args for lock_release: ' + str(args))
    force_lock = args.force.lower() in ['true', 'yes', 't', 'y']
    absolute_lock = args.absolute.lower() in ['true', 'yes', 't', 'y']
    ignore_status = args.ignore_status.lower() in ['true', 'yes', 't', 'y']
    if not args.brutal_release:
        sys.exit(
            lock_release(
                args.testbed,
                args.action,
                args.hours,
                args.user,
                args.reason,
                force_lock,
                absolute_lock,
                ignore_status,
                args.endpoint_testbed,
            )
        )
    else:
        testbed_res = get_testbed(args.testbed, args.endpoint_testbeds)

        if not testbed_res:
            print('Failed to get testbed details')
            sys.exit(3)

        locked_by = testbed_res.get('locked_by')
        if not locked_by:
            print('Testbed "{}" is not locked by anyone'.format(args.testbed))
            sys.exit(0)

        sys.exit(
            lock_release(
                args.testbed,
                'release',
                args.hours,
                locked_by,
                args.reason,
                force_lock,
                absolute_lock,
                ignore_status,
                args.endpoint_testbed
            )
        )
