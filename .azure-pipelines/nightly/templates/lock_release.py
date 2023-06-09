from __future__ import print_function
import argparse
import os
import requests
import sys

DEFAULT_LOCK_HOURS = 36


def get_token():
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


def get_testbed(testbed_name):
    """
    Get testbed info by search testbed name.
    """
    try:
        # Use the same API as testbed mgmt page
        url = '{}/query_by_keyword?keyword={}&testbed_type=PHYSICAL&page=1&page_size=1'.format(os.environ.get("ELASTICTEST_MGMT_TESTBEDS_URL"), testbed_name)
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


def lock_release(testbed, action, hours, user, reason, force, absolute):
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
        resp = requests.post("{}/{}".format(os.environ.get("ELASTICTEST_MGMT_TESTBED_URL"), action),
                             json=data,
                             headers=headers).json()

        if 'failed' in resp and resp['failed']:
            print('[Elastictest] {} testbed {} failed'.format(action, testbed))
            if 'msg' in resp:
                print(resp['msg'])
            return 2
        else:
            if not resp['success']:
                print('[Elastictest] Lock testbeds failed with error: {}'.format(resp['errmsg']))
                return 2
            if action == "lock":
                if resp['data'] is None or (len(resp['data']) < lock_tb_num):
                    print("[Elastictest] Lock testbed failed, can't lock expected testbed")
                    return 2
            print('[Elastictest] {} testbed {} succeeded'.format(action, testbed))
            return 0

    except Exception as e:
        print('[Elastictest] {} testbed {} failed with exception: {}'.format(action, testbed, repr(e)))
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

    parser.add_argument('-R',
        action='store_true',
        dest='brutal_release',
        required=False,
        help='Brutal force release flag.')

    args = parser.parse_args()

    if args.user == '':
        build_name = os.environ.get('BUILD_DEFINITIONNAME')
        build_id = os.environ.get('BUILD_BUILDID')
        user = '{}_{}'.format(build_name, build_id)
        args.user = user

    client_id = os.environ.get('TBSHARE_AAD_CLIENT_ID')
    client_secret = os.environ.get('TBSHARE_AAD_CLIENT_SECRET')

    if not client_id or not client_secret:
        print('Need environment variables: TBSHARE_AAD_CLIENT_ID, TBSHARE_AAD_CLIENT_SECRET')
        sys.exit(1)

    proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('http_proxy')
    }

    print('Args for lock_release: ' + str(args))
    force_lock = args.force.lower() in ['true', 'yes', 't', 'y']
    absolute_lock = args.absolute.lower() in ['true', 'yes', 't', 'y']
    if not args.brutal_release:
        sys.exit(lock_release(args.testbed, args.action, args.hours, args.user, args.reason, force_lock, absolute_lock))
    else:
        testbed_res = get_testbed(args.testbed)

        if not testbed_res:
            print('Failed to get testbed details')
            sys.exit(3)

        locked_by = testbed_res.get('locked_by')
        if not locked_by:
            print('Testbed "{}" is not locked by anyone'.format(args.testbed))
            sys.exit(0)

        sys.exit(lock_release(args.testbed, 'release', args.hours, locked_by, args.reason, force_lock, absolute_lock))
