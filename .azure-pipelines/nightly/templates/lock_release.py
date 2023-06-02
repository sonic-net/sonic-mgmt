from __future__ import print_function
import argparse
import os
import requests
import sys

DEFAULT_LOCK_HOURS = 36


# todo: remove this method if new lock_release is stable for a time
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


def get_token_from_elastictest():
    token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(os.environ.get('ELASTICTEST_MSAL_TENANT'))
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


def get_testbed(testbed, token, proxies):
    try:
        url = 'https://tbshare.azurewebsites.net/api/testbed/{}'.format(testbed)
        headers = {
            'Authorization': 'Bearer ' + token
        }
        return requests.get(url, headers=headers, proxies=proxies, timeout=10).json()
    except:
        return {}


# todo: remove this method if new lock_release is stable for a time
def lock_release(testbed, action, token, proxies, hours, user, reason, force, absolute):
    try:
        url = 'https://tbshare.azurewebsites.net/api/{}'.format(action)
        headers = {
            'Authorization': 'Bearer ' + token
        }
        params = {
            'name': testbed,
            'user': user,
            'force': force
        }
        if action == 'lock':
            # Extra params required only for lock
            params.update({
                'hours': hours,
                'lock_reason': reason,
                'absolute': absolute
            })

        result = requests.get(url, headers=headers, params=params, proxies=proxies, timeout=10).json()
        if 'failed' in result and result['failed']:
            print('{} testbed {} failed'.format(action, testbed))
            if 'msg' in result:
                print(result['msg'])
            return 2
        else:
            print('{} testbed {} succeeded'.format(action, testbed))
            # sync lock/release to Elastictest, but not block current operation
            lock_release_from_elastictest(testbed, action, hours, user, reason, force, absolute)
            return 0

    except Exception as e:
        print('{} testbed {} failed with exception: {}'.format(action, testbed, repr(e)))
        return 3


def lock_release_from_elastictest(testbed, action, hours, user, reason, force, absolute):
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
            }

        headers = {
            'Authorization': 'Bearer {}'.format(get_token_from_elastictest())
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

    token = get_token(client_id, client_secret, proxies)
    if not token:
        sys.exit(2)

    print('Args for lock_release: ' + str(args))
    if not args.brutal_release:
        sys.exit(lock_release_from_elastictest(args.testbed, args.action, args.hours, args.user, args.reason, args.force, args.absolute))
    else:
        testbed_res = get_testbed(args.testbed, token, proxies)

        if testbed_res.get('failed', True):
            print('Failed to get testbed details')
            sys.exit(3)

        locked_by = testbed_res.get('testbed').get('locked_by')
        if not locked_by:
            print('Testbed "{}" is not locked by anyone'.format(args.testbed))
            sys.exit(0)

        sys.exit(lock_release_from_elastictest(args.testbed, 'release', args.hours, locked_by, args.reason, args.force, args.absolute))
