from __future__ import print_function
import argparse
import os
import requests
import sys

DEFAULT_LOCK_HOURS = 36

def get_token(client_id, client_secret):
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
            return 0
    except Exception as e:
        print('{} testbed {} failed with exception: {}'.format(action, testbed, repr(e)))
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
        help='Force lock. Valid values: true, yes, t, y, false, no, f, n. Case insensitive')

    parser.add_argument('-b', '--absolute',
        type=str,
        dest='absolute',
        required=False,
        default="yes",
        help='Absolute lock. Valid values: true, yes, t, y, false, no, f, n. Case insensitive')

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

    token = get_token(client_id, client_secret)
    if not token:
        sys.exit(1)

    sys.exit(lock_release(args.testbed, args.action, token, proxies, args.hours, args.user, args.reason, args.force, args.absolute))
