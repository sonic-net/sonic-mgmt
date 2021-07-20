from __future__ import print_function
import os
import requests
import sys


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


def lock_release(testbed, action, token, proxies):
    try:
        url = 'https://tbshare.azurewebsites.net/api/{}'.format(action)
        headers = {
            'Authorization': 'Bearer ' + token
        }
        params = {
            'name': testbed,
            'user': 'Azure Pipeline',
            'force': 'yes'
        }
        if action == 'lock':
            # Extra params required only for lock
            params.update({
                'hours': '36',
                'lock_reason': 'NightlyTest',
                'absolute': 'yes'
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

    usage = 'usage: python lock_release.py [lock|release]'

    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    action = sys.argv[1]
    if action not in ['lock', 'release']:
        print(usage)
        sys.exit(1)

    testbed = os.environ.get('TESTBED_NAME')
    client_id = os.environ.get('TBSHARE_AAD_CLIENT_ID')
    client_secret = os.environ.get('TBSHARE_AAD_CLIENT_SECRET')

    if not testbed or not client_id or not client_secret:
        print('Need environment variables: TESTBED_NAME, TBSHARE_AAD_CLIENT_ID, TBSHARE_AAD_CLIENT_SECRET')
        sys.exit(1)

    proxies = {
        'http': os.environ.get('http_proxy'),
        'https': os.environ.get('http_proxy')
    }

    token = get_token(client_id, client_secret)
    if not token:
        sys.exit(1)

    sys.exit(lock_release(testbed, action, token, proxies))
