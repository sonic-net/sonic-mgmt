# This file contains the list of API's which performs REST operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import json
import requests
import warnings
from spytest import st
from apis.system.basic import service_operations_by_systemctl

# disable warnings from SSL/TLS certificates
requests.packages.urllib3.disable_warnings()

global request_id
request_id = 1


def send_rest_request(dut, feature, method, parms_data, timeout=30, port=8361):
    """
    Construct URL for rest request and send to device
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    Ex:- http://10.130.84.46:80/broadview/bst/clear-bst-thresholds

    :param dut:
    :param feature:
    :param method:
    :param parms_data:
    :param timeout: (Default 30sec)
    :param port: (Default 8361)
    :return:
    """
    global request_id
    device_ip = st.get_mgmt_ip(dut)
    url = 'http://{}:{}/broadview/{}/{}'.format(device_ip, port, feature, method)
    st.log("URL: {}".format(url))

    json_data = '{"jsonrpc": "2.0", "method": "' + method + '", "asic-id": "0","params": ' + \
                json.dumps(parms_data) + ',"id": ' + str(request_id) + '}'
    request_id += 1
    st.log("JSON Data: {}".format(json_data))

    try:
        response = requests.post(url, data=json_data, timeout=timeout)
    except requests.ConnectionError:
        st.error("A Connection error occurred.")
        return False
    except requests.Timeout:
        st.error("The request timed out.")
        return False

    st.log("Response code : {}".format(response.status_code))
    if response.status_code != 200:
        st.log("Error: Response : {}".format(response))
        st.log("Error: Response.text : {}".format(response.text))
        return False
    return response


def client_auth(dut, **kwargs):
    """
    To enable disable REST client auth.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    st.log("Configuring REST authentication.")
    docer_name = "mgmt-framework"
    show_command = []
    if 'auth_type' in kwargs:
        show_command.append('sonic-cfggen -d -v "REST_SERVER"')
        if kwargs.get('auth_type'):
            command = 'redis-cli -n 4 hmset "REST_SERVER|default" client_auth "{}"'.format(kwargs.get('auth_type'))
        else:
            command = 'redis-cli -n 4 hdel "REST_SERVER|default" client_auth'
        st.config(dut, command)
    if 'ca_crt' in kwargs:
        show_command.append('redis-cli -n 4 hgetall "DEVICE_METADATA|x509"')
        if kwargs.get('ca_crt'):
            command = 'redis-cli -n 4 hmset "DEVICE_METADATA|x509" ca_crt {}'.format(kwargs.get('ca_crt'))
        else:
            command = 'redis-cli -n 4 hdel "DEVICE_METADATA|x509" ca_crt'
        st.config(dut, command)
    service_operations_by_systemctl(dut, docer_name, 'stop')
    service_operations_by_systemctl(dut, docer_name, 'start')
    st.config(dut, show_command)
    return True


def rest_call(dut, **kwargs):
    """
    Rest call to perform GET, POST, PUT operation with auth and JWT token.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:

    Usage:

    # User based calls
    rest_call(dut, headers=headers1, username='test', password='pass',
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='get')
    rest_call(dut, headers=headers1, username='test', password='pass',
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='put',
            data={"sonic-port:admin_status":"down"})
    rest_call(dut, headers=headers1, username='test', password='pass',
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='get')

    # Token based calls
    rest_call(dut, headers=headers2,
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='get')
    rest_call(dut, headers=headers2,
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='put',
            data={"sonic-port:admin_status":"up"})
    rest_call(dut, headers=headers2,
            url='restconf/data/sonic-port:sonic-port/PORT/PORT_LIST=Ethernet0/admin_status', call_type='get')
    """
    device_ip = st.get_mgmt_ip(dut)
    call_type = kwargs.get('call_type', 'get')
    port = kwargs.get('port', '443')
    url = kwargs.get('url')
    headers = kwargs.get('headers')
    data = kwargs.get('data')
    username = kwargs.get('username')
    password = kwargs.get('password')
    timeout = kwargs.get('timeout', 30)
    cert = kwargs.get('cert')
    verify = kwargs.get('verify', False)

    if port:
        final_url = "https://{}:{}/{}".format(device_ip, port, url)
    else:
        final_url = "https://{}/{}".format(device_ip, url)
    st.log("{} - URL : {}".format(call_type.upper(), final_url))

    call_data = {'verify': verify, 'timeout': timeout}
    if data:
        if isinstance(data, dict):
            call_data['data'] = json.dumps(data)
        else:
            call_data['data'] = data
    if username and password:
        call_data['auth'] = (username, password)
    if headers:
        call_data['headers'] = headers
    if cert:
        call_data['cert'] = cert

    st.log("Call Data : {}".format(call_data))

    # response type
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    try:
        if call_type == 'put':
            response = requests.put(final_url, **call_data)
        elif call_type == 'post':
            response = requests.post(final_url, **call_data)
        elif call_type == 'patch':
            response = requests.patch(final_url, **call_data)
        elif call_type == 'delete':
            response = requests.delete(final_url, **call_data)
        else:
            response = requests.get(final_url, **call_data)
    except requests.ConnectionError:
        st.error("A Connection error occurred.")
        return False
    except requests.Timeout:
        st.error("The request timed out.")
        return False
    except Exception as e:
        st.error(e)
        return False
    st.log("Response Code: {}, Text: {}".format(response.status_code, response.text))
    return {"status": response.status_code, "output": response.text}


def get_jwt_token(dut, **kwargs):
    """
    To get JWT token using REST call.
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:

    Usage:
    get_jwt_token(dut, username='test', password='pass')
    """
    username = kwargs.get('username')
    password = kwargs.get('password')
    url = kwargs.get('url', 'authenticate')
    headers = kwargs.get('headers', {'Accept': 'application/json'})
    data = {'username': username, 'password': password}
    out = rest_call(dut, data=data, headers=headers, url=url, call_type='post')
    if not out:
        return None
    if out.get('status') not in [200]:
        return None
    token_dic = eval(out['output'])
    return token_dic.get('access_token', None)


def rest_status(status):
    """
    To give the response as per status code
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param status:
    :return:
    """
    if status in [200, 201, 204]:
        st.log("Rest operation successful")
        return True
    else:
        if status == 400:
            st.log("Bad Request")
        elif status == 401:
            st.log("Unauthorized")
        elif status == 403:
            st.log("Forbidden")
        elif status == 404:
            st.log("Page not found")
        elif status == 405:
            st.log("Method not allowed")
        elif status == 409:
            st.log("Conflict")
        elif status == 415:
            st.log("Unsupported Media Type")
        else:
            st.log("Internal Server Error")
        return False
