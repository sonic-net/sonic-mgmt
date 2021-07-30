# This file contains the list of API's which performs REST operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import json
import requests
import warnings
import re
from spytest import st
from apis.common import redis
from utilities.common import filter_and_select, do_eval


# disable warnings from SSL/TLS certificates
requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
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
    response_flag = False
    for retry in range(1, 4):
        msg = "Trying REST request for iteration '{}'".format(retry)
        st.log(msg)
        try:
            response = requests.post(url, data=json_data, timeout=timeout)
            response_flag = True
            break
        except requests.ConnectionError:
            st.error("A Connection error occurred.")
        except requests.Timeout:
            st.error("The request timed out.")
        except Exception as e:
            st.error(e)
    if not response_flag:
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
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "REST_SERVER|default" client_auth "{}"'.format(kwargs.get('auth_type')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "REST_SERVER|default" client_auth')
        st.config(dut, command)
    if 'ca_crt' in kwargs:
        show_command.append(redis.build(dut, redis.CONFIG_DB, 'hgetall "DEVICE_METADATA|x509"'))
        if kwargs.get('ca_crt'):
            command = redis.build(dut, redis.CONFIG_DB, 'hmset "DEVICE_METADATA|x509" ca_crt {}'.format(kwargs.get('ca_crt')))
        else:
            command = redis.build(dut, redis.CONFIG_DB, 'hdel "DEVICE_METADATA|x509" ca_crt')
        st.config(dut, command)
    from apis.system.basic import service_operations_by_systemctl
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
    response_flag = False
    for retry in range(1,4):
        msg = "Trying REST call for iteration '{}'".format(retry)
        st.log(msg)
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
            response_flag = True
            break
        except requests.ConnectionError:
            st.error("A Connection error occurred.")
        except requests.Timeout:
            st.error("The request timed out.")
        except Exception as e:
            st.error(e)
    if not response_flag:
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
    token_dic = do_eval(out['output'])
    return token_dic.get('access_token', None)


def rest_status(status):
    """
    To give the response as per status code
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param status:
    :return:
    """
    if status in [200, 201, 204]:
        return True
    elif status in [400, 401, 403, 404, 405, 409, 415, 500]:
        return False

def rest_operation(dut, **kwargs):
    op = kwargs.get("http_method")
    url = kwargs.get("rest_url")
    data = kwargs.get("json_data")
    timeout = kwargs.get("timeout", 5)
    log_msg = []
    status_map = {200 : "Rest operation successful", 201 : "Rest operation successful", 204 : "Rest operation successful", 400 : "Bad Request", 401 : "Unauthorized", 403 : "Forbidden", 404 : "Page not found", 405 : "Method not allowed", 409 : "Conflict", 415 : "Unsupported Media Type", 500 : "Internal Server Error"}
    retval = {}
    rest_result = True
    log_msg.append("[{}] -- HTTP METHOD : {}".format(dut, op.upper()))
    log_msg.append("URL : {}".format(url))
    if data:
        log_msg.append("PAYLOAD : {}".format(data))
    if not op or not url:
        st.log("Please provide http_method: {} or rest_url: {}".format(op,url))
        return False
    op = op.lower()
    if op in ["get","delete"]:
        params = {"path":url, "rest_timeout":timeout}
    elif op in ["post", "put", "patch"]:
        params = {"path": url, "data":data,"rest_timeout": timeout}
    else:
        st.log("Please provide valid Http method")
        return False
    if kwargs.get("username"):
        params.update({"rest_username":kwargs.get("username")})
    if kwargs.get("password"):
        params.update({"rest_password":kwargs.get("password")})
    for iteration in range(1,5):
        try:
            if op == "get":
                retval = st.rest_read(dut, **params)
            elif op == "post":
                retval = st.rest_create(dut, **params)
            elif op == "put":
                retval = st.rest_update(dut, **params)
            elif op == "delete":
                retval = st.rest_delete(dut, **params)
            elif op == "patch":
                retval = st.rest_modify(dut, **params)
            else:
                st.log("Please provide valid Http method")
                return False
            break
        except Exception as e:
            if iteration > 2:
                credentials = st.get_credentials(dut)
                st.rest_init(dut, credentials[0], credentials[1], credentials[2])
            if op == "get":
                tout = 180 if int(timeout) < 180 else timeout
                st.log("Setting timeout to {} sec".format(tout))
                params.update({"rest_timeout": tout})
            st.error(e)
    if "url" in retval.keys():
        host_ip = re.findall(r'([0-9]+(?:\.[0-9]+){3})', retval["url"])
        if host_ip:
            log_msg.insert(1, "HOST IP : {}".format(host_ip[0]))
    if "status" in retval.keys():
        log_msg.append("STATUS : {} - {}".format(retval["status"], status_map[retval["status"]]))
        rest_result = True if retval["status"] in [200, 201, 204] else False
    if op == "get":
        if "output" in retval.keys():
            log_msg.append("OUTPUT : {}".format(retval["output"]))
    if rest_result:
        st.log("{}".format(", ".join(log_msg)))
    else:
        st.error("{}".format(", ".join(log_msg)))
    return retval

######################################################
# REST APIS FOR CONFIG, GET, DELETE AND VERIFY STARTS
######################################################
def build_url(dut, name, *args):
    rest_urls = st.get_datastore(dut, 'rest_urls')
    return rest_urls[name].format(*args)


def fix_set_url(url, data):
    if re.search(r"Eth\d+/\d+/\d+", url):
        url = re.sub(r"Eth(\d+)/(\d+)/(\d+)", r"Eth\1%2F\2%2F\3", url)
    elif re.search(r"Eth\d+/\d+", url):
        url = re.sub(r"Eth(\d+)/(\d+)", r"Eth\1%2F\2", url)
    if "|" not in url:
        return url, data
    parts = url.split("|")
    portions = parts[0].split("/")
    new_url = "/".join(portions[:-1])
    data_key = list(data.keys())[0]
    data_value = list(data.values())[0]
    node = data_key.replace(":config","").replace(":interface","")
    if "{}s".format(node) == portions[-2]:
        new_portion = portions[-2]
        node = ""
    else:
        if node in portions[-2]:
            new_portion = portions[-2].replace(node,"")
        else:
            new_portion = portions[-2]
    if node:
        new_key = "{}:{}".format(node, new_portion.replace(":",""))
        if not isinstance(data_value, list):
            new_data_dict = {"config": data_value}
        else:
            new_data_dict = data_value[0]
    else:
        new_key = new_portion
        if isinstance(data_value, list):
            new_data_dict = data_value[0]
        else:
            new_data_dict = data_value
    for i in range(1, len(parts), 2):
        new_keys = parts[i].split(",")
        new_parts = parts[i+1].split(",")
        for index, part in enumerate(new_parts):
            if re.search(r"Eth\d+/\d+/\d+", part):
                part = re.sub(r"Eth(\d+)/(\d+)/(\d+)", r"Eth\1%2F\2%2F\3", part)
            elif re.search(r"Eth\d+/\d+", part):
                part = re.sub(r"Eth(\d+)/(\d+)", r"Eth\1%2F\2", part)
            value = part.split("/")[0].replace("=","").replace(",", "").replace("%2F","/")
            try:
                new_data_dict[new_keys[index]] = int(value)
            except Exception:
                new_data_dict[new_keys[index]] = value
    new_data = {new_key: {portions[-1]:[new_data_dict]}}
    return new_url, new_data


def fix_get_url(url):
    if re.search(r"Eth\d+/\d+/\d+", url):
        url = re.sub(r"Eth(\d+)/(\d+)/(\d+)", r"Eth\1%2F\2%2F\3", url)
    elif re.search(r"Eth\d+/\d+", url):
        url = re.sub(r"Eth(\d+)/(\d+)", r"Eth\1%2F\2", url)
    if "|" not in url:
        return url
    parts = url.split("|")
    new_parts = [parts[0]]
    for i in range(1, len(parts), 2):
        new_parts.append(parts[i+1])
    return "".join(new_parts)


def config_rest(dut, **kwargs):
    """
    Api to perform REST calls(POST,PUT and PATCH)
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    http_method = "PUT/POST/PATCH"
    rest_url = "OCYANG/SONIC YANG and itef"
    username = <username configured on DUT>
    password = <password configured on DUT>
    json_data = "JSON PAYLOAD"
    get_response = True/False(optional) (Send True if you want the output)
    """
    if kwargs.get("http_method") == "rest-put":
       kwargs["http_method"] = "put"
    elif kwargs.get("http_method") == "rest-patch":
       kwargs["http_method"] = "patch"
    if kwargs.get("http_method") not in ["put", "post", "patch"]:
        st.log("UNSUPPORTED HTTP METHOD FOR CONFIGURATION")
        return False
    if not kwargs.get("json_data"):
        st.log("Please provide json data to configure")
        return False
    get_response = kwargs.get("get_response", False)
    st.debug("BEFORE CONVERSION - {} .....".format(kwargs.get("http_method").upper()))
    st.debug("URL : {}".format(kwargs["rest_url"]))
    st.debug("PAYLOAD : {}".format(kwargs["json_data"]))
    if "/restconf/data/sonic-" not in kwargs["rest_url"]:
        url, data = fix_set_url(kwargs["rest_url"], kwargs["json_data"])
        kwargs.update({"rest_url": url, "json_data": data})
    st.debug("AFTER CONVERSION - {} .....".format(kwargs.get("http_method").upper()))
    st.debug("URL : {}".format(kwargs["rest_url"]))
    st.debug("PAYLOAD : {}".format(kwargs["json_data"]))
    output = rest_operation(dut, **kwargs)
    if not get_response:
        if output and output.get("status"):
            return rest_status(output['status'])
        return False
    else:
        return output


def get_rest(dut,**kwargs):
    """
    Api to perform REST call GET
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    username = <username configured on DUT>
    password = <password configured on DUT>
    rest_url = "OCYANG/SONIC YANG and itef"
    """
    kwargs["http_method"] = "get"
    kwargs["timeout"] = kwargs.get("timeout", 10)
    st.debug("BEFORE CONVERSION - GET.....")
    st.debug("URL : {}".format(kwargs["rest_url"]))
    if "/restconf/data/sonic-" not in kwargs["rest_url"]:
        url = fix_get_url(kwargs.get("rest_url"))
        kwargs.update({"rest_url":url})
    st.debug("AFTER CONVERSION - GET.....")
    st.debug("URL : {}".format(kwargs["rest_url"]))
    return rest_operation(dut, **kwargs)


def delete_rest(dut,**kwargs):
    """
    Api to perform REST call Delete
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    username = <username configured on DUT>
    password = <password configured on DUT>
    rest_url = "OCYANG/SONIC YANG and itef"
    get_response = True/False(optional) (Send True if you want the output)
    """
    kwargs["http_method"] = "delete"
    get_response = kwargs.get("get_response", False)
    st.debug("BEFORE CONVERSION - DELETE.....")
    st.debug("URL : {}".format(kwargs["rest_url"]))
    if "/restconf/data/sonic-" not in kwargs["rest_url"]:
        url = fix_get_url(kwargs.get("rest_url"))
        kwargs.update({"rest_url": url})
    st.debug("AFTER CONVERSION -DELETE.....")
    st.debug("URL : {}".format(kwargs["rest_url"]))
    output = rest_operation(dut, **kwargs)
    if not get_response:
        if output and output.get("status"):
            return rest_status(output['status'])
        return False
    else:
        return output


def verify_rest(get_response, match):
    """
    Api to verify POST/PUT/PATCH/user defined data with get response
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param get_response: REST call Get output
    :param match: POST/PUT/PATCH/ user defined data
    :return:
    """
    if isinstance(match[list(match.keys())[0]], list):
        return compare_dict(get_response, match, post=True)
    else:
        return compare_dict(get_response, match, post=False)


def compare_dict(get_response, match,post=False):
    """
    This is a helper function to compare two dictionaries
    :param get_response:
    :param match:
    :param post:
    :return:
    """
    if post:
        post_data = dict()
        for key, value in match.items():
            try:
                post_data[key.split(":")[1]] = match[key]
            except Exception:
                st.log("Invalid post data")
                return False
        if not compare_dict(list(get_response.values())[0], post_data,post=False):
            return False
    else:
        for key, value in match.items():
            if key not in get_response:
                st.log("key: {} not present in get response".format(key))
                return False
            if isinstance(value, dict):
                if not compare_dict(get_response[key], value):
                    return False
            elif isinstance(value, list):
                for each in value:
                    if isinstance(each, dict):
                        result = filter_and_select(output=get_response[key], select=each)
                        flag = 0
                        for each_item in result:
                            if compare_dict(each_item, each):
                                flag = 1
                                break
                        if not flag:
                            return False
                    else:
                        if each not in get_response[key]:
                            st.log("{} {} is not present in get response".format(key, each))
                            return False
            else:
                if not value == get_response[key]:
                    st.debug("{} is {} expected {}".format(key, get_response[key], value))
                    return False
    return True


def rest_data_refresh(dut_list):
    for dut in dut_list:
        credentials = st.get_credentials(dut)
        st.rest_init(dut, credentials[0], credentials[1], credentials[2])


def convert_to_post(input_data):
    """
    Api to get POST json data using PATCH/PUT json data
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    :param: input_data (PATCH/PUT data)
    :return: POST data
    """
    post_data = dict()
    temp = list(input_data.keys())[0]
    if isinstance(input_data[temp], dict):
        for key, value in input_data[temp].items():
            post_data["{}:{}".format(temp.split(':')[0], key)] = value
    else:
        for key, value in input_data[temp][0].items():
            if isinstance(value, dict):
                if "{}".format(temp.split('-')[0]) not in key:
                    post_data["{}:{}".format(temp.split(':')[0], key)] = value
                else:
                    post_data[key] = value
    return post_data


def get_http_method(dut=None):
    """
    Common method to fetch the HTTP method
    :param dut:
    :return:
    """
    http_method = "patch" # This line will be replaced with infra provided API to fetch the HTTP method option from Command Line
    return  http_method

####################################################
# REST APIS FOR CONFIG, GET, DELETE AND VERIFY ENDS
####################################################
