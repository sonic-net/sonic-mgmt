#!/usr/bin/env python3
"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

python3 CLI utility for interacting with Network Elements using gNMI.

This utility can be utilized as a reference, or standalone utility, for
interacting with Network Elements which support OpenConfig and gNMI.

Current supported gNMI features:
- GetRequest
- SetRequest (Update, Replace, Delete)
- Target hostname override
- Auto-loads Target cert from Target if not specified
- User/password based authentication
- Certifificate based authentication
- Capabilities
- Subscribe: On-Change

Current unsupported gNMI features:
- 
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import argparse
import json
import logging
import os
import re
import ssl
import sys
import six
from time import sleep
import threading
from random import seed
from random import randint
from functools import reduce

from gnmi_base_ap import ApData, GnmiApBase
from queue import Queue
from logger.cafylog import CafyLog
import grpc

TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

log = CafyLog("GNMI Test Lib")
try:
  import gnmi_pb2
except ImportError:
  print('ERROR: Ensure you\'ve installed dependencies from requirements.txt\n'
        'eg, pip install -r requirements.txt')
import gnmi_pb2_grpc
sys.path.append('../p4/')
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError
import google.protobuf.json_format

__version__ = '0.4'

_RE_PATH_COMPONENT = re.compile(r'''
^
(?P<pname>[^[]+)  # gNMI path name
(\[(?P<key>\w+)   # gNMI path key
=
(?P<value>.*)    # gNMI path value
\])?$
''', re.VERBOSE)


class Error(Exception):
    """Module-level Exception class."""


class XpathError(Error):
    """Error parsing xpath provided."""


class ValError(Error):
    """Error parsing provided val from CLI."""


class JsonReadError(Error):
    """Error parsing provided JSON file."""


class FindTypeError(Error):
    """Error identifying type of provided value."""


# List of all active connections
connections = []


class GnmiConnection(object):

    def __init__(self, target='127.0.0.1', port=9339, notls=True, get_cert=None, certs=None, host_override=None):
        self.target = target
        self.port = port
        self.creds = _build_creds(target, port, get_cert, certs, notls)
        if self.creds:
            if host_override:
                self.channel = gnmi_pb2_grpc.grpc.secure_channel(
                    target + ':' + port, self.creds, (('grpc.ssl_target_name_override', host_override,),))
            else:
                self.channel = gnmi_pb2_grpc.grpc.secure_channel(
                    target + ':' + port, self.creds)
        else:
            self.channel = grpc.insecure_channel(target + ':' + port)

        self.stub = gnmi_pb2_grpc.gNMIStub(self.channel)
        connections.append(self)

    def shutdown(self):
        self.channel.close()

    def closeAllConnections(self):
        for c in connections:
            log.info("Shutting down connection: {}".format(c))
            c.shutdown()


def _create_parser():
    """Create parser for arguments passed into the program from the CLI.

    Returns:
      Argparse object.
    """
    parser = argparse.ArgumentParser(description='gNMI CLI utility.')
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExample'
        ' GetRequest without user/password and over-riding Target certificate CN:'
        '\npython py_gnmicli.py -t 127.0.0.1 -p 8080 -x \'/access-points/'
        'access-point[hostname=test-ap]/\' -rcert ~/certs/target-cert.crt -o '
        'openconfig.example.com')
    parser.add_argument('-t', '--target', type=str, help='The gNMI Target',
                        required=True)
    parser.add_argument('-p', '--port', type=str, help='The port the gNMI Target '
                        'is listening on', required=True)
    parser.add_argument('-user', '--username', type=str, help='Username to use'
                        'when establishing a gNMI Channel to the Target',
                        required=False)
    parser.add_argument('-pass', '--password', type=str, help='Password to use'
                        'when establishing a gNMI Channel to the Target',
                        required=False)
    parser.add_argument('-m', '--mode', choices=[
        'get', 'set-update', 'set-replace', 'set-delete', 'subscribe-onchange',
                        'subscribe', 'capabilities'], help='Mode of operation when interacting with network element.'
                        ' Default=get. If set, it can be either value \nor JSON '
                        'file (prepend filename with "@")', default='get')
    parser.add_argument('-val', '--value', type=str, help='Value for SetRequest.'
                        '\nCan be Leaf value or JSON file. If JSON file, prepend'
                        ' with "@"; eg "@interfaces.json".',
                        required=False)
    parser.add_argument('-pkey', '--private_key', type=str, help='Fully'
                        'quallified path to Private key to use when establishing'
                        'a gNMI Channel to the Target', required=False)
    parser.add_argument('-rcert', '--root_cert', type=str, help='Fully quallified'
                        'Path to Root CA to use when building the gNMI Channel',
                        required=False)
    parser.add_argument('-cchain', '--cert_chain', type=str, help='Fully'
                        'quallified path to Certificate chain to use when'
                        'establishing a gNMI Channel to the Target', default=None,
                        required=False)
    parser.add_argument('-g', '--get_cert', help='Obtain certificate from gNMI '
                        'Target when establishing secure gRPC channel.',
                        required=False, action='store_true')
    parser.add_argument('-x', '--xpath', type=str, help='The gNMI path utilized'
                        'in the GetRequest or Subscirbe', required=True)
    parser.add_argument('-o', '--host_override', type=str, help='Use this as '
                        'Targets hostname/peername when checking it\'s'
                        'certificate CN. You can check the cert with:\nopenssl '
                        'x509 -in certificate.crt -text -noout', required=False)
    parser.add_argument('-f', '--format', type=str, action='store', help='Format '
                        'of the GetResponse to be printed. Default=JSON.',
                        choices=['json', 'protobuff'], default='json',
                        required=False)
    parser.add_argument('-V', '--version', help='Print program version',
                        action='store_true', required=False)
    parser.add_argument('-d', '--debug', help='Enable gRPC debugging',
                        required=False, action='store_true')
    parser.add_argument('-n', '--notls', help='gRPC insecure mode',
                        required=False, action='store_true')
    return parser


def json_load_byteified(file_handle):
    return _byteify(json.load(file_handle, object_hook=_byteify),
                    ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    # if this is a unicode string, return its string representation
    # if isinstance(data, unicode):
    if isinstance(data, str):
        return data
        # For Python2 - return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.items()
        }
    # if it's anything else, return it in its original form
    return data

def _path_names(xpath):
  """Parses the xpath names.

    This takes an input string and converts it to a list of gNMI Path names. Those
    are later turned into a gNMI Path Class object for use in the Get/SetRequests.
    Args:
      xpath: (str) xpath formatted path.

  Returns:
    list of gNMI path names.
  """
  if not xpath or xpath == '/':  # A blank xpath was provided at CLI.
    return []
  print(xpath)
  xpath = xpath.strip().strip('/')  
  ppath = re.split('''/(?=(?:[^\[\]]|\[[^\[\]]+\])*$)''', xpath)
  #print(ppath)
  return ppath
  #return xpath.strip().strip('/').split('/')  # Remove leading and trailing '/'.


def _parse_path(p_names,target=None):
  """Parses a list of path names for path keys.

  Args:
    p_names: (list) of path elements, which may include keys.

  Returns:
    a gnmi_pb2.Path object representing gNMI path elements.

  Raises:
    XpathError: Unabled to parse the xpath provided.
  """
  gnmi_elems = []
  #print(p_names)
  for word in p_names:
    #print(word)
    word_search = _RE_PATH_COMPONENT.search(word)
    if not word_search:  # Invalid path specified.
      raise XpathError('xpath component parse error: %s' % word)
    if word_search.group('key') is not None:  # A path key was provided.
      tmp_key = {}
      for x in re.findall(r'\[([^]]*)\]', word):
        tmp_key[x.split("=")[0]] = x.split("=")[-1]
      gnmi_elems.append(gnmi_pb2.PathElem(name=word_search.group(
          'pname'), key=tmp_key))
    else:
      gnmi_elems.append(gnmi_pb2.PathElem(name=word, key={}))

  if target is not None:
    return gnmi_pb2.Path(elem=gnmi_elems,target=target)
  else:
    return gnmi_pb2.Path(elem=gnmi_elems)



def _create_stub(creds, target, port, host_override):
    """Creates a gNMI Stub.

    Args:
      creds: (object) of gNMI Credentials class used to build the secure channel.
      target: (str) gNMI Target.
      port: (str) gNMI Target IP port.
      host_override: (str) Hostname being overridden for Cert check.

    Returns:
      a gnmi_pb2_grpc object representing a gNMI Stub.
    """
    if creds:
        if host_override:
            channel = gnmi_pb2_grpc.grpc.secure_channel(target + ':' + port, creds, ((
                'grpc.ssl_target_name_override', host_override,),))
        else:
            channel = gnmi_pb2_grpc.grpc.secure_channel(
                target + ':' + port, creds)
    else:
        #channel = gnmi_pb2_grpc.grpc.insecure_channel(target + ':' + port)
        channel = grpc.insecure_channel(target + ':' + port)
    return gnmi_pb2_grpc.gNMIStub(channel)


def _format_type(json_value):
    """Helper to determine the Python type of the provided value from CLI.

    Args:
      json_value: (str) Value providing from CLI.

    Returns:
      json_value: The provided input coerced into proper Python Type.
    """
    if (json_value.startswith('-') and json_value[1:].isdigit()) or (
            json_value.isdigit()):
        return int(json_value)
    if (json_value.startswith('-') and json_value[1].isdigit()) or (
            json_value[0].isdigit()):
        return float(json_value)
    if json_value.capitalize() == 'True':
        return True
    if json_value.capitalize() == 'False':
        return False
    return json_value  # The value is a string.


def _get_val(json_value):
    """Get the gNMI val for path definition.

    Args:
      json_value: (str) JSON_IETF or file.

    Returns:
      gnmi_pb2.TypedValue()
    """
    val = gnmi_pb2.TypedValue()
    if '@' in json_value:
        try:
            set_json = json.loads(six.moves.builtins.open(
                json_value.strip('@'), 'r').read())
        except (IOError, ValueError) as e:
            raise JsonReadError('Error while loading JSON: %s' % str(e))
        val.json_ietf_val = json.dumps(set_json).encode()
        return val
    coerced_val = _format_type(json_value)
    type_to_value = {bool: 'bool_val', int: 'int_val', float: 'float_val',
                     str: 'string_val'}
    if type_to_value.get(type(coerced_val)):
        setattr(val, type_to_value.get(type(coerced_val)), coerced_val)
    return val


def _get_val_neg_payload(json_value):
    """Get the gNMI val for path definition.

    Args:
      json_value: (str) JSON_IETF or file.

    Returns:
      gnmi_pb2.TypedValue()
    """
    val = gnmi_pb2.TypedValue()
    # print(type(json_value))
    set_json = json.dumps(json_value).encode()
    # print(set_json)
    val.proto_bytes = set_json
    return val


def _get_val_in(json_value):
    """Get the gNMI val for path definition.

    Args:
      json_value: (str) JSON_IETF or file.

    Returns:
      gnmi_pb2.TypedValue()
    """
    val = gnmi_pb2.TypedValue()
    # print(type(json_value))
    set_json = json.dumps(json_value).encode()
    # print(set_json)
    val.json_ietf_val = set_json
    return val


def _cap(stub, username, password):
    """Create a gNMI CapabilitiesRequest.

    Args:
      stub: (class) gNMI Stub used to build the secure channel.
      paths: gNMI Path
      username: (str) Username used when building the channel.
      password: (str) Password used when building the channel.

    Returns:
      a gnmi_pb2.CapResponse object representing a gNMI GetResponse.
    """
    if username:  # User/pass supplied for Authentication.
        return stub.Capabilities(
            gnmi_pb2.CapabilityRequest(),
            metadata=[('username', username), ('password', password)])
    return stub.Capabilities(gnmi_pb2.CapabilityRequest())


def _get(stub, paths, username, password, prefix="/", type='ALL', encoding='PROTO', use_models=None, extension=None, target=None):
    """Create a gNMI GetRequest.

    Args:
      stub: (class) gNMI Stub used to build the secure channel.
      paths: gNMI Path
      username: (str) Username used when building the channel.
      password: (str) Password used when building the channel.

    Returns:
      a gnmi_pb2.GetResponse object representing a gNMI GetResponse.
    """
    if target is not None:
        prefix = _parse_path(_path_names(prefix),target)
    else:
        prefix = _parse_path(_path_names(prefix))
    print("pfx: {}".format(prefix))
    print("path: {}".format([paths]))
    if username:  # User/pass supplied for Authentication.
        return stub.Get(
            gnmi_pb2.GetRequest(
                path=[paths], prefix=prefix, type=type, encoding=encoding),
            metadata=[('username', username), ('password', password)])
    #request = gnmi_pb2.GetRequest(path=[paths], prefix=prefix, type=type, encoding=encoding)
    #print(request.encoding)
    return stub.Get(gnmi_pb2.GetRequest(path=[paths], prefix=prefix, type=type, encoding=encoding))


def _get_wo_encoding(stub, paths, username, password, prefix="/", type='ALL', use_models=None, extension=None):
    """Create a gNMI GetRequest.

    Args:
      stub: (class) gNMI Stub used to build the secure channel.
      paths: gNMI Path
      username: (str) Username used when building the channel.
      password: (str) Password used when building the channel.

    Returns:
      a gnmi_pb2.GetResponse object representing a gNMI GetResponse.
    """
    prefix = _parse_path(_path_names(prefix))
    if username:  # User/pass supplied for Authentication.
        return stub.Get(
            gnmi_pb2.GetRequest(path=[paths], prefix=prefix, type=type),
            metadata=[('username', username), ('password', password)])
    return stub.Get(gnmi_pb2.GetRequest(path=[paths], prefix=prefix, type=type))


def _set(stub, paths, set_type, username, password, json_value, pfx_paths=None, neg_payload=None):
    """Create a gNMI SetRequest.

    Args:
      stub: (class) gNMI Stub used to build the secure channel.
      paths: gNMI Path
      set_type: (str) Type of gNMI SetRequest.
      username: (str) Username used when building the channel.
      password: (str) Password used when building the channel.
      json_value: (str) JSON_IETF or file.

    Returns:
      a gnmi_pb2.SetResponse object representing a gNMI SetResponse.
    """
    request = gnmi_pb2.SetRequest()

    if (pfx_paths is not None):
        request.prefix.CopyFrom(pfx_paths)
        print(request)

    if json_value:  # Specifying ONLY a path is possible (eg delete).
        #val = _get_val(json_value)
        val = _get_val_in(json_value)
        path_val = gnmi_pb2.Update(path=paths, val=val,)

    if neg_payload:
        val = _get_val_neg_payload(json_value)
        path_val = gnmi_pb2.Update(path=paths, val=val,)

    if set_type == 'multiple':
        print(json_value)
        print("############")
        if 'set-replace' in json_value['set-lst'].keys():
            set_json = json_value['set-lst']['set-replace']
            print(set_json)
            val = _get_val_in(set_json)
            path_val = gnmi_pb2.Update(path=paths, val=val,)
            request.replace.extend([path_val])

        if 'set-update' in json_value['set-lst'].keys():
            set_json = json_value['set-lst']['set-update']
            print(set_json)
            val = _get_val_in(set_json)
            path_val = gnmi_pb2.Update(path=paths, val=val,)
            request.update.extend([path_val])

        if 'set-delete' in json_value['set-lst'].keys():
            set_path = json_value['set-lst']['set-delete']['path']
            log.info(set_path)
            paths = _parse_path(_path_names(set_path))
            request.delete.extend([paths])

    kwargs = {}
    if username:
        kwargs = {'metadata': [('username', username), ('password', password)]}

    if set_type == 'delete':
        request.delete.extend([paths])
    elif set_type == 'update':
        request.update.extend([path_val])
    elif set_type == 'replace':
        request.replace.extend([path_val])

    print("=== Below SET REQUEST Sent===")
    print(request)
    reply = stub.Set(request, **kwargs)

    return reply


"""
  kwargs = {}
  if username:
    kwargs = {'metadata': [('username', username), ('password', password)]}
  if set_type == 'delete':
    return stub.Set(gnmi_pb2.SetRequest(delete=[paths]), **kwargs)
  elif set_type == 'update':
    return stub.Set(gnmi_pb2.SetRequest(update=[path_val]), **kwargs)
  return stub.Set(gnmi_pb2.SetRequest(replace=[path_val]), **kwargs)
"""


def print_msg(msg, prompt):
    print("***************************")
    print(prompt)
    print(msg)
    print("***************************")


def parse_key_val(key_val_str):
    # [key1=val1,key2=val2,.....]
    key_val_str = key_val_str[1:-1]  # remove "[]"
    return [kv.split('=') for kv in key_val_str.split(',')]

# parse path_str string and add elements to path (gNMI Path class)


def build_path(path_str, path):
    if path_str == '/':
        # the root path should be an empty path
        return

    path_elem_info_list = re.findall(
        r'/([^/\[]+)(\[([^=]+=[^\]]+)\])?', path_str)

    for path_elem_info in path_elem_info_list:
        # [('interfaces', ''), ('interface', '[name=1/1/1]'), ...]
        pe = path.elem.add()
        pe.name = path_elem_info[0]

        if path_elem_info[1]:
            for kv in parse_key_val(path_elem_info[1]):
                # [('name', '1/1/1'), ...]
                pe.key[kv[0]] = kv[1]


# for subscrption
stream_out_q = Queue()
stream_in_q = Queue()
stream = None


def _sub_onchange(stub, paths, username, password):
    """Create a gNMI onChange SubscribeRequest.

     Args:
      stub: (class) gNMI Stub used to build the secure channel.
      paths: gNMI Path
      set_type: (str) Type of gNMI SetRequest.
      username: (str) Username used when building the channel.
      password: (str) Password used when building the channel.

    Returns:
      a gnmi_pb2.SubscribeResponse object representing a gNMI onChangeSubscribe Response.
    """

    kwargs = {}
    if username:
        kwargs = {'metadata': [('username', username), ('password', password)]}
    req = gnmi_pb2.SubscribeRequest()
    subList = req.subscribe
    subList.mode = gnmi_pb2.SubscriptionList.STREAM
    subList.updates_only = True
    sub = subList.subscription.add()
    sub.mode = gnmi_pb2.ON_CHANGE
    # The below build_path proc can also be used to create Path Elements if needed
    # If build_path is used then 'xpath' needs to be passed as arg to _sub_onchange
    #path = sub.path
    #build_path(xpath, path)
    path = sub.path
    path.CopyFrom(paths)
    print("Path Elements to be added to Subscribe Msg:: ", path)
    return req


'''
  stream_out_q.put(req)
  stream = stub.Subscribe(req_iterator())
  stream_recv_thread = threading.Thread(
            target=stream_recv, args=(stream,))
        stream_recv_thread.start()

        try:
            while True:
                sleep(1)
        except KeyboardInterrupt:
            stream_out_q.put(None)
            stream_recv_thread.join()
'''


def req_iterator():
    while True:
        req = stream_out_q.get()
        if req is None:
            print("BREAKKKK")
            break
        print_msg(req, "REQUEST")
        yield req


def stream_recv(stream):
    for resp in stream:
        print_msg(resp, "RESPONSE")
        stream_in_q.put(resp)


def _build_creds(target, port, get_cert, certs, notls):
    """Define credentials used in gNMI Requests.

    Args:
      target: (str) gNMI Target.
      port: (str) gNMI Target IP port.
      get_cert: (str) Certificate should be obtained from Target for gRPC channel.
      certs: (dict) Certificates to use in building the gRPC channel.

    Returns:
      a gRPC.ssl_channel_credentials object.
    """
    if notls:
        return
    if get_cert:
        logging.info('Obtaining certificate from Target')
        rcert = ssl.get_server_certificate((target, port)).encode('utf-8')
        return gnmi_pb2_grpc.grpc.ssl_channel_credentials(
            root_certificates=rcert, private_key=certs['private_key'],
            certificate_chain=certs['cert_chain'])
    return gnmi_pb2_grpc.grpc.ssl_channel_credentials(
        root_certificates=certs['root_cert'], private_key=certs['private_key'],
        certificate_chain=certs['cert_chain'])


def _open_certs(**kwargs):
    """Opens provided certificate files.

    Args:
      root_cert: (str) Root certificate file to use in the gRPC channel.
      cert_chain: (str) Certificate chain file to use in the gRPC channel.
      private_key: (str) Private key file to use in the gRPC channel.

    Returns:
      root_cert: (str) Root certificate to use in the gRPC channel.
      cert_chain: (str) Certificate chain to use in the gRPC channel.
      private_key: (str) Private key to use in the gRPC channel.
    """
    for key, value in kwargs.items():
        if value:
            kwargs[key] = six.moves.builtins.open(value, 'rb').read()
    return kwargs

# This proc works for oc-interfaces, ietf-interfaces, Any response that has a key:name pair in prefix:elem
# As more response types come about, we will need to add more procs to cover them.

def get_response_dict(get_value):
    main_key = None
    old_key = None
    response_dict = dict()
    prefix_dict = dict()
    ans_dict = dict()
    main_key_dict = dict()
    pfx_list = list()

    try:
        value_dict = get_value['notification']
    except KeyError:
        response_dict = None
        return response_dict

    for value in value_dict:
        ans_dict = dict()
        prefix_dict = dict()
        first_val = True
        target_dict = dict()
        for key_val in value['prefix']['elem']:
            try:
                main_key = key_val['key']['name']
                main_key = main_key.replace("\'","")
                #main_key = re.sub(r'\W+', '',main_key)

                if old_key is None:
                    old_key = main_key
                
            except KeyError:
                pass
            if first_val:
                full_key = key_val['name']
                first_val = False
                continue
            if type(key_val['name']) != bool:
                full_key = full_key + "," + key_val['name']
        prefix_key = full_key
        
        try:
            target = value['prefix']['target']
        except KeyError:
            target = None
        
        target_dict['target'] = target

        values = value['update']
        for val in values:
            i = 0
            #keys = val['val'].keys()
            lkeys = list(val['val'].keys())
            ans = val['val'][lkeys[i]]

            for key_val in val['path']['elem']:
                if type(key_val['name']) != bool:
                    full_key = prefix_key + "," + key_val['name']

            if main_key is not None:
                full_key = main_key + "," + full_key

            ans_dict[key_val['name']] = ans
            response_dict[full_key] = ans

        prefix_dict[prefix_key] = ans_dict

        if main_key != old_key:
            if main_key in main_key_dict.keys():
                pfx_list = main_key_dict[main_key]
                pfx_list.append(prefix_dict)
                main_key_dict[main_key] = pfx_list
            else:
                pfx_list = list();pfx_list.append(prefix_dict)
                pfx_list.append(target_dict)
                main_key_dict[main_key] = pfx_list
            old_key = main_key
            prefix_dict = dict()
        else:
            if old_key in main_key_dict.keys():
                pfx_list = main_key_dict[old_key]
                pfx_list.append(prefix_dict)
                main_key_dict[old_key] = pfx_list
            else:
                pfx_list = list();pfx_list.append(prefix_dict)
                pfx_list.append(target_dict)
                main_key_dict[old_key] = pfx_list

    return main_key_dict
    #return response_dict


def parallel_oper(oper):
    user = None
    password = None
    err_msg = list()
    result = dict()
    result['oper'] = oper
    seed(1)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration(
        "test_gnmi_parallel_oper/input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.port_addr)
    stub = gnmi_conn.stub

    if 'set' in oper:
        try:
            for num in range(1, 4096):
                intf_num = randint(1, 4095)
                log.info("SET INTF_NUM {}".format(intf_num))
                set_info = input_conf["SCALE_INTF_{}".format(intf_num)]["config"]
                xpath = "/"
                paths = _parse_path(_path_names(xpath))
                reply = _set(stub, paths, 'update', user, password, set_info)
                if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                    log.info("test_parallel_set_get:Passed - was able to do SET-UPDATE with input json")
                else:
                    log.error(
                        "test_parallel_set_get:Failed - was unable to do SET-UPDATE with input json")
                    err_msg.append(
                        "test_parallel_set_get:Failed - was unable to do SET-UPDATE with input json")
        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append(
                "Test test_parallel_set_get failed due to Grpc Error {err}".format(err=e.details()))
        gnmi_conn.shutdown()
    elif 'get' in oper:
        try:
            for num in range(1, 4096):
                intf_num = randint(1, 4095)
                log.info("PARALLEL GET INTF_NUM {}".format(intf_num))
                set_info = input_conf["SCALE_INTF_{}".format(intf_num)]["config"]
                prefix = input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['prefix']
                #prefix = _parse_path(_path_names(prefix))
                path = input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['path']
                path = _parse_path(_path_names(path))
                response = _get(stub, path, user, password,prefix,type='CONFIG')
                #log.info(response)
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                resp_dict = get_response_dict(msg_dict)
                for cfg in input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['config']:
                    section = cfg['section']
                    set_info = input_conf[section]['config']
                    ver_result = verify_get_response(resp_dict,set_info,cfg)
                    err_msg = ver_result['err_msg'] + err_msg

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append(
                "Test test_parallel_set_get failed due to Grpc Error {err}".format(err=e.details()))
        gnmi_conn.shutdown()

    if len(err_msg) != 0:
        result["msg"] = err_msg
        result["status"] = False
    else:
        result["status"] = True

    return result

def parallel_target_oper(ops):
    user = None
    password = None
    err_msg = list()
    ret_result = dict()
    oper = ops.split(":")[0]
    encoding = ops.split(":")[1]
    ret_result['oper'] = oper
    
    try:    
        gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.port_addr)
        stub = gnmi_conn.stub
        tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
        input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
        #print(input_conf)

        if 'SETPfxPath2_1' in input_conf:
            set_info1 = input_conf['SETPfxPath2_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            target = 'SET_GNMI_TGT'

            prefix = input_conf['VERIFY_SETPfxPath2_1']['prefix']
            path = input_conf['VERIFY_SETPfxPath2_1']['path']
            path = _parse_path(_path_names(path))
            if 'no_target' in oper:
                response = _get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            else:
                response = _get(stub, path, user, password,prefix,type='CONFIG',target=target,encoding=encoding)

            #log.info(response) 
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = get_response_dict(msg_dict)
                if 'no_target' in oper:
                    for cfg in input_conf['VERIFY_PARALLEL_NO_TGT']['config']:
                        section = cfg['section']
                        set_info = input_conf[section]
                        result = verify_get_response(resp_dict,set_info,cfg)
                        err_msg = result['err_msg'] + err_msg
                else:
                    for cfg in input_conf['VERIFY_SETPfxPath2_1']['config']:
                        section = cfg['section']
                        set_info = input_conf[section]
                        result = verify_get_response(resp_dict,set_info,cfg)
                        err_msg = result['err_msg'] + err_msg
        
            elif 'JSON_IETF' in encoding:
                resp_target = response.notification[0].prefix.target
                if 'no_target' in oper:
                    resp_target = response.notification[0].prefix.target
                    if resp_target is not "":
                        log.error("GET response should not have a target set, current target set as : %s" % resp_target)
                        err_msg.append("GET response should not have a target set, current target set as : %s" % resp_target)
                    else:
                        log.info("GET response does not have target set as expected")
                else:
                    if resp_target is not "":
                        if resp_target == target:
                            log.info("Received matching target in GET response")
                        else:
                            log.error("Received target does not match the target set")
                            err_msg.append("Received target does not match the target set")
                    else:
                        log.error("GET response does not have target set")
                        err_msg.append("GET response does not have target set")

                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                #print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = set_info1['Updates']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append(
            "Test test_multiple_target_get failed due to Grpc Error {err}".format(err=e.details()))
    gnmi_conn.shutdown()

    if len(err_msg) != 0:
        ret_result["msg"] = err_msg
        ret_result["status"] = False
    else:
        ret_result["status"] = True

    return ret_result


def verify_get_response(resp_dict,set_info,cfg_section,target=None):
    err_msg = list()
    result = dict()
    status = True
    resp_key = cfg_section['name']
    log.info(resp_dict)

    get_var = None
    get_key = cfg_section.get('get_key')
    set_key = cfg_section.get('set_key')
    chk_var_list = cfg_section.get('check_var_list')
    expected_result = cfg_section.get('exp_result')
    if expected_result is None:
        expected_result = True

    if resp_key in resp_dict.keys():
        for var in chk_var_list:
            work_set_info = set_info
            if set_key is None:
                value = work_set_info.get(var)
                set_var = value
            else:
                for val in set_key:
                    if type(val) is str:
                        value = work_set_info.get(val)
                        work_set_info = value
                    if type(val) is int:
                        value = work_set_info[val]
                        work_set_info = value
                set_var = work_set_info.get(var)
            
            if set_var is None:
                for key in work_set_info.keys():
                    if var in key:
                        set_var = work_set_info[key]
            for key_var in resp_dict[resp_key]:
                if get_key is None:
                    if var in key_var.keys():
                        try:
                            get_var = key_var[var]
                        except KeyError:
                            err_msg.append("No matching check variable: {} in the Get response dict".format(var))

                else:
                    if get_key in key_var.keys():
                        try:
                            get_var = key_var[get_key][var]
                        except KeyError:
                            err_msg.append("No matching check variable: {} in the Get response dict".format(var))

            if set_var != None:
                # As more combination arises, this logic will need to be looked at. 
                # This entire proc is getting a bit complicated with various combinations of check
                # currently if the get_var returned is None, for e.g. target None, the error message is misleading but 
                # expected result is accurate.
                if get_var != None:
                    if type(set_var) is int or type(get_var) is int:
                        if int(get_var) != int(set_var):
                            err_msg.append("{} does not match the {} in input json file: {}".format(get_var,var,set_var))
                        else:
                            log.info("{} from config file matches Gnmi Get :{}".format(set_var,get_var))
                    else:
                        if str(get_var) not in str(set_var):
                            err_msg.append("{} does not match the {} in input json file: {}".format(get_var,var,set_var))
                        else:
                            log.info("{} from config file matches Gnmi Get :{}".format(set_var,get_var))
                else:
                    err_msg.append("No matching variable: {} in the Get response dict".format(var))
            else:
                err_msg.append("Var {} not found in the set config section".format(var))

    else:
        err_msg.append("Interface {} missing from the GET response".format(resp_key))

    if len(err_msg) != 0:
        if expected_result is True:
            status = False
        else:
            log.info(' '.join(map(str, err_msg)))
            log.info("Expected the result to be Fail")
            status = True
            err_msg = list()

    result['err_msg'] = err_msg
    result["status"] = status

    return result

def verify_json_ietf_response(set_dict,get_dict):
    err_msg = list()
    result = dict()
    status = True

    for (key, value) in set_dict.items():
        if key in get_dict.keys():
            if type(value) is str or type(get_dict[key]) is str:
                if str(value) in str(get_dict[key]):
                    log.info("{} matches {}".format(value, get_dict[key]))
                else:
                    log.error("{} does not match {}".format(value, get_dict[key]))
                    err_msg.append("{} does not match {}".format(value, get_dict[key]))
            elif type(value) is int or type(get_dict[key]) is int:
                if int(value) == int(get_dict[key]):
                    log.info("{} matches {}".format(value, get_dict[key]))
                else:
                    log.error("{} does not match {}".format(value, get_dict[key]))
                    err_msg.append("{} does not match {}".format(value, get_dict[key]))
        else:
            log.error("{} missing in {}".format(key,get_dict.keys()))
            err_msg.append("{} missing in {}".format(key,get_dict.keys()))

    result['err_msg'] = err_msg
    result["status"] = status

    return result