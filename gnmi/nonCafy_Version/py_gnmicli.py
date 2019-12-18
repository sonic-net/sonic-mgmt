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
import google.protobuf.json_format
from queue import Queue
import grpc
try:
  import gnmi_pb2
except ImportError:
  print('ERROR: Ensure you\'ve installed dependencies from requirements.txt\n'
        'eg, pip install -r requirements.txt')
import gnmi_pb2_grpc

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
                      'subscribe', 'capabilities'], help=
                      'Mode of operation when interacting with network element.'
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
  return xpath.strip().strip('/').split('/')  # Remove leading and trailing '/'.


def _parse_path(p_names):
  """Parses a list of path names for path keys.

  Args:
    p_names: (list) of path elements, which may include keys.

  Returns:
    a gnmi_pb2.Path object representing gNMI path elements.

  Raises:
    XpathError: Unabled to parse the xpath provided.
  """
  gnmi_elems = []
  for word in p_names:
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
      channel = gnmi_pb2_grpc.grpc.secure_channel(target + ':' + port, creds)
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


def _get(stub, paths, username, password,type='CONFIG'):
  """Create a gNMI GetRequest.

  Args:
    stub: (class) gNMI Stub used to build the secure channel.
    paths: gNMI Path
    username: (str) Username used when building the channel.
    password: (str) Password used when building the channel.

  Returns:
    a gnmi_pb2.GetResponse object representing a gNMI GetResponse.
  """
  pfx = "/"
  pfx = _parse_path(_path_names("/"))
  if username:  # User/pass supplied for Authentication.
    return stub.Get(
        gnmi_pb2.GetRequest(path=[paths], encoding='PROTO',type=type),
        metadata=[('username', username), ('password', password)])
  return stub.Get(gnmi_pb2.GetRequest(path=[paths], prefix=pfx, type=type, encoding='PROTO'))

def _set(stub, paths, set_type, username, password, json_value):
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
  if json_value:  # Specifying ONLY a path is possible (eg delete).
    val = _get_val(json_value)
    path_val = gnmi_pb2.Update(path=paths, val=val,)

  kwargs = {}
  if username:
    kwargs = {'metadata': [('username', username), ('password', password)]}
  if set_type == 'delete':
    return stub.Set(gnmi_pb2.SetRequest(delete=[paths]), **kwargs)
  elif set_type == 'update':
    return stub.Set(gnmi_pb2.SetRequest(update=[path_val]), **kwargs)
  return stub.Set(gnmi_pb2.SetRequest(replace=[path_val]), **kwargs)


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

    path_elem_info_list = re.findall(r'/([^/\[]+)(\[([^=]+=[^\]]+)\])?', path_str)

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
            print ("BREAKKKK")
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


def main():
  argparser = _create_parser()
  args = vars(argparser.parse_args())
  if args['version']:
    print(__version__)
    sys.exit()
  if args['debug']:
    os.environ['GRPC_TRACE'] = 'all'
    os.environ['GRPC_VERBOSITY'] = 'DEBUG'
  mode = args['mode']
  target = args['target']
  port = args['port']
  notls = args['notls']
  get_cert = args['get_cert']
  root_cert = args['root_cert']
  cert_chain = args['cert_chain']
  json_value = args['value']
  private_key = args['private_key']
  xpath = args['xpath']
  host_override = args['host_override']
  user = args['username']
  password = args['password']
  form = args['format']
  paths = _parse_path(_path_names(xpath))
  kwargs = {'root_cert': root_cert, 'cert_chain': cert_chain,
            'private_key': private_key}
  certs = _open_certs(**kwargs)
  creds = _build_creds(target, port, get_cert, certs, notls)
  stub = _create_stub(creds, target, port, host_override)
  if mode == 'get':
    print('Performing GetRequest, encoding=JSON_IETF', 'to', target,
          ' with the following gNMI Path\n', '-'*25, '\n', paths)
    response = _get(stub, paths, user, password)
    print_msg(response, "REQUEST")
    #resp = stub.Get(req)
    #print_msg(resp, "RESPONSE")
    #print('The GetResponse is below\n' + '-'*25 + '\n')
    #if form == 'protobuff':
    #  print(response)
    #elif response.notification[0].update[0].val.json_ietf_val:
    #  print(json.dumps(json.loads(response.notification[0].update[0].val.
    #                              json_ietf_val), indent=2))
    #elif response.notification[0].update[0].val.string_val:
    #  print(response.notification[0].update[0].val.string_val)
    #else:
    #  print('JSON Format specified, but gNMI Response was not json_ietf_val')
    #  print(response)
  elif mode == 'capabilities':
    print('Performing CapabilitiesRequest to target \n')
    response = _cap(stub, user, password)
    print('The CapabilitiesRequest response is below\n' + '-'*25 + '\n', response)
  elif mode == 'set-update':
    print('Performing SetRequest Update, encoding=JSON_IETF', ' to ', target,
          ' with the following gNMI Path\n', '-'*25, '\n', paths, json_value)
    response = _set(stub, paths, 'update', user, password, json_value)
    print('The SetRequest response is below\n' + '-'*25 + '\n', response)
  elif mode == 'set-replace':
    print('Performing SetRequest Replace, encoding=JSON_IETF', ' to ', target,
          ' with the following gNMI Path\n', '-'*25, '\n', paths)
    response = _set(stub, paths, 'replace', user, password, json_value)
    print('The SetRequest response is below\n' + '-'*25 + '\n', response)
  elif mode == 'set-delete':
    print('Performing SetRequest Delete, encoding=JSON_IETF', ' to ', target,
          ' with the following gNMI Path\n', '-'*25, '\n', paths)
    response = _set(stub, paths, 'delete', user, password, json_value)
    print('The SetRequest response is below\n' + '-'*25 + '\n', response)
  elif mode == 'subscribe-onchange':
    print('Performing Subscribe Onchange Request', 'to', target,
          ' with the following gNMI Path\n', '-'*25, '\n', paths)
    request = _sub_onchange(stub, paths, user, password)
    print('Subscribe REQUEST Sent')
    print (request)
    print('The Subscribe Onchange Request response is below\n' + '-'*25 + '\n')
    stream_out_q.put(request)
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
  elif mode == 'subscribe':
    print('This mode not available in this version')
    sys.exit()


if __name__ == '__main__':
  main()