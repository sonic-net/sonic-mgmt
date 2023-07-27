import os
import re
import traceback
import json
import pprint

from spytest.dicts import SpyTestDict
from spytest.gnmi.wrapper import _gnmi_get, _gnmi_set, gnmiCreateJsonFile, gnmiCreateProtoFile

class gNMI(object):

    def __init__(self, logger=None, devName='DUT'):
        self.dev_name = devName
        self.target_addr = os.getenv("SPYTEST_GNMI_ADDRESS")
        self.target_name = os.getenv("SPYTEST_GNMI_NAME")
        self.logger     = logger
        self.timeout    = 10
        self.ip         = None
        self.inSecure   = True

    def configure(self, ip=None, port=8080, targetName=None, username='admin',
                  password=None, ca=None, cert=None, inSecure=True, noTls=False,
                  timeout=10, params=None):
        self.target_name = targetName
        self.username   = username
        self.password   = password
        self.ca         = ca
        self.cert       = cert
        self.inSecure   = inSecure
        self.noTls      = noTls
        self.timeout    = timeout
        self.defTimeout = timeout
        self.params     = params

        if ip:
            self.reinit(ip , port=port)
        return self

    def reinit(self, ip, port=8080):
        self.ip     = ip.decode('utf-8') if type(ip) == bytes else str(ip)
        self.port   = int(port)
        self.target_addr = "{}:{}".format(self.ip, self.port)
        return self

    def _compose_params(self, action, path, *args):
        param = [action, path]
        if self.target_addr: param.extend(['-target_addr', self.target_addr])
        if self.inSecure: param.append( "-insecure")
        if self.noTls: param.append( "-notls")
        if self.username: param.extend(['-username', self.username])
        if self.password: param.extend(['-password', self.password])
        if self.ca: param.extend(['-ca', self.ca])
        if self.cert: param.extend(['-cert', self.cert])
        if self.timeout and self.timeout != 10: param.extend(['-time_out', re.sub(r'\..*|\D', '', str(self.timeout))+'s'])
        param.extend(args)
        return param

    def _log(self, msg):
        if self.logger:
            self.logger.info(msg)
        else:
            print(msg)

    def _warn(self, msg):
        if self.logger:
            self.logger.warning(msg)
        else:
            print("WARNING:: "+str(msg))

    def _json(self, retval=''):
        try:
            return json.loads(retval) if retval else ''
        except Exception as exp:
            self._log('Invalid JSON: {}\n"{}"'.format(exp, retval))
            # traceback.print_exc()
            # return default
            return None

    def _result(self, operation, path, retval, inp=None):
        resp = SpyTestDict()
        resp.url = path
        resp.operation = operation
        resp.status = bool(retval["ok"])
        resp.input = inp
        resp.output = self._json(retval.get('return')) or retval.get('return', retval)
        self._log(json.dumps(resp))
        return resp

    def get(self, path, params='', encoding=None):
        from apis.gnmi.gnmi_utils import SanitizePathPayload
        path_change = False
        if encoding:
            attr = path.split("/")[-1]
            new_path = SanitizePathPayload(path)
            if new_path != path:
                path_change = True
                self._warn("GNMI GET with Encoding Path/Data changed:\n... From path='{}'\n...   To path='{}'".format(path, new_path))
            path = new_path
        param = self._compose_params('-xpath', path, "-alsologtostderr")
        if params: param.extend(params.split())
        self._log("GNMI [GET]: {}".format(path))
        try:
            ret_val = _gnmi_get(param, display=False, encoding=encoding)

            if path_change and "return" in ret_val:
               output = json.loads(ret_val["return"])
               self._log("GNMI [GET] original : {}".format(output))

               if output:
                  new_key =  list(output.keys())[0]
                  output = output[new_key]
                  ret_val["return"] = {}
                  if attr in output:
                     if ":" in attr:
                        new_key = attr
                     else:
                        new_key = new_key.split(":")[0] + ":"+attr
                     ret_val["return"] = {new_key:output[attr]}

            return self._result('GET', path, ret_val)
        except Exception as e:
            self._log("params: {}".format(param))
            traceback.print_exc()
            raise e

    def _set(self, path, action, params='', data={}, encoding=None):
        data_path = None
        if data and len(data):
            if encoding == 'ANY' and action.lower() not in ['delete']:
                new_path, data_path = gnmiCreateProtoFile(path, data, self.dev_name)
                if new_path != path:
                    self._warn("GNMI SET with Encoding Path/Data changed:\n... From path='{}'\n...   To path='{}'".format(path, new_path))
                path = '{}:@{}'.format(new_path, data_path)
            else:
                data_path = gnmiCreateJsonFile(data, self.dev_name)
                path = '{}:@{}'.format(path, data_path)
        param = self._compose_params('-{}'.format(action.lower()), path, "-alsologtostderr")
        if params: param.extend(params.split())
        self._log("GNMI [{}]: {}".format(action.upper(), path))
        if data: self._log("data:\n{}".format(pprint.pformat(data)))
        try:
            ret_val = _gnmi_set(param, display=False, encoding=encoding)
            return self._result(action.upper(), path, ret_val, data)
        except Exception as e:
            self._log("params: {}".format(param))
            traceback.print_exc()
            raise e
        finally:
            if data_path and os.path.exists(data_path):
                os.remove(data_path)

    def create(self, path, params='', data={}, encoding=None):
        return self._set(path, 'create', params=params, data=data, encoding=encoding)

    def update(self, path, params='', data={}, encoding=None):
        return self._set(path, 'update', params=params, data=data, encoding=encoding)

    def replace(self, path, params='', data={}, encoding=None):
        return self._set(path, 'replace', params=params, data=data, encoding=encoding)

    def delete(self, path, params='', data={}, encoding=None):
        return self._set(path, 'delete', params=params, data=data, encoding=encoding)

    def send(self, path, action='', params='', data=None, encoding=None, timeout=None):
        self.timeout = timeout if timeout else self.defTimeout
        if action.lower() in ['create', 'update', 'replace', 'delete']:
            return self._set(path, action, params=params, data=data, encoding=encoding)
        else:
            return self.get(path, params=params, encoding=encoding)

if __name__ == '__main__':
    def _main():
        r = gNMI().configure(ip='100.94.116.37', password='admin') #'Sonic@Dell')
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/"))
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/", encoding='PROTO'))
        r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu",
            action='replace', data={"openconfig-interfaces:mtu": 1450})
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/"))
        r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu",
            action='update', data={"openconfig-interfaces:mtu": 9000}, encoding='ANY')
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu", encoding='PROTO'))
        pprint.pprint(r.send('/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global', encoding='PROTO'))
    _main()
