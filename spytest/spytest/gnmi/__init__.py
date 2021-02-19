import os, sys, re, time, traceback
import json, pprint

from spytest.dicts import SpyTestDict
from spytest.gnmi.wrapper import _gnmi_get, _gnmi_set, gnmiReplaceData, gnmiCreateJsonFile

class gNMI(object):

    def __init__(self, logger=None, devName=''):
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

    def _json(self, retval=''):
        try:
            return json.loads(retval)
        except Exception:
            # self._log('Invalid JSON: {}\n{}'.format(exp, retval))
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

    def get(self, path, params=''):
        param = self._compose_params('-xpath', path, "-alsologtostderr")
        if params: param.extend(params.split())
        self._log("GNMI [GET]: {}".format(path))
        try:
            ret_val = _gnmi_get(param, display=False)
            return self._result('GET', path, ret_val)
        except Exception as e:
            self._log("params: {}".format(param))
            traceback.print_exc()
            raise e

    def _set(self, path, action, params='', data={}):
        data_path = None
        if data and len(data):
            data_path = gnmiCreateJsonFile(data, '{}-{}'.format(self.dev_name, int(round(time.time() * 1000))))
            path = '{}:@{}'.format(path, data_path)
        param = self._compose_params('-{}'.format(action.lower()), path, "-alsologtostderr")
        if params: param.extend(params.split())
        self._log("GNMI [{}]: {}".format(action.upper(), path))
        if data: self._log("data:\n{}".format(pprint.pformat(data)))
        try:
            ret_val = _gnmi_set(param, display=False)
            return self._result(action.upper(), path, ret_val, data)
        except Exception as e:
            self._log("params: {}".format(param))
            traceback.print_exc()
            raise e
        finally:
            if data_path and os.path.exists(data_path):
                os.unlink(data_path)

    def create(self, path, params='', data={}):
        return self._set(path, 'create', params=params, data=data)

    def update(self, path, params='', data={}):
        return self._set(path, 'update', params=params, data=data)

    def replace(self, path, params='', data={}):
        return self._set(path, 'replace', params=params, data=data)

    def delete(self, path, params='', data={}):
        return self._set(path, 'delete', params=params, data=data)

    def send(self, path, action='', params='', data=None, timeout=None):
        self.timeout = timeout if timeout else self.defTimeout
        if action.lower() in ['create', 'update', 'replace', 'delete']:
            return self._set(path, action, params=params, data=data)
        else:
            return self.get(path, params=params)

if __name__ == '__main__':
    def _main():
        r = gNMI().configure(ip='10.11.68.14', password='Sonic@Dell')
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/"))
        r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu",
            action='replace', data={"openconfig-interfaces:mtu": 1450})
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/"))
        r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu",
            action='update', data={"openconfig-interfaces:mtu": 9000})
        pprint.pprint(r.send("/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/"))
    _main()

