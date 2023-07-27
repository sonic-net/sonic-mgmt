import subprocess
import sys
import json
import yaml
import os
import re
import time
from collections import defaultdict
from utilities.common import open_file

"""
Example: GET
         python -m gnmi get -target_addr 10.11.97.10:8080 -alsologtostderr -insecure -xpath "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/" -username admin -password YourPaSsWoRd -display
         python -m gnmi get -val-only -target_addr 10.11.97.10:8080 "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/"
         or
         python -m gnmi get -xpath "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/"
         or
         python -m gnmi -xpath "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/"


example: SET (-replace & -delete )

         python -m gnmi set -target_addr 10.11.97.10:8080 -alsologtostderr -insecure
                -replace "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/mtu:@./interface_mtu.json"
         python -m gnmi set -target_addr 10.11.97.10:8080 -alsologtostderr -insecure
                -delete "/openconfig-acl:acl/acl-sets/acl-set[name=MyACL4][type=ACL_IPV4]/acl-entries/acl-entry[sequence-id=1]"
         or
         python -m gnmi set -replace "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/mtu:@./interface_mtu.json"
         python -m gnmi set -delete "/openconfig-acl:acl/acl-sets/acl-set[name=MyACL4][type=ACL_IPV4]/acl-entries/acl-entry[sequence-id=1]"


Config File (sgnmi.yaml)
Note. Parameter passed through CLI will have higher precedence than the config file

parameters:
    host:  10.11.97.10
    port:  8080
    ca: ~                       //unused for now
    cert: ~                       //unused for now
    username: ~                       //unused for now
    password: ~                       //unused for now
    options:
        - -alsologtostderr
        - -insecure
        - -val-only             // if successfull GET, it only outpu JSON w/ TAB formatting



"""

BASE_DIR = os.path.dirname(__file__)
GNMI_GET = os.path.join(BASE_DIR, "gnmi_get")
GNMI_SET = os.path.join(BASE_DIR, "gnmi_set")
VAL_SECT = "val: <"
VAL_ANY = r"any_val: <([^>]+)>"
VAL_JSON = "json_ietf_val"  # expected return with successfull GET
OP_KEY = "op:"  #expected return with successfull SET operation
CONFIG_YAML = os.path.join(BASE_DIR, "conf.yaml")
TEMP_FILE_PATH = "/tmp/"


def yamlParser(src):
    class ctLoader(yaml.loader.Loader):  # pylint: disable=too-many-ancestors
        pass

    def construct_mapping(loader, node, deep=False):
        mapping = defaultdict(list)
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            value = loader.construct_object(value_node, deep=deep)
            mapping[key].append(value)
        return mapping

    ctLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    return yaml.load(src, ctLoader)


def gnmiSend(action="GET", xpath="", target_addr="", inSecure=True, encoding=None, parameters=""):
    from apis.gnmi.gnmi_utils import SanitizePathPayload
    ret_val = ""
    if (action == "GET"):
        if encoding:
            new_path = SanitizePathPayload(xpath)
            if new_path != xpath:
                print("GNMI GET with Encoding Path/Data changed:\n... From path='{}'\n...   To path='{}'".format(xpath, new_path))
            xpath = new_path
        param = ['-xpath', xpath, "-alsologtostderr"]
        if target_addr != "": param.extend(['-target_addr', target_addr])
        if inSecure is True: param.append("-insecure")
        if parameters != "": param.extend(parameters.split())
        # print( "@gnmiSend parameters: %s"%param)
        ret_val = _gnmi_get(param, display=False, encoding=encoding)
    else:
        param = []
        if (action == "DELETE"):
            param = ["-delete", xpath]
        elif (action == "UPDATE"):
            param = ["-update", xpath]
        elif (action == "CREATE"):
            param = ["-create", xpath]
        else:
            param = ["-replace", xpath]

        param.extend(["-target_addr", target_addr, "-alsologtostderr"])
        if inSecure is True: param.append("-insecure")
        if parameters != "": param.extend(parameters.split())

        # print( "@gnmiSend to _gnmi_set parameters: %s"%param)
        ret_val = _gnmi_set(param, display=False, encoding=encoding)
    return ret_val


def _tmpOutputFile(ftype='json', dut_name="sgnmi"):
    return "{}gnmi_output_{}-{}.{}".format(TEMP_FILE_PATH, dut_name, int(round(time.time() * 1000)), ftype)


def _gnmi_get(param, display=False, default_param=False, encoding=None):
    pretty = False
    ret_val = {}

    # print ("@_gnmi_get() param: %s"%param)
    if default_param:
        param = _getDefaultParam(param)

    if "-val-only" in param:
        pretty = True
        param.remove("-val-only")

    if "-display" in param:
        display = True
        param.remove("-display")

    if encoding:
        param.extend(['-encoding', encoding])

    outputFile = _tmpOutputFile(ftype='proto' if encoding else 'json')
    param.extend(['-output', outputFile])

    execution = [GNMI_GET] + list(map(str, param))
    # print ("Executing GET %s"%(execution))

    if os.getenv("SPYTEST_FILE_MODE", "0") != "0":
        return {"ok": False}

    get_out = subprocess.Popen(execution, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    o, _ = get_out.communicate()

    # print( 'Output: ' + o.decode('ascii'))
    # print ('code: ' + str(get_out.returncode))
    if get_out.returncode != 0:
        # print 'Error: '  + str(o.decode('ascii'))
        error = _returnErr(o.decode('ascii'))
        ret_val = {"ok": False, 'errorCode': get_out.returncode, 'message': error}
    else:
        rval = _returnVal(o, outputFile)
        if rval != "":
            if pretty:
                val = json.loads(rval)
                # print val
                ret_val = json.dumps(val, indent=4, sort_keys=True, ensure_ascii=False)
            else:
                ret_val = {"ok": True, "return": rval}
        else:
            ret_val = {"ok": False, "return": ""}

    if display:
        print(str(ret_val))

    return ret_val


def gnmiCreateProtoFile(path, data={}, dut_name="sgnmi"):
    from apis.gnmi.gnmi_utils import JsonToProto, SanitizePathPayload
    proto_file = ""

    # print ('gnmiCreateProtoFile::org input\n{}\n{}'.format(path, data))
    path, data = SanitizePathPayload(path, data)
    fpath = "{}gnmi_data_{}-{}.{}".format(TEMP_FILE_PATH, dut_name, int(round(time.time() * 1000)), "proto")
    # print ('gnmiCreateProtoFile::sanitzed input\n{}\n{}'.format(path, data))
    proto_data = JsonToProto(path, data)
    # print ('gnmiCreateProtoFile::proto_data\n{}'.format(proto_data))
    try:
        if proto_data is not None:
            f = open(fpath, "w")
            f.write(str(proto_data))
            f.close()
        else:
            raise ValueError("PROTO data is None!")

        if os.path.exists(fpath):
            proto_file = fpath
    except Exception as e:
        print("Unable to create/update file %s for GNMI! \n %s" % (fpath, str(e)))

    return path, proto_file


def gnmiCreateJsonFile(data={}, dut_name="sgnmi"):
    json_file = ""

    fpath = "{}gnmi_data_{}-{}.{}".format(TEMP_FILE_PATH, dut_name, int(round(time.time() * 1000)), "json")
    json_data = json.dumps(data, ensure_ascii=False)
    try:
        f = open(fpath, "w")
        f.write(json_data)
        f.close()

        if os.path.exists(fpath):
            json_file = fpath
    except Exception as e:
        print("Unable to create/update file %s for GNMI! \n %s" % (fpath, str(e)))

    return json_file


def gnmiReplaceData(data, path, target, dut_name="sgnmi", parameters=""):
    success = False
    json_file_path = gnmiCreateJsonFile(data, dut_name)
    jpath = path + ":@" + json_file_path

    val = gnmiSend(action="REPLACE", xpath=jpath, target_addr=target, parameters=parameters)
    if val["ok"]:
        success = True
    return success


def _gnmi_set(param, display=False, default_param=False, encoding=None):
    ret_val = {}
    # ret_op = "REPLACE" #default as REPLACE
    pretty = False

    if default_param:
        param = _getDefaultParam(param)

    # if "-delete" in param:
        # ret_op = "DELETE"

    if "-val-only" in param:
        pretty = True
        param.remove("-val-only")

    if "-display" in param:
        display = True
        param.remove("-display")

    if encoding:
        param.extend(['-encoding', encoding])

    execution = [GNMI_SET] + list(map(str, param))
    # print("Executing SET %s"%(execution))

    if os.getenv("SPYTEST_FILE_MODE", "0") != "0":
        return {"ok": False}

    get_out = subprocess.Popen(execution, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    o, _ = get_out.communicate()

    # print( 'Output: ' + o.decode('ascii'))
    # print( 'code: ' + str(get_out.returncode))
    # print( 'Error: >>'  + _returnErr(o) + '<<')
    if get_out.returncode != 0:
        error = _returnErr(o)
        ret_val = {"ok": False, 'errorCode': get_out.returncode, 'message': error}
    else:
        if pretty:
            val = json.loads(_returnVal(o))
            # print("VAL = ",val)
            ret_val = json.dumps(val, indent=4, sort_keys=True, ensure_ascii=False)
        else:
            ret_val = {"ok": True, "return": "", "operation": _returnOpVal(o)}

    if display:
        print(str(ret_val))

    return ret_val


def _returnVal(output, file=None):
    from apis.gnmi.gnmi_utils import ProtoToJson
    ret_val = ""
    js = {}
    val_sect_found = False
    txt = output.decode()
    lSect = [x for x in re.split(r'== (\w+):\s*', re.sub(r'\\(\w+)', r'\\\\\1', txt).replace('<', '').replace('>', '')) if x]
    # import pprint
    # pprint.pprint(['out lSect', lSect, len(lSect) ])
    sects = {lSect[i]: (yamlParser(lSect[i + 1]) if i < len(lSect) - 1 else '') for i in range(0, len(lSect), 2)}
    # pprint.pprint(['out', sects ])
    path = ''.join(['/' + x['name'][0] for x in sects['getRequest']['path'][0]['elem']])
    for line in txt.splitlines():
        ln = line.strip()
        if VAL_SECT == ln: val_sect_found = True
        if val_sect_found:
            if not (file and os.path.exists(file)) and ln.startswith(VAL_JSON + ':'):
                js.update(json.loads(json.loads(ln.replace(VAL_JSON + ':', '', 1))))
    anyValMatch = re.search(VAL_ANY, txt)
    if file and os.path.exists(file):
        with open_file(file, "r") as fh:
            data = fh.read()
            print('output from file:{}\n"{}"'.format(file, data))
            if anyValMatch:
                js.update(ProtoToJson(path, data))
            elif data != '<nil>':
                js.update(json.loads(data))
            elif anyValMatch:
                print('output from screen:\n"{}"'.format(anyValMatch.group(1)))
                js.update(ProtoToJson(path, anyValMatch.group(1)))
            else:
                print('no output match:\n"{}"'.format(txt))
        os.remove(file)
    elif anyValMatch:
        js.update(ProtoToJson(path, anyValMatch.group(1)))
    else:
        print('no file or output match:\n"{}"'.format(txt))
    ret_val = json.dumps(js, ensure_ascii=False)
    # print("ret_val: {}".format(ret_val))
    return ret_val


def _returnOpVal(output):
    ret_val = {}
    for line in output.decode().splitlines():
        if OP_KEY in line:
            ret_val = line.split(OP_KEY)[1].strip()
            break

    return ret_val


def _returnErr(output):
    errorLine = ""
    for line in output.splitlines():
        if "failed" in str(line):
            # errorLine = str(line).split('] ')[1]
            errorLine = line.decode() if isinstance(line, bytes) else str(line)
            break
    return errorLine


def _getDefaultParam(input_params):
    merge_params = input_params
    # print "original params: ", input_params
    stream = open(CONFIG_YAML, 'r')
    defaults = yaml.load(stream, Loader=yaml.FullLoader)  # pylint: disable=no-member
    # for key, value in defaults.items():
    #    print key + " : " + str(value)

    if "-target_addr" not in input_params:
        target_addr = str(defaults["parameters"]["host"]) + ":" + str(defaults["parameters"]["port"])
        merge_params = merge_params + ["-target_addr", target_addr]

    for option in defaults["parameters"]["options"]:
        if option not in input_params:
            merge_params.append(option)

    # print "new params: ", merge_params
    return merge_params


def main():
    if sys.argv[1] == 'get':
        _gnmi_get(sys.argv[2:])
    elif sys.argv[1] == 'set':
        _gnmi_set(sys.argv[2:])
    else:
        _gnmi_get(sys.argv[1:])


if __name__ == "__main__":
    main()
