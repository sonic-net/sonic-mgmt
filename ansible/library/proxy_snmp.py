#!/usr/bin/python

DOCUMENTATION = '''
module:  proxy_snmp
version_added:  "2.0.0.2"
short_description:  Parse the SNMPProxy call return value

Options:
    - action
      description: HTTP request action
      required: True
      Default: None

    - hostname: SONiC DUT name to test SNMPProxy query
      description: SONiC name that mach in inventory file
      required: True
      Default: None

'''

RETURN = '''
    ansible_fact: snmp_proxy_response
        {"_items": [
             "OutputItemOfkeysxxxxx": [
                    { "ErrorCode": "Success" },
                    { "Hostname": "str-s6000-acs-8" },
                    { "Timestamp": "2018-04-15T10:20:58.4394284-07:00"},
                    { "Value": "SONiC.20180104.06"}
                    ]
             ]
          "url": "http://corpsnmpproxy.autopilot.cy2.ap.gbl/snmpproxy/web/GetFirmwareVersion?Machine=str-s6000-acs-8&skipproxy=true"
       }

'''

EXAMPLES = '''
    -  name: Issue GetFirmwareVersion SNMPProxy call and parse the return result
       proxy_snmp: action="GetFirmwareVersion" hostname="{{ inventory_hostname }}"
       connection: local

'''

import requests
import lxml.etree as ET
from ansible.module_utils.basic import *

### use CO4 test cluster TestSnmpProxy machine
url_host = 'http://TestSnmpProxy.autopilot.co4.ap.gbl/snmpproxy/web/'
ns = 'http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution.SnmpProxy'
nsl = len(ns)+2

def parse_snmp_ele(ele):
    '''
        parse SNMPProxy returned _items elements
    '''
    name = ele.tag[nsl:]
    if len(ele):
        inner = []
        for i in ele:
            inner.append(parse_snmp_ele(i))
        return {name: inner}
    else:
        return   {name: ele.text}

def parse_snmp_proxy(action, dut):
    '''
        Parse SNMPProxy response XML string
        return: parsed xml response
    '''
    url = "%s%s?Machine=%s&skipproxy=true" % (url_host, action, dut)
    rr = {}
    rr['url'] = url
    resp = requests.get(url)
    root = ET.fromstring(resp.text)
    for e in root:
        name = e.tag[nsl:]
        if len(e):
            if e.tag == str(ET.QName(ns, '_items')):
                for item in e:
                    if len(item):
                        iname = item.tag[nsl:]
                        rr['_items'] = parse_snmp_ele(item)
            else:
                rr[name] = e.text
    return rr


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(required=True, type='str'),
            hostname=dict(required=True, type='str'),
        ),
        supports_check_mode=False)

    argus = module.params
    try:
        snmp_response = parse_snmp_proxy(argus['action'], argus['hostname'])
    except:
        err = str(sys.exc_info())
        module.fail_json(msg="Error: %s" % err)
    module.exit_json(ansible_facts={'snmp_proxy_response': snmp_response})

if __name__ == '__main__':
     main()
