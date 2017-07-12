#!/usr/bin/python
from netaddr import *
import sys
import ipaddress

DOCUMENTATION = '''
module:         get_ip_in_range
version_added:  "1.0"
short_description: Get certain number of ips within a prefix
description:
    - Generate certain number of unique IP withn a subnet
    - Generated ips will be inserted into the 'generated_ips' key
options:
   num:
      description:
          - set to the number of ip that needs to be generated.
      required: true
   prefix:
      description:
          - the required ip range in prefix format.
      required: true
   exclude_ips:
      description:
          - the ips within the prefix that are excluded.
      required: false
'''

EXAMPLES = '''
- name: Get IP in range
  get_ip_in_range: num={{num}} prefix={{prefix}}
'''


class IpRangeModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
              num=dict(required=True, type='int'),
              prefix=dict(required=True),
              exclude_ips=dict(required=False, default=[], type='list'),
            ),
            supports_check_mode=True)

        self.out = None
        self.facts = {}

        return

    def run(self):
        """
            Main method of the class
        
        """
        m_args = self.module.params
        exclude_ips = []
        ip_list = m_args['exclude_ips']
        for ip in ip_list:
            exclude_ips.append(IPAddress(ip))

        self.generate_ips(m_args['num'], m_args['prefix'], exclude_ips)
        self.module.exit_json(ansible_facts=self.facts)


    def generate_ips(self, num, prefix, exclude_ips):
        """
           Generate ips
        """
        prefix = IPNetwork(prefix)
        exclude_ips.append(prefix.broadcast)
        exclude_ips.append(prefix.network)
        available_ips = list(prefix)

        if len(available_ips) - len(exclude_ips)< num: 
           self.module.fail_json(msg="Don't have enough available ips in prefix, num=%d, prefix=%s, exclude_ips=%s." % 
                                (num, prefix, exclude_ips))   
        generated_ips = []
        for available_ip in available_ips:
            if available_ip not in exclude_ips:
                generated_ips.append(str(available_ip) + '/' + str(prefix.prefixlen))
            if len(generated_ips) == num:
                break            
        self.facts['generated_ips'] = generated_ips
        return


def main():
    ip_range = IpRangeModule()
    ip_range.run()

    return


from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
