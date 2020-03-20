#!/usr/bin/python
import sys

DOCUMENTATION = '''
module:         combine_list_to_dict
version_added:  "1.0"
short_description: Combine a list of key and list of value to a key-value dictionary
description:
    - Generate the dictionary based on key and value list
    - key and value are 1:1 mapping in sequence, and values with the same key will combined into a list.
    - Generated dict will be inserted into the 'combined_dict' key
options:
   keys:
      description:
          - the required key list
      required: true
   values:
      description:
          - the required value list.
      required: true
'''

EXAMPLES = '''
- name: Combine list to dict
  combine_list_to_dict: keys={{keys}} values={{values}}
'''

class CombineListModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
              keys=dict(required=True, type='list'),
              values=dict(required=True, type='list'),
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
        keys = m_args['keys']
        values = m_args['values']
        combined_dict = {}
        for key, value in zip(keys, values):
            if key not in combined_dict:
                combined_dict[key] = [value]
            else:
                combined_dict[key].append(value)
        self.facts['combined_dict'] = combined_dict
        self.module.exit_json(ansible_facts=self.facts)

def main():
    combine_list = CombineListModule()
    combine_list.run()

    return

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
