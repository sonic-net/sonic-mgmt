from __future__ import (absolute_import, division, print_function)
import os.path
import yaml
import xml.etree.ElementTree as ET

from ansible.utils.display import Display
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
__metaclass__ = type

DOCUMENTATION = """
        lookup: graphfile
        version_added: "1.0"
        short_description: find connection graph file that has DUTs listed defined.
        description:
            - This lookup returns the connection graph file contains the DUTs.
        options:
          _terms:
            description: list of DUT hostnames
            required: True
"""

display = Display()
LAB_CONNECTION_GRAPH_FILE = 'graph_files.yml'


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        hostnames = terms[0]
        display.debug('Graph file lookup DUTs: %s' % hostnames)
        graph_list_file = self.find_file_in_search_path(variables, 'files', LAB_CONNECTION_GRAPH_FILE)
        if not graph_list_file:
            raise AnsibleError('Unable to locate %s' % LAB_CONNECTION_GRAPH_FILE)
        with open(graph_list_file) as fd:
            file_list = yaml.safe_load(fd)

        for gf in file_list:
            display.debug('Looking at conn graph file: %s' % gf)
            gf = self.find_file_in_search_path(variables, 'files', gf)
            if not gf:
                continue
            with open(gf) as fd:
                root = ET.fromstring(fd.read())
                hosts_all = [d.attrib['Hostname'] for d in root.iter('Device')]
                if set(hostnames) <= set(hosts_all):
                    return [os.path.basename(gf)]
        return []
