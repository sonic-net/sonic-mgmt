from __future__ import (absolute_import, division, print_function)
import os.path

try:
    from xmlrpclib import ServerProxy
except ImportError:
    from xmllib.client import ServerProxy
from ansible.utils.display import Display
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError
__metaclass__ = type

DOCUMENTATION = """
        lookup: servercfgd_client
        version_added: "1.0"
        short_description: Dispatches calls to remote functions registered in servercfgd
        description:
          - This lookup will make servercfgd procedure calls.
        options:
          _terms:
            description: list of servercfgd registered function names
            required: True
          servercfgd_host:
            description: IP address of target server that running servercfgd
            type: string
          conn_graph_file_content:
            description: Content of connection graph file to provision db
            type: string
            required: False
          enforce_provision:
            description: True to enforce provisioning db
            type: boolean
            required: False
          scripts:
            description: List of Lua scripts to register
            type: list
            required: False
"""

display = Display()


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        """Dispatches calls to servercfgd register functions."""
        self.set_options(var_options=variables, direct=kwargs)
        servercfgd_host = self.get_option('servercfgd_host')
        display.vvv('servercfgd host address: %s' % servercfgd_host)
        servercfgd = ServerProxy('http://%s:10033' % servercfgd_host)
        display.vvv('servercfgd supported remote calls: %s' % servercfgd.system.listMethods())
        for fname in terms:
            if fname == 'init_connection_db':
                servercfgd.init_connection_db()
            elif fname == 'provision_connection_db':
                conn_graph_file_content = str(self.get_option('conn_graph_file_content'))
                enforce_provision = self.get_option('enforce_provision')
                if not conn_graph_file_content:
                    raise AnsibleError("'conn_graph_file_content' is required for %s" % fname)
                servercfgd.provision_connection_db(conn_graph_file_content, enforce_provision)
            elif fname == 'register_scripts':
                for script in self.get_option('scripts'):
                    script_name = os.path.splitext(os.path.basename(script))[0]
                    script_content = open(script).read()
                    servercfgd.register_script(script_name, script_content)
            else:
                raise AnsibleError('%s unsupported by servercfgd.' % fname)
