def main():
    module = AnsibleModule(
        argument_spec=dict(
            vm_topo_config=dict(required=True, type="dict"),
            tunnel_config=dict(required=False, type='str', default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    tunnel_config = m_args['tunnel_config']

    tunnel_configs = {}
    try:
        if 'tunnel_configs' in m_args['vm_topo_config']['DUT']:
            if tunnel_config is None or len(tunnel_config) == 0:
                tunnel_config = m_args['vm_topo_config']['DUT']['tunnel_configs']['default_tunnel_config']

            tunnels = m_args['vm_topo_config']['DUT']['tunnel_configs'][tunnel_config]
            for tunnel, tunnel_param in tunnels.items():
                tunnel_configs.update({tunnel : {}})
                tunnel_configs[tunnel]['type'] = tunnel_param['type']
                tunnel_configs[tunnel]['attach_to'] = tunnel_param['attach_to']
                tunnel_configs[tunnel]['dscp'] = tunnel_param['dscp']
                tunnel_configs[tunnel]['ecn_encap'] = tunnel_param['ecn_encap']
                tunnel_configs[tunnel]['ecn_decap'] = tunnel_param['ecn_decap']
                tunnel_configs[tunnel]['ttl_mode'] = tunnel_param['ttl_mode']

    except Exception as e:
        module.fail_json(msg = traceback.format_exc())
    else:
        module.exit_json(ansible_facts={'tunnel_configs' : tunnel_configs})

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
    