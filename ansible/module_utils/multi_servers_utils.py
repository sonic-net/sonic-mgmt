class MultiServersUtils:
    @staticmethod
    def filter_by_dut_interfaces_util(values, dut_interfaces):
        if isinstance(dut_interfaces, str) or isinstance(dut_interfaces, unicode):  # noqa F821
            dut_interfaces = MultiServersUtils.parse_multi_servers_interface(dut_interfaces)

        if isinstance(values, dict):
            return {k: v for k, v in values.items() if int(k) in dut_interfaces}
        elif isinstance(values, list):
            return [v for v in values if int(v) in dut_interfaces]
        else:
            raise ValueError('Unsupported type "{}"'.format(type(values)))

    @staticmethod
    def parse_multi_servers_interface(intf_pattern):
        intf_pattern = str(intf_pattern)
        intfs = []
        for intf in iter(map(str.strip, intf_pattern.split(','))):
            if intf.isdigit():
                intfs.append(int(intf))
            elif '-' in intf:
                intf_range = list(map(int, map(str.strip, intf.split('-'))))
                assert len(intf_range) == 2, 'Invalid interface range "{}"'.format(intf)
                intfs.extend(list(range(intf_range[0], intf_range[1]+1)))
            else:
                raise ValueError('Unsupported format "{}"'.format(intf_pattern))
        if len(intfs) != len(set(intfs)):
            raise ValueError('There are interface duplication/overlap in "{}"'.format(intf_pattern))
        return intfs

    @staticmethod
    def parse_topology_vms(VMs, dut_interfaces):
        if not dut_interfaces:
            return VMs

        if isinstance(dut_interfaces, str) or isinstance(dut_interfaces, unicode):  # noqa F821
            dut_interfaces = MultiServersUtils.parse_multi_servers_interface(dut_interfaces)

        result = {}
        offset = 0
        for hostname, attr in VMs.items():
            if dut_interfaces and attr['vlans'][0] not in dut_interfaces:
                continue
            result[hostname] = attr
            result[hostname]['vm_offset'] = offset
            offset += 1
        return result

    @staticmethod
    def generate_vm_name_mapping(servers_info, topo_vms):
        _m = {}

        for server_attr in servers_info.values():
            if 'dut_interfaces' in server_attr:
                filtered_vms = MultiServersUtils.parse_topology_vms(topo_vms, server_attr['dut_interfaces'])
                vm_base = server_attr['vm_base']
                vm_start_index = int(vm_base[2:])
                vm_name_fmt = 'VM%0{}d'.format(len(vm_base) - 2)

                for hostname, host_attr in filtered_vms.items():
                    vm_name = vm_name_fmt % (vm_start_index + host_attr['vm_offset'])
                    _m[hostname] = vm_name
        return _m
