#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Hewlett-Packard Development Company, L.P.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: floating_ip
author: OpenStack Ansible SIG
short_description: Manage floating IP addresses for OpenStack servers
description:
   - Add or remove an floating ip address to/from an OpenStack server.
   - Returns the floating IP when attaching only if I(wait) is C(true).
   - When detaching a floating IP there might be a delay until an server
     does not list the floating IP any more.
options:
   fixed_address:
     description:
        - To which fixed IP of server the floating IP address should be
          attached to.
     type: str
   floating_ip_address:
     description:
        - A floating IP address to attach or to detach. When I(state) is
          present can be used to specify a IP address to attach.
          I(floating_ip_address) requires I(network) to be set.
     type: str
   nat_destination:
     description:
        - The name or id of a neutron private network that the fixed IP to
          attach floating IP is on
     aliases: ["fixed_network", "internal_network"]
     type: str
   network:
     description:
        - The name or ID of a neutron external network or a nova pool name.
     type: str
   purge:
     description:
        - When I(state) is absent, indicates whether or not to delete the
          floating IP completely, or only detach it from the server.
          Default is to detach only.
     type: bool
     default: 'false'
   reuse:
     description:
        - When I(state) is present, and I(floating_ip_address) is not present,
          this parameter can be used to specify whether we should try to reuse
          a floating IP address already allocated to the project.
        - When I(reuse) is C(true), I(network) is defined and
          I(floating_ip_address) is undefined, then C(nat_destination) and
          C(fixed_address) will be ignored.
     type: bool
     default: 'false'
   server:
     description:
        - The name or ID of the server to which the IP address
          should be assigned.
     required: true
     type: str
   state:
     description:
       - Should the resource be present or absent.
     choices: [present, absent]
     default: present
     type: str
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
# Assign a floating IP to the first interface of `cattle001` from an existing
# external network or nova pool. A new floating IP from the first available
# external network is allocated to the project.
- openstack.cloud.floating_ip:
     cloud: dguerri
     server: cattle001

# Assign a new floating IP to the server fixed ip `192.0.2.3` of
# `cattle001`. If a free floating IP is already allocated to the project, it is
# reused; if not, a new one is created.
- openstack.cloud.floating_ip:
     cloud: dguerri
     state: present
     reuse: true
     server: cattle001
     network: ext_net
     fixed_address: 192.0.2.3
     wait: true
     timeout: 180

# Assign a new floating IP from the network `ext_net` to the server fixed
# ip in network `private_net` of `cattle001`.
- openstack.cloud.floating_ip:
     cloud: dguerri
     state: present
     server: cattle001
     network: ext_net
     nat_destination: private_net
     wait: true
     timeout: 180

# Detach a floating IP address from a server
- openstack.cloud.floating_ip:
     cloud: dguerri
     state: absent
     floating_ip_address: 203.0.113.2
     server: cattle001
'''

RETURN = '''
floating_ip:
  description: Dictionary describing the floating ip address.
  type: dict
  returned: success
  contains:
    created_at:
      description: Timestamp at which the floating IP was assigned.
      type: str
    description:
      description: The description of a floating IP.
      type: str
    dns_domain:
      description: The DNS domain.
      type: str
    dns_name:
      description: The DNS name.
      type: str
    fixed_ip_address:
      description: The fixed IP address associated with a floating IP address.
      type: str
    floating_ip_address:
      description: The IP address of a floating IP.
      type: str
    floating_network_id:
      description: The id of the network associated with a floating IP.
      type: str
    id:
      description: Id of the floating ip.
      type: str
    name:
      description: Name of the floating ip.
      type: str
    port_details:
      description: |
        The details of the port that this floating IP associates
        with. Present if C(fip-port-details) extension is loaded.
      type: dict
    port_id:
      description: The port ID floating ip associated with.
      type: str
    project_id:
      description: The ID of the project this floating IP is associated with.
      type: str
    qos_policy_id:
      description: The ID of the QoS policy attached to the floating IP.
      type: str
    revision_number:
      description: Revision number.
      type: str
    router_id:
      description: The id of the router floating ip associated with.
      type: str
    status:
      description: |
        The status of a floating IP, which can be 'ACTIVE' or 'DOWN'.
      type: str
    subnet_id:
      description: The id of the subnet the floating ip associated with.
      type: str
    tags:
      description: List of tags.
      type: list
      elements: str
    updated_at:
      description: Timestamp at which the floating IP was last updated.
      type: str
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class NetworkingFloatingIPModule(OpenStackModule):
    argument_spec = dict(
        fixed_address=dict(),
        floating_ip_address=dict(),
        nat_destination=dict(aliases=['fixed_network', 'internal_network']),
        network=dict(),
        purge=dict(type='bool', default=False),
        reuse=dict(type='bool', default=False),
        server=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        required_if=[
            ['state', 'absent', ['floating_ip_address']]
        ],
        required_by={
            'floating_ip_address': ('network'),
        }
    )

    def run(self):
        self._init()
        if self.params['state'] == 'present':
            self._create_and_attach()

        else:  # self.params['state'] == 'absent'
            self._detach_and_delete()

    def _create_and_attach(self):
        changed = False
        fixed_address = self.params['fixed_address']
        floating_ip_address = self.params['floating_ip_address']
        nat_destination_name_or_id = self.params['nat_destination']
        network_id = self.network['id'] if self.network else None

        ips = self._find_ips(
            server=self.server,
            floating_ip_address=floating_ip_address,
            network_id=network_id,
            fixed_address=fixed_address,
            nat_destination_name_or_id=nat_destination_name_or_id)

        # First floating ip satisfies our requirements
        ip = ips[0] if ips else None

        if floating_ip_address:
            # A specific floating ip address has been requested

            if not ip:
                # If a specific floating ip address has been requested
                # and it does not exist yet then create it

                # openstacksdk's create_ip requires floating_ip_address
                # and floating_network_id to be set
                self.conn.network.create_ip(
                    floating_ip_address=floating_ip_address,
                    floating_network_id=network_id)
                changed = True

            else:  # ip
                # Requested floating ip address exists already

                if ip.port_details and (ip.port_details['status'] == 'ACTIVE') \
                   and (floating_ip_address not in self._filter_ips(
                        self.server)):
                    # Floating ip address exists and has been attached
                    # but to a different server

                    # Requested ip has been attached to different server
                    self.fail_json(
                        msg="Floating ip {0} has been attached to different "
                            "server".format(floating_ip_address))

            if not ip \
               or floating_ip_address not in self._filter_ips(self.server):
                # Requested floating ip address does not exist or has not been
                # assigned to server

                self.conn.add_ip_list(
                    server=self.server,
                    ips=[floating_ip_address],
                    wait=self.params['wait'],
                    timeout=self.params['timeout'],
                    fixed_address=fixed_address)
                changed = True
            else:
                # Requested floating ip address has been assigned to server
                pass

        elif not ips:  # and not floating_ip_address
            # No specific floating ip has been requested and none of the
            # floating ips which have been assigned to the server matches
            # requirements

            # add_ips_to_server() will handle several scenarios:
            #
            # If a specific floating ip address has been requested then it
            # will be attached to the server. The floating ip address has
            # either been created in previous steps or it already existed.
            # Ref.: https://github.com/openstack/openstacksdk/blob/
            #       9d3ee1d32149ba2a8bb3dc894295e180746cdddc/openstack/cloud
            #       /_floating_ip.py#L985
            #
            # If no specific floating ip address has been requested, reuse
            # is allowed and a network has been given (with ip_pool) from
            # which floating ip addresses will be drawn, then any existing
            # floating ip address from ip_pool=network which is not
            # attached to any other server will be attached to the server.
            # If no such floating ip address exists or if reuse is not
            # allowed, then a new floating ip address will be created
            # within ip_pool=network and attached to the server.
            # Ref.: https://github.com/openstack/openstacksdk/blob/
            #       9d3ee1d32149ba2a8bb3dc894295e180746cdddc/openstack/cloud/
            #       _floating_ip.py#L981
            #
            # If no specific floating ip address has been requested and no
            # network has been given (with ip_pool) from which floating ip
            # addresses will be taken, then a floating ip address might be
            # added to the server, refer to _needs_floating_ip() for
            # details.
            # Ref.:
            # * https://github.com/openstack/openstacksdk/blob/
            #   9d3ee1d32149ba2a8bb3dc894295e180746cdddc/openstack/cloud/\
            #   _floating_ip.py#L989
            # * https://github.com/openstack/openstacksdk/blob/
            #   9d3ee1d32149ba2a8bb3dc894295e180746cdddc/openstack/cloud/
            #   _floating_ip.py#L995
            #
            # Both floating_ip_address and network are mutually exclusive
            # in add_ips_to_server(), i.e.add_ips_to_server will ignore
            # floating_ip_address if network is not None. To prefer
            # attaching a specific floating ip address over assigning any
            # fip, ip_pool is only defined if floating_ip_address is None.
            # Ref.: https://github.com/openstack/openstacksdk/blob/
            #       a6b0ece2821ea79330c4067100295f6bdcbe456e/openstack/cloud/
            #       _floating_ip.py#L987
            self.conn.add_ips_to_server(
                server=self.server,
                ip_pool=network_id,
                ips=None,  # No specific floating ip requested
                reuse=self.params['reuse'],
                fixed_address=fixed_address,
                wait=self.params['wait'],
                timeout=self.params['timeout'],
                nat_destination=nat_destination_name_or_id)
            changed = True
        else:
            # Found one or more floating ips which satisfy requirements
            pass

        if changed:
            # update server details such as addresses
            self.server = self.conn.compute.get_server(self.server)

            # Update the floating ip resource
            ips = self._find_ips(
                self.server, floating_ip_address, network_id,
                fixed_address, nat_destination_name_or_id)

        # ips can be empty, e.g. when server has no private ipv4
        # address to which a floating ip address can be attached

        self.exit_json(
            changed=changed,
            floating_ip=ips[0].to_dict(computed=False) if ips else None)

    def _detach_and_delete(self):
        ips = self._find_ips(
            server=self.server,
            floating_ip_address=self.params['floating_ip_address'],
            network_id=self.network['id'] if self.network else None,
            fixed_address=self.params['fixed_address'],
            nat_destination_name_or_id=self.params['nat_destination'])

        if not ips:
            # Nothing to detach
            self.exit_json(changed=False)

        changed = False
        for ip in ips:
            if ip['fixed_ip_address']:
                # Silently ignore that ip might not be attached to server
                #
                # self.conn.network.update_ip(ip_id, port_id=None) does not
                # handle nova network but self.conn.detach_ip_from_server()
                # does so
                self.conn.detach_ip_from_server(server_id=self.server['id'],
                                                floating_ip_id=ip['id'])

                # OpenStackSDK sets {"port_id": None} to detach a floating
                # ip from a device, but there might be a delay until a
                # server does not list it in addresses any more.
                changed = True

            if self.params['purge']:
                self.conn.network.delete_ip(ip['id'])
                changed = True

        self.exit_json(changed=changed)

    def _filter_ips(self, server):
        # Extract floating ips from server

        def _flatten(lists):
            return [item for sublist in lists for item in sublist]

        if server['addresses'] is None:
            # fetch server with details
            server = self.conn.compute.get_server(server)

        if not server['addresses']:
            return []

        # Returns a list not an iterator here because
        # it is iterated several times below
        return [address['addr']
                for address in _flatten(server['addresses'].values())
                if address['OS-EXT-IPS:type'] == 'floating']

    def _find_ips(self,
                  server,
                  floating_ip_address,
                  network_id,
                  fixed_address,
                  nat_destination_name_or_id):
        # Check which floating ips matches our requirements.
        # They might or might not be attached to our server.
        if floating_ip_address:
            # A specific floating ip address has been requested
            ip = self.conn.network.find_ip(floating_ip_address)
            return [ip] if ip else []
        elif (not fixed_address and nat_destination_name_or_id):
            # No specific floating ip and no specific fixed ip have been
            # requested but a private network (nat_destination) has been
            # given where the floating ip should be attached to.
            return self._find_ips_by_nat_destination(
                server, nat_destination_name_or_id)
        else:
            # not floating_ip_address
            # and (fixed_address or not nat_destination_name_or_id)

            # An analysis of all floating ips of server is required
            return self._find_ips_by_network_id_and_fixed_address(
                server, fixed_address, network_id)

    def _find_ips_by_nat_destination(self,
                                     server,
                                     nat_destination_name_or_id):

        if not server['addresses']:
            return None

        # Check if we have any floating ip on
        # the given nat_destination network
        nat_destination = self.conn.network.find_network(
            nat_destination_name_or_id, ignore_missing=False)

        fips_with_nat_destination = [
            addr for addr
            in server['addresses'].get(nat_destination['name'], [])
            if addr['OS-EXT-IPS:type'] == 'floating']

        if not fips_with_nat_destination:
            return None

        # One or more floating ip addresses have been assigned
        # to the requested nat_destination; return the first.
        return [self.conn.network.find_ip(fip['addr'], ignore_missing=False)
                for fip in fips_with_nat_destination]

    def _find_ips_by_network_id_and_fixed_address(self,
                                                  server,
                                                  fixed_address=None,
                                                  network_id=None):
        # Get any of the floating ips that matches fixed_address and/or network
        ips = [ip for ip in self.conn.network.ips()
               if ip['floating_ip_address'] in self._filter_ips(server)]

        matching_ips = []
        for ip in ips:
            if network_id and ip['floating_network_id'] != network_id:
                # Requested network does not
                # match network of floating ip
                continue

            if not fixed_address:  # and not nat_destination_name_or_id
                # Any floating ip will fullfil these requirements
                matching_ips.append(ip)

            if (fixed_address and ip['fixed_ip_address'] == fixed_address):
                # A floating ip address has been assigned that
                # points to the requested fixed_address
                matching_ips.append(ip)

        return matching_ips

    def _init(self):
        server_name_or_id = self.params['server']
        server = self.conn.compute.find_server(server_name_or_id,
                                               ignore_missing=False)
        # fetch server details such as addresses
        self.server = self.conn.compute.get_server(server)

        network_name_or_id = self.params['network']
        if network_name_or_id:
            self.network = self.conn.network.find_network(
                name_or_id=network_name_or_id, ignore_missing=False)
        else:
            self.network = None


def main():
    module = NetworkingFloatingIPModule()
    module()


if __name__ == '__main__':
    main()
