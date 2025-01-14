#
# Cookbook Name:: sonic
# Recipe:: vlan
#
# Copyright 2019, Broadcom
#
# All rights reserved - Do Not Redistribute
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

hostname = node[:hostname]
Chef::Log.info "My hostname is #{hostname}"

sonic_vlan_provider = node[:sonic][:providers][:vlan]
Chef::Log.info "My provider is #{sonic_vlan_provider}"

vlans = node['vlans']
if !vlans.nil?
  vlans.each do |name, attribs|
    Chef::Log.info "Processing vlan #{name}"

    if attribs['action'] == 'delete'
      sonic_vlan name do
        provider sonic_vlan_provider
        vlan_id attribs['vlan_id'].to_i
        participation_list attribs['participation_list']
        action [:del_participation, :delete]
      end

    elsif attribs['action'] == 'del_participation'
      sonic_vlan name do
        provider sonic_vlan_provider
        vlan_id attribs['vlan_id'].to_i
        participation_list attribs['participation_list']
        action [:del_participation]
      end

    else
      sonic_vlan name do
        provider sonic_vlan_provider
        vlan_id attribs['vlan_id'].to_i
        tagging_mode attribs['tagging_mode']
        participation_list attribs['participation_list']
        action [:create, :add_participation]
      end
    end

  end
end

