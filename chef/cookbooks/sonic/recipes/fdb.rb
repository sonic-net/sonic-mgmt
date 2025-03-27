#
# Cookbook Name:: sonic
# Recipe:: fdb
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

sonic_fdb_provider = node[:sonic][:providers][:fdb]
Chef::Log.info "My provider is #{sonic_fdb_provider}"

fdbs = node['fdbs']
if !fdbs.nil?
  fdbs.each do |name, attribs|
    Chef::Log.info "Processing fdb #{name}"

    if attribs['action'] == 'delete'
      sonic_fdb name do
        provider sonic_fdb_provider
        mac attribs['mac']
        vlan_id attribs['vlan_id'].to_i
        action [:delete]
      end

    else
      sonic_fdb name do
        provider sonic_fdb_provider
        mac attribs['mac']
        vlan_id attribs['vlan_id'].to_i
        port attribs['port']
        action [:create]
      end
    end

  end
end

