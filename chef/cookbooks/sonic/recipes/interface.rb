#
# Cookbook Name:: sonic
# Recipe:: interface 
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

sonic_interface_provider = node[:sonic][:providers][:interface]
Chef::Log.info "My provider is #{sonic_interface_provider}"

interfaces = node['interfaces']
if !interfaces.nil?
  interfaces.each do |name, attribs|
    Chef::Log.info "Processing interface #{name}"

    sonic_interface name do
      provider sonic_interface_provider
      admin_status attribs['admin_status']
      speed attribs['speed']
      action [:set]
    end
  end
end
