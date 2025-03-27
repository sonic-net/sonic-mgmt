#
# Cookbook Name:: sonic
# File:: providers/fdb.rb
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

def whyrun_supported?
  true
end

action :create do
  converge_by("create FDB entry with mac address '#{@new_resource.mac}', VLAN '#{@new_resource.vlan_id}' and port '#{@new_resource.port}'") do
    create_fdb_entry
  end
end

action :delete do
  converge_by("delete FDB entry with mac address '#{@new_resource.mac}' and VLAN '#{@new_resource.vlan_id}'") do
    delete_fdb_entry
  end
end

def create_fdb_entry
  command = "config mac add " + new_resource.mac + " " + new_resource.vlan_id.to_s + " " + new_resource.port
  system (command)
end

def delete_fdb_entry
  command = "config mac del " + new_resource.mac + " " + new_resource.vlan_id.to_s
  system (command)
end

