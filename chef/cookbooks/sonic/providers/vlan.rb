#
# Cookbook Name:: sonic
# File:: providers/vlan.rb
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
  converge_by("create VLAN '#{@new_resource.vlan_id}'") do
    create_vlan
  end
end

action :add_participation do
  if !new_resource.participation_list.nil?
    converge_by("add ports '#{@new_resource.participation_list.join(', ')}' to VLAN '#{@new_resource.vlan_id}'") do
      add_participation_vlan
    end
  end
end

action :del_participation do
  if !new_resource.participation_list.nil?
    converge_by("delete ports '#{@new_resource.participation_list.join(', ')}' from VLAN '#{@new_resource.vlan_id}'") do
      del_participation_vlan
    end
  end
end

action :delete do
  converge_by("delete VLAN '#{@new_resource.vlan_id}'") do
    delete_vlan
  end
end

def add_participation_vlan
  Chef::Log.info "Tagging mode '#{@new_resource.tagging_mode}'"
  ports = @new_resource.participation_list
  ports.each { |intf|
    if new_resource.tagging_mode == 'untagged'
      command = "config vlan member add -u " + new_resource.vlan_id.to_s + " " + intf.to_s
    else
      command = "config vlan member add " + new_resource.vlan_id.to_s + " " + intf.to_s
    end
    system (command)
    }
end

def del_participation_vlan
  ports = @new_resource.participation_list
  ports.each { |intf|
    command = "config vlan member del " + new_resource.vlan_id.to_s + " " + intf.to_s
    system (command)
    }
end

def create_vlan
  command = "config vlan add " + new_resource.vlan_id.to_s
  system (command)
end

def delete_vlan
  command = "config vlan del " + new_resource.vlan_id.to_s
  system (command)
end

