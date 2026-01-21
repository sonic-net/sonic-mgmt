#
# Cookbook Name:: sonic
# File:: providers/lag.rb
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
  converge_by("create Port Channel '#{@new_resource.name}'") do
    create_lag
  end
end

action :add_members do
  if !new_resource.links.nil?
    converge_by("add ports '#{@new_resource.links.join(', ')}' to Port Channel '#{@new_resource.name}'") do
      add_members_lag
    end
  end
end

action :del_members do
  if !new_resource.links.nil?
    converge_by("delete ports '#{@new_resource.links.join(', ')}' from Port Channel '#{@new_resource.name}'") do
      del_members_lag
    end
  end
end

action :delete do
  converge_by("delete Port Channel '#{@new_resource.name}'") do
    delete_lag
  end
end

def add_members_lag
  ports = @new_resource.links
  ports.each { |intf|
    command = "config portchannel member add " + new_resource.name + " " + intf.to_s
    system (command)
    }
end

def del_members_lag
  ports = @new_resource.links
  ports.each { |intf|
    command = "config portchannel member del " + new_resource.name + " " + intf.to_s
    system (command)
    }
end

def create_lag
  Chef::Log.info "Minimum Links '#{@new_resource.minimum_links.to_s}'"
  Chef::Log.info "Fallback '#{@new_resource.fallback}'"

  command = "config portchannel add"

  if !new_resource.minimum_links.nil?
    # Including min-links option in the command.
    command = command + " --min-links " + new_resource.minimum_links.to_s
  end

  if !new_resource.fallback.nil?
    # Including fallback option in the command.
    command = command + " --fallback " + new_resource.fallback.to_s
  end

  command = command + " " + new_resource.name
  system (command)
end

def delete_lag
  command = "config portchannel del " + new_resource.name
  system (command)
end

