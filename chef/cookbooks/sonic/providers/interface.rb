#
# Cookbook Name:: sonic
# File:: providers/interface.rb
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

action :set do
  converge_by("setting interface '#{@new_resource.name}' properties") do
    set_interface_properties
  end
end

def set_interface_properties
  Chef::Log.info "Admin status '#{@new_resource.admin_status}'"
  Chef::Log.info "Speed '#{@new_resource.speed}'"

  if !new_resource.admin_status.nil?
    # Setting Interface Admin Status.
    if new_resource.admin_status == 'up'
      command = "config interface startup " + new_resource.name
    else
      command = "config interface shutdown " + new_resource.name
    end
    system (command)
  end

  if !new_resource.speed.nil?
    # Setting Interface Speed.
    command = "config interface speed " + new_resource.name + " " + new_resource.speed
    system (command)
  end
end

