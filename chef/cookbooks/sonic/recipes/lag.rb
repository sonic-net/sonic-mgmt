#
# Cookbook Name:: sonic
# Recipe:: lag
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

sonic_lag_provider = node[:sonic][:providers][:lag]
Chef::Log.info "My provider is #{sonic_lag_provider}"

lags = node['lags']
if !lags.nil?
  lags.each do |name, attribs|
    Chef::Log.info "Processing lag #{name}"

    if attribs['action'] == 'delete'
      sonic_lag name do
        provider sonic_lag_provider
        links attribs['links']
        action [:del_members, :delete]
      end

    elsif attribs['action'] == 'del_members'
      sonic_lag name do
        provider sonic_lag_provider
        links attribs['links']
        action [:del_members]
      end

    else
      sonic_lag name do
        provider sonic_lag_provider
        minimum_links attribs['minimum_links'].to_i
        fallback attribs['fallback']
        links attribs['links']
        action [:create, :add_members]
      end
    end

  end
end

