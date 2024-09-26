#
# Cookbook Name:: sonic
# File:: resources/fdb.rb
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
actions :create, :delete
default_action :create

attribute :name,               :kind_of => String, :name_attribute => true
attribute :mac,                :kind_of => String, :required => true
attribute :vlan_id,            :kind_of => Integer, :required => true, :regex => /^([2-9]|[1-9][0-9]{1,2}|[1-3][0-9]{3}|40[0-8][0-9]|409[0-3])$/
attribute :port,               :kind_of => String

attr_accessor :exists

