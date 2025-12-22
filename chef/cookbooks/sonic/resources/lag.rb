#
# Cookbook Name:: sonic
# File:: resources/lag.rb
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
actions :create, :delete, :add_members, :del_members
default_action :create

attribute :name,           :kind_of => String, :name_attribute => true
attribute :links,          :kind_of => Array
attribute :minimum_links,  :kind_of => Integer
attribute :fallback,       :kind_of => [TrueClass, FalseClass], :default => false

attr_accessor :exists

