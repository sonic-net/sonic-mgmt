#
# Cookbook Name:: sonic
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

name             'sonic'
maintainer       'Broadcom'
maintainer_email 'support@broadcom.com'
license          'All rights reserved'
description      'Installs/Configures SONiC'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          '0.1.0'

recipe "vlan",
  "Manages vlan resources on SONiC devices"

attribute 'sonic/providers/vlan',
  :display_name => "Provider for sonic_vlan LWRP",
  :description => "Creates/deletes VLANs and adds (tagged or untagged)/delete port participation on SONiC devices.",
  :type => "string",
  :required => "required",
  :recipes => [ 'sonic::vlan' ],
  :default => 'sonic_vlan'

recipe "interface",
  "Manages interface resources on SONiC devices"

attribute 'sonic/providers/interface',
  :display_name => "Provider for sonic_interface LWRP",
  :description => "Sets the interface properties like admin status and speed on SONiC devices.",
  :type => "string",
  :required => "required",
  :recipes => [ 'sonic::interface' ],
  :default => 'sonic_interface'

recipe "lag",
  "Manages lag resources on SONiC devices"

attribute 'sonic/providers/lag',
  :display_name => "Provider for sonic_lag LWRP",
  :description => "Creates/deletes Port channel interfaces and set its properties like minimum number of links, addition and deletion of members and fallback on SONiC devices.",
  :type => "string",
  :required => "required",
  :recipes => [ 'sonic::lag' ],
  :default => 'sonic_lag'

recipe "fdb",
  "Manages fdb resources on SONiC devices"

attribute 'sonic/providers/fdb',
  :display_name => "Provider for sonic_fdb LWRP",
  :description => "Creates and deletes static FDB entries on SONiC devices.",
  :type => "string",
  :required => "required",
  :recipes => [ 'sonic::fdb' ],
  :default => 'sonic_fdb'

