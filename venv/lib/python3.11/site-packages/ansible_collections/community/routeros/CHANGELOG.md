# Community RouterOS Release Notes

**Topics**

- <a href="#v3-14-0">v3\.14\.0</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v3-13-0">v3\.13\.0</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
- <a href="#v3-12-1">v3\.12\.1</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v3-12-0">v3\.12\.0</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
    - <a href="#bugfixes-2">Bugfixes</a>
- <a href="#v3-11-0">v3\.11\.0</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#minor-changes-3">Minor Changes</a>
    - <a href="#bugfixes-3">Bugfixes</a>
- <a href="#v3-10-0">v3\.10\.0</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#minor-changes-4">Minor Changes</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v3-9-0">v3\.9\.0</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#minor-changes-5">Minor Changes</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v3-8-1">v3\.8\.1</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#bugfixes-6">Bugfixes</a>
- <a href="#v3-8-0">v3\.8\.0</a>
    - <a href="#release-summary-8">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
- <a href="#v3-7-0">v3\.7\.0</a>
    - <a href="#release-summary-9">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
- <a href="#v3-6-0">v3\.6\.0</a>
    - <a href="#release-summary-10">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
- <a href="#v3-5-0">v3\.5\.0</a>
    - <a href="#release-summary-11">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
- <a href="#v3-4-0">v3\.4\.0</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#bugfixes-7">Bugfixes</a>
- <a href="#v3-3-0">v3\.3\.0</a>
    - <a href="#release-summary-13">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
- <a href="#v3-2-0">v3\.2\.0</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
- <a href="#v3-1-0">v3\.1\.0</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#minor-changes-13">Minor Changes</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v3-0-0">v3\.0\.0</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#breaking-changes--porting-guide">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
- <a href="#v2-20-0">v2\.20\.0</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#minor-changes-14">Minor Changes</a>
- <a href="#v2-19-0">v2\.19\.0</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#minor-changes-15">Minor Changes</a>
- <a href="#v2-18-0">v2\.18\.0</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#minor-changes-16">Minor Changes</a>
    - <a href="#deprecated-features">Deprecated Features</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v2-17-0">v2\.17\.0</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#minor-changes-17">Minor Changes</a>
- <a href="#v2-16-0">v2\.16\.0</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#minor-changes-18">Minor Changes</a>
- <a href="#v2-15-0">v2\.15\.0</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#minor-changes-19">Minor Changes</a>
- <a href="#v2-14-0">v2\.14\.0</a>
    - <a href="#release-summary-23">Release Summary</a>
    - <a href="#minor-changes-20">Minor Changes</a>
- <a href="#v2-13-0">v2\.13\.0</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#minor-changes-21">Minor Changes</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v2-12-0">v2\.12\.0</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#minor-changes-22">Minor Changes</a>
- <a href="#v2-11-0">v2\.11\.0</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#minor-changes-23">Minor Changes</a>
- <a href="#v2-10-0">v2\.10\.0</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#minor-changes-24">Minor Changes</a>
    - <a href="#bugfixes-11">Bugfixes</a>
- <a href="#v2-9-0">v2\.9\.0</a>
    - <a href="#release-summary-28">Release Summary</a>
    - <a href="#minor-changes-25">Minor Changes</a>
    - <a href="#bugfixes-12">Bugfixes</a>
- <a href="#v2-8-3">v2\.8\.3</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#known-issues">Known Issues</a>
- <a href="#v2-8-2">v2\.8\.2</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#bugfixes-13">Bugfixes</a>
- <a href="#v2-8-1">v2\.8\.1</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#bugfixes-14">Bugfixes</a>
- <a href="#v2-8-0">v2\.8\.0</a>
    - <a href="#release-summary-32">Release Summary</a>
    - <a href="#minor-changes-26">Minor Changes</a>
    - <a href="#bugfixes-15">Bugfixes</a>
- <a href="#v2-7-0">v2\.7\.0</a>
    - <a href="#release-summary-33">Release Summary</a>
    - <a href="#minor-changes-27">Minor Changes</a>
    - <a href="#bugfixes-16">Bugfixes</a>
- <a href="#v2-6-0">v2\.6\.0</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#minor-changes-28">Minor Changes</a>
    - <a href="#bugfixes-17">Bugfixes</a>
- <a href="#v2-5-0">v2\.5\.0</a>
    - <a href="#release-summary-35">Release Summary</a>
    - <a href="#minor-changes-29">Minor Changes</a>
    - <a href="#bugfixes-18">Bugfixes</a>
- <a href="#v2-4-0">v2\.4\.0</a>
    - <a href="#release-summary-36">Release Summary</a>
    - <a href="#minor-changes-30">Minor Changes</a>
    - <a href="#bugfixes-19">Bugfixes</a>
    - <a href="#known-issues-1">Known Issues</a>
- <a href="#v2-3-1">v2\.3\.1</a>
    - <a href="#release-summary-37">Release Summary</a>
    - <a href="#known-issues-2">Known Issues</a>
- <a href="#v2-3-0">v2\.3\.0</a>
    - <a href="#release-summary-38">Release Summary</a>
    - <a href="#minor-changes-31">Minor Changes</a>
    - <a href="#bugfixes-20">Bugfixes</a>
- <a href="#v2-2-1">v2\.2\.1</a>
    - <a href="#release-summary-39">Release Summary</a>
    - <a href="#bugfixes-21">Bugfixes</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-40">Release Summary</a>
    - <a href="#minor-changes-32">Minor Changes</a>
    - <a href="#bugfixes-22">Bugfixes</a>
    - <a href="#new-modules">New Modules</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-41">Release Summary</a>
    - <a href="#minor-changes-33">Minor Changes</a>
    - <a href="#bugfixes-23">Bugfixes</a>
    - <a href="#new-modules-1">New Modules</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-42">Release Summary</a>
    - <a href="#minor-changes-34">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-1">Breaking Changes / Porting Guide</a>
    - <a href="#bugfixes-24">Bugfixes</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#filter">Filter</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-43">Release Summary</a>
    - <a href="#minor-changes-35">Minor Changes</a>
    - <a href="#bugfixes-25">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-44">Release Summary</a>
    - <a href="#minor-changes-36">Minor Changes</a>
- <a href="#v1-0-1">v1\.0\.1</a>
    - <a href="#release-summary-45">Release Summary</a>
    - <a href="#bugfixes-26">Bugfixes</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-46">Release Summary</a>
    - <a href="#bugfixes-27">Bugfixes</a>
- <a href="#v0-1-1">v0\.1\.1</a>
    - <a href="#release-summary-47">Release Summary</a>
    - <a href="#bugfixes-28">Bugfixes</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-48">Release Summary</a>
    - <a href="#minor-changes-37">Minor Changes</a>

<a id="v3-14-0"></a>
## v3\.14\.0

<a id="release-summary"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes"></a>
### Minor Changes

* api\_info\, api\_modify \- add missing attribute <code>radsec\-timeout</code> for the <code>radius</code> path which exists since RouterOS version 7\.19\.6 \([https\://github\.com/ansible\-collections/community\.routeros/pull/412](https\://github\.com/ansible\-collections/community\.routeros/pull/412)\)\.
* api\_info\, api\_modify \- add support for path <code>interface dot1x client</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/414](https\://github\.com/ansible\-collections/community\.routeros/pull/414)\)\.
* api\_info\, api\_modify \- add support for path <code>interface dot1x server</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/413](https\://github\.com/ansible\-collections/community\.routeros/pull/413)\)\.
* api\_info\, api\_modify \- add support for paths <code>ip hotspot</code>\, <code>ip hotspot profile</code>\, <code>ip hotspot user</code>\, <code>ip hotspot user profile</code>\, <code>ip hotspot walled\-garden</code>\, and <code>ip hotspot walled\-garden ip</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/418](https\://github\.com/ansible\-collections/community\.routeros/pull/418)\)\.
* api\_info\, api\_modify \- allow the <code>fib</code> parameter to be disabled for the <code>routing table</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/368](https\://github\.com/ansible\-collections/community\.routeros/issues/368)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/417](https\://github\.com/ansible\-collections/community\.routeros/pull/417)\)\.
* api\_info\, api\_modify \- remove primary key constraint on \'peer\' for path <code>ip ipsec identity</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/421](https\://github\.com/ansible\-collections/community\.routeros/pull/421)\)\.

<a id="bugfixes"></a>
### Bugfixes

* api\_modify\, api\_info \- in the <code>routing bgp connection</code> and <code>bgp templates</code> paths\, fix spelling of the <code>output\.remove\-private\-as</code> parameter \([https\://github\.com/ansible\-collections/community\.routeros/issues/415](https\://github\.com/ansible\-collections/community\.routeros/issues/415)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/416](https\://github\.com/ansible\-collections/community\.routeros/pull/416)\)\.
* api\_modify\, api\_info \- in the <code>routing bgp instance</code> path\, fix \'Cannot add new entry to this path\' error \([https\://github\.com/ansible\-collections/community\.routeros/issues/409](https\://github\.com/ansible\-collections/community\.routeros/issues/409)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/420](https\://github\.com/ansible\-collections/community\.routeros/pull/420)\)\.
* api\_modify\, api\_info \- in the <code>routing bgp templates</code> path\, remove <code>address\-families</code> for RouterOS 7\.19\+ \([https\://github\.com/ansible\-collections/community\.routeros/issues/415](https\://github\.com/ansible\-collections/community\.routeros/issues/415)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/416](https\://github\.com/ansible\-collections/community\.routeros/pull/416)\)\.
* api\_modify\, api\_info \- in the <code>routing bgp templates</code> path\, remove <code>router\-id</code> for RouterOS 7\.20\+ \([https\://github\.com/ansible\-collections/community\.routeros/issues/415](https\://github\.com/ansible\-collections/community\.routeros/issues/415)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/416](https\://github\.com/ansible\-collections/community\.routeros/pull/416)\)\.
* api\_modify\, api\_info \- in the <code>routing bgp templates</code> path\, support <code>afi</code> \(RouterOS 7\.19\+\) \(RouterOS 7\.19 and before\) \([https\://github\.com/ansible\-collections/community\.routeros/issues/415](https\://github\.com/ansible\-collections/community\.routeros/issues/415)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/416](https\://github\.com/ansible\-collections/community\.routeros/pull/416)\)\.

<a id="v3-13-0"></a>
## v3\.13\.0

<a id="release-summary-1"></a>
### Release Summary

Feature release\.

<a id="minor-changes-1"></a>
### Minor Changes

* api\_modify \- add <code>vrf</code> for <code>snmp</code> with a default of <code>main</code> for RouterOS 7\.3 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/411](https\://github\.com/ansible\-collections/community\.routeros/pull/411)\)\.

<a id="v3-12-1"></a>
## v3\.12\.1

<a id="release-summary-2"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-1"></a>
### Bugfixes

* Fix accidental type extensions \([https\://github\.com/ansible\-collections/community\.routeros/pull/406](https\://github\.com/ansible\-collections/community\.routeros/pull/406)\)\.

<a id="v3-12-0"></a>
## v3\.12\.0

<a id="release-summary-3"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-2"></a>
### Minor Changes

* api\_modify \- add <code>vrf</code> for <code>system logging action</code> with a default of <code>main</code> for RouterOS 7\.19 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/401](https\://github\.com/ansible\-collections/community\.routeros/pull/401)\)\.
* api\_modify\, api\_info \- field <code>instance</code> in <code>routing bgp connection</code> path is required\, and <code>router\-id</code> has been moved to <code>routing bgp instance</code> by RouterOS 7\.20 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/404](https\://github\.com/ansible\-collections/community\.routeros/pull/404)\)\.
* api\_modify\, api\_info \- support for field <code>new\-priority</code> in API path <code>ipv6 firewall mangle\`</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/402](https\://github\.com/ansible\-collections/community\.routeros/pull/402)\)\.

<a id="bugfixes-2"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.routeros/pull/405](https\://github\.com/ansible\-collections/community\.routeros/pull/405)\)\.

<a id="v3-11-0"></a>
## v3\.11\.0

<a id="release-summary-4"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-3"></a>
### Minor Changes

* api\_find\_and\_modify\, api\_modify \- instead of comparing supplied values as\-is to values retrieved from the API and converted to some types \(int\, bool\) by librouteros\, instead compare values by converting them to strings first\, using similar conversion rules that librouteros uses \([https\://github\.com/ansible\-collections/community\.routeros/issues/389](https\://github\.com/ansible\-collections/community\.routeros/issues/389)\, [https\://github\.com/ansible\-collections/community\.routeros/issues/370](https\://github\.com/ansible\-collections/community\.routeros/issues/370)\, [https\://github\.com/ansible\-collections/community\.routeros/issues/325](https\://github\.com/ansible\-collections/community\.routeros/issues/325)\, [https\://github\.com/ansible\-collections/community\.routeros/issues/169](https\://github\.com/ansible\-collections/community\.routeros/issues/169)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/397](https\://github\.com/ansible\-collections/community\.routeros/pull/397)\)\.

<a id="bugfixes-3"></a>
### Bugfixes

* api \- allow querying for keys containing <code>id</code>\, as long as the key itself is not <code>id</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/396](https\://github\.com/ansible\-collections/community\.routeros/issues/396)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/398](https\://github\.com/ansible\-collections/community\.routeros/pull/398)\)\.

<a id="v3-10-0"></a>
## v3\.10\.0

<a id="release-summary-5"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-4"></a>
### Minor Changes

* api\_info\, api\_modify \- add <code>show\-at\-cli\-login</code> property in <code>system note</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/392](https\://github\.com/ansible\-collections/community\.routeros/pull/392)\)\.
* api\_info\, api\_modify \- set default value for <code>include</code> and <code>exclude</code> properties in <code>system note</code> to an empty string \([https\://github\.com/ansible\-collections/community\.routeros/pull/394](https\://github\.com/ansible\-collections/community\.routeros/pull/394)\)\.

<a id="bugfixes-4"></a>
### Bugfixes

* api\_facts \- also report interfaces that are inferred only by reference by IP addresses\.
  RouterOS\'s APIs have IPv4 and IPv6 addresses point at interfaces by their name\, which can
  change over time and in\-between API calls\, such that interfaces may have been enumerated
  under another name\, or not at all \(for example when removed\)\. Such interfaces are now reported
  under their new or temporary name and with a synthetic <code>type</code> property set to differentiate
  the more likely and positively confirmed removal case \(with <code>type\: \"ansible\:unknown\"</code>\) from
  the unlikely and probably transient naming mismatch \(with <code>type\: \"ansible\:mismatch\"</code>\)\.
  Previously\, the api\_facts module would have crashed with a <code>KeyError</code> exception
  \([https\://github\.com/ansible\-collections/community\.routeros/pull/391](https\://github\.com/ansible\-collections/community\.routeros/pull/391)\)\.

<a id="v3-9-0"></a>
## v3\.9\.0

<a id="release-summary-6"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-5"></a>
### Minor Changes

* api\_info\, api modify \- add <code>remote\-log\-format</code>\, <code>remote\-protocol</code>\, and <code>event\-delimiter</code> to <code>system logging action</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/381](https\://github\.com/ansible\-collections/community\.routeros/pull/381)\)\.
* api\_info\, api\_modify \- add <code>disable\-link\-local\-address</code> and <code>stale\-neighbor\-timeout</code> fields to <code>ipv6 settings</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/380](https\://github\.com/ansible\-collections/community\.routeros/pull/380)\)\.
* api\_info\, api\_modify \- adjust neighbor limit fields in <code>ipv6 settings</code> to match RouterOS 7\.18 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/380](https\://github\.com/ansible\-collections/community\.routeros/pull/380)\)\.
* api\_info\, api\_modify \- set <code>passthrough</code> default in <code>ip firewall mangle</code> to <code>true</code> for RouterOS 7\.19 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/382](https\://github\.com/ansible\-collections/community\.routeros/pull/382)\)\.
* api\_info\, api\_modify \- since RouterOS 7\.17 VRF is supported for OVPN server\. It now supports multiple entries\, while <code>api\_modify</code> so far only accepted a single entry\. The <code>interface ovpn\-server server</code> path now allows multiple entries on RouterOS 7\.17 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/383](https\://github\.com/ansible\-collections/community\.routeros/pull/383)\)\.

<a id="bugfixes-5"></a>
### Bugfixes

* routeros terminal plugin \- fix <code>terminal\_stdout\_re</code> pattern to handle long system identities when connecting to RouterOS through SSH \([https\://github\.com/ansible\-collections/community\.routeros/pull/386](https\://github\.com/ansible\-collections/community\.routeros/pull/386)\)\.

<a id="v3-8-1"></a>
## v3\.8\.1

<a id="release-summary-7"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-6"></a>
### Bugfixes

* facts and api\_facts modules \- prevent deprecation warnings when used with ansible\-core 2\.19 \([https\://github\.com/ansible\-collections/community\.routeros/pull/384](https\://github\.com/ansible\-collections/community\.routeros/pull/384)\)\.

<a id="v3-8-0"></a>
## v3\.8\.0

<a id="release-summary-8"></a>
### Release Summary

Feature release\.

<a id="minor-changes-6"></a>
### Minor Changes

* api\_info\, api\_modify \- add <code>interface ethernet switch port\-isolation</code> which is supported since RouterOS 6\.43 \([https\://github\.com/ansible\-collections/community\.routeros/pull/375](https\://github\.com/ansible\-collections/community\.routeros/pull/375)\)\.
* api\_info\, api\_modify \- add <code>routing bfd configuration</code>\. Officially stabilized BFD support for BGP and OSPF is available since RouterOS 7\.11
  \([https\://github\.com/ansible\-collections/community\.routeros/pull/375](https\://github\.com/ansible\-collections/community\.routeros/pull/375)\)\.
* api\_modify\, api\_info \- support API path <code>ip ipsec mode\-config</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/376](https\://github\.com/ansible\-collections/community\.routeros/pull/376)\)\.

<a id="v3-7-0"></a>
## v3\.7\.0

<a id="release-summary-9"></a>
### Release Summary

Feature release\.

<a id="minor-changes-7"></a>
### Minor Changes

* api\_find\_and\_modify \- allow to control whether <code>dynamic</code> and/or <code>builtin</code> entries are ignored with the new <code>ignore\_dynamic</code> and <code>ignore\_builtin</code> options \([https\://github\.com/ansible\-collections/community\.routeros/issues/372](https\://github\.com/ansible\-collections/community\.routeros/issues/372)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/373](https\://github\.com/ansible\-collections/community\.routeros/pull/373)\)\.
* api\_info\, api\_modify \- add <code>port\-cost\-mode</code> to <code>interface bridge</code> which is supported since RouterOS 7\.13 \([https\://github\.com/ansible\-collections/community\.routeros/pull/371](https\://github\.com/ansible\-collections/community\.routeros/pull/371)\)\.

<a id="v3-6-0"></a>
## v3\.6\.0

<a id="release-summary-10"></a>
### Release Summary

Feature release\.

<a id="minor-changes-8"></a>
### Minor Changes

* api\_info\, api\_modify \- add <code>mdns\-repeat\-ifaces</code> to <code>ip dns</code> for RouterOS 7\.16 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/358](https\://github\.com/ansible\-collections/community\.routeros/pull/358)\)\.
* api\_info\, api\_modify \- field name change in <code>routing bgp connection</code> path implemented by RouterOS 7\.19 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/360](https\://github\.com/ansible\-collections/community\.routeros/pull/360)\)\.
* api\_info\, api\_modify \- rename <code>is\-responder</code> property in <code>interface wireguard peers</code> to <code>responder</code> for RouterOS 7\.17 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/364](https\://github\.com/ansible\-collections/community\.routeros/pull/364)\)\.

<a id="v3-5-0"></a>
## v3\.5\.0

<a id="release-summary-11"></a>
### Release Summary

Feature release\.

<a id="minor-changes-9"></a>
### Minor Changes

* api\_info\, api\_modify \- change default for <code>/ip/cloud/ddns\-enabled</code> for RouterOS 7\.17 and newer from <code>yes</code> to <code>auto</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/350](https\://github\.com/ansible\-collections/community\.routeros/pull/350)\)\.

<a id="v3-4-0"></a>
## v3\.4\.0

<a id="release-summary-12"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-10"></a>
### Minor Changes

* api\_info\, api\_modify \- add support for the <code>ip dns forwarders</code> path implemented by RouterOS 7\.17 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/343](https\://github\.com/ansible\-collections/community\.routeros/pull/343)\)\.

<a id="bugfixes-7"></a>
### Bugfixes

* api\_info\, api\_modify \- remove the primary key <code>action</code> from the <code>interface wifi provisioning</code> path\, since RouterOS also allows to create completely duplicate entries \([https\://github\.com/ansible\-collections/community\.routeros/issues/344](https\://github\.com/ansible\-collections/community\.routeros/issues/344)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/345](https\://github\.com/ansible\-collections/community\.routeros/pull/345)\)\.

<a id="v3-3-0"></a>
## v3\.3\.0

<a id="release-summary-13"></a>
### Release Summary

Feature release\.

<a id="minor-changes-11"></a>
### Minor Changes

* api\_info\, api\_modify \- add missing attribute <code>require\-message\-auth</code> for the <code>radius</code> path which exists since RouterOS version 7\.15 \([https\://github\.com/ansible\-collections/community\.routeros/issues/338](https\://github\.com/ansible\-collections/community\.routeros/issues/338)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/339](https\://github\.com/ansible\-collections/community\.routeros/pull/339)\)\.
* api\_info\, api\_modify \- add the <code>interface 6to4</code> path\. Used to manage IPv6 tunnels via tunnel\-brokers like HE\, where native IPv6 is not provided \([https\://github\.com/ansible\-collections/community\.routeros/pull/342](https\://github\.com/ansible\-collections/community\.routeros/pull/342)\)\.
* api\_info\, api\_modify \- add the <code>interface wireless access\-list</code> and <code>interface wireless connect\-list</code> paths \([https\://github\.com/ansible\-collections/community\.routeros/issues/284](https\://github\.com/ansible\-collections/community\.routeros/issues/284)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/340](https\://github\.com/ansible\-collections/community\.routeros/pull/340)\)\.
* api\_info\, api\_modify \- add the <code>use\-interface\-duid</code> option for <code>ipv6 dhcp\-client</code> path\. This option prevents issues with Fritzbox modems and routers\, when using virtual interfaces \(like VLANs\) may create duplicated records in hosts config\, this breaks original \"expose\-host\" function\. Also add the <code>script</code>\, <code>custom\-duid</code> and <code>validate\-server\-duid</code> as backport from 7\.15 version update \([https\://github\.com/ansible\-collections/community\.routeros/pull/341](https\://github\.com/ansible\-collections/community\.routeros/pull/341)\)\.

<a id="v3-2-0"></a>
## v3\.2\.0

<a id="release-summary-14"></a>
### Release Summary

Feature release\.

<a id="minor-changes-12"></a>
### Minor Changes

* api\_info\, api\_modify \- add support for the <code>routing filter community\-list</code> path implemented by RouterOS 7 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/331](https\://github\.com/ansible\-collections/community\.routeros/pull/331)\)\.

<a id="v3-1-0"></a>
## v3\.1\.0

<a id="release-summary-15"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-13"></a>
### Minor Changes

* api\_info\, api\_modify \- add missing fields <code>comment</code>\, <code>next\-pool</code> to <code>ip pool</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/327](https\://github\.com/ansible\-collections/community\.routeros/pull/327)\)\.

<a id="bugfixes-8"></a>
### Bugfixes

* api\_info\, api\_modify \- fields <code>log</code> and <code>log\-prefix</code> in paths <code>ip firewall filter</code>\, <code>ip firewall mangle</code>\, <code>ip firewall nat</code>\, <code>ip firewall raw</code> now have the correct default values \([https\://github\.com/ansible\-collections/community\.routeros/pull/324](https\://github\.com/ansible\-collections/community\.routeros/pull/324)\)\.

<a id="v3-0-0"></a>
## v3\.0\.0

<a id="release-summary-16"></a>
### Release Summary

Major release that drops support for End of Life Python versions and fixes check mode for community\.routeros\.command\.

<a id="breaking-changes--porting-guide"></a>
### Breaking Changes / Porting Guide

* command \- the module no longer declares that it supports check mode \([https\://github\.com/ansible\-collections/community\.routeros/pull/318](https\://github\.com/ansible\-collections/community\.routeros/pull/318)\)\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The collection no longer supports Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, ansible\-core 2\.13\, and ansible\-core 2\.14\. If you need to continue using End of Life versions of Ansible/ansible\-base/ansible\-core\, please use community\.routeros 2\.x\.y \([https\://github\.com/ansible\-collections/community\.routeros/pull/318](https\://github\.com/ansible\-collections/community\.routeros/pull/318)\)\.

<a id="v2-20-0"></a>
## v2\.20\.0

<a id="release-summary-17"></a>
### Release Summary

Feature release\.

<a id="minor-changes-14"></a>
### Minor Changes

* api\_info\, api\_modify \- add new parameters from the RouterOS 7\.16 release \([https\://github\.com/ansible\-collections/community\.routeros/pull/323](https\://github\.com/ansible\-collections/community\.routeros/pull/323)\)\.
* api\_info\, api\_modify \- add support <code>interface l2tp\-client</code> configuration \([https\://github\.com/ansible\-collections/community\.routeros/pull/322](https\://github\.com/ansible\-collections/community\.routeros/pull/322)\)\.
* api\_info\, api\_modify \- add support for the <code>cpu\-frequency</code>\, <code>memory\-frequency</code>\, <code>preboot\-etherboot</code> and <code>preboot\-etherboot\-server</code> properties in <code>system routerboard settings</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/320](https\://github\.com/ansible\-collections/community\.routeros/pull/320)\)\.
* api\_info\, api\_modify \- add support for the <code>matching\-type</code> property in <code>ip dhcp\-server matcher</code> introduced by RouterOS 7\.16 \([https\://github\.com/ansible\-collections/community\.routeros/pull/321](https\://github\.com/ansible\-collections/community\.routeros/pull/321)\)\.

<a id="v2-19-0"></a>
## v2\.19\.0

<a id="release-summary-18"></a>
### Release Summary

Feature release\.

<a id="minor-changes-15"></a>
### Minor Changes

* api\_info\, api\_modify \- add support for the <code>ip dns adlist</code> path implemented by RouterOS 7\.15 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/310](https\://github\.com/ansible\-collections/community\.routeros/pull/310)\)\.
* api\_info\, api\_modify \- add support for the <code>mld\-version</code> and <code>multicast\-querier</code> properties in <code>interface bridge</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/315](https\://github\.com/ansible\-collections/community\.routeros/pull/315)\)\.
* api\_info\, api\_modify \- add support for the <code>routing filter num\-list</code> path implemented by RouterOS 7 and newer \([https\://github\.com/ansible\-collections/community\.routeros/pull/313](https\://github\.com/ansible\-collections/community\.routeros/pull/313)\)\.
* api\_info\, api\_modify \- add support for the <code>routing igmp\-proxy</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/309](https\://github\.com/ansible\-collections/community\.routeros/pull/309)\)\.
* api\_modify\, api\_info \- add read\-only <code>default</code> field to <code>snmp community</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/311](https\://github\.com/ansible\-collections/community\.routeros/pull/311)\)\.

<a id="v2-18-0"></a>
## v2\.18\.0

<a id="release-summary-19"></a>
### Release Summary

Feature release\.

<a id="minor-changes-16"></a>
### Minor Changes

* api\_info \- allow to restrict the output by limiting fields to specific values with the new <code>restrict</code> option \([https\://github\.com/ansible\-collections/community\.routeros/pull/305](https\://github\.com/ansible\-collections/community\.routeros/pull/305)\)\.
* api\_info\, api\_modify \- add support for the <code>ip dhcp\-server matcher</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/300](https\://github\.com/ansible\-collections/community\.routeros/pull/300)\)\.
* api\_info\, api\_modify \- add support for the <code>ipv6 nd prefix</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/303](https\://github\.com/ansible\-collections/community\.routeros/pull/303)\)\.
* api\_info\, api\_modify \- add support for the <code>name</code> and <code>is\-responder</code> properties under the <code>interface wireguard peers</code> path introduced in RouterOS 7\.15 \([https\://github\.com/ansible\-collections/community\.routeros/pull/304](https\://github\.com/ansible\-collections/community\.routeros/pull/304)\)\.
* api\_info\, api\_modify \- add support for the <code>routing ospf static\-neighbor</code> path in RouterOS 7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/302](https\://github\.com/ansible\-collections/community\.routeros/pull/302)\)\.
* api\_info\, api\_modify \- set default for <code>force</code> in <code>ip dhcp\-server option</code> to an explicit <code>false</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/300](https\://github\.com/ansible\-collections/community\.routeros/pull/300)\)\.
* api\_modify \- allow to restrict what is updated by limiting fields to specific values with the new <code>restrict</code> option \([https\://github\.com/ansible\-collections/community\.routeros/pull/305](https\://github\.com/ansible\-collections/community\.routeros/pull/305)\)\.

<a id="deprecated-features"></a>
### Deprecated Features

* The collection deprecates support for all Ansible/ansible\-base/ansible\-core versions that are currently End of Life\, [according to the ansible\-core support matrix](https\://docs\.ansible\.com/ansible\-core/devel/reference\_appendices/release\_and\_maintenance\.html\#ansible\-core\-support\-matrix)\. This means that the next major release of the collection will no longer support Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, ansible\-core 2\.13\, and ansible\-core 2\.14\.

<a id="bugfixes-9"></a>
### Bugfixes

* api\_modify\, api\_info \- change the default of <code>ingress\-filtering</code> in paths <code>interface bridge</code> and <code>interface bridge port</code> back to <code>false</code> for RouterOS before version 7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/305](https\://github\.com/ansible\-collections/community\.routeros/pull/305)\)\.

<a id="v2-17-0"></a>
## v2\.17\.0

<a id="release-summary-20"></a>
### Release Summary

Feature release\.

<a id="minor-changes-17"></a>
### Minor Changes

* api\_info\, api\_modify \- add <code>system health settings</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/294](https\://github\.com/ansible\-collections/community\.routeros/pull/294)\)\.
* api\_info\, api\_modify \- add missing path <code>/system resource irq rps</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/295](https\://github\.com/ansible\-collections/community\.routeros/pull/295)\)\.
* api\_info\, api\_modify \- add parameter <code>host\-key\-type</code> for <code>ip ssh</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/280](https\://github\.com/ansible\-collections/community\.routeros/issues/280)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/297](https\://github\.com/ansible\-collections/community\.routeros/pull/297)\)\.

<a id="v2-16-0"></a>
## v2\.16\.0

<a id="release-summary-21"></a>
### Release Summary

Feature release\.

<a id="minor-changes-18"></a>
### Minor Changes

* api\_info\, api\_modify \- add missing path <code>/ppp secret</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/286](https\://github\.com/ansible\-collections/community\.routeros/pull/286)\)\.
* api\_info\, api\_modify \- minor changes <code>/interface ethernet</code> path fields \([https\://github\.com/ansible\-collections/community\.routeros/pull/288](https\://github\.com/ansible\-collections/community\.routeros/pull/288)\)\.

<a id="v2-15-0"></a>
## v2\.15\.0

<a id="release-summary-22"></a>
### Release Summary

Feature release\.

<a id="minor-changes-19"></a>
### Minor Changes

* api\_info\, api\_modify \- Add RouterOS 7\.x support to <code>/mpls ldp</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/271](https\://github\.com/ansible\-collections/community\.routeros/pull/271)\)\.
* api\_info\, api\_modify \- add <code>/ip route rule</code> path for RouterOS 6\.x \([https\://github\.com/ansible\-collections/community\.routeros/pull/278](https\://github\.com/ansible\-collections/community\.routeros/pull/278)\)\.
* api\_info\, api\_modify \- add <code>/routing filter</code> path for RouterOS 6\.x \([https\://github\.com/ansible\-collections/community\.routeros/pull/279](https\://github\.com/ansible\-collections/community\.routeros/pull/279)\)\.
* api\_info\, api\_modify \- add default value for <code>from\-pool</code> field in <code>/ipv6 address</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/270](https\://github\.com/ansible\-collections/community\.routeros/pull/270)\)\.
* api\_info\, api\_modify \- add missing path <code>/interface pppoe\-server server</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/273](https\://github\.com/ansible\-collections/community\.routeros/pull/273)\)\.
* api\_info\, api\_modify \- add missing path <code>/ip dhcp\-relay</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/276](https\://github\.com/ansible\-collections/community\.routeros/pull/276)\)\.
* api\_info\, api\_modify \- add missing path <code>/queue simple</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/269](https\://github\.com/ansible\-collections/community\.routeros/pull/269)\)\.
* api\_info\, api\_modify \- add missing path <code>/queue type</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/274](https\://github\.com/ansible\-collections/community\.routeros/pull/274)\)\.
* api\_info\, api\_modify \- add missing paths <code>/routing bgp aggregate</code>\, <code>/routing bgp network</code> and <code>/routing bgp peer</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/277](https\://github\.com/ansible\-collections/community\.routeros/pull/277)\)\.
* api\_info\, api\_modify \- add support for paths <code>/mpls interface</code>\, <code>/mpls ldp accept\-filter</code>\, <code>/mpls ldp advertise\-filter</code> and <code>mpls ldp interface</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/272](https\://github\.com/ansible\-collections/community\.routeros/pull/272)\)\.

<a id="v2-14-0"></a>
## v2\.14\.0

<a id="release-summary-23"></a>
### Release Summary

Feature release\.

<a id="minor-changes-20"></a>
### Minor Changes

* api\_info\, api\_modify \- add read\-only fields <code>installed\-version</code>\, <code>latest\-version</code> and <code>status</code> in <code>system package update</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/263](https\://github\.com/ansible\-collections/community\.routeros/pull/263)\)\.
* api\_info\, api\_modify \- added support for <code>interface wifi</code> and its sub\-paths \([https\://github\.com/ansible\-collections/community\.routeros/pull/266](https\://github\.com/ansible\-collections/community\.routeros/pull/266)\)\.
* api\_info\, api\_modify \- remove default value for read\-only <code>running</code> field in <code>interface wireless</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/264](https\://github\.com/ansible\-collections/community\.routeros/pull/264)\)\.

<a id="v2-13-0"></a>
## v2\.13\.0

<a id="release-summary-24"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-21"></a>
### Minor Changes

* api\_info\, api\_modify \- make path <code>user group</code> modifiable and add <code>comment</code> attribute \([https\://github\.com/ansible\-collections/community\.routeros/issues/256](https\://github\.com/ansible\-collections/community\.routeros/issues/256)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/257](https\://github\.com/ansible\-collections/community\.routeros/pull/257)\)\.
* api\_modify\, api\_info \- add support for the <code>ip vrf</code> path in RouterOS 7  \([https\://github\.com/ansible\-collections/community\.routeros/pull/259](https\://github\.com/ansible\-collections/community\.routeros/pull/259)\)

<a id="bugfixes-10"></a>
### Bugfixes

* facts \- fix date not getting removed for idempotent config export \([https\://github\.com/ansible\-collections/community\.routeros/pull/262](https\://github\.com/ansible\-collections/community\.routeros/pull/262)\)\.

<a id="v2-12-0"></a>
## v2\.12\.0

<a id="release-summary-25"></a>
### Release Summary

Feature release\.

<a id="minor-changes-22"></a>
### Minor Changes

* api\_info\, api\_modify \- add <code>interface ovpn\-client</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/242](https\://github\.com/ansible\-collections/community\.routeros/issues/242)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/244](https\://github\.com/ansible\-collections/community\.routeros/pull/244)\)\.
* api\_info\, api\_modify \- add <code>radius</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/241](https\://github\.com/ansible\-collections/community\.routeros/issues/241)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/245](https\://github\.com/ansible\-collections/community\.routeros/pull/245)\)\.
* api\_info\, api\_modify \- add <code>routing rule</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/162](https\://github\.com/ansible\-collections/community\.routeros/issues/162)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/246](https\://github\.com/ansible\-collections/community\.routeros/pull/246)\)\.
* api\_info\, api\_modify \- add missing path <code>routing bgp template</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/243](https\://github\.com/ansible\-collections/community\.routeros/pull/243)\)\.
* api\_info\, api\_modify \- add support for the <code>tx\-power</code> attribute in <code>interface wireless</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/239](https\://github\.com/ansible\-collections/community\.routeros/pull/239)\)\.
* api\_info\, api\_modify \- removed <code>host</code> primary key in <code>tool netwatch</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/248](https\://github\.com/ansible\-collections/community\.routeros/pull/248)\)\.
* api\_modify\, api\_info \- added support for <code>interface wifiwave2</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/226](https\://github\.com/ansible\-collections/community\.routeros/pull/226)\)\.

<a id="v2-11-0"></a>
## v2\.11\.0

<a id="release-summary-26"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-23"></a>
### Minor Changes

* api\_info\, api\_modify \- add missing DoH parameters <code>doh\-max\-concurrent\-queries</code>\, <code>doh\-max\-server\-connections</code>\, and <code>doh\-timeout</code> to the <code>ip dns</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/230](https\://github\.com/ansible\-collections/community\.routeros/issues/230)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/235](https\://github\.com/ansible\-collections/community\.routeros/pull/235)\)
* api\_info\, api\_modify \- add missing parameters <code>address\-list</code>\, <code>address\-list\-timeout</code>\, <code>randomise\-ports</code>\, and <code>realm</code> to subpaths of the <code>ip firewall</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/236](https\://github\.com/ansible\-collections/community\.routeros/issues/236)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/237](https\://github\.com/ansible\-collections/community\.routeros/pull/237)\)\.
* api\_info\, api\_modify \- mark the <code>interface wireless</code> parameter <code>running</code> as read\-only \([https\://github\.com/ansible\-collections/community\.routeros/pull/233](https\://github\.com/ansible\-collections/community\.routeros/pull/233)\)\.
* api\_info\, api\_modify \- set the default value to <code>false</code> for the  <code>disabled</code> parameter in some more paths where it can be seen in the documentation \([https\://github\.com/ansible\-collections/community\.routeros/pull/237](https\://github\.com/ansible\-collections/community\.routeros/pull/237)\)\.
* api\_modify \- add missing <code>comment</code> attribute to <code>/routing id</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/234](https\://github\.com/ansible\-collections/community\.routeros/pull/234)\)\.
* api\_modify \- add missing attributes to the <code>routing bgp connection</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/234](https\://github\.com/ansible\-collections/community\.routeros/pull/234)\)\.
* api\_modify \- add versioning to the <code>/tool e\-mail</code> path \(RouterOS 7\.12 release\) \([https\://github\.com/ansible\-collections/community\.routeros/pull/234](https\://github\.com/ansible\-collections/community\.routeros/pull/234)\)\.
* api\_modify \- make <code>/ip traffic\-flow target</code> a multiple value attribute \([https\://github\.com/ansible\-collections/community\.routeros/pull/234](https\://github\.com/ansible\-collections/community\.routeros/pull/234)\)\.

<a id="v2-10-0"></a>
## v2\.10\.0

<a id="release-summary-27"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-24"></a>
### Minor Changes

* api\_info \- add new <code>include\_read\_only</code> option to select behavior for read\-only values\. By default these are not returned \([https\://github\.com/ansible\-collections/community\.routeros/pull/213](https\://github\.com/ansible\-collections/community\.routeros/pull/213)\)\.
* api\_info\, api\_modify \- add support for <code>address\-list</code> and <code>match\-subdomain</code> introduced by RouterOS 7\.7 in the <code>ip dns static</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/197](https\://github\.com/ansible\-collections/community\.routeros/pull/197)\)\.
* api\_info\, api\_modify \- add support for <code>user</code>\, <code>time</code> and <code>gmt\-offset</code> under the <code>system clock</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/210](https\://github\.com/ansible\-collections/community\.routeros/pull/210)\)\.
* api\_info\, api\_modify \- add support for the <code>interface ppp\-client</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/199](https\://github\.com/ansible\-collections/community\.routeros/pull/199)\)\.
* api\_info\, api\_modify \- add support for the <code>interface wireless</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/195](https\://github\.com/ansible\-collections/community\.routeros/pull/195)\)\.
* api\_info\, api\_modify \- add support for the <code>iot modbus</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/205](https\://github\.com/ansible\-collections/community\.routeros/pull/205)\)\.
* api\_info\, api\_modify \- add support for the <code>ip dhcp\-server option</code> and <code>ip dhcp\-server option sets</code> paths \([https\://github\.com/ansible\-collections/community\.routeros/pull/223](https\://github\.com/ansible\-collections/community\.routeros/pull/223)\)\.
* api\_info\, api\_modify \- add support for the <code>ip upnp interfaces</code>\, <code>tool graphing interface</code>\, <code>tool graphing resource</code> paths \([https\://github\.com/ansible\-collections/community\.routeros/pull/227](https\://github\.com/ansible\-collections/community\.routeros/pull/227)\)\.
* api\_info\, api\_modify \- add support for the <code>ipv6 firewall nat</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/204](https\://github\.com/ansible\-collections/community\.routeros/pull/204)\)\.
* api\_info\, api\_modify \- add support for the <code>mode</code> property in <code>ip neighbor discovery\-settings</code> introduced in RouterOS 7\.7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/198](https\://github\.com/ansible\-collections/community\.routeros/pull/198)\)\.
* api\_info\, api\_modify \- add support for the <code>port remote\-access</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/224](https\://github\.com/ansible\-collections/community\.routeros/pull/224)\)\.
* api\_info\, api\_modify \- add support for the <code>routing filter rule</code> and <code>routing filter select\-rule</code> paths \([https\://github\.com/ansible\-collections/community\.routeros/pull/200](https\://github\.com/ansible\-collections/community\.routeros/pull/200)\)\.
* api\_info\, api\_modify \- add support for the <code>routing table</code> path in RouterOS 7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/215](https\://github\.com/ansible\-collections/community\.routeros/pull/215)\)\.
* api\_info\, api\_modify \- add support for the <code>tool netwatch</code> path in RouterOS 7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/216](https\://github\.com/ansible\-collections/community\.routeros/pull/216)\)\.
* api\_info\, api\_modify \- add support for the <code>user settings</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/201](https\://github\.com/ansible\-collections/community\.routeros/pull/201)\)\.
* api\_info\, api\_modify \- add support for the <code>user</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/211](https\://github\.com/ansible\-collections/community\.routeros/pull/211)\)\.
* api\_info\, api\_modify \- finalize fields for the <code>interface wireless security\-profiles</code> path and enable it \([https\://github\.com/ansible\-collections/community\.routeros/pull/203](https\://github\.com/ansible\-collections/community\.routeros/pull/203)\)\.
* api\_info\, api\_modify \- finalize fields for the <code>ppp profile</code> path and enable it \([https\://github\.com/ansible\-collections/community\.routeros/pull/217](https\://github\.com/ansible\-collections/community\.routeros/pull/217)\)\.
* api\_modify \- add new <code>handle\_read\_only</code> and <code>handle\_write\_only</code> options to handle the module\'s behavior for read\-only and write\-only fields \([https\://github\.com/ansible\-collections/community\.routeros/pull/213](https\://github\.com/ansible\-collections/community\.routeros/pull/213)\)\.
* api\_modify\, api\_info \- support API paths <code>routing id</code>\, <code>routing bgp connection</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/220](https\://github\.com/ansible\-collections/community\.routeros/pull/220)\)\.

<a id="bugfixes-11"></a>
### Bugfixes

* api\_info\, api\_modify \- in the <code>snmp</code> path\, ensure that <code>engine\-id\-suffix</code> is only available on RouterOS 7\.10\+\, and that <code>engine\-id</code> is read\-only on RouterOS 7\.10\+ \([https\://github\.com/ansible\-collections/community\.routeros/issues/208](https\://github\.com/ansible\-collections/community\.routeros/issues/208)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/218](https\://github\.com/ansible\-collections/community\.routeros/pull/218)\)\.

<a id="v2-9-0"></a>
## v2\.9\.0

<a id="release-summary-28"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-25"></a>
### Minor Changes

* api\_info\, api\_modify \- add path <code>caps\-man channel</code> and enable path <code>caps\-man manager interface</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/193](https\://github\.com/ansible\-collections/community\.routeros/issues/193)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/194](https\://github\.com/ansible\-collections/community\.routeros/pull/194)\)\.
* api\_info\, api\_modify \- add path <code>ip traffic\-flow target</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/191](https\://github\.com/ansible\-collections/community\.routeros/issues/191)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/192](https\://github\.com/ansible\-collections/community\.routeros/pull/192)\)\.

<a id="bugfixes-12"></a>
### Bugfixes

* api\_modify\, api\_info \- add missing parameter <code>engine\-id\-suffix</code> for the <code>snmp</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/189](https\://github\.com/ansible\-collections/community\.routeros/issues/189)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/190](https\://github\.com/ansible\-collections/community\.routeros/pull/190)\)\.

<a id="v2-8-3"></a>
## v2\.8\.3

<a id="release-summary-29"></a>
### Release Summary

Maintenance release with updated documentation\.

From this version on\, community\.routeros is using the new [Ansible semantic markup](https\://docs\.ansible\.com/ansible/devel/dev\_guide/developing\_modules\_documenting\.html\#semantic\-markup\-within\-module\-documentation)
in its documentation\. If you look at documentation with the ansible\-doc CLI tool
from ansible\-core before 2\.15\, please note that it does not render the markup
correctly\. You should be still able to read it in most cases\, but you need
ansible\-core 2\.15 or later to see it as it is intended\. Alternatively you can
look at [the devel docsite](https\://docs\.ansible\.com/ansible/devel/collections/community/routeros/)
for the rendered HTML version of the documentation of the latest release\.

<a id="known-issues"></a>
### Known Issues

* Ansible markup will show up in raw form on ansible\-doc text output for ansible\-core before 2\.15\. If you have trouble deciphering the documentation markup\, please upgrade to ansible\-core 2\.15 \(or newer\)\, or read the HTML documentation on [https\://docs\.ansible\.com/ansible/devel/collections/community/routeros/](https\://docs\.ansible\.com/ansible/devel/collections/community/routeros/)\.

<a id="v2-8-2"></a>
## v2\.8\.2

<a id="release-summary-30"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-13"></a>
### Bugfixes

* api\_modify\, api\_info \- add missing parameter <code>tls</code> for the <code>tool e\-mail</code> path \([https\://github\.com/ansible\-collections/community\.routeros/issues/179](https\://github\.com/ansible\-collections/community\.routeros/issues/179)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/180](https\://github\.com/ansible\-collections/community\.routeros/pull/180)\)\.

<a id="v2-8-1"></a>
## v2\.8\.1

<a id="release-summary-31"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-14"></a>
### Bugfixes

* facts \- do not crash in CLI output preprocessing in unexpected situations during line unwrapping \([https\://github\.com/ansible\-collections/community\.routeros/issues/170](https\://github\.com/ansible\-collections/community\.routeros/issues/170)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/177](https\://github\.com/ansible\-collections/community\.routeros/pull/177)\)\.

<a id="v2-8-0"></a>
## v2\.8\.0

<a id="release-summary-32"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-26"></a>
### Minor Changes

* api\_modify \- adapt data for API paths <code>ip dhcp\-server network</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/156](https\://github\.com/ansible\-collections/community\.routeros/pull/156)\)\.
* api\_modify \- add support for API path <code>snmp community</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/159](https\://github\.com/ansible\-collections/community\.routeros/pull/159)\)\.
* api\_modify \- add support for <code>trap\-interfaces</code> in API path <code>snmp</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/159](https\://github\.com/ansible\-collections/community\.routeros/pull/159)\)\.
* api\_modify \- add support to disable IPv6 in API paths <code>ipv6 settings</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/158](https\://github\.com/ansible\-collections/community\.routeros/pull/158)\)\.
* api\_modify \- support API paths <code>ip firewall layer7\-protocol</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/153](https\://github\.com/ansible\-collections/community\.routeros/pull/153)\)\.
* command \- workaround for extra characters in stdout in RouterOS versions between 6\.49 and 7\.1\.5 \([https\://github\.com/ansible\-collections/community\.routeros/issues/62](https\://github\.com/ansible\-collections/community\.routeros/issues/62)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/161](https\://github\.com/ansible\-collections/community\.routeros/pull/161)\)\.

<a id="bugfixes-15"></a>
### Bugfixes

* api\_info\, api\_modify \- fix default and remove behavior for <code>dhcp\-options</code> in path <code>ip dhcp\-client</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/148](https\://github\.com/ansible\-collections/community\.routeros/issues/148)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/154](https\://github\.com/ansible\-collections/community\.routeros/pull/154)\)\.
* api\_modify \- fix handling of disabled keys on creation \([https\://github\.com/ansible\-collections/community\.routeros/pull/154](https\://github\.com/ansible\-collections/community\.routeros/pull/154)\)\.
* various plugins and modules \- remove unnecessary imports \([https\://github\.com/ansible\-collections/community\.routeros/pull/149](https\://github\.com/ansible\-collections/community\.routeros/pull/149)\)\.

<a id="v2-7-0"></a>
## v2\.7\.0

<a id="release-summary-33"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-27"></a>
### Minor Changes

* api\_modify\, api\_info \- support API paths <code>ip arp</code>\, <code>ip firewall raw</code>\, <code>ipv6 firewall raw</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/144](https\://github\.com/ansible\-collections/community\.routeros/pull/144)\)\.

<a id="bugfixes-16"></a>
### Bugfixes

* api\_modify\, api\_info \- defaults corrected for fields in <code>interface wireguard peers</code> API path \([https\://github\.com/ansible\-collections/community\.routeros/pull/144](https\://github\.com/ansible\-collections/community\.routeros/pull/144)\)\.

<a id="v2-6-0"></a>
## v2\.6\.0

<a id="release-summary-34"></a>
### Release Summary

Regular bugfix and feature release\.

<a id="minor-changes-28"></a>
### Minor Changes

* api\_modify\, api\_info \- add field <code>regexp</code> to <code>ip dns static</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/141](https\://github\.com/ansible\-collections/community\.routeros/issues/141)\)\.
* api\_modify\, api\_info \- support API paths <code>interface wireguard</code>\, <code>interface wireguard peers</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/143](https\://github\.com/ansible\-collections/community\.routeros/pull/143)\)\.

<a id="bugfixes-17"></a>
### Bugfixes

* api\_modify \- do not use <code>name</code> as a unique key in <code>ip dns static</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/141](https\://github\.com/ansible\-collections/community\.routeros/issues/141)\)\.
* api\_modify\, api\_info \- do not crash if router contains <code>regexp</code> DNS entries in <code>ip dns static</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/141](https\://github\.com/ansible\-collections/community\.routeros/issues/141)\)\.

<a id="v2-5-0"></a>
## v2\.5\.0

<a id="release-summary-35"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-29"></a>
### Minor Changes

* api\_info\, api\_modify \- support API paths <code>interface ethernet poe</code>\, <code>interface gre6</code>\, <code>interface vrrp</code> and also support all previously missing fields of entries in <code>ip dhcp\-server</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/137](https\://github\.com/ansible\-collections/community\.routeros/pull/137)\)\.

<a id="bugfixes-18"></a>
### Bugfixes

* api\_modify \- <code>address\-pool</code> field of entries in API path <code>ip dhcp\-server</code> is not required anymore \([https\://github\.com/ansible\-collections/community\.routeros/pull/137](https\://github\.com/ansible\-collections/community\.routeros/pull/137)\)\.

<a id="v2-4-0"></a>
## v2\.4\.0

<a id="release-summary-36"></a>
### Release Summary

Feature release improving the <code>api\*</code> modules\.

<a id="minor-changes-30"></a>
### Minor Changes

* api\* modules \- Add new option <code>force\_no\_cert</code> to connect with ADH ciphers \([https\://github\.com/ansible\-collections/community\.routeros/pull/124](https\://github\.com/ansible\-collections/community\.routeros/pull/124)\)\.
* api\_info \- new parameter <code>include\_builtin</code> which allows to include \"builtin\" entries that are automatically generated by ROS and cannot be modified by the user \([https\://github\.com/ansible\-collections/community\.routeros/pull/130](https\://github\.com/ansible\-collections/community\.routeros/pull/130)\)\.
* api\_modify\, api\_info \- support API paths \- <code>interface bonding</code>\, <code>interface bridge mlag</code>\, <code>ipv6 firewall mangle</code>\, <code>ipv6 nd</code>\, <code>system scheduler</code>\, <code>system script</code>\, <code>system ups</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/133](https\://github\.com/ansible\-collections/community\.routeros/pull/133)\)\.
* api\_modify\, api\_info \- support API paths <code>caps\-man access\-list</code>\, <code>caps\-man configuration</code>\, <code>caps\-man datapath</code>\, <code>caps\-man manager</code>\, <code>caps\-man provisioning</code>\, <code>caps\-man security</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/126](https\://github\.com/ansible\-collections/community\.routeros/pull/126)\)\.
* api\_modify\, api\_info \- support API paths <code>interface list</code> and <code>interface list member</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/120](https\://github\.com/ansible\-collections/community\.routeros/pull/120)\)\.
* api\_modify\, api\_info \- support API paths <code>interface pppoe\-client</code>\, <code>interface vlan</code>\, <code>interface bridge</code>\, <code>interface bridge vlan</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/125](https\://github\.com/ansible\-collections/community\.routeros/pull/125)\)\.
* api\_modify\, api\_info \- support API paths <code>ip ipsec identity</code>\, <code>ip ipsec peer</code>\, <code>ip ipsec policy</code>\, <code>ip ipsec profile</code>\, <code>ip ipsec proposal</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/129](https\://github\.com/ansible\-collections/community\.routeros/pull/129)\)\.
* api\_modify\, api\_info \- support API paths <code>ip route</code> and <code>ip route vrf</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/123](https\://github\.com/ansible\-collections/community\.routeros/pull/123)\)\.
* api\_modify\, api\_info \- support API paths <code>ipv6 address</code>\, <code>ipv6 dhcp\-server</code>\, <code>ipv6 dhcp\-server option</code>\, <code>ipv6 route</code>\, <code>queue tree</code>\, <code>routing ospf area</code>\, <code>routing ospf area range</code>\, <code>routing ospf instance</code>\, <code>routing ospf interface\-template</code>\, <code>routing pimsm instance</code>\, <code>routing pimsm interface\-template</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.
* api\_modify\, api\_info \- support API paths <code>system logging</code>\, <code>system logging action</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/127](https\://github\.com/ansible\-collections/community\.routeros/pull/127)\)\.
* api\_modify\, api\_info \- support field <code>hw\-offload</code> for path <code>ip firewall filter</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/121](https\://github\.com/ansible\-collections/community\.routeros/pull/121)\)\.
* api\_modify\, api\_info \- support fields <code>address\-list</code>\, <code>address\-list\-timeout</code>\, <code>connection\-bytes</code>\, <code>connection\-limit</code>\, <code>connection\-mark</code>\, <code>connection\-rate</code>\, <code>connection\-type</code>\, <code>content</code>\, <code>disabled</code>\, <code>dscp</code>\, <code>dst\-address\-list</code>\, <code>dst\-address\-type</code>\, <code>dst\-limit</code>\, <code>fragment</code>\, <code>hotspot</code>\, <code>icmp\-options</code>\, <code>in\-bridge\-port</code>\, <code>in\-bridge\-port\-list</code>\, <code>ingress\-priority</code>\, <code>ipsec\-policy</code>\, <code>ipv4\-options</code>\, <code>jump\-target</code>\, <code>layer7\-protocol</code>\, <code>limit</code>\, <code>log</code>\, <code>log\-prefix</code>\, <code>nth</code>\, <code>out\-bridge\-port</code>\, <code>out\-bridge\-port\-list</code>\, <code>packet\-mark</code>\, <code>packet\-size</code>\, <code>per\-connection\-classifier</code>\, <code>port</code>\, <code>priority</code>\, <code>psd</code>\, <code>random</code>\, <code>realm</code>\, <code>routing\-mark</code>\, <code>same\-not\-by\-dst</code>\, <code>src\-address</code>\, <code>src\-address\-list</code>\, <code>src\-address\-type</code>\, <code>src\-mac\-address</code>\, <code>src\-port</code>\, <code>tcp\-mss</code>\, <code>time</code>\, <code>tls\-host</code>\, <code>ttl</code> in <code>ip firewall nat</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/133](https\://github\.com/ansible\-collections/community\.routeros/pull/133)\)\.
* api\_modify\, api\_info \- support fields <code>combo\-mode</code>\, <code>comment</code>\, <code>fec\-mode</code>\, <code>mdix\-enable</code>\, <code>poe\-out</code>\, <code>poe\-priority</code>\, <code>poe\-voltage</code>\, <code>power\-cycle\-interval</code>\, <code>power\-cycle\-ping\-address</code>\, <code>power\-cycle\-ping\-enabled</code>\, <code>power\-cycle\-ping\-timeout</code> for path <code>interface ethernet</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/121](https\://github\.com/ansible\-collections/community\.routeros/pull/121)\)\.
* api\_modify\, api\_info \- support fields <code>jump\-target</code>\, <code>reject\-with</code> in <code>ip firewall filter</code> API path\, field <code>comment</code> in <code>ip firwall address\-list</code> API path\, field <code>jump\-target</code> in <code>ip firewall mangle</code> API path\, field <code>comment</code> in <code>ipv6 firewall address\-list</code> API path\, fields <code>jump\-target</code>\, <code>reject\-with</code> in <code>ipv6 firewall filter</code> API path \([https\://github\.com/ansible\-collections/community\.routeros/pull/133](https\://github\.com/ansible\-collections/community\.routeros/pull/133)\)\.
* api\_modify\, api\_info \- support for API fields that can be disabled and have default value at the same time\, support API paths <code>interface gre</code>\, <code>interface eoip</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/128](https\://github\.com/ansible\-collections/community\.routeros/pull/128)\)\.
* api\_modify\, api\_info \- support for fields <code>blackhole</code>\, <code>pref\-src</code>\, <code>routing\-table</code>\, <code>suppress\-hw\-offload</code>\, <code>type</code>\, <code>vrf\-interface</code> in <code>ip route</code> path \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.
* api\_modify\, api\_info \- support paths <code>system ntp client servers</code> and <code>system ntp server</code> available in ROS7\, as well as new fields <code>servers</code>\, <code>mode</code>\, and <code>vrf</code> for <code>system ntp client</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/122](https\://github\.com/ansible\-collections/community\.routeros/pull/122)\)\.

<a id="bugfixes-19"></a>
### Bugfixes

* api\_modify \- <code>ip route</code> entry can be defined without the need of <code>gateway</code> field\, which is correct for unreachable/blackhole type of routes \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.
* api\_modify \- <code>queue interface</code> path works now \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.
* api\_modify\, api\_info \- removed wrong field <code>dynamic</code> from API path <code>ipv6 firewall address\-list</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/133](https\://github\.com/ansible\-collections/community\.routeros/pull/133)\)\.
* api\_modify\, api\_info \- the default of the field <code>ingress\-filtering</code> in <code>interface bridge port</code> is now <code>true</code>\, which is the default in ROS \([https\://github\.com/ansible\-collections/community\.routeros/pull/125](https\://github\.com/ansible\-collections/community\.routeros/pull/125)\)\.
* command\, facts \- commands do not timeout in safe mode anymore \([https\://github\.com/ansible\-collections/community\.routeros/pull/134](https\://github\.com/ansible\-collections/community\.routeros/pull/134)\)\.

<a id="known-issues-1"></a>
### Known Issues

* api\_modify \- when limits for entries in <code>queue tree</code> are defined as human readable \- for example <code>25M</code> \-\, the configuration will be correctly set in ROS\, but the module will indicate the item is changed on every run even when there was no change done\. This is caused by the ROS API which returns the number in bytes \- for example <code>25000000</code> \(which is inconsistent with the CLI behavior\)\. In order to mitigate that\, the limits have to be defined in bytes \(those will still appear as human readable in the ROS CLI\) \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.
* api\_modify\, api\_info \- <code>routing ospf area</code>\, <code>routing ospf area range</code>\, <code>routing ospf instance</code>\, <code>routing ospf interface\-template</code> paths are not fully implemented for ROS6 due to the significant changes between ROS6 and ROS7 \([https\://github\.com/ansible\-collections/community\.routeros/pull/131](https\://github\.com/ansible\-collections/community\.routeros/pull/131)\)\.

<a id="v2-3-1"></a>
## v2\.3\.1

<a id="release-summary-37"></a>
### Release Summary

Maintenance release with improved documentation\.

<a id="known-issues-2"></a>
### Known Issues

* The <code>community\.routeros\.command</code> module claims to support check mode\. Since it cannot judge whether the commands executed modify state or not\, this behavior is incorrect\. Since this potentially breaks existing playbooks\, we will not change this behavior until community\.routeros 3\.0\.0\.

<a id="v2-3-0"></a>
## v2\.3\.0

<a id="release-summary-38"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-31"></a>
### Minor Changes

* The collection repository conforms to the [REUSE specification](https\://reuse\.software/spec/) except for the changelog fragments \([https\://github\.com/ansible\-collections/community\.routeros/pull/108](https\://github\.com/ansible\-collections/community\.routeros/pull/108)\)\.
* api\* modules \- added <code>timeout</code> parameter \([https\://github\.com/ansible\-collections/community\.routeros/pull/109](https\://github\.com/ansible\-collections/community\.routeros/pull/109)\)\.
* api\_modify\, api\_info \- support API path <code>ip firewall mangle</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/110](https\://github\.com/ansible\-collections/community\.routeros/pull/110)\)\.

<a id="bugfixes-20"></a>
### Bugfixes

* api\_modify\, api\_info \- make API path <code>ip dhcp\-server</code> support <code>script</code>\, and <code>ip firewall nat</code> support <code>in\-interface</code> and <code>in\-interface\-list</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/110](https\://github\.com/ansible\-collections/community\.routeros/pull/110)\)\.

<a id="v2-2-1"></a>
## v2\.2\.1

<a id="release-summary-39"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-21"></a>
### Bugfixes

* api\_modify\, api\_info \- make API path <code>ip dhcp\-server lease</code> support <code>server\=all</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/104](https\://github\.com/ansible\-collections/community\.routeros/issues/104)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/107](https\://github\.com/ansible\-collections/community\.routeros/pull/107)\)\.
* api\_modify\, api\_info \- make API path <code>ip dhcp\-server network</code> support missing options <code>boot\-file\-name</code>\, <code>dhcp\-option\-set</code>\, <code>dns\-none</code>\, <code>domain</code>\, and <code>next\-server</code> \([https\://github\.com/ansible\-collections/community\.routeros/issues/104](https\://github\.com/ansible\-collections/community\.routeros/issues/104)\, [https\://github\.com/ansible\-collections/community\.routeros/pull/106](https\://github\.com/ansible\-collections/community\.routeros/pull/106)\)\.

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-40"></a>
### Release Summary

New feature release\.

<a id="minor-changes-32"></a>
### Minor Changes

* All software licenses are now in the <code>LICENSES/</code> directory of the collection root\. Moreover\, <code>SPDX\-License\-Identifier\:</code> is used to declare the applicable license for every file that is not automatically generated \([https\://github\.com/ansible\-collections/community\.routeros/pull/101](https\://github\.com/ansible\-collections/community\.routeros/pull/101)\)\.

<a id="bugfixes-22"></a>
### Bugfixes

* Include <code>LICENSES/BSD\-2\-Clause\.txt</code> file for the <code>routeros</code> module utils \([https\://github\.com/ansible\-collections/community\.routeros/pull/101](https\://github\.com/ansible\-collections/community\.routeros/pull/101)\)\.

<a id="new-modules"></a>
### New Modules

* community\.routeros\.api\_info \- Retrieve information from API
* community\.routeros\.api\_modify \- Modify data at paths with API

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-41"></a>
### Release Summary

Feature and bugfix release with new modules\.

<a id="minor-changes-33"></a>
### Minor Changes

* Added a <code>community\.routeros\.api</code> module defaults group\. Use with <code>group/community\.routeros\.api</code> to provide options for all API\-based modules \([https\://github\.com/ansible\-collections/community\.routeros/pull/89](https\://github\.com/ansible\-collections/community\.routeros/pull/89)\)\.
* Prepare collection for inclusion in an Execution Environment by declaring its dependencies \([https\://github\.com/ansible\-collections/community\.routeros/pull/83](https\://github\.com/ansible\-collections/community\.routeros/pull/83)\)\.
* api \- add new option <code>extended query</code> more complex queries against RouterOS API \([https\://github\.com/ansible\-collections/community\.routeros/pull/63](https\://github\.com/ansible\-collections/community\.routeros/pull/63)\)\.
* api \- update <code>query</code> to accept symbolic parameters \([https\://github\.com/ansible\-collections/community\.routeros/pull/63](https\://github\.com/ansible\-collections/community\.routeros/pull/63)\)\.
* api\* modules \- allow to set an encoding other than the default ASCII for communicating with the API \([https\://github\.com/ansible\-collections/community\.routeros/pull/95](https\://github\.com/ansible\-collections/community\.routeros/pull/95)\)\.

<a id="bugfixes-23"></a>
### Bugfixes

* query \- fix query function check for <code>\.id</code> vs\. <code>id</code> arguments to not conflict with routeros arguments like <code>identity</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/68](https\://github\.com/ansible\-collections/community\.routeros/pull/68)\, [https\://github\.com/ansible\-collections/community\.routeros/issues/67](https\://github\.com/ansible\-collections/community\.routeros/issues/67)\)\.
* quoting and unquoting filter plugins\, api module \- handle the escape sequence <code>\\\_</code> correctly as escaping a space and not an underscore \([https\://github\.com/ansible\-collections/community\.routeros/pull/89](https\://github\.com/ansible\-collections/community\.routeros/pull/89)\)\.

<a id="new-modules-1"></a>
### New Modules

* community\.routeros\.api\_facts \- Collect facts from remote devices running MikroTik RouterOS using the API
* community\.routeros\.api\_find\_and\_modify \- Find and modify information using the API

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-42"></a>
### Release Summary

A new major release with breaking changes in the behavior of <code>community\.routeros\.api</code> and <code>community\.routeros\.command</code>\.

<a id="minor-changes-34"></a>
### Minor Changes

* api \- make validation of <code>WHERE</code> for <code>query</code> more strict \([https\://github\.com/ansible\-collections/community\.routeros/pull/53](https\://github\.com/ansible\-collections/community\.routeros/pull/53)\)\.
* command \- the <code>commands</code> and <code>wait\_for</code> options now convert the list elements to strings \([https\://github\.com/ansible\-collections/community\.routeros/pull/55](https\://github\.com/ansible\-collections/community\.routeros/pull/55)\)\.
* facts \- the <code>gather\_subset</code> option now converts the list elements to strings \([https\://github\.com/ansible\-collections/community\.routeros/pull/55](https\://github\.com/ansible\-collections/community\.routeros/pull/55)\)\.

<a id="breaking-changes--porting-guide-1"></a>
### Breaking Changes / Porting Guide

* api \- due to a programming error\, the module never failed on errors\. This has now been fixed\. If you are relying on the module not failing in case of idempotent commands \(resulting in errors like <code>failure\: already have such address</code>\)\, you need to adjust your roles/playbooks\. We suggest to use <code>failed\_when</code> to accept failure in specific circumstances\, for example <code>failed\_when\: \"\'failure\: already have \' in result\.msg\[0\]\"</code> \([https\://github\.com/ansible\-collections/community\.routeros/pull/39](https\://github\.com/ansible\-collections/community\.routeros/pull/39)\)\.
* api \- splitting commands no longer uses a naive split by whitespace\, but a more RouterOS CLI compatible splitting algorithm \([https\://github\.com/ansible\-collections/community\.routeros/pull/45](https\://github\.com/ansible\-collections/community\.routeros/pull/45)\)\.
* command \- the module now always indicates that a change happens\. If this is not correct\, please use <code>changed\_when</code> to determine the correct changed status for a task \([https\://github\.com/ansible\-collections/community\.routeros/pull/50](https\://github\.com/ansible\-collections/community\.routeros/pull/50)\)\.

<a id="bugfixes-24"></a>
### Bugfixes

* api \- improve splitting of <code>WHERE</code> queries \([https\://github\.com/ansible\-collections/community\.routeros/pull/47](https\://github\.com/ansible\-collections/community\.routeros/pull/47)\)\.
* api \- when converting result lists to dictionaries\, no longer removes second <code>\=</code> and text following that if present \([https\://github\.com/ansible\-collections/community\.routeros/pull/47](https\://github\.com/ansible\-collections/community\.routeros/pull/47)\)\.
* routeros cliconf plugin \- adjust function signature that was modified in Ansible after creation of this plugin \([https\://github\.com/ansible\-collections/community\.routeros/pull/43](https\://github\.com/ansible\-collections/community\.routeros/pull/43)\)\.

<a id="new-plugins"></a>
### New Plugins

<a id="filter"></a>
#### Filter

* community\.routeros\.join \- Join a list of arguments to a command
* community\.routeros\.list\_to\_dict \- Convert a list of arguments to a list of dictionary
* community\.routeros\.quote\_argument \- Quote an argument
* community\.routeros\.quote\_argument\_value \- Quote an argument value
* community\.routeros\.split \- Split a command into arguments

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-43"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-35"></a>
### Minor Changes

* Avoid internal ansible\-core module\_utils in favor of equivalent public API available since at least Ansible 2\.9 \([https\://github\.com/ansible\-collections/community\.routeros/pull/38](https\://github\.com/ansible\-collections/community\.routeros/pull/38)\)\.
* api \- add options <code>validate\_certs</code> \(default value <code>true</code>\)\, <code>validate\_cert\_hostname</code> \(default value <code>false</code>\)\, and <code>ca\_path</code> to control certificate validation \([https\://github\.com/ansible\-collections/community\.routeros/pull/37](https\://github\.com/ansible\-collections/community\.routeros/pull/37)\)\.
* api \- rename option <code>ssl</code> to <code>tls</code>\, and keep the old name as an alias \([https\://github\.com/ansible\-collections/community\.routeros/pull/37](https\://github\.com/ansible\-collections/community\.routeros/pull/37)\)\.
* fact \- add fact <code>ansible\_net\_config\_nonverbose</code> to get idempotent config \(no date\, no verbose\) \([https\://github\.com/ansible\-collections/community\.routeros/pull/23](https\://github\.com/ansible\-collections/community\.routeros/pull/23)\)\.

<a id="bugfixes-25"></a>
### Bugfixes

* api \- when using TLS/SSL\, remove explicit cipher configuration to insecure values\, which also makes it impossible to connect to newer RouterOS versions \([https\://github\.com/ansible\-collections/community\.routeros/pull/34](https\://github\.com/ansible\-collections/community\.routeros/pull/34)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-44"></a>
### Release Summary

This release allow dashes in usernames for SSH\-based modules\.

<a id="minor-changes-36"></a>
### Minor Changes

* command \- added support for a dash \(<code>\-</code>\) in username \([https\://github\.com/ansible\-collections/community\.routeros/pull/18](https\://github\.com/ansible\-collections/community\.routeros/pull/18)\)\.
* facts \- added support for a dash \(<code>\-</code>\) in username \([https\://github\.com/ansible\-collections/community\.routeros/pull/18](https\://github\.com/ansible\-collections/community\.routeros/pull/18)\)\.

<a id="v1-0-1"></a>
## v1\.0\.1

<a id="release-summary-45"></a>
### Release Summary

Maintenance release with a bugfix for <code>api</code>\.

<a id="bugfixes-26"></a>
### Bugfixes

* api \- remove <code>id to \.id</code> as default requirement which conflicts with RouterOS <code>id</code> configuration parameter \([https\://github\.com/ansible\-collections/community\.routeros/pull/15](https\://github\.com/ansible\-collections/community\.routeros/pull/15)\)\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-46"></a>
### Release Summary

This is the first production \(non\-prerelease\) release of <code>community\.routeros</code>\.

<a id="bugfixes-27"></a>
### Bugfixes

* routeros terminal plugin \- allow slashes in hostnames for terminal detection\. Without this\, slashes in hostnames will result in connection timeouts \([https\://github\.com/ansible\-collections/community\.network/pull/138](https\://github\.com/ansible\-collections/community\.network/pull/138)\)\.

<a id="v0-1-1"></a>
## v0\.1\.1

<a id="release-summary-47"></a>
### Release Summary

Small improvements and bugfixes over the initial release\.

<a id="bugfixes-28"></a>
### Bugfixes

* api \- fix crash when the <code>ssl</code> parameter is used \([https\://github\.com/ansible\-collections/community\.routeros/pull/3](https\://github\.com/ansible\-collections/community\.routeros/pull/3)\)\.

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-48"></a>
### Release Summary

The <code>community\.routeros</code> continues the work on the Ansible RouterOS modules from their state in <code>community\.network</code> 1\.2\.0\. The changes listed here are thus relative to the modules <code>community\.network\.routeros\_\*</code>\.

<a id="minor-changes-37"></a>
### Minor Changes

* facts \- now also collecting data about BGP and OSPF \([https\://github\.com/ansible\-collections/community\.network/pull/101](https\://github\.com/ansible\-collections/community\.network/pull/101)\)\.
* facts \- set configuration export on to verbose\, for full configuration export \([https\://github\.com/ansible\-collections/community\.network/pull/104](https\://github\.com/ansible\-collections/community\.network/pull/104)\)\.
