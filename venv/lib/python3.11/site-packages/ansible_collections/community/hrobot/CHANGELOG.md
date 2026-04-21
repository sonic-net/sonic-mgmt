# Community Hetzner Robot Collection Release Notes

**Topics**

- <a href="#v2-7-0">v2\.7\.0</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#deprecated-features">Deprecated Features</a>
- <a href="#v2-6-1">v2\.6\.1</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v2-6-0">v2\.6\.0</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#deprecated-features-1">Deprecated Features</a>
- <a href="#v2-5-2">v2\.5\.2</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v2-5-1">v2\.5\.1</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#bugfixes-2">Bugfixes</a>
- <a href="#v2-5-0">v2\.5\.0</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
    - <a href="#bugfixes-3">Bugfixes</a>
    - <a href="#known-issues">Known Issues</a>
- <a href="#v2-4-0">v2\.4\.0</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#bugfixes-4">Bugfixes</a>
    - <a href="#new-modules">New Modules</a>
- <a href="#v2-3-0">v2\.3\.0</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#new-modules-1">New Modules</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-8">Release Summary</a>
    - <a href="#new-modules-2">New Modules</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-9">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
    - <a href="#deprecated-features-2">Deprecated Features</a>
    - <a href="#new-modules-3">New Modules</a>
- <a href="#v2-0-3">v2\.0\.3</a>
    - <a href="#release-summary-10">Release Summary</a>
- <a href="#v2-0-2">v2\.0\.2</a>
    - <a href="#release-summary-11">Release Summary</a>
- <a href="#v2-0-1">v2\.0\.1</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-13">Release Summary</a>
    - <a href="#major-changes">Major Changes</a>
    - <a href="#minor-changes-3">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
- <a href="#v1-9-2">v1\.9\.2</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#bugfixes-6">Bugfixes</a>
- <a href="#v1-9-1">v1\.9\.1</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#security-fixes">Security Fixes</a>
- <a href="#v1-9-0">v1\.9\.0</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#minor-changes-4">Minor Changes</a>
    - <a href="#deprecated-features-3">Deprecated Features</a>
- <a href="#v1-8-2">v1\.8\.2</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#bugfixes-7">Bugfixes</a>
- <a href="#v1-8-1">v1\.8\.1</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#known-issues-1">Known Issues</a>
- <a href="#v1-8-0">v1\.8\.0</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#major-changes-1">Major Changes</a>
    - <a href="#minor-changes-5">Minor Changes</a>
- <a href="#v1-7-0">v1\.7\.0</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#new-modules-4">New Modules</a>
- <a href="#v1-6-0">v1\.6\.0</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
- <a href="#v1-5-2">v1\.5\.2</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
- <a href="#v1-5-1">v1\.5\.1</a>
    - <a href="#release-summary-23">Release Summary</a>
- <a href="#v1-5-0">v1\.5\.0</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
- <a href="#v1-4-0">v1\.4\.0</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
- <a href="#v1-3-1">v1\.3\.1</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v1-3-0">v1\.3\.0</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v1-2-3">v1\.2\.3</a>
    - <a href="#release-summary-28">Release Summary</a>
- <a href="#v1-2-2">v1\.2\.2</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v1-2-1">v1\.2\.1</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
    - <a href="#new-modules-5">New Modules</a>
- <a href="#v1-1-1">v1\.1\.1</a>
    - <a href="#release-summary-32">Release Summary</a>
    - <a href="#bugfixes-11">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-33">Release Summary</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#inventory">Inventory</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-1">Breaking Changes / Porting Guide</a>

<a id="v2-7-0"></a>
## v2\.7\.0

<a id="release-summary"></a>
### Release Summary

Feature release\.

<a id="minor-changes"></a>
### Minor Changes

* storagebox\_subaccount \- filter by username when looking for existing accounts by username \([https\://github\.com/ansible\-collections/community\.hrobot/pull/182](https\://github\.com/ansible\-collections/community\.hrobot/pull/182)\)\.
* storagebox\_subaccount \- use the new <code>change\_home\_directory</code> action to update a subaccount\'s home directory\, instead of using the now deprecated way using the <code>update\_access\_settings</code> action \([https\://github\.com/ansible\-collections/community\.hrobot/pull/181](https\://github\.com/ansible\-collections/community\.hrobot/pull/181)\)\.

<a id="deprecated-features"></a>
### Deprecated Features

* storagebox\_subaccount \- <code>password\_mode\=set\-to\-random</code> is deprecated and will be removed from community\.hrobot 3\.0\.0\. Hetzner\'s new API does not support this anyway\, it can only be used with the legacy API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/183](https\://github\.com/ansible\-collections/community\.hrobot/pull/183)\)\.

<a id="v2-6-1"></a>
## v2\.6\.1

<a id="release-summary-1"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> in more places to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/179](https\://github\.com/ansible\-collections/community\.hrobot/pull/179)\)\.

<a id="v2-6-0"></a>
## v2\.6\.0

<a id="release-summary-2"></a>
### Release Summary

Maintenance release deprecating support the old storage box API\.

<a id="deprecated-features-1"></a>
### Deprecated Features

* storagebox\* modules \- membership in the <code>community\.hrobot\.robot</code> action group \(module defaults group\) is deprecated\; the modules will be removed from the group in community\.hrobot 3\.0\.0\. Use <code>community\.hrobot\.api</code> instead \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\* modules \- the <code>hetzner\_token</code> option for these modules will be required from community\.hrobot 3\.0\.0 on \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\* modules \- the <code>hetzner\_user</code> and <code>hetzner\_pass</code> options for these modules are deprecated\; support will be removed in community\.hrobot 3\.0\.0\. Use <code>hetzner\_token</code> instead \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_info \- the <code>storageboxes\[\]\.login</code>\, <code>storageboxes\[\]\.disk\_quota</code>\, <code>storageboxes\[\]\.disk\_usage</code>\, <code>storageboxes\[\]\.disk\_usage\_data</code>\, <code>storageboxes\[\]\.disk\_usage\_snapshot</code>\, <code>storageboxes\[\]\.webdav</code>\, <code>storageboxes\[\]\.samba</code>\, <code>storageboxes\[\]\.ssh</code>\, <code>storageboxes\[\]\.external\_reachability</code>\, and <code>storageboxes\[\]\.zfs</code> return values are deprecated and will be removed from community\.routeros\. Check out the documentation to find out their new names according to the new API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_snapshot\_info \- the <code>snapshots\[\]\.timestamp</code>\, <code>snapshots\[\]\.size</code>\, <code>snapshots\[\]\.filesystem\_size</code>\, <code>snapshots\[\]\.automatic</code>\, and <code>snapshots\[\]\.comment</code> return values are deprecated and will be removed from community\.routeros\. Check out the documentation to find out their new names according to the new API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_snapshot\_plan \- the <code>plans\[\]\.month</code> return value is deprecated\, since it only returns <code>null</code> with the new API and cannot be set to any other value \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_snapshot\_plan\_info \- the <code>plans\[\]\.month</code> return value is deprecated\, since it only returns <code>null</code> with the new API and cannot be set to any other value \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_subaccount \- the <code>subaccount\.homedirectory</code>\, <code>subaccount\.samba</code>\, <code>subaccount\.ssh</code>\, <code>subaccount\.external\_reachability</code>\, <code>subaccount\.webdav</code>\, <code>subaccount\.readonly</code>\, <code>subaccount\.createtime</code>\, and <code>subaccount\.comment</code> return values are deprecated and will be removed from community\.routeros\. Check out the documentation to find out their new names according to the new API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.
* storagebox\_subaccount\_info \- the <code>subaccounts\[\]\.accountid</code>\, <code>subaccounts\[\]\.homedirectory</code>\, <code>subaccounts\[\]\.samba</code>\, <code>subaccounts\[\]\.ssh</code>\, <code>subaccounts\[\]\.external\_reachability</code>\, <code>subaccounts\[\]\.webdav</code>\, <code>subaccounts\[\]\.readonly</code>\, <code>subaccounts\[\]\.createtime</code>\, and <code>subaccounts\[\]\.comment</code> return values are deprecated and will be removed from community\.routeros\. Check out the documentation to find out their new names according to the new API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/178](https\://github\.com/ansible\-collections/community\.hrobot/pull/178)\)\.

<a id="v2-5-2"></a>
## v2\.5\.2

<a id="release-summary-3"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-1"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/177](https\://github\.com/ansible\-collections/community\.hrobot/pull/177)\)\.

<a id="v2-5-1"></a>
## v2\.5\.1

<a id="release-summary-4"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-2"></a>
### Bugfixes

* Avoid deprecated functionality in ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/174](https\://github\.com/ansible\-collections/community\.hrobot/pull/174)\)\.

<a id="v2-5-0"></a>
## v2\.5\.0

<a id="release-summary-5"></a>
### Release Summary

Feature and bugfix release\.

This release adds support for the [new Hetzner API for the storage box modules](https\://docs\.hetzner\.cloud/changelog\#2025\-06\-25\-new\-api\-for\-storage\-boxes)\.
You need to use <code>hetzner\_token</code> instead of <code>hetzner\_user</code>/<code>hetzner\_password</code>
to use the new API\. Please note that the old API will be sunset on July 30th\, 2025\;
the modules will then stop working if you do not provide <code>hetzner\_token</code> and stop
providing <code>hetzner\_user</code>/<code>hetzner\_password</code>\.

<a id="minor-changes-1"></a>
### Minor Changes

* Introduced a new action group \(module defaults group\) <code>community\.hrobot\.api</code> that includes all modules that support the new Hetzner API\. This is currently limited to a subset of the storage box modules\; these currently support both the <code>community\.hrobot\.robot</code> and the new <code>community\.hrobot\.api</code> action group\, and will eventually drop the <code>community\.hrobot\.robot</code> action group once the Robot API for storage boxes is removed by Hetzner \([https\://github\.com/ansible\-collections/community\.hrobot/pull/166](https\://github\.com/ansible\-collections/community\.hrobot/pull/166)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/167](https\://github\.com/ansible\-collections/community\.hrobot/pull/167)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/169](https\://github\.com/ansible\-collections/community\.hrobot/pull/169)\)\.
* storagebox \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/166](https\://github\.com/ansible\-collections/community\.hrobot/pull/166)\)\.
* storagebox\_info \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/166](https\://github\.com/ansible\-collections/community\.hrobot/pull/166)\)\.
* storagebox\_set\_password \- support the new Hetzner API\. Note that the new API does not support setting a random password\; you must always provide a password when using the new API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.
* storagebox\_snapshot \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.
* storagebox\_snapshot\_info \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.
* storagebox\_snapshot\_plan \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/167](https\://github\.com/ansible\-collections/community\.hrobot/pull/167)\)\.
* storagebox\_snapshot\_plan\_info \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/167](https\://github\.com/ansible\-collections/community\.hrobot/pull/167)\)\.
* storagebox\_subaccount \- no longer mark <code>password\_mode</code> as <code>no\_log</code> \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.
* storagebox\_subaccount \- support the new Hetzner API\. Note that the new API does not support setting a random password\; you must always provide a password when using the new API to create a storagebox \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.
* storagebox\_subaccount\_info \- support the new Hetzner API \([https\://github\.com/ansible\-collections/community\.hrobot/pull/168](https\://github\.com/ansible\-collections/community\.hrobot/pull/168)\)\.

<a id="bugfixes-3"></a>
### Bugfixes

* robot inventory plugin \- avoid using deprecated option when templating options \([https\://github\.com/ansible\-collections/community\.hrobot/pull/165](https\://github\.com/ansible\-collections/community\.hrobot/pull/165)\)\.

<a id="known-issues"></a>
### Known Issues

* storagebox\* modules \- the Hetzner Robot API for storage boxes is [deprecated and will be sunset on July 30\, 2025](https\://docs\.hetzner\.cloud/changelog\#2025\-06\-25\-new\-api\-for\-storage\-boxes)\. The modules are currently not compatible with the new API\. We will try to adjust them until then\, but usage and return values might change slightly due to differences in the APIs\.
  For the new API\, an API token needs to be registered and provided as <code>hetzner\_token</code> \([https\://github\.com/ansible\-collections/community\.hrobot/pull/166](https\://github\.com/ansible\-collections/community\.hrobot/pull/166)\)\.

<a id="v2-4-0"></a>
## v2\.4\.0

<a id="release-summary-6"></a>
### Release Summary

Bugfix and feature release\.
This release contains three new modules that support the remaining aspects of Hetzner Storage Boxes that were not covered so far\.

<a id="bugfixes-4"></a>
### Bugfixes

* storagebox \- make sure that changes of boolean parameters are sent correctly to the Robot service \([https\://github\.com/ansible\-collections/community\.hrobot/issues/160](https\://github\.com/ansible\-collections/community\.hrobot/issues/160)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/161](https\://github\.com/ansible\-collections/community\.hrobot/pull/161)\)\.

<a id="new-modules"></a>
### New Modules

* community\.hrobot\.storagebox\_snapshot\_info \- Query the snapshots for a storage box\.
* community\.hrobot\.storagebox\_subaccount \- Create\, update\, or delete a subaccount for a storage box\.
* community\.hrobot\.storagebox\_subaccount\_info \- Query the subaccounts for a storage box\.

<a id="v2-3-0"></a>
## v2\.3\.0

<a id="release-summary-7"></a>
### Release Summary

Feature release\.

<a id="new-modules-1"></a>
### New Modules

* community\.hrobot\.storagebox\_snapshot \- Create\, update\, or delete a snapshot of a storage box\.

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-8"></a>
### Release Summary

Feature release\.

<a id="new-modules-2"></a>
### New Modules

* community\.hrobot\.reset\_info \- Query information on the resetter of a dedicated server\.

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-9"></a>
### Release Summary

Feature release with several new modules and a deprecation\.

<a id="minor-changes-2"></a>
### Minor Changes

* All modules and plugins now have a <code>rate\_limit\_retry\_timeout</code> option\, which allows to configure for how long to wait in case of rate limiting errors\. By default\, the modules wait indefinitely\. Setting the option to <code>0</code> does not retry \(this was the behavior in previous versions\)\, and a positive value sets a number of seconds to wait at most \([https\://github\.com/ansible\-collections/community\.hrobot/pull/140](https\://github\.com/ansible\-collections/community\.hrobot/pull/140)\)\.
* boot \- it is now possible to specify SSH public keys in <code>authorized\_keys</code>\. The fingerprint needed by the Robot API will be extracted automatically \([https\://github\.com/ansible\-collections/community\.hrobot/pull/134](https\://github\.com/ansible\-collections/community\.hrobot/pull/134)\)\.
* v\_switch \- the module is now part of the <code>community\.hrobot\.robot</code> action group\, despite already being documented as part of it \([https\://github\.com/ansible\-collections/community\.hrobot/pull/136](https\://github\.com/ansible\-collections/community\.hrobot/pull/136)\)\.

<a id="deprecated-features-2"></a>
### Deprecated Features

* boot \- the various <code>arch</code> suboptions have been deprecated and will be removed from community\.hrobot 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/134](https\://github\.com/ansible\-collections/community\.hrobot/pull/134)\)\.

<a id="new-modules-3"></a>
### New Modules

* community\.hrobot\.storagebox \- Modify a storage box\'s basic configuration\.
* community\.hrobot\.storagebox\_info \- Query information on one or more storage boxes\.
* community\.hrobot\.storagebox\_set\_password \- \(Re\)set the password for a storage box\.
* community\.hrobot\.storagebox\_snapshot\_plan \- Modify a storage box\'s snapshot plans\.
* community\.hrobot\.storagebox\_snapshot\_plan\_info \- Query the snapshot plans for a storage box\.

<a id="v2-0-3"></a>
## v2\.0\.3

<a id="release-summary-10"></a>
### Release Summary

Maintenance release with updated documentation\.

<a id="v2-0-2"></a>
## v2\.0\.2

<a id="release-summary-11"></a>
### Release Summary

Maintenance release with updated documentation\.

<a id="v2-0-1"></a>
## v2\.0\.1

<a id="release-summary-12"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-5"></a>
### Bugfixes

* boot \- use PHP array form encoding when sending multiple <code>authorized\_key</code> \([https\://github\.com/ansible\-collections/community\.hrobot/issues/112](https\://github\.com/ansible\-collections/community\.hrobot/issues/112)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/113](https\://github\.com/ansible\-collections/community\.hrobot/pull/113)\)\.

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-13"></a>
### Release Summary

New major release 2\.0\.0\.

<a id="major-changes"></a>
### Major Changes

* The <code>community\.hrobot</code> collection now depends on the <code>community\.library\_inventory\_filtering\_v1</code> collection\. This utility collection provides host filtering functionality for inventory plugins\. If you use the Ansible community package\, both collections are included and you do not have to do anything special\. If you install the collection with <code>ansible\-galaxy collection install</code>\, it will be installed automatically\. If you install the collection by copying the files of the collection to a place where ansible\-core can find it\, for example by cloning the git repository\, you need to make sure that you also have to install the dependency if you are using the inventory plugin \([https\://github\.com/ansible\-collections/community\.hrobot/pull/101](https\://github\.com/ansible\-collections/community\.hrobot/pull/101)\)\.

<a id="minor-changes-3"></a>
### Minor Changes

* robot inventory plugin \- add <code>filter</code> option which allows to include and exclude hosts based on Jinja2 conditions \([https\://github\.com/ansible\-collections/community\.hrobot/pull/101](https\://github\.com/ansible\-collections/community\.hrobot/pull/101)\)\.

<a id="breaking-changes--porting-guide"></a>
### Breaking Changes / Porting Guide

* robot inventory plugin \- <code>filters</code> is now no longer an alias of <code>simple\_filters</code>\, but a new\, different option \([https\://github\.com/ansible\-collections/community\.hrobot/pull/101](https\://github\.com/ansible\-collections/community\.hrobot/pull/101)\)\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The collection no longer supports Ansible\, ansible\-base\, and ansible\-core releases that are currently End of Life at the time of the 2\.0\.0 release\. This means that Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, and ansible\-core 2\.13 are no longer supported\. The collection might still work with these versions\, but it can stop working at any moment without advance notice\, and this will not be considered a bug \([https\://github\.com/ansible\-collections/community\.hrobot/pull/101](https\://github\.com/ansible\-collections/community\.hrobot/pull/101)\)\.

<a id="v1-9-2"></a>
## v1\.9\.2

<a id="release-summary-14"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-6"></a>
### Bugfixes

* inventory plugins \- add unsafe wrapper to avoid marking strings that do not contain <code>\{</code> or <code>\}</code> as unsafe\, to work around a bug in AWX \([https\://github\.com/ansible\-collections/community\.hrobot/pull/102](https\://github\.com/ansible\-collections/community\.hrobot/pull/102)\)\.

<a id="v1-9-1"></a>
## v1\.9\.1

<a id="release-summary-15"></a>
### Release Summary

Bugfix release\.

<a id="security-fixes"></a>
### Security Fixes

* robot inventory plugin \- make sure all data received from the Hetzner robot service server is marked as unsafe\, so remote code execution by obtaining texts that can be evaluated as templates is not possible \([https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/](https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/99](https\://github\.com/ansible\-collections/community\.hrobot/pull/99)\)\.

<a id="v1-9-0"></a>
## v1\.9\.0

<a id="release-summary-16"></a>
### Release Summary

Feature and maintenance release\.

<a id="minor-changes-4"></a>
### Minor Changes

* robot inventory plugin \- the <code>filters</code> option has been renamed to <code>simple\_filters</code>\. The old name still works until community\.hrobot 2\.0\.0\. Then it will change to allow more complex filtering with the <code>community\.library\_inventory\_filtering\_v1</code> collection\'s functionality \([https\://github\.com/ansible\-collections/community\.hrobot/pull/94](https\://github\.com/ansible\-collections/community\.hrobot/pull/94)\)\.

<a id="deprecated-features-3"></a>
### Deprecated Features

* robot inventory plugin \- the <code>filters</code> option has been renamed to <code>simple\_filters</code>\. The old name will stop working in community\.hrobot 2\.0\.0 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/94](https\://github\.com/ansible\-collections/community\.hrobot/pull/94)\)\.

<a id="v1-8-2"></a>
## v1\.8\.2

<a id="release-summary-17"></a>
### Release Summary

Maintenance release with updated documentation\.

<a id="bugfixes-7"></a>
### Bugfixes

* Show more information \(if available\) from error messages \([https\://github\.com/ansible\-collections/community\.hrobot/pull/89](https\://github\.com/ansible\-collections/community\.hrobot/pull/89)\)\.

<a id="v1-8-1"></a>
## v1\.8\.1

<a id="release-summary-18"></a>
### Release Summary

Maintenance release with updated documentation\.

From this version on\, community\.hrobot is using the new [Ansible semantic markup](https\://docs\.ansible\.com/ansible/devel/dev\_guide/developing\_modules\_documenting\.html\#semantic\-markup\-within\-module\-documentation)
in its documentation\. If you look at documentation with the ansible\-doc CLI tool
from ansible\-core before 2\.15\, please note that it does not render the markup
correctly\. You should be still able to read it in most cases\, but you need
ansible\-core 2\.15 or later to see it as it is intended\. Alternatively you can
look at [the devel docsite](https\://docs\.ansible\.com/ansible/devel/collections/community/hrobot/)
for the rendered HTML version of the documentation of the latest release\.

<a id="known-issues-1"></a>
### Known Issues

* Ansible markup will show up in raw form on ansible\-doc text output for ansible\-core before 2\.15\. If you have trouble deciphering the documentation markup\, please upgrade to ansible\-core 2\.15 \(or newer\)\, or read the HTML documentation on [https\://docs\.ansible\.com/ansible/devel/collections/community/hrobot/](https\://docs\.ansible\.com/ansible/devel/collections/community/hrobot/)\.

<a id="v1-8-0"></a>
## v1\.8\.0

<a id="release-summary-19"></a>
### Release Summary

Feature release for the Hetzner firewall changes\.

<a id="major-changes-1"></a>
### Major Changes

* firewall \- Hetzner added output rules support to the firewall\. This change unfortunately means that using old versions of the firewall module will always set the output rule list to empty\, thus disallowing the server to send out packets \([https\://github\.com/ansible\-collections/community\.hrobot/issues/75](https\://github\.com/ansible\-collections/community\.hrobot/issues/75)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/76](https\://github\.com/ansible\-collections/community\.hrobot/pull/76)\)\.

<a id="minor-changes-5"></a>
### Minor Changes

* firewall\, firewall\_info \- add <code>filter\_ipv6</code> and <code>rules\.output</code> output to support the new IPv6 filtering and output rules features \([https\://github\.com/ansible\-collections/community\.hrobot/issues/75](https\://github\.com/ansible\-collections/community\.hrobot/issues/75)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/76](https\://github\.com/ansible\-collections/community\.hrobot/pull/76)\)\.
* firewall\, firewall\_info \- add <code>server\_number</code> option that can be used instead of <code>server\_ip</code> to identify the server\. Hetzner deprecated configuring the firewall by <code>server\_ip</code>\, so using <code>server\_ip</code> will stop at some point in the future \([https\://github\.com/ansible\-collections/community\.hrobot/pull/77](https\://github\.com/ansible\-collections/community\.hrobot/pull/77)\)\.

<a id="v1-7-0"></a>
## v1\.7\.0

<a id="release-summary-20"></a>
### Release Summary

Feature release\.

<a id="new-modules-4"></a>
### New Modules

* community\.hrobot\.v\_switch \- Manage Hetzner\'s vSwitch

<a id="v1-6-0"></a>
## v1\.6\.0

<a id="release-summary-21"></a>
### Release Summary

Feature release with improved documentation\.

<a id="minor-changes-6"></a>
### Minor Changes

* Added a <code>community\.hrobot\.robot</code> module defaults group / action group\. Use with <code>group/community\.hrobot\.robot</code> to provide options for all Hetzner Robot modules \([https\://github\.com/ansible\-collections/community\.hrobot/pull/65](https\://github\.com/ansible\-collections/community\.hrobot/pull/65)\)\.

<a id="v1-5-2"></a>
## v1\.5\.2

<a id="release-summary-22"></a>
### Release Summary

Maintenance release with a documentation improvement\.

<a id="minor-changes-7"></a>
### Minor Changes

* The collection repository conforms to the [REUSE specification](https\://reuse\.software/spec/) except for the changelog fragments \([https\://github\.com/ansible\-collections/community\.hrobot/pull/60](https\://github\.com/ansible\-collections/community\.hrobot/pull/60)\)\.

<a id="v1-5-1"></a>
## v1\.5\.1

<a id="release-summary-23"></a>
### Release Summary

Maintenance release with small documentation fixes\.

<a id="v1-5-0"></a>
## v1\.5\.0

<a id="release-summary-24"></a>
### Release Summary

Maintenance release changing the way licenses are declared\. No functional changes\.

<a id="minor-changes-8"></a>
### Minor Changes

* All software licenses are now in the <code>LICENSES/</code> directory of the collection root\. Moreover\, <code>SPDX\-License\-Identifier\:</code> is used to declare the applicable license for every file that is not automatically generated \([https\://github\.com/ansible\-collections/community\.hrobot/pull/52](https\://github\.com/ansible\-collections/community\.hrobot/pull/52)\)\.

<a id="v1-4-0"></a>
## v1\.4\.0

<a id="release-summary-25"></a>
### Release Summary

Feature release\.

<a id="minor-changes-9"></a>
### Minor Changes

* robot inventory plugin \- allow to template <code>hetzner\_user</code> and <code>hetzner\_password</code> \([https\://github\.com/ansible\-collections/community\.hrobot/pull/49](https\://github\.com/ansible\-collections/community\.hrobot/pull/49)\)\.

<a id="v1-3-1"></a>
## v1\.3\.1

<a id="release-summary-26"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-8"></a>
### Bugfixes

* Include <code>simplified\_bsd\.txt</code> license file for the <code>robot</code> and <code>failover</code> module utils\.

<a id="v1-3-0"></a>
## v1\.3\.0

<a id="release-summary-27"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-10"></a>
### Minor Changes

* Prepare collection for inclusion in an Execution Environment by declaring its dependencies \([https\://github\.com/ansible\-collections/community\.hrobot/pull/45](https\://github\.com/ansible\-collections/community\.hrobot/pull/45)\)\.

<a id="bugfixes-9"></a>
### Bugfixes

* robot inventory plugin \- do not crash if a server neither has name or primary IP set\. Instead\, fall back to using the server\'s number as the name\. This can happen if unnamed rack reservations show up in your server list \([https\://github\.com/ansible\-collections/community\.hrobot/issues/40](https\://github\.com/ansible\-collections/community\.hrobot/issues/40)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/47](https\://github\.com/ansible\-collections/community\.hrobot/pull/47)\)\.

<a id="v1-2-3"></a>
## v1\.2\.3

<a id="release-summary-28"></a>
### Release Summary

Docs update release\.

<a id="v1-2-2"></a>
## v1\.2\.2

<a id="release-summary-29"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-10"></a>
### Bugfixes

* boot \- fix incorrect handling of SSH authorized keys \([https\://github\.com/ansible\-collections/community\.hrobot/issues/32](https\://github\.com/ansible\-collections/community\.hrobot/issues/32)\, [https\://github\.com/ansible\-collections/community\.hrobot/pull/33](https\://github\.com/ansible\-collections/community\.hrobot/pull/33)\)\.

<a id="v1-2-1"></a>
## v1\.2\.1

<a id="release-summary-30"></a>
### Release Summary

Maintenance release\.

<a id="minor-changes-11"></a>
### Minor Changes

* Generic module HTTP support code \- fix usage of <code>fetch\_url</code> with changes in latest ansible\-core <code>devel</code> branch \([https\://github\.com/ansible\-collections/community\.hrobot/pull/30](https\://github\.com/ansible\-collections/community\.hrobot/pull/30)\)\.

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-31"></a>
### Release Summary

Feature release with multiple new modules\.

<a id="minor-changes-12"></a>
### Minor Changes

* Avoid internal ansible\-core module\_utils in favor of equivalent public API available since at least Ansible 2\.9 \([https\://github\.com/ansible\-collections/community\.hrobot/pull/18](https\://github\.com/ansible\-collections/community\.hrobot/pull/18)\)\.
* firewall \- rename option <code>whitelist\_hos</code> to <code>allowlist\_hos</code>\, keep old name as alias \([https\://github\.com/ansible\-collections/community\.hrobot/pull/15](https\://github\.com/ansible\-collections/community\.hrobot/pull/15)\)\.
* firewall\, firewall\_info \- add return value <code>allowlist\_hos</code>\, which contains the same value as <code>whitelist\_hos</code>\. The old name <code>whitelist\_hos</code> will be removed eventually \([https\://github\.com/ansible\-collections/community\.hrobot/pull/15](https\://github\.com/ansible\-collections/community\.hrobot/pull/15)\)\.
* robot module utils \- add <code>allow\_empty\_result</code> parameter to <code>plugin\_open\_url\_json</code> and <code>fetch\_url\_json</code> \([https\://github\.com/ansible\-collections/community\.hrobot/pull/16](https\://github\.com/ansible\-collections/community\.hrobot/pull/16)\)\.

<a id="new-modules-5"></a>
### New Modules

* community\.hrobot\.boot \- Set boot configuration
* community\.hrobot\.reset \- Reset a dedicated server
* community\.hrobot\.reverse\_dns \- Set or remove reverse DNS entry for IP
* community\.hrobot\.server \- Update server information
* community\.hrobot\.server\_info \- Query information on one or more servers
* community\.hrobot\.ssh\_key \- Add\, remove or update SSH key
* community\.hrobot\.ssh\_key\_info \- Query information on SSH keys

<a id="v1-1-1"></a>
## v1\.1\.1

<a id="release-summary-32"></a>
### Release Summary

Bugfix release which reduces the number of HTTPS queries for the modules and plugins\.

<a id="bugfixes-11"></a>
### Bugfixes

* robot \- force HTTP basic authentication to reduce number of HTTPS requests \([https\://github\.com/ansible\-collections/community\.hrobot/pull/9](https\://github\.com/ansible\-collections/community\.hrobot/pull/9)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-33"></a>
### Release Summary

Release with a new inventory plugin\.

<a id="new-plugins"></a>
### New Plugins

<a id="inventory"></a>
#### Inventory

* community\.hrobot\.robot \- Hetzner Robot inventory source

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-34"></a>
### Release Summary

The <code>community\.hrobot</code> continues the work on the Hetzner Robot modules from their state in <code>community\.general</code> 1\.2\.0\. The changes listed here are thus relative to the modules <code>community\.general\.hetzner\_\*</code>\.

<a id="breaking-changes--porting-guide-1"></a>
### Breaking Changes / Porting Guide

* firewall \- now requires the [ipaddress](https\://pypi\.org/project/ipaddress/) library \([https\://github\.com/ansible\-collections/community\.hrobot/pull/2](https\://github\.com/ansible\-collections/community\.hrobot/pull/2)\)\.
