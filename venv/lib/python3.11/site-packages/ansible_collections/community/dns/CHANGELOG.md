# Community DNS Collection Release Notes

**Topics**

- <a href="#v3-4-1">v3\.4\.1</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v3-4-0">v3\.4\.0</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes-1">Bugfixes</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#lookup">Lookup</a>
- <a href="#v3-3-4">v3\.3\.4</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
    - <a href="#bugfixes-2">Bugfixes</a>
- <a href="#v3-3-3">v3\.3\.3</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#bugfixes-3">Bugfixes</a>
- <a href="#v3-3-2">v3\.3\.2</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v3-3-1">v3\.3\.1</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v3-3-0">v3\.3\.0</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#bugfixes-6">Bugfixes</a>
    - <a href="#new-modules">New Modules</a>
- <a href="#v3-2-7">v3\.2\.7</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#bugfixes-7">Bugfixes</a>
- <a href="#v3-2-6">v3\.2\.6</a>
    - <a href="#release-summary-8">Release Summary</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v3-2-5">v3\.2\.5</a>
    - <a href="#release-summary-9">Release Summary</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v3-2-4">v3\.2\.4</a>
    - <a href="#release-summary-10">Release Summary</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v3-2-3">v3\.2\.3</a>
    - <a href="#release-summary-11">Release Summary</a>
    - <a href="#bugfixes-11">Bugfixes</a>
- <a href="#v3-2-2">v3\.2\.2</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#bugfixes-12">Bugfixes</a>
- <a href="#v3-2-1">v3\.2\.1</a>
    - <a href="#release-summary-13">Release Summary</a>
    - <a href="#bugfixes-13">Bugfixes</a>
- <a href="#v3-2-0">v3\.2\.0</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
    - <a href="#bugfixes-14">Bugfixes</a>
- <a href="#v3-1-2">v3\.1\.2</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#bugfixes-15">Bugfixes</a>
- <a href="#v3-1-1">v3\.1\.1</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#bugfixes-16">Bugfixes</a>
- <a href="#v3-1-0">v3\.1\.0</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#minor-changes-3">Minor Changes</a>
    - <a href="#bugfixes-17">Bugfixes</a>
    - <a href="#new-plugins-1">New Plugins</a>
        - <a href="#filter">Filter</a>
        - <a href="#lookup-1">Lookup</a>
- <a href="#v3-0-7">v3\.0\.7</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#bugfixes-18">Bugfixes</a>
- <a href="#v3-0-6">v3\.0\.6</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#bugfixes-19">Bugfixes</a>
- <a href="#v3-0-5">v3\.0\.5</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#bugfixes-20">Bugfixes</a>
- <a href="#v3-0-4">v3\.0\.4</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#bugfixes-21">Bugfixes</a>
- <a href="#v3-0-3">v3\.0\.3</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#bugfixes-22">Bugfixes</a>
- <a href="#v3-0-2">v3\.0\.2</a>
    - <a href="#release-summary-23">Release Summary</a>
    - <a href="#bugfixes-23">Bugfixes</a>
- <a href="#v3-0-1">v3\.0\.1</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#bugfixes-24">Bugfixes</a>
- <a href="#v3-0-0">v3\.0\.0</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#major-changes">Major Changes</a>
    - <a href="#minor-changes-4">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
    - <a href="#bugfixes-25">Bugfixes</a>
- <a href="#v2-9-0">v2\.9\.0</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#bugfixes-26">Bugfixes</a>
    - <a href="#new-plugins-2">New Plugins</a>
        - <a href="#filter-1">Filter</a>
- <a href="#v2-8-3">v2\.8\.3</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#bugfixes-27">Bugfixes</a>
- <a href="#v2-8-2">v2\.8\.2</a>
    - <a href="#release-summary-28">Release Summary</a>
    - <a href="#security-fixes">Security Fixes</a>
    - <a href="#bugfixes-28">Bugfixes</a>
- <a href="#v2-8-1">v2\.8\.1</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#bugfixes-29">Bugfixes</a>
- <a href="#v2-8-0">v2\.8\.0</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#minor-changes-5">Minor Changes</a>
    - <a href="#deprecated-features">Deprecated Features</a>
    - <a href="#bugfixes-30">Bugfixes</a>
- <a href="#v2-7-0">v2\.7\.0</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
    - <a href="#bugfixes-31">Bugfixes</a>
- <a href="#v2-6-4">v2\.6\.4</a>
    - <a href="#release-summary-32">Release Summary</a>
    - <a href="#bugfixes-32">Bugfixes</a>
- <a href="#v2-6-3">v2\.6\.3</a>
    - <a href="#release-summary-33">Release Summary</a>
    - <a href="#bugfixes-33">Bugfixes</a>
- <a href="#v2-6-2">v2\.6\.2</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#bugfixes-34">Bugfixes</a>
- <a href="#v2-6-1">v2\.6\.1</a>
    - <a href="#release-summary-35">Release Summary</a>
    - <a href="#bugfixes-35">Bugfixes</a>
- <a href="#v2-6-0">v2\.6\.0</a>
    - <a href="#release-summary-36">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
    - <a href="#bugfixes-36">Bugfixes</a>
    - <a href="#new-plugins-3">New Plugins</a>
        - <a href="#lookup-2">Lookup</a>
    - <a href="#new-modules-1">New Modules</a>
- <a href="#v2-5-7">v2\.5\.7</a>
    - <a href="#release-summary-37">Release Summary</a>
    - <a href="#bugfixes-37">Bugfixes</a>
- <a href="#v2-5-6">v2\.5\.6</a>
    - <a href="#release-summary-38">Release Summary</a>
    - <a href="#known-issues">Known Issues</a>
- <a href="#v2-5-5">v2\.5\.5</a>
    - <a href="#release-summary-39">Release Summary</a>
    - <a href="#bugfixes-38">Bugfixes</a>
- <a href="#v2-5-4">v2\.5\.4</a>
    - <a href="#release-summary-40">Release Summary</a>
    - <a href="#bugfixes-39">Bugfixes</a>
- <a href="#v2-5-3">v2\.5\.3</a>
    - <a href="#release-summary-41">Release Summary</a>
    - <a href="#bugfixes-40">Bugfixes</a>
- <a href="#v2-5-2">v2\.5\.2</a>
    - <a href="#release-summary-42">Release Summary</a>
    - <a href="#bugfixes-41">Bugfixes</a>
- <a href="#v2-5-1">v2\.5\.1</a>
    - <a href="#release-summary-43">Release Summary</a>
    - <a href="#bugfixes-42">Bugfixes</a>
- <a href="#v2-5-0">v2\.5\.0</a>
    - <a href="#release-summary-44">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
    - <a href="#deprecated-features-1">Deprecated Features</a>
    - <a href="#bugfixes-43">Bugfixes</a>
- <a href="#v2-4-2">v2\.4\.2</a>
    - <a href="#release-summary-45">Release Summary</a>
    - <a href="#bugfixes-44">Bugfixes</a>
- <a href="#v2-4-1">v2\.4\.1</a>
    - <a href="#release-summary-46">Release Summary</a>
    - <a href="#bugfixes-45">Bugfixes</a>
- <a href="#v2-4-0">v2\.4\.0</a>
    - <a href="#release-summary-47">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
    - <a href="#bugfixes-46">Bugfixes</a>
- <a href="#v2-3-4">v2\.3\.4</a>
    - <a href="#release-summary-48">Release Summary</a>
    - <a href="#bugfixes-47">Bugfixes</a>
- <a href="#v2-3-3">v2\.3\.3</a>
    - <a href="#release-summary-49">Release Summary</a>
    - <a href="#bugfixes-48">Bugfixes</a>
- <a href="#v2-3-2">v2\.3\.2</a>
    - <a href="#release-summary-50">Release Summary</a>
    - <a href="#bugfixes-49">Bugfixes</a>
- <a href="#v2-3-1">v2\.3\.1</a>
    - <a href="#release-summary-51">Release Summary</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#bugfixes-50">Bugfixes</a>
- <a href="#v2-3-0">v2\.3\.0</a>
    - <a href="#release-summary-52">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
    - <a href="#bugfixes-51">Bugfixes</a>
- <a href="#v2-2-1">v2\.2\.1</a>
    - <a href="#release-summary-53">Release Summary</a>
    - <a href="#bugfixes-52">Bugfixes</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-54">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
    - <a href="#bugfixes-53">Bugfixes</a>
- <a href="#v2-1-1">v2\.1\.1</a>
    - <a href="#release-summary-55">Release Summary</a>
    - <a href="#bugfixes-54">Bugfixes</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-56">Release Summary</a>
    - <a href="#minor-changes-13">Minor Changes</a>
    - <a href="#bugfixes-55">Bugfixes</a>
- <a href="#v2-0-9">v2\.0\.9</a>
    - <a href="#release-summary-57">Release Summary</a>
    - <a href="#bugfixes-56">Bugfixes</a>
- <a href="#v2-0-8">v2\.0\.8</a>
    - <a href="#release-summary-58">Release Summary</a>
    - <a href="#bugfixes-57">Bugfixes</a>
- <a href="#v2-0-7">v2\.0\.7</a>
    - <a href="#release-summary-59">Release Summary</a>
    - <a href="#bugfixes-58">Bugfixes</a>
- <a href="#v2-0-6">v2\.0\.6</a>
    - <a href="#release-summary-60">Release Summary</a>
    - <a href="#bugfixes-59">Bugfixes</a>
- <a href="#v2-0-5">v2\.0\.5</a>
    - <a href="#release-summary-61">Release Summary</a>
    - <a href="#bugfixes-60">Bugfixes</a>
- <a href="#v2-0-4">v2\.0\.4</a>
    - <a href="#release-summary-62">Release Summary</a>
    - <a href="#bugfixes-61">Bugfixes</a>
- <a href="#v2-0-3">v2\.0\.3</a>
    - <a href="#release-summary-63">Release Summary</a>
    - <a href="#minor-changes-14">Minor Changes</a>
- <a href="#v2-0-2">v2\.0\.2</a>
    - <a href="#release-summary-64">Release Summary</a>
    - <a href="#bugfixes-62">Bugfixes</a>
- <a href="#v2-0-1">v2\.0\.1</a>
    - <a href="#release-summary-65">Release Summary</a>
    - <a href="#bugfixes-63">Bugfixes</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-66">Release Summary</a>
    - <a href="#minor-changes-15">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-1">Breaking Changes / Porting Guide</a>
    - <a href="#deprecated-features-2">Deprecated Features</a>
    - <a href="#bugfixes-64">Bugfixes</a>
    - <a href="#new-plugins-4">New Plugins</a>
        - <a href="#inventory">Inventory</a>
    - <a href="#new-modules-2">New Modules</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-67">Release Summary</a>
    - <a href="#minor-changes-16">Minor Changes</a>
    - <a href="#bugfixes-65">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-68">Release Summary</a>
    - <a href="#minor-changes-17">Minor Changes</a>
    - <a href="#bugfixes-66">Bugfixes</a>
- <a href="#v1-0-1">v1\.0\.1</a>
    - <a href="#release-summary-69">Release Summary</a>
    - <a href="#bugfixes-67">Bugfixes</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-70">Release Summary</a>
    - <a href="#bugfixes-68">Bugfixes</a>
- <a href="#v0-3-0">v0\.3\.0</a>
    - <a href="#release-summary-71">Release Summary</a>
    - <a href="#minor-changes-18">Minor Changes</a>
    - <a href="#bugfixes-69">Bugfixes</a>
    - <a href="#new-modules-3">New Modules</a>
- <a href="#v0-2-0">v0\.2\.0</a>
    - <a href="#release-summary-72">Release Summary</a>
    - <a href="#major-changes-1">Major Changes</a>
    - <a href="#minor-changes-19">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-2">Breaking Changes / Porting Guide</a>
    - <a href="#bugfixes-70">Bugfixes</a>
    - <a href="#new-modules-4">New Modules</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-73">Release Summary</a>
    - <a href="#new-plugins-5">New Plugins</a>
        - <a href="#filter-2">Filter</a>
    - <a href="#new-modules-5">New Modules</a>

<a id="v3-4-1"></a>
## v3\.4\.1

<a id="release-summary"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-4-0"></a>
## v3\.4\.0

<a id="release-summary-1"></a>
### Release Summary

Feature and maintenance release\.

<a id="minor-changes"></a>
### Minor Changes

* lookup\_\* plugins \- support <code>type\=HTTPS</code> and <code>type\=SVCB</code> \([https\://github\.com/ansible\-collections/community\.dns/issues/299](https\://github\.com/ansible\-collections/community\.dns/issues/299)\, [https\://github\.com/ansible\-collections/community\.dns/pull/300](https\://github\.com/ansible\-collections/community\.dns/pull/300)\)\.
* nameserver\_record\_info \- support <code>type\=HTTPS</code> and <code>type\=SVCB</code> \([https\://github\.com/ansible\-collections/community\.dns/issues/299](https\://github\.com/ansible\-collections/community\.dns/issues/299)\, [https\://github\.com/ansible\-collections/community\.dns/pull/300](https\://github\.com/ansible\-collections/community\.dns/pull/300)\)\.
* nameserver\_record\_info \- the return value <code>results\[\]\.result\[\]\.values</code> has been renamed to <code>results\[\]\.result\[\]\.entries</code>\. The old name will still be available for a longer time \([https\://github\.com/ansible\-collections/community\.dns/issues/289](https\://github\.com/ansible\-collections/community\.dns/issues/289)\, [https\://github\.com/ansible\-collections/community\.dns/pull/298](https\://github\.com/ansible\-collections/community\.dns/pull/298)\)\.
* wait\_for\_txt \- the option <code>records\[\]\.values</code> now has an alias <code>records\[\]\.entries</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/298](https\://github\.com/ansible\-collections/community\.dns/pull/298)\)\.
* wait\_for\_txt \- the return value <code>records\[\]\.values</code> has been renamed to <code>records\[\]\.entries</code>\. The old name will still be available for a longer time \([https\://github\.com/ansible\-collections/community\.dns/issues/289](https\://github\.com/ansible\-collections/community\.dns/issues/289)\, [https\://github\.com/ansible\-collections/community\.dns/pull/298](https\://github\.com/ansible\-collections/community\.dns/pull/298)\)\.

<a id="bugfixes-1"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> in more places to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.dns/pull/291](https\://github\.com/ansible\-collections/community\.dns/pull/291)\)\.
* Update Public Suffix List\.

<a id="new-plugins"></a>
### New Plugins

<a id="lookup"></a>
#### Lookup

* community\.dns\.lookup\_rfc8427 \- Look up DNS records and return RFC 8427 JSON format\.

<a id="v3-3-4"></a>
## v3\.3\.4

<a id="release-summary-2"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="minor-changes-1"></a>
### Minor Changes

* Note that some new code in <code>plugins/module\_utils/\_six\.py</code> is MIT licensed \([https\://github\.com/ansible\-collections/community\.dns/pull/287](https\://github\.com/ansible\-collections/community\.dns/pull/287)\)\.

<a id="bugfixes-2"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.dns/pull/287](https\://github\.com/ansible\-collections/community\.dns/pull/287)\)\.
* Update Public Suffix List\.

<a id="v3-3-3"></a>
## v3\.3\.3

<a id="release-summary-3"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-3"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-3-2"></a>
## v3\.3\.2

<a id="release-summary-4"></a>
### Release Summary

Bugfix and maintenance release with updated PSL\.

<a id="bugfixes-4"></a>
### Bugfixes

* Update Public Suffix List\.
* various DNS lookup plugins and modules \- improve handling of invalid nameserver IPs/names \([https\://github\.com/ansible\-collections/community\.dns/issues/282](https\://github\.com/ansible\-collections/community\.dns/issues/282)\, [https\://github\.com/ansible\-collections/community\.dns/pull/284](https\://github\.com/ansible\-collections/community\.dns/pull/284)\)\.

<a id="v3-3-1"></a>
## v3\.3\.1

<a id="release-summary-5"></a>
### Release Summary

Bugfix and maintenance release with updated PSL\.

<a id="bugfixes-5"></a>
### Bugfixes

* Avoid deprecated functionality in ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.dns/pull/280](https\://github\.com/ansible\-collections/community\.dns/pull/280)\)\.
* Update Public Suffix List\.
* nameserver\_record\_info \- removed type <code>ALL</code>\, which never worked \([https\://github\.com/ansible\-collections/community\.dns/issues/278](https\://github\.com/ansible\-collections/community\.dns/issues/278)\, [https\://github\.com/ansible\-collections/community\.dns/pull/279](https\://github\.com/ansible\-collections/community\.dns/pull/279)\)\.

<a id="v3-3-0"></a>
## v3\.3\.0

<a id="release-summary-6"></a>
### Release Summary

Feature release with support for AdGuard Home\.

<a id="bugfixes-6"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="new-modules"></a>
### New Modules

* community\.dns\.adguardhome\_rewrite \- Add\, update or delete DNS rewrite rules from AdGuardHome\.
* community\.dns\.adguardhome\_rewrite\_info \- Retrieve DNS rewrite rules from AdGuardHome\.

<a id="v3-2-7"></a>
## v3\.2\.7

<a id="release-summary-7"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-7"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-2-6"></a>
## v3\.2\.6

<a id="release-summary-8"></a>
### Release Summary

Regular bugfix and maintenance release with updated PSL\.

<a id="bugfixes-8"></a>
### Bugfixes

* Update Public Suffix List\.
* hetzner\_dns\_records inventory plugin \- avoid using deprecated option when templating options \([https\://github\.com/ansible\-collections/community\.dns/pull/266](https\://github\.com/ansible\-collections/community\.dns/pull/266)\)\.
* hosttech\_dns\_records inventory plugin \- avoid using deprecated option when templating options \([https\://github\.com/ansible\-collections/community\.dns/pull/266](https\://github\.com/ansible\-collections/community\.dns/pull/266)\)\.

<a id="v3-2-5"></a>
## v3\.2\.5

<a id="release-summary-9"></a>
### Release Summary

Regular maintenance release with bugfixes and updated PSL\.

<a id="bugfixes-9"></a>
### Bugfixes

* Update Public Suffix List\.
* lookup and lookup\_as\_dict lookup plugins \- removed type <code>ALL</code>\, which never worked \([https\://github\.com/ansible\-collections/community\.dns/issues/264](https\://github\.com/ansible\-collections/community\.dns/issues/264)\, [https\://github\.com/ansible\-collections/community\.dns/pull/265](https\://github\.com/ansible\-collections/community\.dns/pull/265)\)\.

<a id="v3-2-4"></a>
## v3\.2\.4

<a id="release-summary-10"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-10"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-2-3"></a>
## v3\.2\.3

<a id="release-summary-11"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-11"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-2-2"></a>
## v3\.2\.2

<a id="release-summary-12"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-12"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-2-1"></a>
## v3\.2\.1

<a id="release-summary-13"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-13"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-2-0"></a>
## v3\.2\.0

<a id="release-summary-14"></a>
### Release Summary

Feature/maintenance release with updated PSL\.

<a id="minor-changes-2"></a>
### Minor Changes

* all filter\, inventory\, and lookup plugins\, and plugin utils \- add type hints to all Python 3 only code \([https\://github\.com/ansible\-collections/community\.dns/pull/239](https\://github\.com/ansible\-collections/community\.dns/pull/239)\)\.
* get\_public\_suffix\, get\_registrable\_domain\, remove\_public\_suffix\, and remove\_registrable\_domain filter plugin \- validate parameters\, and correctly handle byte strings when passed for input \([https\://github\.com/ansible\-collections/community\.dns/pull/239](https\://github\.com/ansible\-collections/community\.dns/pull/239)\)\.

<a id="bugfixes-14"></a>
### Bugfixes

* Fix various issues and potential bugs pointed out by linters \([https\://github\.com/ansible\-collections/community\.dns/pull/242](https\://github\.com/ansible\-collections/community\.dns/pull/242)\, [https\://github\.com/ansible\-collections/community\.dns/pull/243](https\://github\.com/ansible\-collections/community\.dns/pull/243)\)\.
* Update Public Suffix List\.

<a id="v3-1-2"></a>
## v3\.1\.2

<a id="release-summary-15"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-15"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-1-1"></a>
## v3\.1\.1

<a id="release-summary-16"></a>
### Release Summary

Maintenance release with updated documentation and PSL\.

<a id="bugfixes-16"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-1-0"></a>
## v3\.1\.0

<a id="release-summary-17"></a>
### Release Summary

Feature release with updated PSL\.

<a id="minor-changes-3"></a>
### Minor Changes

* all controller code \- modernize Python code \([https\://github\.com/ansible\-collections/community\.dns/pull/231](https\://github\.com/ansible\-collections/community\.dns/pull/231)\)\.

<a id="bugfixes-17"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="new-plugins-1"></a>
### New Plugins

<a id="filter"></a>
#### Filter

* community\.dns\.reverse\_pointer \- Convert an IP address into a DNS name for reverse lookup\.

<a id="lookup-1"></a>
#### Lookup

* community\.dns\.reverse\_lookup \- Reverse\-look up IP addresses\.

<a id="v3-0-7"></a>
## v3\.0\.7

<a id="release-summary-18"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-18"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-6"></a>
## v3\.0\.6

<a id="release-summary-19"></a>
### Release Summary

Regular maintenance release\.

<a id="bugfixes-19"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-5"></a>
## v3\.0\.5

<a id="release-summary-20"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-20"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-4"></a>
## v3\.0\.4

<a id="release-summary-21"></a>
### Release Summary

Regular maintenance release with updated PSL\.

<a id="bugfixes-21"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-3"></a>
## v3\.0\.3

<a id="release-summary-22"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-22"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-2"></a>
## v3\.0\.2

<a id="release-summary-23"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-23"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-1"></a>
## v3\.0\.1

<a id="release-summary-24"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-24"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v3-0-0"></a>
## v3\.0\.0

<a id="release-summary-25"></a>
### Release Summary

New major release\.

<a id="major-changes"></a>
### Major Changes

* The <code>community\.dns</code> collection now depends on the <code>community\.library\_inventory\_filtering\_v1</code> collection\. This utility collection provides host filtering functionality for inventory plugins\. If you use the Ansible community package\, both collections are included and you do not have to do anything special\. If you install the collection with <code>ansible\-galaxy collection install</code>\, it will be installed automatically\. If you install the collection by copying the files of the collection to a place where ansible\-core can find it\, for example by cloning the git repository\, you need to make sure that you also have to install the dependency if you are using the inventory plugins \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.

<a id="minor-changes-4"></a>
### Minor Changes

* inventory plugins \- add <code>filter</code> option which allows to include and exclude hosts based on Jinja2 conditions \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* lookup\, lookup\_as\_dict \- it is now possible to configure whether the input should be treated as an absolute domain name \(<code>search\=false</code>\)\, or potentially as a relative domain name \(<code>search\=true</code>\)  \([https\://github\.com/ansible\-collections/community\.dns/issues/200](https\://github\.com/ansible\-collections/community\.dns/issues/200)\, [https\://github\.com/ansible\-collections/community\.dns/pull/201](https\://github\.com/ansible\-collections/community\.dns/pull/201)\)\.

<a id="breaking-changes--porting-guide"></a>
### Breaking Changes / Porting Guide

* The default for the <code>txt\_character\_encoding</code> options in various modules and plugins changed from <code>octal</code> to <code>decimal</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* inventory plugins \- <code>filters</code> is now no longer an alias of <code>simple\_filters</code>\, but a new\, different option \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* inventory plugins \- the <code>plugin</code> option is now required \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* lookup\, lookup\_as\_dict \- the default for <code>search</code> changed from <code>false</code> \(implicit default for community\.dns 2\.x\.y\) to <code>true</code> \([https\://github\.com/ansible\-collections/community\.dns/issues/200](https\://github\.com/ansible\-collections/community\.dns/issues/200)\, [https\://github\.com/ansible\-collections/community\.dns/pull/201](https\://github\.com/ansible\-collections/community\.dns/pull/201)\)\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The collection no longer supports Ansible\, ansible\-base\, and ansible\-core releases that are currently End of Life at the time of the 3\.0\.0 release\. This means that Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, and ansible\-core 2\.13 are no longer supported\. The collection might still work with these versions\, but it can stop working at any moment without advance notice\, and this will not be considered a bug \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* hetzner\_dns\_record\_set\, hetzner\_dns\_record \- the deprecated alias <code>name</code> of the prefix option was removed \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.
* hosttech\_dns\_records \- the redirect to the <code>hosttech\_dns\_record\_sets</code> module has been removed \([https\://github\.com/ansible\-collections/community\.dns/pull/196](https\://github\.com/ansible\-collections/community\.dns/pull/196)\)\.

<a id="bugfixes-25"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-9-0"></a>
## v2\.9\.0

<a id="release-summary-26"></a>
### Release Summary

Feature and bugfix release\.

<a id="bugfixes-26"></a>
### Bugfixes

* Update Public Suffix List\.
* inventory plugins \- add unsafe wrapper to avoid marking strings that do not contain <code>\{</code> or <code>\}</code> as unsafe\, to work around a bug in AWX \([https\://github\.com/ansible\-collections/community\.dns/pull/197](https\://github\.com/ansible\-collections/community\.dns/pull/197)\)\.

<a id="new-plugins-2"></a>
### New Plugins

<a id="filter-1"></a>
#### Filter

* community\.dns\.quote\_txt \- Quotes a string to use as a TXT record entry
* community\.dns\.unquote\_txt \- Unquotes a TXT record entry to a string

<a id="v2-8-3"></a>
## v2\.8\.3

<a id="release-summary-27"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-27"></a>
### Bugfixes

* DNS record modules\, inventory plugins \- fix the TXT entry encoder to avoid splitting up escape sequences for quotes and backslashes over multiple TXT strings \([https\://github\.com/ansible\-collections/community\.dns/issues/190](https\://github\.com/ansible\-collections/community\.dns/issues/190)\, [https\://github\.com/ansible\-collections/community\.dns/pull/191](https\://github\.com/ansible\-collections/community\.dns/pull/191)\)\.
* Update Public Suffix List\.

<a id="v2-8-2"></a>
## v2\.8\.2

<a id="release-summary-28"></a>
### Release Summary

Bugfix release\.

<a id="security-fixes"></a>
### Security Fixes

* hosttech\_dns\_records and hetzner\_dns\_records inventory plugins \- make sure all data received from the remote servers is marked as unsafe\, so remote code execution by obtaining texts that can be evaluated as templates is not possible \([https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/](https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/)\, [https\://github\.com/ansible\-collections/community\.dns/pull/189](https\://github\.com/ansible\-collections/community\.dns/pull/189)\)\.

<a id="bugfixes-28"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-8-1"></a>
## v2\.8\.1

<a id="release-summary-29"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-29"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-8-0"></a>
## v2\.8\.0

<a id="release-summary-30"></a>
### Release Summary

Feature and maintenance release with updated PSL\.

<a id="minor-changes-5"></a>
### Minor Changes

* hetzner\_dns\_records and hosttech\_dns\_records inventory plugins \- the <code>filters</code> option has been renamed to <code>simple\_filters</code>\. The old name still works until community\.hrobot 2\.0\.0\. Then it will change to allow more complex filtering with the <code>community\.library\_inventory\_filtering\_v1</code> collection\'s functionality \([https\://github\.com/ansible\-collections/community\.dns/pull/181](https\://github\.com/ansible\-collections/community\.dns/pull/181)\)\.

<a id="deprecated-features"></a>
### Deprecated Features

* hetzner\_dns\_records and hosttech\_dns\_records inventory plugins \- the <code>filters</code> option has been renamed to <code>simple\_filters</code>\. The old name will stop working in community\.hrobot 2\.0\.0 \([https\://github\.com/ansible\-collections/community\.dns/pull/181](https\://github\.com/ansible\-collections/community\.dns/pull/181)\)\.

<a id="bugfixes-30"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-7-0"></a>
## v2\.7\.0

<a id="release-summary-31"></a>
### Release Summary

Bugfix and feature release with updated PSL\.

<a id="minor-changes-6"></a>
### Minor Changes

* nameserver\_info and nameserver\_record\_info \- add <code>server</code> parameter to specify custom DNS servers \([https\://github\.com/ansible\-collections/community\.dns/pull/168](https\://github\.com/ansible\-collections/community\.dns/pull/168)\, [https\://github\.com/ansible\-collections/community\.dns/pull/178](https\://github\.com/ansible\-collections/community\.dns/pull/178)\)\.
* wait\_for\_txt \- add <code>server</code> parameter to specify custom DNS servers \([https\://github\.com/ansible\-collections/community\.dns/pull/178](https\://github\.com/ansible\-collections/community\.dns/pull/178)\)\.

<a id="bugfixes-31"></a>
### Bugfixes

* Update Public Suffix List\.
* wait\_for\_txt\, nameserver\_info\, nameserver\_record\_info \- when looking up nameservers for a domain\, do not treat <code>NXDOMAIN</code> as a fatal error \([https\://github\.com/ansible\-collections/community\.dns/pull/177](https\://github\.com/ansible\-collections/community\.dns/pull/177)\)\.

<a id="v2-6-4"></a>
## v2\.6\.4

<a id="release-summary-32"></a>
### Release Summary

Bugfix and maintenance version\.

<a id="bugfixes-32"></a>
### Bugfixes

* Update Public Suffix List\.
* nameserver\_record\_info \- fix crash when more than one record is retrieved \([https\://github\.com/ansible\-collections/community\.dns/pull/172](https\://github\.com/ansible\-collections/community\.dns/pull/172)\)\.

<a id="v2-6-3"></a>
## v2\.6\.3

<a id="release-summary-33"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-33"></a>
### Bugfixes

* HTTP module utils \- make compatible with ansible\-core 2\.17 \([https\://github\.com/ansible\-collections/community\.dns/pull/165](https\://github\.com/ansible\-collections/community\.dns/pull/165)\)\.
* Update Public Suffix List\.

<a id="v2-6-2"></a>
## v2\.6\.2

<a id="release-summary-34"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-34"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-6-1"></a>
## v2\.6\.1

<a id="release-summary-35"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-35"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-6-0"></a>
## v2\.6\.0

<a id="release-summary-36"></a>
### Release Summary

Feature release with an updated Public Suffix List\.

<a id="minor-changes-7"></a>
### Minor Changes

* wait\_for\_txt \- add <code>servfail\_retries</code> parameter that allows retrying after SERVFAIL errors \([https\://github\.com/ansible\-collections/community\.dns/pull/159](https\://github\.com/ansible\-collections/community\.dns/pull/159)\)\.
* wait\_for\_txt\, resolver module utils \- use [EDNS](https\://en\.wikipedia\.org/wiki/Extension\_Mechanisms\_for\_DNS) \([https\://github\.com/ansible\-collections/community\.dns/pull/158](https\://github\.com/ansible\-collections/community\.dns/pull/158)\)\.

<a id="bugfixes-36"></a>
### Bugfixes

* Update Public Suffix List\.
* wait\_for\_txt\, resolver module utils \- improve error handling \([https\://github\.com/ansible\-collections/community\.dns/pull/158](https\://github\.com/ansible\-collections/community\.dns/pull/158)\)\.

<a id="new-plugins-3"></a>
### New Plugins

<a id="lookup-2"></a>
#### Lookup

* community\.dns\.lookup \- Look up DNS records
* community\.dns\.lookup\_as\_dict \- Look up DNS records as dictionaries

<a id="new-modules-1"></a>
### New Modules

* community\.dns\.nameserver\_info \- Look up nameservers for a DNS name
* community\.dns\.nameserver\_record\_info \- Look up all records of a type from all nameservers for a DNS name

<a id="v2-5-7"></a>
## v2\.5\.7

<a id="release-summary-37"></a>
### Release Summary

Regular maintenance release with updated Public Suffix List\.

<a id="bugfixes-37"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-6"></a>
## v2\.5\.6

<a id="release-summary-38"></a>
### Release Summary

Maintenance release\.

From this version on\, community\.dns is using the new [Ansible semantic markup](https\://docs\.ansible\.com/projects/ansible/devel/dev\_guide/developing\_modules\_documenting\.html\#semantic\-markup\-within\-module\-documentation)
in its documentation\. If you look at documentation with the ansible\-doc CLI tool
from ansible\-core before 2\.15\, please note that it does not render the markup
correctly\. You should be still able to read it in most cases\, but you need
ansible\-core 2\.15 or later to see it as it is intended\. Alternatively you can
look at [the devel docsite](https\://docs\.ansible\.com/projects/ansible/devel/collections/community/dns/)
for the rendered HTML version of the documentation of the latest release\.

<a id="known-issues"></a>
### Known Issues

* Ansible markup will show up in raw form on ansible\-doc text output for ansible\-core before 2\.15\. If you have trouble deciphering the documentation markup\, please upgrade to ansible\-core 2\.15 \(or newer\)\, or read the HTML documentation on [https\://docs\.ansible\.com/projects/ansible/devel/collections/community/dns/](https\://docs\.ansible\.com/projects/ansible/devel/collections/community/dns/)\.

<a id="v2-5-5"></a>
## v2\.5\.5

<a id="release-summary-39"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-38"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-4"></a>
## v2\.5\.4

<a id="release-summary-40"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-39"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-3"></a>
## v2\.5\.3

<a id="release-summary-41"></a>
### Release Summary

Maintenance release with updated PSL\.

<a id="bugfixes-40"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-2"></a>
## v2\.5\.2

<a id="release-summary-42"></a>
### Release Summary

Maintenance release with improved documentation and updated PSL\.

<a id="bugfixes-41"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-1"></a>
## v2\.5\.1

<a id="release-summary-43"></a>
### Release Summary

Maintenance release \(updated PSL\)\.

<a id="bugfixes-42"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-5-0"></a>
## v2\.5\.0

<a id="release-summary-44"></a>
### Release Summary

Feature and bugfix release with updated PSL\.

<a id="minor-changes-8"></a>
### Minor Changes

* hosttech inventory plugin \- allow to configure token\, username\, and password with <code>ANSIBLE\_HOSTTECH\_DNS\_TOKEN</code>\, <code>ANSIBLE\_HOSTTECH\_API\_USERNAME</code>\, and <code>ANSIBLE\_HOSTTECH\_API\_PASSWORD</code> environment variables\, respectively \([https\://github\.com/ansible\-collections/community\.dns/pull/131](https\://github\.com/ansible\-collections/community\.dns/pull/131)\)\.
* various modules and inventory plugins \- add new option <code>txt\_character\_encoding</code> which controls whether numeric escape sequences are interpreted as octals or decimals when <code>txt\_transformation\=quoted</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/134](https\://github\.com/ansible\-collections/community\.dns/pull/134)\)\.

<a id="deprecated-features-1"></a>
### Deprecated Features

* The default of the newly added option <code>txt\_character\_encoding</code> will change from <code>octal</code> to <code>decimal</code> in community\.dns 3\.0\.0\. The new default will be compatible with [RFC 1035](https\://www\.ietf\.org/rfc/rfc1035\.txt) \([https\://github\.com/ansible\-collections/community\.dns/pull/134](https\://github\.com/ansible\-collections/community\.dns/pull/134)\)\.

<a id="bugfixes-43"></a>
### Bugfixes

* Update Public Suffix List\.
* inventory plugins \- document <code>plugin</code> option used by the <code>ansible\.builtin\.auto</code> inventory plugin and mention required file ending in the documentation \([https\://github\.com/ansible\-collections/community\.dns/issues/130](https\://github\.com/ansible\-collections/community\.dns/issues/130)\, [https\://github\.com/ansible\-collections/community\.dns/pull/131](https\://github\.com/ansible\-collections/community\.dns/pull/131)\)\.

<a id="v2-4-2"></a>
## v2\.4\.2

<a id="release-summary-45"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-44"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-4-1"></a>
## v2\.4\.1

<a id="release-summary-46"></a>
### Release Summary

Regular maintenance release\.

<a id="bugfixes-45"></a>
### Bugfixes

* Update Public Suffix List\.
* wait\_for\_txt \- also retrieve IPv6 addresses of nameservers\. Prevents failures with IPv6 only nameservers \([https\://github\.com/ansible\-collections/community\.dns/issues/120](https\://github\.com/ansible\-collections/community\.dns/issues/120)\, [https\://github\.com/ansible\-collections/community\.dns/pull/121](https\://github\.com/ansible\-collections/community\.dns/pull/121)\)\.

<a id="v2-4-0"></a>
## v2\.4\.0

<a id="release-summary-47"></a>
### Release Summary

Feature and maintenance release\.

<a id="minor-changes-9"></a>
### Minor Changes

* Added a <code>community\.dns\.hetzner</code> module defaults group / action group\. Use with <code>group/community\.dns\.hetzner</code> to provide options for all Hetzner DNS modules \([https\://github\.com/ansible\-collections/community\.dns/pull/119](https\://github\.com/ansible\-collections/community\.dns/pull/119)\)\.
* Added a <code>community\.dns\.hosttech</code> module defaults group / action group\. Use with <code>group/community\.dns\.hosttech</code> to provide options for all Hosttech DNS modules \([https\://github\.com/ansible\-collections/community\.dns/pull/119](https\://github\.com/ansible\-collections/community\.dns/pull/119)\)\.
* wait\_for\_txt \- the module now supports check mode\. The only practical change in behavior is that in check mode\, the module is now executed instead of skipped\. Since the module does not change anything\, it should have been marked as supporting check mode since it was originally added \([https\://github\.com/ansible\-collections/community\.dns/pull/119](https\://github\.com/ansible\-collections/community\.dns/pull/119)\)\.

<a id="bugfixes-46"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-3-4"></a>
## v2\.3\.4

<a id="release-summary-48"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-47"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-3-3"></a>
## v2\.3\.3

<a id="release-summary-49"></a>
### Release Summary

Maintenance release including an updated Public Suffix List\.

<a id="bugfixes-48"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-3-2"></a>
## v2\.3\.2

<a id="release-summary-50"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-49"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-3-1"></a>
## v2\.3\.1

<a id="release-summary-51"></a>
### Release Summary

Maintenance release including an updated Public Suffix List\.

<a id="minor-changes-10"></a>
### Minor Changes

* The collection repository conforms to the [REUSE specification](https\://reuse\.software/spec/) except for the changelog fragments \([https\://github\.com/ansible\-collections/community\.dns/pull/112](https\://github\.com/ansible\-collections/community\.dns/pull/112)\)\.

<a id="bugfixes-50"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-3-0"></a>
## v2\.3\.0

<a id="release-summary-52"></a>
### Release Summary

Maintenance release including an updated Public Suffix List\.

<a id="minor-changes-11"></a>
### Minor Changes

* All software licenses are now in the <code>LICENSES/</code> directory of the collection root\. Moreover\, <code>SPDX\-License\-Identifier\:</code> is used to declare the applicable license for every file that is not automatically generated \([https\://github\.com/ansible\-collections/community\.dns/pull/109](https\://github\.com/ansible\-collections/community\.dns/pull/109)\)\.

<a id="bugfixes-51"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-2-1"></a>
## v2\.2\.1

<a id="release-summary-53"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-52"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-54"></a>
### Release Summary

Feature release\.

<a id="minor-changes-12"></a>
### Minor Changes

* hetzner\_dns\_records and hosttech\_dns\_records inventory plugins \- allow to template provider\-specific credentials and the <code>zone\_name</code>\, <code>zone\_id</code> options \([https\://github\.com/ansible\-collections/community\.dns/pull/106](https\://github\.com/ansible\-collections/community\.dns/pull/106)\)\.
* wait\_for\_txt \- improve error messages so that in case of SERVFAILs or other DNS errors it is clear which record was queried from which DNS server \([https\://github\.com/ansible\-collections/community\.dns/pull/105](https\://github\.com/ansible\-collections/community\.dns/pull/105)\)\.

<a id="bugfixes-53"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-1-1"></a>
## v2\.1\.1

<a id="release-summary-55"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-54"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-56"></a>
### Release Summary

Feature and maintenance release with updated PSL\.

<a id="minor-changes-13"></a>
### Minor Changes

* Prepare collection for inclusion in an Execution Environment by declaring its dependencies \([https\://github\.com/ansible\-collections/community\.dns/pull/93](https\://github\.com/ansible\-collections/community\.dns/pull/93)\)\.

<a id="bugfixes-55"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-9"></a>
## v2\.0\.9

<a id="release-summary-57"></a>
### Release Summary

Maintenance release with updated Public Suffix List and added collection links file\.

<a id="bugfixes-56"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-8"></a>
## v2\.0\.8

<a id="release-summary-58"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-57"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-7"></a>
## v2\.0\.7

<a id="release-summary-59"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-58"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-6"></a>
## v2\.0\.6

<a id="release-summary-60"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-59"></a>
### Bugfixes

* Update Public Suffix List\.
* wait\_for\_txt \- do not fail if <code>NXDOMAIN</code> result is returned\. Also do not succeed if no nameserver can be found \([https\://github\.com/ansible\-collections/community\.dns/issues/81](https\://github\.com/ansible\-collections/community\.dns/issues/81)\, [https\://github\.com/ansible\-collections/community\.dns/pull/82](https\://github\.com/ansible\-collections/community\.dns/pull/82)\)\.

<a id="v2-0-5"></a>
## v2\.0\.5

<a id="release-summary-61"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-60"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-4"></a>
## v2\.0\.4

<a id="release-summary-62"></a>
### Release Summary

Maintenance release with updated Public Suffix List\.

<a id="bugfixes-61"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-3"></a>
## v2\.0\.3

<a id="release-summary-63"></a>
### Release Summary

Bugfix release\.

<a id="minor-changes-14"></a>
### Minor Changes

* HTTP API module utils \- fix usage of <code>fetch\_url</code> with changes in latest ansible\-core <code>devel</code> branch \([https\://github\.com/ansible\-collections/community\.dns/pull/73](https\://github\.com/ansible\-collections/community\.dns/pull/73)\)\.

<a id="v2-0-2"></a>
## v2\.0\.2

<a id="release-summary-64"></a>
### Release Summary

Regular maintenance release\.

<a id="bugfixes-62"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-1"></a>
## v2\.0\.1

<a id="release-summary-65"></a>
### Release Summary

Maintenance release with Public Suffix List updates\.

<a id="bugfixes-63"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-66"></a>
### Release Summary

This release contains many new features\, modules and plugins\, but also has several breaking changes to the 1\.x\.y versions\. Please read the changelog carefully to determine what to change if you used an earlier version of this collection\.

<a id="minor-changes-15"></a>
### Minor Changes

* Add support for Hetzner DNS \([https\://github\.com/ansible\-collections/community\.dns/pull/27](https\://github\.com/ansible\-collections/community\.dns/pull/27)\)\.
* Added a <code>txt\_transformation</code> option to all modules and plugins working with DNS records \([https\://github\.com/ansible\-collections/community\.dns/issues/48](https\://github\.com/ansible\-collections/community\.dns/issues/48)\, [https\://github\.com/ansible\-collections/community\.dns/pull/57](https\://github\.com/ansible\-collections/community\.dns/pull/57)\, [https\://github\.com/ansible\-collections/community\.dns/pull/60](https\://github\.com/ansible\-collections/community\.dns/pull/60)\)\.
* The hosttech\_dns\_records module has been renamed to hosttech\_dns\_record\_sets \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.
* The internal API now supports bulk DNS record changes\, if supported by the API \([https\://github\.com/ansible\-collections/community\.dns/pull/39](https\://github\.com/ansible\-collections/community\.dns/pull/39)\)\.
* The internal record API allows to manage extra data \([https\://github\.com/ansible\-collections/community\.dns/pull/63](https\://github\.com/ansible\-collections/community\.dns/pull/63)\)\.
* Use HTTP helper class to make API implementations work for both plugins and modules\. Make WSDL API use <code>fetch\_url</code> instead of <code>open\_url</code> for modules \([https\://github\.com/ansible\-collections/community\.dns/pull/36](https\://github\.com/ansible\-collections/community\.dns/pull/36)\)\.
* hetzner\_dns\_record and hosttech\_dns\_record \- when not using check mode\, use actual return data for diff\, instead of input data\, so that extra data can be shown \([https\://github\.com/ansible\-collections/community\.dns/pull/63](https\://github\.com/ansible\-collections/community\.dns/pull/63)\)\.
* hetzner\_dns\_zone\_info \- the <code>legacy\_ns</code> return value is now sorted\, since its order is unstable \([https\://github\.com/ansible\-collections/community\.dns/pull/46](https\://github\.com/ansible\-collections/community\.dns/pull/46)\)\.
* hosttech\_dns\_\* modules \- rename <code>zone</code> parameter to <code>zone\_name</code>\. The old name <code>zone</code> can still be used as an alias \([https\://github\.com/ansible\-collections/community\.dns/pull/32](https\://github\.com/ansible\-collections/community\.dns/pull/32)\)\.
* hosttech\_dns\_record\_set \- <code>value</code> is no longer required when <code>state\=absent</code> and <code>overwrite\=true</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.
* hosttech\_dns\_record\_sets \- <code>records</code> has been renamed to <code>record\_sets</code>\. The old name <code>records</code> can still be used as an alias \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.
* hosttech\_dns\_zone\_info \- return extra information as <code>zone\_info</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/38](https\://github\.com/ansible\-collections/community\.dns/pull/38)\)\.

<a id="breaking-changes--porting-guide-1"></a>
### Breaking Changes / Porting Guide

* All Hetzner modules and plugins which handle DNS records now work with unquoted TXT values by default\. The old behavior can be obtained by setting <code>txt\_transformation\=api</code> \([https\://github\.com/ansible\-collections/community\.dns/issues/48](https\://github\.com/ansible\-collections/community\.dns/issues/48)\, [https\://github\.com/ansible\-collections/community\.dns/pull/57](https\://github\.com/ansible\-collections/community\.dns/pull/57)\, [https\://github\.com/ansible\-collections/community\.dns/pull/60](https\://github\.com/ansible\-collections/community\.dns/pull/60)\)\.
* Hosttech API creation \- now requires a <code>ModuleOptionProvider</code> object instead of an <code>AnsibleModule</code> object\. Alternatively an Ansible plugin instance can be passed \([https\://github\.com/ansible\-collections/community\.dns/pull/37](https\://github\.com/ansible\-collections/community\.dns/pull/37)\)\.
* The hetzner\_dns\_record\_info and hosttech\_dns\_record\_info modules have been renamed to hetzner\_dns\_record\_set\_info and hosttech\_dns\_record\_set\_info\, respectively \([https\://github\.com/ansible\-collections/community\.dns/pull/54](https\://github\.com/ansible\-collections/community\.dns/pull/54)\)\.
* The hosttech\_dns\_record module has been renamed to hosttech\_dns\_record\_set \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.
* The internal bulk record updating helper \(<code>bulk\_apply\_changes</code>\) now also returns the records that were deleted\, created or updated \([https\://github\.com/ansible\-collections/community\.dns/pull/63](https\://github\.com/ansible\-collections/community\.dns/pull/63)\)\.
* The internal record API no longer allows to manage comments explicitly \([https\://github\.com/ansible\-collections/community\.dns/pull/63](https\://github\.com/ansible\-collections/community\.dns/pull/63)\)\.
* When using the internal modules API\, now a zone ID type and a provider information object must be passed \([https\://github\.com/ansible\-collections/community\.dns/pull/27](https\://github\.com/ansible\-collections/community\.dns/pull/27)\)\.
* hetzner\_dns\_record\* modules \- implement correct handling of default TTL\. The value <code>none</code> is now accepted and returned in this case \([https\://github\.com/ansible\-collections/community\.dns/pull/52](https\://github\.com/ansible\-collections/community\.dns/pull/52)\, [https\://github\.com/ansible\-collections/community\.dns/issues/50](https\://github\.com/ansible\-collections/community\.dns/issues/50)\)\.
* hetzner\_dns\_record\, hetzner\_dns\_record\_set\, hetzner\_dns\_record\_sets \- the default TTL is now 300 and no longer 3600\, which equals the default in the web console \([https\://github\.com/ansible\-collections/community\.dns/pull/43](https\://github\.com/ansible\-collections/community\.dns/pull/43)\)\.
* hosttech\_dns\_record\_set \- the option <code>overwrite</code> was replaced by a new option <code>on\_existing</code>\. Specifying <code>overwrite\=true</code> is equivalent to <code>on\_existing\=replace</code> \(the new default\)\. Specifying <code>overwrite\=false</code> with <code>state\=present</code> is equivalent to <code>on\_existing\=keep\_and\_fail</code>\, and specifying <code>overwrite\=false</code> with <code>state\=absent</code> is equivalent to <code>on\_existing\=keep</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.

<a id="deprecated-features-2"></a>
### Deprecated Features

* The hosttech\_dns\_records module has been renamed to hosttech\_dns\_record\_sets\. The old name will stop working in community\.dns 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.dns/pull/31](https\://github\.com/ansible\-collections/community\.dns/pull/31)\)\.

<a id="bugfixes-64"></a>
### Bugfixes

* Hetzner API \- interpret missing TTL as 300\, which is what the web console also does \([https\://github\.com/ansible\-collections/community\.dns/pull/42](https\://github\.com/ansible\-collections/community\.dns/pull/42)\)\.
* Update Public Suffix List\.
* Update Public Suffix List\.
* Update Public Suffix List\.
* hetzner API code \- make sure to also handle errors returned by the API if the HTTP status code indicates success\. This sometimes happens for 500 Internal Server Error \([https\://github\.com/ansible\-collections/community\.dns/pull/58](https\://github\.com/ansible\-collections/community\.dns/pull/58)\)\.
* hosttech\_dns\_zone\_info \- make sure that full information is returned both when requesting a zone by ID or by name \([https\://github\.com/ansible\-collections/community\.dns/pull/56](https\://github\.com/ansible\-collections/community\.dns/pull/56)\)\.
* wait\_for\_txt \- fix handling of too long TXT values \([https\://github\.com/ansible\-collections/community\.dns/pull/65](https\://github\.com/ansible\-collections/community\.dns/pull/65)\)\.
* wait\_for\_txt \- resolving nameservers sometimes resulted in an empty list\, yielding wrong results \([https\://github\.com/ansible\-collections/community\.dns/pull/64](https\://github\.com/ansible\-collections/community\.dns/pull/64)\)\.

<a id="new-plugins-4"></a>
### New Plugins

<a id="inventory"></a>
#### Inventory

* community\.dns\.hetzner\_dns\_records \- Create inventory from Hetzner DNS records
* community\.dns\.hosttech\_dns\_records \- Create inventory from Hosttech DNS records

<a id="new-modules-2"></a>
### New Modules

* community\.dns\.hetzner\_dns\_record \- Add or delete a single record in Hetzner DNS service
* community\.dns\.hetzner\_dns\_record\_info \- Retrieve records in Hetzner DNS service
* community\.dns\.hetzner\_dns\_record\_set \- Add or delete record sets in Hetzner DNS service
* community\.dns\.hetzner\_dns\_record\_set\_info \- Retrieve record sets in Hetzner DNS service
* community\.dns\.hetzner\_dns\_record\_sets \- Bulk synchronize DNS record sets in Hetzner DNS service
* community\.dns\.hetzner\_dns\_zone\_info \- Retrieve zone information in Hetzner DNS service
* community\.dns\.hosttech\_dns\_record \- Add or delete a single record in Hosttech DNS service
* community\.dns\.hosttech\_dns\_record\_info \- Retrieve records in Hosttech DNS service
* community\.dns\.hosttech\_dns\_record\_set \- Add or delete record sets in Hosttech DNS service
* community\.dns\.hosttech\_dns\_record\_sets \- Bulk synchronize DNS record sets in Hosttech DNS service

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-67"></a>
### Release Summary

Last minor 1\.x\.0 version\. The 2\.0\.0 version will have some backwards incompatible changes to the <code>hosttech\_dns\_record</code> and <code>hosttech\_dns\_records</code> modules which will require user intervention\. These changes should result in a better UX\.

<a id="minor-changes-16"></a>
### Minor Changes

* hosttech modules \- add <code>api\_token</code> alias for <code>hosttech\_token</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/26](https\://github\.com/ansible\-collections/community\.dns/pull/26)\)\.
* hosttech\_dns\_record \- in <code>diff</code> mode\, also return <code>diff</code> data structure when <code>changed</code> is <code>false</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/28](https\://github\.com/ansible\-collections/community\.dns/pull/28)\)\.
* module utils \- add default implementation for some zone/record API functions\, and move common JSON API code to helper class \([https\://github\.com/ansible\-collections/community\.dns/pull/26](https\://github\.com/ansible\-collections/community\.dns/pull/26)\)\.

<a id="bugfixes-65"></a>
### Bugfixes

* Update Public Suffix List\.
* hosttech\_dns\_record \- correctly handle quoting in CAA records for JSON API \([https\://github\.com/ansible\-collections/community\.dns/pull/30](https\://github\.com/ansible\-collections/community\.dns/pull/30)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-68"></a>
### Release Summary

Regular maintenance release\.

<a id="minor-changes-17"></a>
### Minor Changes

* Avoid internal ansible\-core module\_utils in favor of equivalent public API available since at least Ansible 2\.9 \([https\://github\.com/ansible\-collections/community\.dns/pull/24](https\://github\.com/ansible\-collections/community\.dns/pull/24)\)\.

<a id="bugfixes-66"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v1-0-1"></a>
## v1\.0\.1

<a id="release-summary-69"></a>
### Release Summary

Regular maintenance release\.

<a id="bugfixes-67"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-70"></a>
### Release Summary

First stable release\.

<a id="bugfixes-68"></a>
### Bugfixes

* Update Public Suffix List\.

<a id="v0-3-0"></a>
## v0\.3\.0

<a id="release-summary-71"></a>
### Release Summary

Fixes bugs\, adds rate limiting for Hosttech JSON API\, and adds a new bulk synchronization module\.

<a id="minor-changes-18"></a>
### Minor Changes

* hosttech\_dns\_\* \- handle <code>419 Too Many Requests</code> with proper rate limiting for JSON API \([https\://github\.com/ansible\-collections/community\.dns/pull/14](https\://github\.com/ansible\-collections/community\.dns/pull/14)\)\.

<a id="bugfixes-69"></a>
### Bugfixes

* Avoid converting ASCII labels which contain underscores or other printable ASCII characters outside <code>\[a\-zA\-Z0\-9\-\]</code> to alabels during normalization \([https\://github\.com/ansible\-collections/community\.dns/pull/13](https\://github\.com/ansible\-collections/community\.dns/pull/13)\)\.
* Updated Public Suffix List\.

<a id="new-modules-3"></a>
### New Modules

* community\.dns\.hosttech\_dns\_records \- Bulk synchronize DNS records in Hosttech DNS service

<a id="v0-2-0"></a>
## v0\.2\.0

<a id="release-summary-72"></a>
### Release Summary

Major refactoring release\, which adds a zone information module and supports HostTech\'s new REST API\.

<a id="major-changes-1"></a>
### Major Changes

* hosttech\_\* modules \- support the new JSON API at [https\://api\.ns1\.hosttech\.eu/api/documentation/](https\://api\.ns1\.hosttech\.eu/api/documentation/) \([https\://github\.com/ansible\-collections/community\.dns/pull/4](https\://github\.com/ansible\-collections/community\.dns/pull/4)\)\.

<a id="minor-changes-19"></a>
### Minor Changes

* hosttech\_dns\_record\* modules \- allow to specify <code>prefix</code> instead of <code>record</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/8](https\://github\.com/ansible\-collections/community\.dns/pull/8)\)\.
* hosttech\_dns\_record\* modules \- allow to specify zone by ID with the <code>zone\_id</code> parameter\, alternatively to the <code>zone</code> parameter \([https\://github\.com/ansible\-collections/community\.dns/pull/7](https\://github\.com/ansible\-collections/community\.dns/pull/7)\)\.
* hosttech\_dns\_record\* modules \- return <code>zone\_id</code> on success \([https\://github\.com/ansible\-collections/community\.dns/pull/7](https\://github\.com/ansible\-collections/community\.dns/pull/7)\)\.
* hosttech\_dns\_record\* modules \- support IDN domain names and prefixes \([https\://github\.com/ansible\-collections/community\.dns/pull/9](https\://github\.com/ansible\-collections/community\.dns/pull/9)\)\.
* hosttech\_dns\_record\_info \- also return <code>prefix</code> for a record set \([https\://github\.com/ansible\-collections/community\.dns/pull/8](https\://github\.com/ansible\-collections/community\.dns/pull/8)\)\.
* hosttech\_record \- allow to delete records without querying their content first by specifying <code>overwrite\=true</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/4](https\://github\.com/ansible\-collections/community\.dns/pull/4)\)\.

<a id="breaking-changes--porting-guide-2"></a>
### Breaking Changes / Porting Guide

* hosttech\_\* module\_utils \- completely rewrite and refactor to support new JSON API and allow to reuse provider\-independent module logic \([https\://github\.com/ansible\-collections/community\.dns/pull/4](https\://github\.com/ansible\-collections/community\.dns/pull/4)\)\.

<a id="bugfixes-70"></a>
### Bugfixes

* Update Public Suffix List\.
* hosttech\_record \- fix diff mode for <code>state\=absent</code> \([https\://github\.com/ansible\-collections/community\.dns/pull/4](https\://github\.com/ansible\-collections/community\.dns/pull/4)\)\.
* hosttech\_record\_info \- fix authentication error handling \([https\://github\.com/ansible\-collections/community\.dns/pull/4](https\://github\.com/ansible\-collections/community\.dns/pull/4)\)\.

<a id="new-modules-4"></a>
### New Modules

* community\.dns\.hosttech\_dns\_zone\_info \- Retrieve zone information in Hosttech DNS service

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-73"></a>
### Release Summary

Initial public release\.

<a id="new-plugins-5"></a>
### New Plugins

<a id="filter-2"></a>
#### Filter

* community\.dns\.get\_public\_suffix \- Returns the public suffix of a DNS name
* community\.dns\.get\_registrable\_domain \- Returns the registrable domain name of a DNS name
* community\.dns\.remove\_public\_suffix \- Removes the public suffix from a DNS name
* community\.dns\.remove\_registrable\_domain \- Removes the registrable domain name from a DNS name

<a id="new-modules-5"></a>
### New Modules

* community\.dns\.hosttech\_dns\_record \- Add or delete entries in Hosttech DNS service
* community\.dns\.hosttech\_dns\_record\_info \- Retrieve entries in Hosttech DNS service
* community\.dns\.wait\_for\_txt \- Wait for TXT entries to be available on all authoritative nameservers
