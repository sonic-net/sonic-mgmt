# Docker Community Collection Release Notes

**Topics**

- <a href="#v4-8-5">v4\.8\.5</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v4-8-4">v4\.8\.4</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v4-8-3">v4\.8\.3</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#bugfixes-2">Bugfixes</a>
    - <a href="#known-issues">Known Issues</a>
- <a href="#v4-8-2">v4\.8\.2</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#bugfixes-3">Bugfixes</a>
- <a href="#v4-8-1">v4\.8\.1</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v4-8-0">v4\.8\.0</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v4-7-0">v4\.7\.0</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
    - <a href="#bugfixes-6">Bugfixes</a>
- <a href="#v4-6-2">v4\.6\.2</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#bugfixes-7">Bugfixes</a>
- <a href="#v4-6-1">v4\.6\.1</a>
    - <a href="#release-summary-8">Release Summary</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v4-6-0">v4\.6\.0</a>
    - <a href="#release-summary-9">Release Summary</a>
    - <a href="#minor-changes-3">Minor Changes</a>
- <a href="#v4-5-2">v4\.5\.2</a>
    - <a href="#release-summary-10">Release Summary</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v4-5-1">v4\.5\.1</a>
    - <a href="#release-summary-11">Release Summary</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v4-5-0">v4\.5\.0</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#minor-changes-4">Minor Changes</a>
- <a href="#v4-4-0">v4\.4\.0</a>
    - <a href="#release-summary-13">Release Summary</a>
    - <a href="#bugfixes-11">Bugfixes</a>
    - <a href="#new-modules">New Modules</a>
- <a href="#v4-3-1">v4\.3\.1</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#bugfixes-12">Bugfixes</a>
- <a href="#v4-3-0">v4\.3\.0</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#minor-changes-5">Minor Changes</a>
- <a href="#v4-2-0">v4\.2\.0</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
    - <a href="#bugfixes-13">Bugfixes</a>
- <a href="#v4-1-0">v4\.1\.0</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
    - <a href="#bugfixes-14">Bugfixes</a>
- <a href="#v4-0-1">v4\.0\.1</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#bugfixes-15">Bugfixes</a>
- <a href="#v4-0-0">v4\.0\.0</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
- <a href="#v3-13-1">v3\.13\.1</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#bugfixes-16">Bugfixes</a>
- <a href="#v3-13-0">v3\.13\.0</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#new-modules-1">New Modules</a>
- <a href="#v3-12-2">v3\.12\.2</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#bugfixes-17">Bugfixes</a>
- <a href="#v3-12-1">v3\.12\.1</a>
    - <a href="#release-summary-23">Release Summary</a>
    - <a href="#deprecated-features">Deprecated Features</a>
- <a href="#v3-12-0">v3\.12\.0</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
    - <a href="#bugfixes-18">Bugfixes</a>
    - <a href="#known-issues-1">Known Issues</a>
- <a href="#v3-11-0">v3\.11\.0</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#bugfixes-19">Bugfixes</a>
- <a href="#v3-10-4">v3\.10\.4</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#bugfixes-20">Bugfixes</a>
- <a href="#v3-10-3">v3\.10\.3</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#bugfixes-21">Bugfixes</a>
- <a href="#v3-10-2">v3\.10\.2</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#bugfixes-22">Bugfixes</a>
- <a href="#v3-10-1">v3\.10\.1</a>
    - <a href="#release-summary-28">Release Summary</a>
    - <a href="#bugfixes-23">Bugfixes</a>
    - <a href="#known-issues-2">Known Issues</a>
- <a href="#v3-10-0">v3\.10\.0</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
    - <a href="#deprecated-features-1">Deprecated Features</a>
- <a href="#v3-9-0">v3\.9\.0</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
    - <a href="#bugfixes-24">Bugfixes</a>
- <a href="#v3-8-1">v3\.8\.1</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#security-fixes">Security Fixes</a>
    - <a href="#bugfixes-25">Bugfixes</a>
- <a href="#v3-8-0">v3\.8\.0</a>
    - <a href="#release-summary-32">Release Summary</a>
    - <a href="#minor-changes-13">Minor Changes</a>
    - <a href="#bugfixes-26">Bugfixes</a>
- <a href="#v3-7-0">v3\.7\.0</a>
    - <a href="#release-summary-33">Release Summary</a>
    - <a href="#minor-changes-14">Minor Changes</a>
    - <a href="#bugfixes-27">Bugfixes</a>
    - <a href="#new-modules-2">New Modules</a>
- <a href="#v3-6-0">v3\.6\.0</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#major-changes">Major Changes</a>
    - <a href="#minor-changes-15">Minor Changes</a>
    - <a href="#bugfixes-28">Bugfixes</a>
    - <a href="#new-modules-3">New Modules</a>
- <a href="#v3-5-0">v3\.5\.0</a>
    - <a href="#release-summary-35">Release Summary</a>
    - <a href="#minor-changes-16">Minor Changes</a>
    - <a href="#deprecated-features-2">Deprecated Features</a>
    - <a href="#bugfixes-29">Bugfixes</a>
- <a href="#v3-4-11">v3\.4\.11</a>
    - <a href="#release-summary-36">Release Summary</a>
    - <a href="#bugfixes-30">Bugfixes</a>
- <a href="#v3-4-10">v3\.4\.10</a>
    - <a href="#release-summary-37">Release Summary</a>
    - <a href="#bugfixes-31">Bugfixes</a>
- <a href="#v3-4-9">v3\.4\.9</a>
    - <a href="#release-summary-38">Release Summary</a>
    - <a href="#bugfixes-32">Bugfixes</a>
- <a href="#v3-4-8">v3\.4\.8</a>
    - <a href="#release-summary-39">Release Summary</a>
    - <a href="#known-issues-3">Known Issues</a>
- <a href="#v3-4-7">v3\.4\.7</a>
    - <a href="#release-summary-40">Release Summary</a>
    - <a href="#bugfixes-33">Bugfixes</a>
- <a href="#v3-4-6">v3\.4\.6</a>
    - <a href="#release-summary-41">Release Summary</a>
    - <a href="#bugfixes-34">Bugfixes</a>
    - <a href="#known-issues-4">Known Issues</a>
- <a href="#v3-4-5">v3\.4\.5</a>
    - <a href="#release-summary-42">Release Summary</a>
    - <a href="#bugfixes-35">Bugfixes</a>
- <a href="#v3-4-4">v3\.4\.4</a>
    - <a href="#release-summary-43">Release Summary</a>
    - <a href="#minor-changes-17">Minor Changes</a>
    - <a href="#known-issues-5">Known Issues</a>
- <a href="#v3-4-3">v3\.4\.3</a>
    - <a href="#release-summary-44">Release Summary</a>
- <a href="#v3-4-2">v3\.4\.2</a>
    - <a href="#release-summary-45">Release Summary</a>
    - <a href="#bugfixes-36">Bugfixes</a>
- <a href="#v3-4-1">v3\.4\.1</a>
    - <a href="#release-summary-46">Release Summary</a>
    - <a href="#bugfixes-37">Bugfixes</a>
- <a href="#v3-4-0">v3\.4\.0</a>
    - <a href="#release-summary-47">Release Summary</a>
    - <a href="#minor-changes-18">Minor Changes</a>
    - <a href="#bugfixes-38">Bugfixes</a>
    - <a href="#new-modules-4">New Modules</a>
- <a href="#v3-3-2">v3\.3\.2</a>
    - <a href="#release-summary-48">Release Summary</a>
    - <a href="#bugfixes-39">Bugfixes</a>
- <a href="#v3-3-1">v3\.3\.1</a>
    - <a href="#release-summary-49">Release Summary</a>
    - <a href="#bugfixes-40">Bugfixes</a>
- <a href="#v3-3-0">v3\.3\.0</a>
    - <a href="#release-summary-50">Release Summary</a>
    - <a href="#minor-changes-19">Minor Changes</a>
    - <a href="#bugfixes-41">Bugfixes</a>
- <a href="#v3-2-2">v3\.2\.2</a>
    - <a href="#release-summary-51">Release Summary</a>
    - <a href="#bugfixes-42">Bugfixes</a>
- <a href="#v3-2-1">v3\.2\.1</a>
    - <a href="#release-summary-52">Release Summary</a>
- <a href="#v3-2-0">v3\.2\.0</a>
    - <a href="#release-summary-53">Release Summary</a>
    - <a href="#minor-changes-20">Minor Changes</a>
    - <a href="#deprecated-features-3">Deprecated Features</a>
- <a href="#v3-1-0">v3\.1\.0</a>
    - <a href="#release-summary-54">Release Summary</a>
    - <a href="#minor-changes-21">Minor Changes</a>
- <a href="#v3-0-2">v3\.0\.2</a>
    - <a href="#release-summary-55">Release Summary</a>
    - <a href="#bugfixes-43">Bugfixes</a>
- <a href="#v3-0-1">v3\.0\.1</a>
    - <a href="#release-summary-56">Release Summary</a>
    - <a href="#bugfixes-44">Bugfixes</a>
- <a href="#v3-0-0">v3\.0\.0</a>
    - <a href="#release-summary-57">Release Summary</a>
    - <a href="#major-changes-1">Major Changes</a>
    - <a href="#minor-changes-22">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-1">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated-1">Removed Features \(previously deprecated\)</a>
    - <a href="#security-fixes-1">Security Fixes</a>
    - <a href="#bugfixes-45">Bugfixes</a>
- <a href="#v2-7-0">v2\.7\.0</a>
    - <a href="#release-summary-58">Release Summary</a>
    - <a href="#minor-changes-23">Minor Changes</a>
    - <a href="#deprecated-features-4">Deprecated Features</a>
    - <a href="#bugfixes-46">Bugfixes</a>
- <a href="#v2-6-0">v2\.6\.0</a>
    - <a href="#release-summary-59">Release Summary</a>
    - <a href="#minor-changes-24">Minor Changes</a>
    - <a href="#deprecated-features-5">Deprecated Features</a>
    - <a href="#bugfixes-47">Bugfixes</a>
- <a href="#v2-5-1">v2\.5\.1</a>
    - <a href="#release-summary-60">Release Summary</a>
    - <a href="#bugfixes-48">Bugfixes</a>
- <a href="#v2-5-0">v2\.5\.0</a>
    - <a href="#release-summary-61">Release Summary</a>
    - <a href="#minor-changes-25">Minor Changes</a>
- <a href="#v2-4-0">v2\.4\.0</a>
    - <a href="#release-summary-62">Release Summary</a>
    - <a href="#minor-changes-26">Minor Changes</a>
    - <a href="#bugfixes-49">Bugfixes</a>
- <a href="#v2-3-0">v2\.3\.0</a>
    - <a href="#release-summary-63">Release Summary</a>
    - <a href="#minor-changes-27">Minor Changes</a>
    - <a href="#bugfixes-50">Bugfixes</a>
- <a href="#v2-2-1">v2\.2\.1</a>
    - <a href="#release-summary-64">Release Summary</a>
    - <a href="#bugfixes-51">Bugfixes</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-65">Release Summary</a>
    - <a href="#minor-changes-28">Minor Changes</a>
    - <a href="#bugfixes-52">Bugfixes</a>
- <a href="#v2-1-1">v2\.1\.1</a>
    - <a href="#release-summary-66">Release Summary</a>
    - <a href="#bugfixes-53">Bugfixes</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-67">Release Summary</a>
    - <a href="#minor-changes-29">Minor Changes</a>
    - <a href="#bugfixes-54">Bugfixes</a>
- <a href="#v2-0-2">v2\.0\.2</a>
    - <a href="#release-summary-68">Release Summary</a>
    - <a href="#bugfixes-55">Bugfixes</a>
- <a href="#v2-0-1">v2\.0\.1</a>
    - <a href="#release-summary-69">Release Summary</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-70">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-2">Breaking Changes / Porting Guide</a>
    - <a href="#deprecated-features-6">Deprecated Features</a>
    - <a href="#removed-features-previously-deprecated-2">Removed Features \(previously deprecated\)</a>
- <a href="#v1-10-0">v1\.10\.0</a>
    - <a href="#release-summary-71">Release Summary</a>
    - <a href="#minor-changes-30">Minor Changes</a>
- <a href="#v1-9-1">v1\.9\.1</a>
    - <a href="#release-summary-72">Release Summary</a>
    - <a href="#bugfixes-56">Bugfixes</a>
- <a href="#v1-9-0">v1\.9\.0</a>
    - <a href="#release-summary-73">Release Summary</a>
    - <a href="#minor-changes-31">Minor Changes</a>
    - <a href="#deprecated-features-7">Deprecated Features</a>
    - <a href="#bugfixes-57">Bugfixes</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#connection">Connection</a>
- <a href="#v1-8-0">v1\.8\.0</a>
    - <a href="#release-summary-74">Release Summary</a>
    - <a href="#minor-changes-32">Minor Changes</a>
    - <a href="#bugfixes-58">Bugfixes</a>
- <a href="#v1-7-0">v1\.7\.0</a>
    - <a href="#release-summary-75">Release Summary</a>
    - <a href="#minor-changes-33">Minor Changes</a>
- <a href="#v1-6-1">v1\.6\.1</a>
    - <a href="#release-summary-76">Release Summary</a>
    - <a href="#bugfixes-59">Bugfixes</a>
- <a href="#v1-6-0">v1\.6\.0</a>
    - <a href="#release-summary-77">Release Summary</a>
    - <a href="#minor-changes-34">Minor Changes</a>
    - <a href="#deprecated-features-8">Deprecated Features</a>
    - <a href="#bugfixes-60">Bugfixes</a>
- <a href="#v1-5-0">v1\.5\.0</a>
    - <a href="#release-summary-78">Release Summary</a>
    - <a href="#minor-changes-35">Minor Changes</a>
    - <a href="#bugfixes-61">Bugfixes</a>
    - <a href="#new-modules-5">New Modules</a>
- <a href="#v1-4-0">v1\.4\.0</a>
    - <a href="#release-summary-79">Release Summary</a>
    - <a href="#minor-changes-36">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-3">Breaking Changes / Porting Guide</a>
    - <a href="#security-fixes-2">Security Fixes</a>
    - <a href="#bugfixes-62">Bugfixes</a>
- <a href="#v1-3-0">v1\.3\.0</a>
    - <a href="#release-summary-80">Release Summary</a>
    - <a href="#minor-changes-37">Minor Changes</a>
    - <a href="#bugfixes-63">Bugfixes</a>
    - <a href="#new-modules-6">New Modules</a>
- <a href="#v1-2-2">v1\.2\.2</a>
    - <a href="#release-summary-81">Release Summary</a>
    - <a href="#security-fixes-3">Security Fixes</a>
- <a href="#v1-2-1">v1\.2\.1</a>
    - <a href="#release-summary-82">Release Summary</a>
    - <a href="#bugfixes-64">Bugfixes</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-83">Release Summary</a>
    - <a href="#minor-changes-38">Minor Changes</a>
    - <a href="#bugfixes-65">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-84">Release Summary</a>
    - <a href="#minor-changes-39">Minor Changes</a>
    - <a href="#deprecated-features-9">Deprecated Features</a>
    - <a href="#bugfixes-66">Bugfixes</a>
    - <a href="#new-plugins-1">New Plugins</a>
        - <a href="#connection-1">Connection</a>
        - <a href="#inventory">Inventory</a>
    - <a href="#new-modules-7">New Modules</a>
- <a href="#v1-0-1">v1\.0\.1</a>
    - <a href="#release-summary-85">Release Summary</a>
    - <a href="#bugfixes-67">Bugfixes</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-86">Release Summary</a>
    - <a href="#minor-changes-40">Minor Changes</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-87">Release Summary</a>
    - <a href="#minor-changes-41">Minor Changes</a>
    - <a href="#removed-features-previously-deprecated-3">Removed Features \(previously deprecated\)</a>
    - <a href="#bugfixes-68">Bugfixes</a>

<a id="v4-8-5"></a>
## v4\.8\.5

<a id="release-summary"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes"></a>
### Bugfixes

* CLI\-based modules \- when parsing JSON output fails\, also provide standard error output\. Also provide information on the command and its result in machine\-readable way \([https\://github\.com/ansible\-collections/community\.docker/issues/1216](https\://github\.com/ansible\-collections/community\.docker/issues/1216)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1221](https\://github\.com/ansible\-collections/community\.docker/pull/1221)\)\.
* docker\_compose\_v2\* modules \- fix Python 2 compatibility when parsing JSON events \([https\://github\.com/ansible\-collections/community\.docker/pull/1220](https\://github\.com/ansible\-collections/community\.docker/pull/1220)\)\.
* docker\_compose\_v2\, docker\_compose\_v2\_pull \- adjust parsing from image pull events to changes in Docker Compose 5\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1219](https\://github\.com/ansible\-collections/community\.docker/pull/1219)\)\.

<a id="v4-8-4"></a>
## v4\.8\.4

<a id="release-summary-1"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-1"></a>
### Bugfixes

* docker\_container \- when the same port is mapped more than once for the same protocol without specifying an interface\, a bug caused an invalid value to be passed for the interface \([https\://github\.com/ansible\-collections/community\.docker/issues/1213](https\://github\.com/ansible\-collections/community\.docker/issues/1213)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1214](https\://github\.com/ansible\-collections/community\.docker/pull/1214)\)\.

<a id="v4-8-3"></a>
## v4\.8\.3

<a id="release-summary-2"></a>
### Release Summary

Bugfix release for Docker 29\.

<a id="bugfixes-2"></a>
### Bugfixes

* Docker CLI based modules \- work around bug in Docker 29\.0\.0 that caused a breaking change in <code>docker version \-\-format json</code> output \([https\://github\.com/ansible\-collections/community\.docker/issues/1185](https\://github\.com/ansible\-collections/community\.docker/issues/1185)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1187](https\://github\.com/ansible\-collections/community\.docker/pull/1187)\)\.
* docker\_container \- fix <code>pull</code> idempotency with Docker 29\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1192](https\://github\.com/ansible\-collections/community\.docker/pull/1192)\)\.
* docker\_container \- fix handling of exposed port ranges\. So far\, the module used an undocumented feature of Docker that was removed from Docker 29\.0\.0\, that allowed to pass the range to the deamon and let handle it\. Now the module explodes ranges into a list of all contained ports\, same as the Docker CLI does\. For backwards compatibility with Docker \< 29\.0\.0\, it also explodes ranges returned by the API for existing containers so that comparison should only indicate a difference if the ranges actually change \([https\://github\.com/ansible\-collections/community\.docker/pull/1192](https\://github\.com/ansible\-collections/community\.docker/pull/1192)\)\.
* docker\_container \- fix idempotency for IPv6 addresses with Docker 29\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1192](https\://github\.com/ansible\-collections/community\.docker/pull/1192)\)\.
* docker\_image \- fix <code>source\=pull</code> idempotency with Docker 29\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1192](https\://github\.com/ansible\-collections/community\.docker/pull/1192)\)\.
* docker\_image\, docker\_image\_push \- adjust image push detection to Docker 29 \([https\://github\.com/ansible\-collections/community\.docker/pull/1199](https\://github\.com/ansible\-collections/community\.docker/pull/1199)\)\.
* docker\_image\_pull \- fix idempotency with Docker 29\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1192](https\://github\.com/ansible\-collections/community\.docker/pull/1192)\)\.
* docker\_network \- fix idempotency for IPv6 addresses and networks with Docker 29\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/1201](https\://github\.com/ansible\-collections/community\.docker/pull/1201)\)\.

<a id="known-issues"></a>
### Known Issues

* docker\_container \- when specifying IPv6 addresses for networks\, Docker since version 29 no longer returns the orignal address used when adding a container to a network\, but normalizes them\. The module will try to normalize IP addresses for comparison\, but it uses the <code>ipaddress</code> module from the Python 3 standard library for that\. When using the module with Python 2\, please install the [ipaddress backport for Python 2\.x](https\://pypi\.org/project/ipaddress/) \([https\://github\.com/ansible\-collections/community\.docker/pull/1198](https\://github\.com/ansible\-collections/community\.docker/pull/1198)\)\.
* docker\_image\, docker\_image\_export \- idempotency for archiving images depends on whether the image IDs used by the image storage backend correspond to the IDs used in the tarball\'s <code>manifest\.json</code> files\. The new default backend in Docker 29 apparently uses image IDs that no longer correspond\, whence idempotency no longer works \([https\://github\.com/ansible\-collections/community\.docker/pull/1199](https\://github\.com/ansible\-collections/community\.docker/pull/1199)\)\.
* docker\_network \- when specifying IPv6 addresses or networks\, Docker since version 29 no longer returns the orignal address/network used when creating a network\, but normalizes them\. The module will try to normalize IP addresses for comparison\, but it uses the <code>ipaddress</code> module from the Python 3 standard library for that\. When using the module with Python 2\, please install the [ipaddress backport for Python 2\.x](https\://pypi\.org/project/ipaddress/) \([https\://github\.com/ansible\-collections/community\.docker/pull/1203](https\://github\.com/ansible\-collections/community\.docker/pull/1203)\)\.

<a id="v4-8-2"></a>
## v4\.8\.2

<a id="release-summary-3"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-3"></a>
### Bugfixes

* docker connection plugin \- fix crash instead of warning if Docker version does not support <code>remote\_user</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1161](https\://github\.com/ansible\-collections/community\.docker/pull/1161)\)\.
* docker\, nsenter connection plugins \- fix handling of <code>become</code> plugin password prompt handling in case multiple events arrive at the same time \([https\://github\.com/ansible\-collections/community\.docker/pull/1158](https\://github\.com/ansible\-collections/community\.docker/pull/1158)\)\.
* docker\_api connection plugin \- fix bug that could lead to loss of data when waiting for <code>become</code> plugin prompt \([https\://github\.com/ansible\-collections/community\.docker/pull/1152](https\://github\.com/ansible\-collections/community\.docker/pull/1152)\)\.
* docker\_compose\_v2\_exec \- fix crash instead of reporting error if <code>detach\=true</code> and <code>stdin</code> is provided \([https\://github\.com/ansible\-collections/community\.docker/pull/1161](https\://github\.com/ansible\-collections/community\.docker/pull/1161)\)\.
* docker\_compose\_v2\_run \- fix crash instead of reporting error if <code>detach\=true</code> and <code>stdin</code> is provided \([https\://github\.com/ansible\-collections/community\.docker/pull/1161](https\://github\.com/ansible\-collections/community\.docker/pull/1161)\)\.
* docker\_container\_exec \- fix bug that could lead to loss of stdout/stderr data \([https\://github\.com/ansible\-collections/community\.docker/pull/1152](https\://github\.com/ansible\-collections/community\.docker/pull/1152)\)\.
* docker\_container\_exec \- make <code>detach\=true</code> work\. So far this resulted in no execution being done \([https\://github\.com/ansible\-collections/community\.docker/pull/1145](https\://github\.com/ansible\-collections/community\.docker/pull/1145)\)\.
* docker\_plugin \- fix diff mode for plugin options \([https\://github\.com/ansible\-collections/community\.docker/pull/1146](https\://github\.com/ansible\-collections/community\.docker/pull/1146)\)\.

<a id="v4-8-1"></a>
## v4\.8\.1

<a id="release-summary-4"></a>
### Release Summary

Maintenance release\.

<a id="minor-changes"></a>
### Minor Changes

* Note that some new code in <code>plugins/module\_utils/\_six\.py</code> is MIT licensed \([https\://github\.com/ansible\-collections/community\.docker/pull/1138](https\://github\.com/ansible\-collections/community\.docker/pull/1138)\)\.

<a id="bugfixes-4"></a>
### Bugfixes

* Avoid remaining usages of deprecated <code>ansible\.module\_utils\.six</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1133](https\://github\.com/ansible\-collections/community\.docker/pull/1133)\)\.
* Avoid usage of deprecated <code>ansible\.module\_utils\.six</code> in all code that does not have to support Python 2 \([https\://github\.com/ansible\-collections/community\.docker/pull/1137](https\://github\.com/ansible\-collections/community\.docker/pull/1137)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1139](https\://github\.com/ansible\-collections/community\.docker/pull/1139)\)\.
* Avoid usage of deprecated <code>ansible\.module\_utils\.six</code> in some of the code that still supports Python 2 \([https\://github\.com/ansible\-collections/community\.docker/pull/1138](https\://github\.com/ansible\-collections/community\.docker/pull/1138)\)\.

<a id="v4-8-0"></a>
## v4\.8\.0

<a id="release-summary-5"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-1"></a>
### Minor Changes

* docker\_container \- support missing fields and new mount types in <code>mounts</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/1129](https\://github\.com/ansible\-collections/community\.docker/issues/1129)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1134](https\://github\.com/ansible\-collections/community\.docker/pull/1134)\)\.

<a id="bugfixes-5"></a>
### Bugfixes

* Avoid deprecated functionality in ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.docker/pull/1117](https\://github\.com/ansible\-collections/community\.docker/pull/1117)\)\.

<a id="v4-7-0"></a>
## v4\.7\.0

<a id="release-summary-6"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-2"></a>
### Minor Changes

* docker\_swarm\_service \- add support for <code>replicated\-job</code> mode for Swarm services \([https\://github\.com/ansible\-collections/community\.docker/issues/626](https\://github\.com/ansible\-collections/community\.docker/issues/626)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1108](https\://github\.com/ansible\-collections/community\.docker/pull/1108)\)\.

<a id="bugfixes-6"></a>
### Bugfixes

* docker\_image\, docker\_image\_push \- work around a bug in Docker 28\.3\.3 that prevents pushing without authentication to a registry \([https\://github\.com/ansible\-collections/community\.docker/pull/1110](https\://github\.com/ansible\-collections/community\.docker/pull/1110)\)\.

<a id="v4-6-2"></a>
## v4\.6\.2

<a id="release-summary-7"></a>
### Release Summary

Bugfix release for Docker Compose 2\.39\.0\+\.

<a id="bugfixes-7"></a>
### Bugfixes

* docker\_compose\_v2 \- adjust to new dry\-run build events in Docker Compose 2\.39\.0\+ \([https\://github\.com/ansible\-collections/community\.docker/pull/1101](https\://github\.com/ansible\-collections/community\.docker/pull/1101)\)\.

<a id="v4-6-1"></a>
## v4\.6\.1

<a id="release-summary-8"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-8"></a>
### Bugfixes

* docker\_compose\_v2 \- handle a \(potentially unintentional\) breaking change in Docker Compose 2\.37\.0\. Note that <code>ContainerName</code> is no longer part of the return value \([https\://github\.com/ansible\-collections/community\.docker/issues/1082](https\://github\.com/ansible\-collections/community\.docker/issues/1082)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1083](https\://github\.com/ansible\-collections/community\.docker/pull/1083)\)\.
* docker\_container \- fix idempotency if <code>command\=\[\]</code> and <code>command\_handling\=correct</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/1080](https\://github\.com/ansible\-collections/community\.docker/issues/1080)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1085](https\://github\.com/ansible\-collections/community\.docker/pull/1085)\)\.

<a id="v4-6-0"></a>
## v4\.6\.0

<a id="release-summary-9"></a>
### Release Summary

Feature release\.

<a id="minor-changes-3"></a>
### Minor Changes

* docker\_container\_copy\_into \- add <code>mode\_parse</code> parameter which determines how <code>mode</code> is parsed \([https\://github\.com/ansible\-collections/community\.docker/pull/1074](https\://github\.com/ansible\-collections/community\.docker/pull/1074)\)\.

<a id="v4-5-2"></a>
## v4\.5\.2

<a id="release-summary-10"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-9"></a>
### Bugfixes

* docker\_compose\_v2 \- fix version check for <code>assume\_yes</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1054](https\://github\.com/ansible\-collections/community\.docker/pull/1054)\)\.
* docker\_compose\_v2 \- use <code>\-\-yes</code> instead of <code>\-y</code> from Docker Compose 2\.34\.0 on \([https\://github\.com/ansible\-collections/community\.docker/pull/1060](https\://github\.com/ansible\-collections/community\.docker/pull/1060)\)\.

<a id="v4-5-1"></a>
## v4\.5\.1

<a id="release-summary-11"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-10"></a>
### Bugfixes

* docker\_compose\_v2 \- rename flag for <code>assume\_yes</code> parameter for <code>docker compose up</code> to <code>\-y</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1054](https\://github\.com/ansible\-collections/community\.docker/pull/1054)\)\.

<a id="v4-5-0"></a>
## v4\.5\.0

<a id="release-summary-12"></a>
### Release Summary

Feature release\.

<a id="minor-changes-4"></a>
### Minor Changes

* docker\_compose\_v2 \- add <code>assume\_yes</code> parameter for <code>docker compose up</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1045](https\://github\.com/ansible\-collections/community\.docker/pull/1045)\)\.
* docker\_network \- add <code>enable\_ipv4</code> option \([https\://github\.com/ansible\-collections/community\.docker/issues/1047](https\://github\.com/ansible\-collections/community\.docker/issues/1047)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1049](https\://github\.com/ansible\-collections/community\.docker/pull/1049)\)\.

<a id="v4-4-0"></a>
## v4\.4\.0

<a id="release-summary-13"></a>
### Release Summary

Feature and bugfix release\.

<a id="bugfixes-11"></a>
### Bugfixes

* docker\_compose\_v2\_run \- the module has a conflict between the type of parameter it expects and the one it tries to sanitize\. Fix removes the label sanitization step because they are already validated by the parameter definition \([https\://github\.com/ansible\-collections/community\.docker/pull/1034](https\://github\.com/ansible\-collections/community\.docker/pull/1034)\)\.
* vendored Docker SDK for Python \- do not assume that <code>KeyError</code> is always for <code>ApiVersion</code> when querying version fails \([https\://github\.com/ansible\-collections/community\.docker/issues/1033](https\://github\.com/ansible\-collections/community\.docker/issues/1033)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1034](https\://github\.com/ansible\-collections/community\.docker/pull/1034)\)\.

<a id="new-modules"></a>
### New Modules

* community\.docker\.docker\_context\_info \- Retrieve information on Docker contexts for the current user\.

<a id="v4-3-1"></a>
## v4\.3\.1

<a id="release-summary-14"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-12"></a>
### Bugfixes

* Fix label sanitization code to avoid crashes in case of errors \([https\://github\.com/ansible\-collections/community\.docker/issues/1028](https\://github\.com/ansible\-collections/community\.docker/issues/1028)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1029](https\://github\.com/ansible\-collections/community\.docker/pull/1029)\)\.

<a id="v4-3-0"></a>
## v4\.3\.0

<a id="release-summary-15"></a>
### Release Summary

Feature release\.

<a id="minor-changes-5"></a>
### Minor Changes

* docker\_compose\_v2\* modules \- determine compose version with <code>docker compose version</code> and only then fall back to <code>docker info</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1021](https\://github\.com/ansible\-collections/community\.docker/pull/1021)\)\.

<a id="v4-2-0"></a>
## v4\.2\.0

<a id="release-summary-16"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-6"></a>
### Minor Changes

* docker\_compose\_v2 \- add <code>ignore\_build\_events</code> option \(default value <code>true</code>\) which allows to \(not\) ignore build events for change detection \([https\://github\.com/ansible\-collections/community\.docker/issues/1005](https\://github\.com/ansible\-collections/community\.docker/issues/1005)\, [https\://github\.com/ansible\-collections/community\.docker/issues/pull/1011](https\://github\.com/ansible\-collections/community\.docker/issues/pull/1011)\)\.
* docker\_image\_build \- <code>outputs\[\]\.name</code> can now be a list of strings \([https\://github\.com/ansible\-collections/community\.docker/pull/1006](https\://github\.com/ansible\-collections/community\.docker/pull/1006)\)\.
* docker\_image\_build \- the executed command is now returned in the <code>command</code> return value in case of success and some errors \([https\://github\.com/ansible\-collections/community\.docker/pull/1006](https\://github\.com/ansible\-collections/community\.docker/pull/1006)\)\.
* docker\_network \- added <code>ingress</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/999](https\://github\.com/ansible\-collections/community\.docker/pull/999)\)\.

<a id="bugfixes-13"></a>
### Bugfixes

* docker\_compose\_v2 \- when using Compose 2\.31\.0 or newer\, revert to the old behavior that image rebuilds\, for example if <code>rebuild\=always</code>\, only result in <code>changed</code> if a container has been restarted \([https\://github\.com/ansible\-collections/community\.docker/issues/1005](https\://github\.com/ansible\-collections/community\.docker/issues/1005)\, [https\://github\.com/ansible\-collections/community\.docker/issues/pull/1011](https\://github\.com/ansible\-collections/community\.docker/issues/pull/1011)\)\.
* docker\_image\_build \- work around bug resp\. very unexpected behavior in Docker buildx that overwrites all image names in <code>\-\-output</code> parameters if <code>\-\-tag</code> is provided\, which the module did by default in the past\. The module now only supplies <code>\-\-tag</code> if <code>outputs</code> is empty\. If <code>outputs</code> has entries\, it will add an additional entry with <code>type\=image</code> if no entry of <code>type\=image</code> contains the image name specified by the <code>name</code> and <code>tag</code> options \([https\://github\.com/ansible\-collections/community\.docker/issues/1001](https\://github\.com/ansible\-collections/community\.docker/issues/1001)\, [https\://github\.com/ansible\-collections/community\.docker/pull/1006](https\://github\.com/ansible\-collections/community\.docker/pull/1006)\)\.
* docker\_network \- added waiting while container actually disconnect from Swarm network \([https\://github\.com/ansible\-collections/community\.docker/pull/999](https\://github\.com/ansible\-collections/community\.docker/pull/999)\)\.
* docker\_network \- containers are only reconnected to a network if they really exist \([https\://github\.com/ansible\-collections/community\.docker/pull/999](https\://github\.com/ansible\-collections/community\.docker/pull/999)\)\.
* docker\_network \- enabled \"force\" option in Docker network container disconnect API call \([https\://github\.com/ansible\-collections/community\.docker/pull/999](https\://github\.com/ansible\-collections/community\.docker/pull/999)\)\.
* docker\_swarm\_info \- do not crash when finding Swarm jobs if <code>services\=true</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/1003](https\://github\.com/ansible\-collections/community\.docker/issues/1003)\)\.

<a id="v4-1-0"></a>
## v4\.1\.0

<a id="release-summary-17"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-7"></a>
### Minor Changes

* docker\_stack \- allow to add <code>\-\-detach\=false</code> option to <code>docker stack deploy</code> command \([https\://github\.com/ansible\-collections/community\.docker/pull/987](https\://github\.com/ansible\-collections/community\.docker/pull/987)\)\.

<a id="bugfixes-14"></a>
### Bugfixes

* docker\_compose\_v2\_exec\, docker\_compose\_v2\_run \- fix missing <code>\-\-env</code> flag while assembling env arguments \([https\://github\.com/ansible\-collections/community\.docker/pull/992](https\://github\.com/ansible\-collections/community\.docker/pull/992)\)\.
* docker\_host\_info \- ensure that the module always returns <code>can\_talk\_to\_docker</code>\, and that it provides the correct value even if <code>api\_version</code> is specified \([https\://github\.com/ansible\-collections/community\.docker/issues/993](https\://github\.com/ansible\-collections/community\.docker/issues/993)\, [https\://github\.com/ansible\-collections/community\.docker/pull/995](https\://github\.com/ansible\-collections/community\.docker/pull/995)\)\.

<a id="v4-0-1"></a>
## v4\.0\.1

<a id="release-summary-18"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-15"></a>
### Bugfixes

* docker\_compose\_v2\_run \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_config \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_network \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_node \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_secret \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_swarm \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_swarm\_service \- make sure to sanitize <code>labels</code> and <code>container\_labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.
* docker\_volume \- make sure to sanitize <code>labels</code> before sending them to the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/985](https\://github\.com/ansible\-collections/community\.docker/pull/985)\)\.

<a id="v4-0-0"></a>
## v4\.0\.0

<a id="release-summary-19"></a>
### Release Summary

Major release with removed deprecated features\.

<a id="minor-changes-8"></a>
### Minor Changes

* docker\_compose\_v2 \- add <code>renew\_anon\_volumes</code> parameter for <code>docker compose up</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/977](https\://github\.com/ansible\-collections/community\.docker/pull/977)\)\.

<a id="breaking-changes--porting-guide"></a>
### Breaking Changes / Porting Guide

* docker\_container \- the default of <code>image\_name\_mismatch</code> changed from <code>ignore</code> to <code>recreate</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The collection no longer supports ansible\-core 2\.11\, 2\.12\, 2\.13\, and 2\.14\. You need ansible\-core 2\.15\.0 or newer to use community\.docker 4\.x\.y \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.
* The docker\_compose module has been removed\. Please migrate to community\.docker\.docker\_compose\_v2 \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.
* docker\_container \- the <code>ignore\_image</code> option has been removed\. Use <code>image\: ignore</code> in <code>comparisons</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.
* docker\_container \- the <code>purge\_networks</code> option has been removed\. Use <code>networks\: strict</code> in <code>comparisons</code> instead and make sure that <code>networks</code> is specified \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.
* various modules and plugins \- remove the <code>ssl\_version</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/971](https\://github\.com/ansible\-collections/community\.docker/pull/971)\)\.

<a id="v3-13-1"></a>
## v3\.13\.1

<a id="release-summary-20"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-16"></a>
### Bugfixes

* docker\_compose\_v2 \- improve parsing of dry\-run image build operations from JSON events \([https\://github\.com/ansible\-collections/community\.docker/issues/975](https\://github\.com/ansible\-collections/community\.docker/issues/975)\, [https\://github\.com/ansible\-collections/community\.docker/pull/976](https\://github\.com/ansible\-collections/community\.docker/pull/976)\)\.

<a id="v3-13-0"></a>
## v3\.13\.0

<a id="release-summary-21"></a>
### Release Summary

Feature release\.

<a id="new-modules-1"></a>
### New Modules

* community\.docker\.docker\_compose\_v2\_exec \- Run command in a container of a Compose service\.
* community\.docker\.docker\_compose\_v2\_run \- Run command in a new container of a Compose service\.

<a id="v3-12-2"></a>
## v3\.12\.2

<a id="release-summary-22"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-17"></a>
### Bugfixes

* docker\_prune \- fix handling of lists for the filter options \([https\://github\.com/ansible\-collections/community\.docker/issues/961](https\://github\.com/ansible\-collections/community\.docker/issues/961)\, [https\://github\.com/ansible\-collections/community\.docker/pull/966](https\://github\.com/ansible\-collections/community\.docker/pull/966)\)\.

<a id="v3-12-1"></a>
## v3\.12\.1

<a id="release-summary-23"></a>
### Release Summary

Maintenance release with updated documentation and changelog\.

<a id="deprecated-features"></a>
### Deprecated Features

* The collection deprecates support for all ansible\-core versions that are currently End of Life\, [according to the ansible\-core support matrix](https\://docs\.ansible\.com/ansible\-core/devel/reference\_appendices/release\_and\_maintenance\.html\#ansible\-core\-support\-matrix)\. This means that the next major release of the collection will no longer support ansible\-core 2\.11\, ansible\-core 2\.12\, ansible\-core 2\.13\, and ansible\-core 2\.14\.

<a id="v3-12-0"></a>
## v3\.12\.0

<a id="release-summary-24"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-9"></a>
### Minor Changes

* docker\, docker\_api connection plugins \- allow to determine the working directory when executing commands with the new <code>working\_dir</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/943](https\://github\.com/ansible\-collections/community\.docker/pull/943)\)\.
* docker\, docker\_api connection plugins \- allow to execute commands with extended privileges with the new <code>privileges</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/943](https\://github\.com/ansible\-collections/community\.docker/pull/943)\)\.
* docker\, docker\_api connection plugins \- allow to pass extra environment variables when executing commands with the new <code>extra\_env</code> option \([https\://github\.com/ansible\-collections/community\.docker/issues/937](https\://github\.com/ansible\-collections/community\.docker/issues/937)\, [https\://github\.com/ansible\-collections/community\.docker/pull/940](https\://github\.com/ansible\-collections/community\.docker/pull/940)\)\.
* docker\_compose\_v2\* modules \- support Docker Compose 2\.29\.0\'s <code>json</code> progress writer to avoid having to parse text output \([https\://github\.com/ansible\-collections/community\.docker/pull/931](https\://github\.com/ansible\-collections/community\.docker/pull/931)\)\.
* docker\_compose\_v2\_pull \- add new options <code>ignore\_buildable</code>\, <code>include\_deps</code>\, and <code>services</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/941](https\://github\.com/ansible\-collections/community\.docker/issues/941)\, [https\://github\.com/ansible\-collections/community\.docker/pull/942](https\://github\.com/ansible\-collections/community\.docker/pull/942)\)\.
* docker\_container \- when creating a container\, directly pass all networks to connect to to the Docker Daemon for API version 1\.44 and newer\. This makes creation more efficient and works around a bug in Docker Daemon that does not use the specified MAC address in at least some cases\, though only for creation \([https\://github\.com/ansible\-collections/community\.docker/pull/933](https\://github\.com/ansible\-collections/community\.docker/pull/933)\)\.

<a id="bugfixes-18"></a>
### Bugfixes

* docker\_compose\_v2 \- handle yet another random unstructured error output from pre\-2\.29\.0 Compose versions \([https\://github\.com/ansible\-collections/community\.docker/issues/948](https\://github\.com/ansible\-collections/community\.docker/issues/948)\, [https\://github\.com/ansible\-collections/community\.docker/pull/949](https\://github\.com/ansible\-collections/community\.docker/pull/949)\)\.
* docker\_compose\_v2 \- make sure that services provided in <code>services</code> are appended to the command line after <code>\-\-</code> and not before it \([https\://github\.com/ansible\-collections/community\.docker/pull/942](https\://github\.com/ansible\-collections/community\.docker/pull/942)\)\.
* docker\_compose\_v2\* modules\, docker\_image\_build \- provide better error message when required fields are not present in <code>docker version</code> or <code>docker info</code> output\. This can happen if Podman is used instead of Docker \([https\://github\.com/ansible\-collections/community\.docker/issues/891](https\://github\.com/ansible\-collections/community\.docker/issues/891)\, [https\://github\.com/ansible\-collections/community\.docker/pull/935](https\://github\.com/ansible\-collections/community\.docker/pull/935)\)\.
* docker\_container \- fix idempotency if <code>network\_mode\=default</code> and Docker 26\.1\.0 or later is used\. There was a breaking change in Docker 26\.1\.0 regarding normalization of <code>NetworkMode</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/934](https\://github\.com/ansible\-collections/community\.docker/issues/934)\, [https\://github\.com/ansible\-collections/community\.docker/pull/936](https\://github\.com/ansible\-collections/community\.docker/pull/936)\)\.
* docker\_container \- restore behavior of the module from community\.docker 2\.x\.y that passes the first network to the Docker Deamon while creating the container \([https\://github\.com/ansible\-collections/community\.docker/pull/933](https\://github\.com/ansible\-collections/community\.docker/pull/933)\)\.
* docker\_image\_build \- fix <code>\-\-output</code> parameter composition for <code>type\=docker</code> and <code>type\=image</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/946](https\://github\.com/ansible\-collections/community\.docker/issues/946)\, [https\://github\.com/ansible\-collections/community\.docker/pull/947](https\://github\.com/ansible\-collections/community\.docker/pull/947)\)\.

<a id="known-issues-1"></a>
### Known Issues

* docker\_container \- when specifying a MAC address for a container\'s network\, and the network is attached after container creation \(for example\, due to idempotency checks\)\, the MAC address is at least in some cases ignored by the Docker Daemon \([https\://github\.com/ansible\-collections/community\.docker/pull/933](https\://github\.com/ansible\-collections/community\.docker/pull/933)\)\.

<a id="v3-11-0"></a>
## v3\.11\.0

<a id="minor-changes-10"></a>
### Minor Changes

* docker\_container \- add support for <code>device\_cgroup\_rules</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/910](https\://github\.com/ansible\-collections/community\.docker/pull/910)\)\.
* docker\_container \- the new <code>state\=healthy</code> allows to wait for a container to become healthy on startup\. The <code>healthy\_wait\_timeout</code> option allows to configure the maximum time to wait for this to happen \([https\://github\.com/ansible\-collections/community\.docker/issues/890](https\://github\.com/ansible\-collections/community\.docker/issues/890)\, [https\://github\.com/ansible\-collections/community\.docker/pull/921](https\://github\.com/ansible\-collections/community\.docker/pull/921)\)\.

<a id="bugfixes-19"></a>
### Bugfixes

* docker\_compose\_v2\* modules \- fix parsing of skipped pull messages for Docker Compose 2\.28\.x \([https\://github\.com/ansible\-collections/community\.docker/issues/911](https\://github\.com/ansible\-collections/community\.docker/issues/911)\, [https\://github\.com/ansible\-collections/community\.docker/pull/916](https\://github\.com/ansible\-collections/community\.docker/pull/916)\)\.
* docker\_compose\_v2\*\, docker\_stack\*\, docker\_image\_build modules \- using <code>cli\_context</code> no longer leads to an invalid parameter combination being passed to the corresponding Docker CLI tool\, unless <code>docker\_host</code> is also provided\. Combining <code>cli\_context</code> and <code>docker\_host</code> is no longer allowed \([https\://github\.com/ansible\-collections/community\.docker/issues/892](https\://github\.com/ansible\-collections/community\.docker/issues/892)\, [https\://github\.com/ansible\-collections/community\.docker/pull/895](https\://github\.com/ansible\-collections/community\.docker/pull/895)\)\.
* docker\_container \- fix possible infinite loop if <code>removal\_wait\_timeout</code> is set \([https\://github\.com/ansible\-collections/community\.docker/pull/922](https\://github\.com/ansible\-collections/community\.docker/pull/922)\)\.
* vendored Docker SDK for Python \- use <code>LooseVersion</code> instead of <code>StrictVersion</code> to compare urllib3 versions\. This is needed for development versions \([https\://github\.com/ansible\-collections/community\.docker/pull/902](https\://github\.com/ansible\-collections/community\.docker/pull/902)\)\.

<a id="v3-10-4"></a>
## v3\.10\.4

<a id="release-summary-25"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-20"></a>
### Bugfixes

* docker\_compose \- make sure that the module uses the <code>api\_version</code> parameter \([https\://github\.com/ansible\-collections/community\.docker/pull/881](https\://github\.com/ansible\-collections/community\.docker/pull/881)\)\.
* docker\_compose\_v2\* modules \- there was no check to make sure that one of <code>project\_src</code> and <code>definition</code> is provided\. The modules crashed if none were provided \([https\://github\.com/ansible\-collections/community\.docker/issues/885](https\://github\.com/ansible\-collections/community\.docker/issues/885)\, [https\://github\.com/ansible\-collections/community\.docker/pull/886](https\://github\.com/ansible\-collections/community\.docker/pull/886)\)\.

<a id="v3-10-3"></a>
## v3\.10\.3

<a id="release-summary-26"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-21"></a>
### Bugfixes

* docker and nsenter connection plugins\, docker\_container\_exec module \- avoid using the deprecated <code>ansible\.module\_utils\.compat\.selectors</code> module util with Python 3 \([https\://github\.com/ansible\-collections/community\.docker/issues/870](https\://github\.com/ansible\-collections/community\.docker/issues/870)\, [https\://github\.com/ansible\-collections/community\.docker/pull/871](https\://github\.com/ansible\-collections/community\.docker/pull/871)\)\.

<a id="v3-10-2"></a>
## v3\.10\.2

<a id="release-summary-27"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-22"></a>
### Bugfixes

* vendored Docker SDK for Python \- include a fix requests 2\.32\.2\+ compatibility \([https\://github\.com/ansible\-collections/community\.docker/issues/860](https\://github\.com/ansible\-collections/community\.docker/issues/860)\, [https\://github\.com/psf/requests/issues/6707](https\://github\.com/psf/requests/issues/6707)\, [https\://github\.com/ansible\-collections/community\.docker/pull/864](https\://github\.com/ansible\-collections/community\.docker/pull/864)\)\.

<a id="v3-10-1"></a>
## v3\.10\.1

<a id="release-summary-28"></a>
### Release Summary

Hotfix release for requests 2\.32\.0 compatibility\.

<a id="bugfixes-23"></a>
### Bugfixes

* vendored Docker SDK for Python \- include a hotfix for requests 2\.32\.0 compatibility \([https\://github\.com/ansible\-collections/community\.docker/issues/860](https\://github\.com/ansible\-collections/community\.docker/issues/860)\, [https\://github\.com/docker/docker\-py/issues/3256](https\://github\.com/docker/docker\-py/issues/3256)\, [https\://github\.com/ansible\-collections/community\.docker/pull/861](https\://github\.com/ansible\-collections/community\.docker/pull/861)\)\.

<a id="known-issues-2"></a>
### Known Issues

* Please note that the fix for requests 2\.32\.0 included in community\.docker 3\.10\.1 only
  fixes problems with the <em>vendored</em> Docker SDK for Python code\. Modules and plugins that
  use Docker SDK for Python can still fail due to the SDK currently being incompatible
  with requests 2\.32\.0\.

  If you still experience problems with requests 2\.32\.0\, such as error messages like
  <code>Not supported URL scheme http\+docker</code>\, please restrict requests to <code>\<2\.32\.0</code>\.

<a id="v3-10-0"></a>
## v3\.10\.0

<a id="release-summary-29"></a>
### Release Summary

Feature release\.

<a id="minor-changes-11"></a>
### Minor Changes

* docker\_container \- adds <code>healthcheck\.start\_interval</code> to support healthcheck start interval setting on containers \([https\://github\.com/ansible\-collections/community\.docker/pull/848](https\://github\.com/ansible\-collections/community\.docker/pull/848)\)\.
* docker\_container \- adds <code>healthcheck\.test\_cli\_compatible</code> to allow omit test option on containers without remove existing image test \([https\://github\.com/ansible\-collections/community\.docker/pull/847](https\://github\.com/ansible\-collections/community\.docker/pull/847)\)\.
* docker\_image\_build \- add <code>outputs</code> option to allow configuring outputs for the build \([https\://github\.com/ansible\-collections/community\.docker/pull/852](https\://github\.com/ansible\-collections/community\.docker/pull/852)\)\.
* docker\_image\_build \- add <code>secrets</code> option to allow passing secrets to the build \([https\://github\.com/ansible\-collections/community\.docker/pull/852](https\://github\.com/ansible\-collections/community\.docker/pull/852)\)\.
* docker\_image\_build \- allow <code>platform</code> to be a list of platforms instead of only a single platform for multi\-platform builds \([https\://github\.com/ansible\-collections/community\.docker/pull/852](https\://github\.com/ansible\-collections/community\.docker/pull/852)\)\.
* docker\_network \- adds <code>config\_only</code> and <code>config\_from</code> to support creating and using config only networks \([https\://github\.com/ansible\-collections/community\.docker/issues/395](https\://github\.com/ansible\-collections/community\.docker/issues/395)\)\.
* docker\_prune \- add new options <code>builder\_cache\_all</code>\, <code>builder\_cache\_filters</code>\, and <code>builder\_cache\_keep\_storage</code>\, and a new return value <code>builder\_cache\_caches\_deleted</code> for pruning build caches \([https\://github\.com/ansible\-collections/community\.docker/issues/844](https\://github\.com/ansible\-collections/community\.docker/issues/844)\, [https\://github\.com/ansible\-collections/community\.docker/issues/845](https\://github\.com/ansible\-collections/community\.docker/issues/845)\)\.
* docker\_swarm\_service \- adds <code>sysctls</code> to support sysctl settings on swarm services \([https\://github\.com/ansible\-collections/community\.docker/issues/190](https\://github\.com/ansible\-collections/community\.docker/issues/190)\)\.

<a id="deprecated-features-1"></a>
### Deprecated Features

* docker\_compose \- the Docker Compose v1 module is deprecated and will be removed from community\.docker 4\.0\.0\. Please migrate to the <code>community\.docker\.docker\_compose\_v2</code> module\, which works with Docker Compose v2 \([https\://github\.com/ansible\-collections/community\.docker/issues/823](https\://github\.com/ansible\-collections/community\.docker/issues/823)\, [https\://github\.com/ansible\-collections/community\.docker/pull/833](https\://github\.com/ansible\-collections/community\.docker/pull/833)\)\.
* various modules and plugins \- the <code>ssl\_version</code> option has been deprecated and will be removed from community\.docker 4\.0\.0\. It has already been removed from Docker SDK for Python 7\.0\.0\, and was only necessary in the past to work around SSL/TLS issues \([https\://github\.com/ansible\-collections/community\.docker/pull/853](https\://github\.com/ansible\-collections/community\.docker/pull/853)\)\.

<a id="v3-9-0"></a>
## v3\.9\.0

<a id="release-summary-30"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-12"></a>
### Minor Changes

* The EE requirements now include PyYAML\, since the <code>docker\_compose\_v2\*</code> modules depend on it when the <code>definition</code> option is used\. This should not have a noticable effect on generated EEs since ansible\-core itself depends on PyYAML as well\, and ansible\-builder explicitly ignores this dependency \([https\://github\.com/ansible\-collections/community\.docker/pull/832](https\://github\.com/ansible\-collections/community\.docker/pull/832)\)\.
* docker\_compose\_v2\* \- the new option <code>check\_files\_existing</code> allows to disable the check for one of the files <code>compose\.yaml</code>\, <code>compose\.yml</code>\, <code>docker\-compose\.yaml</code>\, and <code>docker\-compose\.yml</code> in <code>project\_src</code> if <code>files</code> is not specified\. This is necessary if a non\-standard compose filename is specified through other means\, like the <code>COMPOSE\_FILE</code> environment variable \([https\://github\.com/ansible\-collections/community\.docker/issues/838](https\://github\.com/ansible\-collections/community\.docker/issues/838)\, [https\://github\.com/ansible\-collections/community\.docker/pull/839](https\://github\.com/ansible\-collections/community\.docker/pull/839)\)\.
* docker\_compose\_v2\* modules \- allow to provide an inline definition of the compose content instead of having to provide a <code>project\_src</code> directory with the compose file written into it \([https\://github\.com/ansible\-collections/community\.docker/issues/829](https\://github\.com/ansible\-collections/community\.docker/issues/829)\, [https\://github\.com/ansible\-collections/community\.docker/pull/832](https\://github\.com/ansible\-collections/community\.docker/pull/832)\)\.
* vendored Docker SDK for Python \- remove unused code that relies on functionality deprecated in Python 3\.12 \([https\://github\.com/ansible\-collections/community\.docker/pull/834](https\://github\.com/ansible\-collections/community\.docker/pull/834)\)\.

<a id="bugfixes-24"></a>
### Bugfixes

* docker\_compose\_v2\* \- allow <code>project\_src</code> to be a relative path\, by converting it to an absolute path before using it \([https\://github\.com/ansible\-collections/community\.docker/issues/827](https\://github\.com/ansible\-collections/community\.docker/issues/827)\, [https\://github\.com/ansible\-collections/community\.docker/pull/828](https\://github\.com/ansible\-collections/community\.docker/pull/828)\)\.
* docker\_compose\_v2\* modules \- abort with a nice error message instead of crash when the Docker Compose CLI plugin version is <code>dev</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/825](https\://github\.com/ansible\-collections/community\.docker/issues/825)\, [https\://github\.com/ansible\-collections/community\.docker/pull/826](https\://github\.com/ansible\-collections/community\.docker/pull/826)\)\.
* inventory plugins \- add unsafe wrapper to avoid marking strings that do not contain <code>\{</code> or <code>\}</code> as unsafe\, to work around a bug in AWX \([https\://github\.com/ansible\-collections/community\.docker/pull/835](https\://github\.com/ansible\-collections/community\.docker/pull/835)\)\.

<a id="v3-8-1"></a>
## v3\.8\.1

<a id="release-summary-31"></a>
### Release Summary

Bugfix release

<a id="security-fixes"></a>
### Security Fixes

* docker\_containers\, docker\_machine\, and docker\_swarm inventory plugins \- make sure all data received from the Docker daemon / Docker machine is marked as unsafe\, so remote code execution by obtaining texts that can be evaluated as templates is not possible \([https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/](https\://www\.die\-welt\.net/2024/03/remote\-code\-execution\-in\-ansible\-dynamic\-inventory\-plugins/)\, [https\://github\.com/ansible\-collections/community\.docker/pull/815](https\://github\.com/ansible\-collections/community\.docker/pull/815)\)\.

<a id="bugfixes-25"></a>
### Bugfixes

* docker\_compose\_v2 \- do not fail when non\-fatal errors occur\. This can happen when pulling an image fails\, but then the image can be built for another service\. Docker Compose emits an error in that case\, but <code>docker compose up</code> still completes successfully \([https\://github\.com/ansible\-collections/community\.docker/issues/807](https\://github\.com/ansible\-collections/community\.docker/issues/807)\, [https\://github\.com/ansible\-collections/community\.docker/pull/810](https\://github\.com/ansible\-collections/community\.docker/pull/810)\, [https\://github\.com/ansible\-collections/community\.docker/pull/811](https\://github\.com/ansible\-collections/community\.docker/pull/811)\)\.
* docker\_compose\_v2\* modules \- correctly parse <code>Warning</code> events emitted by Docker Compose \([https\://github\.com/ansible\-collections/community\.docker/issues/807](https\://github\.com/ansible\-collections/community\.docker/issues/807)\, [https\://github\.com/ansible\-collections/community\.docker/pull/811](https\://github\.com/ansible\-collections/community\.docker/pull/811)\)\.
* docker\_compose\_v2\* modules \- parse <code>logfmt</code> warnings emitted by Docker Compose \([https\://github\.com/ansible\-collections/community\.docker/issues/787](https\://github\.com/ansible\-collections/community\.docker/issues/787)\, [https\://github\.com/ansible\-collections/community\.docker/pull/811](https\://github\.com/ansible\-collections/community\.docker/pull/811)\)\.
* docker\_compose\_v2\_pull \- fixing idempotence by checking actual pull progress events instead of service\-level pull request when <code>policy\=always</code>\. This stops the module from reporting <code>changed\=true</code> if no actual change happened when pulling\. In check mode\, it has to assume that a change happens though \([https\://github\.com/ansible\-collections/community\.docker/issues/813](https\://github\.com/ansible\-collections/community\.docker/issues/813)\, [https\://github\.com/ansible\-collections/community\.docker/pull/814](https\://github\.com/ansible\-collections/community\.docker/pull/814)\)\.

<a id="v3-8-0"></a>
## v3\.8\.0

<a id="release-summary-32"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-13"></a>
### Minor Changes

* docker\_compose\_v2 \- allow to wait until containers are running/health when running <code>docker compose up</code> with the new <code>wait</code> option \([https\://github\.com/ansible\-collections/community\.docker/issues/794](https\://github\.com/ansible\-collections/community\.docker/issues/794)\, [https\://github\.com/ansible\-collections/community\.docker/pull/796](https\://github\.com/ansible\-collections/community\.docker/pull/796)\)\.
* docker\_container \- the <code>pull\_check\_mode\_behavior</code> option now allows to control the module\'s behavior in check mode when <code>pull\=always</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/792](https\://github\.com/ansible\-collections/community\.docker/issues/792)\, [https\://github\.com/ansible\-collections/community\.docker/pull/797](https\://github\.com/ansible\-collections/community\.docker/pull/797)\)\.
* docker\_container \- the <code>pull</code> option now accepts the three values <code>never</code>\, <code>missing\_image</code> \(default\)\, and <code>never</code>\, next to the previously valid values <code>true</code> \(equivalent to <code>always</code>\) and <code>false</code> \(equivalent to <code>missing\_image</code>\)\. This allows the equivalent to <code>\-\-pull\=never</code> from the Docker command line \([https\://github\.com/ansible\-collections/community\.docker/issues/783](https\://github\.com/ansible\-collections/community\.docker/issues/783)\, [https\://github\.com/ansible\-collections/community\.docker/pull/797](https\://github\.com/ansible\-collections/community\.docker/pull/797)\)\.

<a id="bugfixes-26"></a>
### Bugfixes

* docker\_compose\_v2 \- do not consider a <code>Waiting</code> event as an action/change \([https\://github\.com/ansible\-collections/community\.docker/pull/804](https\://github\.com/ansible\-collections/community\.docker/pull/804)\)\.
* docker\_compose\_v2 \- do not treat service\-level pull events as changes to avoid incorrect <code>changed\=true</code> return value of <code>pull\=always</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/802](https\://github\.com/ansible\-collections/community\.docker/issues/802)\, [https\://github\.com/ansible\-collections/community\.docker/pull/803](https\://github\.com/ansible\-collections/community\.docker/pull/803)\)\.
* docker\_compose\_v2\, docker\_compose\_v2\_pull \- fix parsing of pull messages for Docker Compose 2\.20\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/785](https\://github\.com/ansible\-collections/community\.docker/issues/785)\, [https\://github\.com/ansible\-collections/community\.docker/pull/786](https\://github\.com/ansible\-collections/community\.docker/pull/786)\)\.

<a id="v3-7-0"></a>
## v3\.7\.0

<a id="release-summary-33"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-14"></a>
### Minor Changes

* docker\_compose\_v2 \- add <code>scale</code> option to allow to explicitly scale services \([https\://github\.com/ansible\-collections/community\.docker/pull/776](https\://github\.com/ansible\-collections/community\.docker/pull/776)\)\.
* docker\_compose\_v2\, docker\_compose\_v2\_pull \- support <code>files</code> parameter to specify multiple Compose files \([https\://github\.com/ansible\-collections/community\.docker/issues/772](https\://github\.com/ansible\-collections/community\.docker/issues/772)\, [https\://github\.com/ansible\-collections/community\.docker/pull/775](https\://github\.com/ansible\-collections/community\.docker/pull/775)\)\.

<a id="bugfixes-27"></a>
### Bugfixes

* docker\_compose\_v2 \- properly parse dry\-run build events from <code>stderr</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/778](https\://github\.com/ansible\-collections/community\.docker/issues/778)\, [https\://github\.com/ansible\-collections/community\.docker/pull/779](https\://github\.com/ansible\-collections/community\.docker/pull/779)\)\.
* docker\_compose\_v2\_pull \- the module was documented as part of the <code>community\.docker\.docker</code> action group\, but was not actually part of it\. That has now been fixed \([https\://github\.com/ansible\-collections/community\.docker/pull/773](https\://github\.com/ansible\-collections/community\.docker/pull/773)\)\.

<a id="new-modules-2"></a>
### New Modules

* community\.docker\.docker\_image\_export \- Export \(archive\) Docker images

<a id="v3-6-0"></a>
## v3\.6\.0

<a id="release-summary-34"></a>
### Release Summary

Bugfix and feature release\.

The collection now includes a bunch of new <code>docker\_image\_\*</code> modules that move features out of the
rather complex <code>docker\_image</code> module\. These new modules are easier to use and can better declare whether
they support check mode\, diff mode\, or none of them\.

This version also features modules that support the Docker CLI plugins <code>buildx</code> and <code>compose</code>\.
The <code>docker\_image\_build</code> module uses the <code>docker buildx</code> command under the hood\, and the <code>docker\_compose\_v2</code>
and <code>docker\_compose\_v2\_pull</code> modules uses the <code>docker compose</code> command\. All these modules use the Docker CLI
instead of directly talking to the API\. The modules support mostly the same interface as the API based modules\,
so the main difference is that instead of some Python requirements\, they depend on the Docker CLI tool <code>docker</code>\.

<a id="major-changes"></a>
### Major Changes

* The <code>community\.docker</code> collection now depends on the <code>community\.library\_inventory\_filtering\_v1</code> collection\. This utility collection provides host filtering functionality for inventory plugins\. If you use the Ansible community package\, both collections are included and you do not have to do anything special\. If you install the collection with <code>ansible\-galaxy collection install</code>\, it will be installed automatically\. If you install the collection by copying the files of the collection to a place where ansible\-core can find it\, for example by cloning the git repository\, you need to make sure that you also have to install the dependency if you are using the inventory plugins \([https\://github\.com/ansible\-collections/community\.docker/pull/698](https\://github\.com/ansible\-collections/community\.docker/pull/698)\)\.

<a id="minor-changes-15"></a>
### Minor Changes

* The <code>ca\_cert</code> option available to almost all modules and plugins has been renamed to <code>ca\_path</code>\. The name <code>ca\_path</code> is also used for similar options in ansible\-core and other collections\. The old name has been added as an alias and can still be used \([https\://github\.com/ansible\-collections/community\.docker/pull/744](https\://github\.com/ansible\-collections/community\.docker/pull/744)\)\.
* The <code>docker\_stack\*</code> modules now use the common CLI\-based module code added for the <code>docker\_image\_build</code> and <code>docker\_compose\_v2</code> modules\. This means that the modules now have various more configuration options with respect to talking to the Docker Daemon\, and now also are part of the <code>community\.docker\.docker</code> and <code>docker</code> module default groups \([https\://github\.com/ansible\-collections/community\.docker/pull/745](https\://github\.com/ansible\-collections/community\.docker/pull/745)\)\.
* docker\_container \- add <code>networks\[\]\.mac\_address</code> option for Docker API 1\.44\+\. Note that Docker API 1\.44 no longer uses the global <code>mac\_address</code> option\, this new option is the only way to set the MAC address for a container \([https\://github\.com/ansible\-collections/community\.docker/pull/763](https\://github\.com/ansible\-collections/community\.docker/pull/763)\)\.
* docker\_image \- allow to specify labels and <code>/dev/shm</code> size when building images \([https\://github\.com/ansible\-collections/community\.docker/issues/726](https\://github\.com/ansible\-collections/community\.docker/issues/726)\, [https\://github\.com/ansible\-collections/community\.docker/pull/727](https\://github\.com/ansible\-collections/community\.docker/pull/727)\)\.
* docker\_image \- allow to specify memory size and swap memory size in other units than bytes \([https\://github\.com/ansible\-collections/community\.docker/pull/727](https\://github\.com/ansible\-collections/community\.docker/pull/727)\)\.
* inventory plugins \- add <code>filter</code> option which allows to include and exclude hosts based on Jinja2 conditions \([https\://github\.com/ansible\-collections/community\.docker/pull/698](https\://github\.com/ansible\-collections/community\.docker/pull/698)\, [https\://github\.com/ansible\-collections/community\.docker/issues/610](https\://github\.com/ansible\-collections/community\.docker/issues/610)\)\.

<a id="bugfixes-28"></a>
### Bugfixes

* Use <code>unix\:///var/run/docker\.sock</code> instead of the legacy <code>unix\://var/run/docker\.sock</code> as default for <code>docker\_host</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/736](https\://github\.com/ansible\-collections/community\.docker/pull/736)\)\.
* docker\_image \- fix archiving idempotency with Docker API 1\.44 or later \([https\://github\.com/ansible\-collections/community\.docker/pull/765](https\://github\.com/ansible\-collections/community\.docker/pull/765)\)\.

<a id="new-modules-3"></a>
### New Modules

* community\.docker\.docker\_compose\_v2 \- Manage multi\-container Docker applications with Docker Compose CLI plugin
* community\.docker\.docker\_compose\_v2\_pull \- Pull a Docker compose project
* community\.docker\.docker\_image\_build \- Build Docker images using Docker buildx
* community\.docker\.docker\_image\_pull \- Pull Docker images from registries
* community\.docker\.docker\_image\_push \- Push Docker images to registries
* community\.docker\.docker\_image\_remove \- Remove Docker images
* community\.docker\.docker\_image\_tag \- Tag Docker images with new names and/or tags

<a id="v3-5-0"></a>
## v3\.5\.0

<a id="release-summary-35"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-16"></a>
### Minor Changes

* docker\_container \- implement better <code>platform</code> string comparisons to improve idempotency \([https\://github\.com/ansible\-collections/community\.docker/issues/654](https\://github\.com/ansible\-collections/community\.docker/issues/654)\, [https\://github\.com/ansible\-collections/community\.docker/pull/705](https\://github\.com/ansible\-collections/community\.docker/pull/705)\)\.
* docker\_container \- internal refactorings which allow comparisons to use more information like details of the current image or the Docker host config \([https\://github\.com/ansible\-collections/community\.docker/pull/713](https\://github\.com/ansible\-collections/community\.docker/pull/713)\)\.

<a id="deprecated-features-2"></a>
### Deprecated Features

* docker\_container \- the default <code>ignore</code> for the <code>image\_name\_mismatch</code> parameter has been deprecated and will switch to <code>recreate</code> in community\.docker 4\.0\.0\. A deprecation warning will be printed in situations where the default value is used and where a behavior would change once the default changes \([https\://github\.com/ansible\-collections/community\.docker/pull/703](https\://github\.com/ansible\-collections/community\.docker/pull/703)\)\.

<a id="bugfixes-29"></a>
### Bugfixes

* modules and plugins using the Docker SDK for Python \- remove <code>ssl\_version</code> from the parameters passed to Docker SDK for Python 7\.0\.0\+\. Explicitly fail with a nicer error message if it was explicitly set in this case \([https\://github\.com/ansible\-collections/community\.docker/pull/715](https\://github\.com/ansible\-collections/community\.docker/pull/715)\)\.
* modules and plugins using the Docker SDK for Python \- remove <code>tls\_hostname</code> from the parameters passed to Docker SDK for Python 7\.0\.0\+\. Explicitly fail with a nicer error message if it was explicitly set in this case \([https\://github\.com/ansible\-collections/community\.docker/pull/721](https\://github\.com/ansible\-collections/community\.docker/pull/721)\)\.
* vendored Docker SDK for Python \- avoid passing on <code>ssl\_version</code> and <code>tls\_hostname</code> if they were not provided by the user\. Remove dead code\. \([https\://github\.com/ansible\-collections/community\.docker/pull/722](https\://github\.com/ansible\-collections/community\.docker/pull/722)\)\.

<a id="v3-4-11"></a>
## v3\.4\.11

<a id="release-summary-36"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-30"></a>
### Bugfixes

* docker\_volume \- fix crash caused by accessing an empty dictionary\. The <code>has\_different\_config\(\)</code> was raising an <code>AttributeError</code> because the <code>self\.existing\_volume\[\"Labels\"\]</code> dictionary was <code>None</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/702](https\://github\.com/ansible\-collections/community\.docker/pull/702)\)\.

<a id="v3-4-10"></a>
## v3\.4\.10

<a id="release-summary-37"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-31"></a>
### Bugfixes

* docker\_swarm \- make init and join operations work again with Docker SDK for Python before 4\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/695](https\://github\.com/ansible\-collections/community\.docker/issues/695)\, [https\://github\.com/ansible\-collections/community\.docker/pull/696](https\://github\.com/ansible\-collections/community\.docker/pull/696)\)\.

<a id="v3-4-9"></a>
## v3\.4\.9

<a id="release-summary-38"></a>
### Release Summary

Maintenance release with updated documentation and vendored Docker SDK for Python code\.

<a id="bugfixes-32"></a>
### Bugfixes

* vendored Docker SDK for Python code \- cherry\-pick changes from the Docker SDK for Python code to align code\. These changes should not affect the parts used by the collection\'s code \([https\://github\.com/ansible\-collections/community\.docker/pull/694](https\://github\.com/ansible\-collections/community\.docker/pull/694)\)\.

<a id="v3-4-8"></a>
## v3\.4\.8

<a id="release-summary-39"></a>
### Release Summary

Maintenance release with updated documentation\.

From this version on\, community\.docker is using the new [Ansible semantic markup](https\://docs\.ansible\.com/ansible/devel/dev\_guide/developing\_modules\_documenting\.html\#semantic\-markup\-within\-module\-documentation)
in its documentation\. If you look at documentation with the ansible\-doc CLI tool
from ansible\-core before 2\.15\, please note that it does not render the markup
correctly\. You should be still able to read it in most cases\, but you need
ansible\-core 2\.15 or later to see it as it is intended\. Alternatively you can
look at [the devel docsite](https\://docs\.ansible\.com/ansible/devel/collections/community/docker/)
for the rendered HTML version of the documentation of the latest release\.

<a id="known-issues-3"></a>
### Known Issues

* Ansible markup will show up in raw form on ansible\-doc text output for ansible\-core before 2\.15\. If you have trouble deciphering the documentation markup\, please upgrade to ansible\-core 2\.15 \(or newer\)\, or read the HTML documentation on [https\://docs\.ansible\.com/ansible/devel/collections/community/docker/](https\://docs\.ansible\.com/ansible/devel/collections/community/docker/)\.

<a id="v3-4-7"></a>
## v3\.4\.7

<a id="release-summary-40"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-33"></a>
### Bugfixes

* docker\_swarm\_info \- if <code>service\=true</code> is used\, do not crash when a service without an endpoint spec is encountered \([https\://github\.com/ansible\-collections/community\.docker/issues/636](https\://github\.com/ansible\-collections/community\.docker/issues/636)\, [https\://github\.com/ansible\-collections/community\.docker/pull/637](https\://github\.com/ansible\-collections/community\.docker/pull/637)\)\.

<a id="v3-4-6"></a>
## v3\.4\.6

<a id="release-summary-41"></a>
### Release Summary

Bugfix release with documentation warnings about using certain functionality when connecting to the Docker daemon with TCP TLS\.

<a id="bugfixes-34"></a>
### Bugfixes

* socket\_handler module utils \- make sure this fully works when Docker SDK for Python is not available \([https\://github\.com/ansible\-collections/community\.docker/pull/620](https\://github\.com/ansible\-collections/community\.docker/pull/620)\)\.
* vendored Docker SDK for Python code \- fix for errors on pipe close in Windows \([https\://github\.com/ansible\-collections/community\.docker/pull/619](https\://github\.com/ansible\-collections/community\.docker/pull/619)\)\.
* vendored Docker SDK for Python code \- respect timeouts on Windows named pipes \([https\://github\.com/ansible\-collections/community\.docker/pull/619](https\://github\.com/ansible\-collections/community\.docker/pull/619)\)\.
* vendored Docker SDK for Python code \- use <code>poll\(\)</code> instead of <code>select\(\)</code> except on Windows \([https\://github\.com/ansible\-collections/community\.docker/pull/619](https\://github\.com/ansible\-collections/community\.docker/pull/619)\)\.

<a id="known-issues-4"></a>
### Known Issues

* docker\_api connection plugin \- does <strong>not work with TCP TLS sockets</strong>\! This is caused by the inability to send an <code>close\_notify</code> TLS alert without closing the connection with Python\'s <code>SSLSocket</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/605](https\://github\.com/ansible\-collections/community\.docker/issues/605)\, [https\://github\.com/ansible\-collections/community\.docker/pull/621](https\://github\.com/ansible\-collections/community\.docker/pull/621)\)\.
* docker\_container\_exec \- does <strong>not work with TCP TLS sockets</strong> when the <code>stdin</code> option is used\! This is caused by the inability to send an <code>close\_notify</code> TLS alert without closing the connection with Python\'s <code>SSLSocket</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/605](https\://github\.com/ansible\-collections/community\.docker/issues/605)\, [https\://github\.com/ansible\-collections/community\.docker/pull/621](https\://github\.com/ansible\-collections/community\.docker/pull/621)\)\.

<a id="v3-4-5"></a>
## v3\.4\.5

<a id="release-summary-42"></a>
### Release Summary

Maintenance release which adds compatibility with requests 2\.29\.0 and 2\.30\.0 and urllib3 2\.0\.

<a id="bugfixes-35"></a>
### Bugfixes

* Make vendored Docker SDK for Python code compatible with requests 2\.29\.0 and urllib3 2\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/613](https\://github\.com/ansible\-collections/community\.docker/pull/613)\)\.

<a id="v3-4-4"></a>
## v3\.4\.4

<a id="release-summary-43"></a>
### Release Summary

Maintenance release with updated EE requirements and updated documentation\.

<a id="minor-changes-17"></a>
### Minor Changes

* Restrict requests to versions before 2\.29\.0\, and urllib3 to versions before 2\.0\.0\. This is necessary until the vendored code from Docker SDK for Python has been fully adjusted to work with a feature of urllib3 that is used since requests 2\.29\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/611](https\://github\.com/ansible\-collections/community\.docker/issues/611)\, [https\://github\.com/ansible\-collections/community\.docker/pull/612](https\://github\.com/ansible\-collections/community\.docker/pull/612)\)\.

<a id="known-issues-5"></a>
### Known Issues

* The modules and plugins using the vendored code from Docker SDK for Python currently do not work with requests 2\.29\.0 and/or urllib3 2\.0\.0\. The same is currently true for the latest version of Docker SDK for Python itself \([https\://github\.com/ansible\-collections/community\.docker/issues/611](https\://github\.com/ansible\-collections/community\.docker/issues/611)\, [https\://github\.com/ansible\-collections/community\.docker/pull/612](https\://github\.com/ansible\-collections/community\.docker/pull/612)\)\.

<a id="v3-4-3"></a>
## v3\.4\.3

<a id="release-summary-44"></a>
### Release Summary

Maintenance release with improved documentation\.

<a id="v3-4-2"></a>
## v3\.4\.2

<a id="release-summary-45"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-36"></a>
### Bugfixes

* docker\_prune \- return correct value for <code>changed</code>\. So far the module always claimed that nothing changed \([https\://github\.com/ansible\-collections/community\.docker/pull/593](https\://github\.com/ansible\-collections/community\.docker/pull/593)\)\.

<a id="v3-4-1"></a>
## v3\.4\.1

<a id="release-summary-46"></a>
### Release Summary

Regular bugfix release\.

<a id="bugfixes-37"></a>
### Bugfixes

* docker\_api connection plugin\, docker\_container\_exec\, docker\_container\_copy\_into \- properly close socket to Daemon after executing commands in containers \([https\://github\.com/ansible\-collections/community\.docker/pull/582](https\://github\.com/ansible\-collections/community\.docker/pull/582)\)\.
* docker\_container \- fix <code>tmfs\_size</code> and <code>tmpfs\_mode</code> not being set \([https\://github\.com/ansible\-collections/community\.docker/pull/580](https\://github\.com/ansible\-collections/community\.docker/pull/580)\)\.
* various plugins and modules \- remove unnecessary imports \([https\://github\.com/ansible\-collections/community\.docker/pull/574](https\://github\.com/ansible\-collections/community\.docker/pull/574)\)\.

<a id="v3-4-0"></a>
## v3\.4\.0

<a id="release-summary-47"></a>
### Release Summary

Regular bugfix and feature release\.

<a id="minor-changes-18"></a>
### Minor Changes

* docker\_api connection plugin \- when copying files to/from a container\, stream the file contents instead of first reading them to memory \([https\://github\.com/ansible\-collections/community\.docker/pull/545](https\://github\.com/ansible\-collections/community\.docker/pull/545)\)\.
* docker\_host\_info \- allow to list all containers with new option <code>containers\_all</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/535](https\://github\.com/ansible\-collections/community\.docker/issues/535)\, [https\://github\.com/ansible\-collections/community\.docker/pull/538](https\://github\.com/ansible\-collections/community\.docker/pull/538)\)\.

<a id="bugfixes-38"></a>
### Bugfixes

* docker\_api connection plugin \- fix error handling when 409 Conflict is returned by the Docker daemon in case of a stopped container \([https\://github\.com/ansible\-collections/community\.docker/pull/546](https\://github\.com/ansible\-collections/community\.docker/pull/546)\)\.
* docker\_container\_exec \- fix error handling when 409 Conflict is returned by the Docker daemon in case of a stopped container \([https\://github\.com/ansible\-collections/community\.docker/pull/546](https\://github\.com/ansible\-collections/community\.docker/pull/546)\)\.
* docker\_plugin \- do not crash if plugin is installed in check mode \([https\://github\.com/ansible\-collections/community\.docker/issues/552](https\://github\.com/ansible\-collections/community\.docker/issues/552)\, [https\://github\.com/ansible\-collections/community\.docker/pull/553](https\://github\.com/ansible\-collections/community\.docker/pull/553)\)\.
* most modules \- fix handling of <code>DOCKER\_TIMEOUT</code> environment variable\, and improve handling of other fallback environment variables \([https\://github\.com/ansible\-collections/community\.docker/issues/551](https\://github\.com/ansible\-collections/community\.docker/issues/551)\, [https\://github\.com/ansible\-collections/community\.docker/pull/554](https\://github\.com/ansible\-collections/community\.docker/pull/554)\)\.

<a id="new-modules-4"></a>
### New Modules

* community\.docker\.docker\_container\_copy\_into \- Copy a file into a Docker container

<a id="v3-3-2"></a>
## v3\.3\.2

<a id="release-summary-48"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-39"></a>
### Bugfixes

* docker\_container \- when <code>detach\=false</code>\, wait indefinitely and not at most one minute\. This was the behavior with Docker SDK for Python\, and was accidentally changed in 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/526](https\://github\.com/ansible\-collections/community\.docker/issues/526)\, [https\://github\.com/ansible\-collections/community\.docker/pull/527](https\://github\.com/ansible\-collections/community\.docker/pull/527)\)\.

<a id="v3-3-1"></a>
## v3\.3\.1

<a id="release-summary-49"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-40"></a>
### Bugfixes

* current\_container\_facts \- make container detection work better in more cases \([https\://github\.com/ansible\-collections/community\.docker/pull/522](https\://github\.com/ansible\-collections/community\.docker/pull/522)\)\.

<a id="v3-3-0"></a>
## v3\.3\.0

<a id="release-summary-50"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-19"></a>
### Minor Changes

* current\_container\_facts \- make work with current Docker version\, also support Podman \([https\://github\.com/ansible\-collections/community\.docker/pull/510](https\://github\.com/ansible\-collections/community\.docker/pull/510)\)\.
* docker\_image \- when using <code>archive\_path</code>\, detect whether changes are necessary based on the image ID \(hash\)\. If the existing tar archive matches the source\, do nothing\. Previously\, each task execution re\-created the archive \([https\://github\.com/ansible\-collections/community\.docker/pull/500](https\://github\.com/ansible\-collections/community\.docker/pull/500)\)\.

<a id="bugfixes-41"></a>
### Bugfixes

* docker\_container\_exec \- fix <code>chdir</code> option which was ignored since community\.docker 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/517](https\://github\.com/ansible\-collections/community\.docker/issues/517)\, [https\://github\.com/ansible\-collections/community\.docker/pull/518](https\://github\.com/ansible\-collections/community\.docker/pull/518)\)\.
* vendored latest Docker SDK for Python bugfix \([https\://github\.com/ansible\-collections/community\.docker/pull/513](https\://github\.com/ansible\-collections/community\.docker/pull/513)\, [https\://github\.com/docker/docker\-py/issues/3045](https\://github\.com/docker/docker\-py/issues/3045)\)\.

<a id="v3-2-2"></a>
## v3\.2\.2

<a id="release-summary-51"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-42"></a>
### Bugfixes

* docker\_container \- the <code>kill\_signal</code> option erroneously did not accept strings anymore since 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/505](https\://github\.com/ansible\-collections/community\.docker/issues/505)\, [https\://github\.com/ansible\-collections/community\.docker/pull/506](https\://github\.com/ansible\-collections/community\.docker/pull/506)\)\.

<a id="v3-2-1"></a>
## v3\.2\.1

<a id="release-summary-52"></a>
### Release Summary

Maintenance release with improved documentation\.

<a id="v3-2-0"></a>
## v3\.2\.0

<a id="release-summary-53"></a>
### Release Summary

Feature and deprecation release\.

<a id="minor-changes-20"></a>
### Minor Changes

* docker\_container \- added <code>image\_name\_mismatch</code> option which allows to control the behavior if the container uses the image specified\, but the container\'s configuration uses a different name for the image than the one provided to the module \([https\://github\.com/ansible\-collections/community\.docker/issues/485](https\://github\.com/ansible\-collections/community\.docker/issues/485)\, [https\://github\.com/ansible\-collections/community\.docker/pull/488](https\://github\.com/ansible\-collections/community\.docker/pull/488)\)\.

<a id="deprecated-features-3"></a>
### Deprecated Features

* docker\_container \- the <code>ignore\_image</code> option is deprecated and will be removed in community\.docker 4\.0\.0\. Use <code>image\: ignore</code> in <code>comparisons</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/487](https\://github\.com/ansible\-collections/community\.docker/pull/487)\)\.
* docker\_container \- the <code>purge\_networks</code> option is deprecated and will be removed in community\.docker 4\.0\.0\. Use <code>networks\: strict</code> in <code>comparisons</code> instead\, and make sure to provide <code>networks</code>\, with value <code>\[\]</code> if all networks should be removed \([https\://github\.com/ansible\-collections/community\.docker/pull/487](https\://github\.com/ansible\-collections/community\.docker/pull/487)\)\.

<a id="v3-1-0"></a>
## v3\.1\.0

<a id="release-summary-54"></a>
### Release Summary

Feature release\.

<a id="minor-changes-21"></a>
### Minor Changes

* The collection repository conforms to the [REUSE specification](https\://reuse\.software/spec/) except for the changelog fragments \([https\://github\.com/ansible\-collections/community\.docker/pull/462](https\://github\.com/ansible\-collections/community\.docker/pull/462)\)\.
* docker\_swarm \- allows usage of the <code>data\_path\_port</code> parameter when initializing a swarm \([https\://github\.com/ansible\-collections/community\.docker/issues/296](https\://github\.com/ansible\-collections/community\.docker/issues/296)\)\.

<a id="v3-0-2"></a>
## v3\.0\.2

<a id="release-summary-55"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-43"></a>
### Bugfixes

* docker\_image \- fix build argument handling \([https\://github\.com/ansible\-collections/community\.docker/issues/455](https\://github\.com/ansible\-collections/community\.docker/issues/455)\, [https\://github\.com/ansible\-collections/community\.docker/pull/456](https\://github\.com/ansible\-collections/community\.docker/pull/456)\)\.

<a id="v3-0-1"></a>
## v3\.0\.1

<a id="release-summary-56"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-44"></a>
### Bugfixes

* docker\_container \- fix handling of <code>env\_file</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/451](https\://github\.com/ansible\-collections/community\.docker/issues/451)\, [https\://github\.com/ansible\-collections/community\.docker/pull/452](https\://github\.com/ansible\-collections/community\.docker/pull/452)\)\.

<a id="v3-0-0"></a>
## v3\.0\.0

<a id="release-summary-57"></a>
### Release Summary

The 3\.0\.0 release features a rewrite of the <code>docker\_container</code> module\, and many modules and plugins no longer depend on the Docker SDK for Python\.

<a id="major-changes-1"></a>
### Major Changes

* The collection now contains vendored code from the Docker SDK for Python to talk to the Docker daemon\. Modules and plugins using this code no longer need the Docker SDK for Python installed on the machine the module or plugin is running on \([https\://github\.com/ansible\-collections/community\.docker/pull/398](https\://github\.com/ansible\-collections/community\.docker/pull/398)\)\.
* docker\_api connection plugin \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/414](https\://github\.com/ansible\-collections/community\.docker/pull/414)\)\.
* docker\_container \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container \- the module was completely rewritten from scratch \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container\_exec \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/401](https\://github\.com/ansible\-collections/community\.docker/pull/401)\)\.
* docker\_container\_info \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/402](https\://github\.com/ansible\-collections/community\.docker/pull/402)\)\.
* docker\_containers inventory plugin \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/413](https\://github\.com/ansible\-collections/community\.docker/pull/413)\)\.
* docker\_host\_info \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/403](https\://github\.com/ansible\-collections/community\.docker/pull/403)\)\.
* docker\_image \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/404](https\://github\.com/ansible\-collections/community\.docker/pull/404)\)\.
* docker\_image\_info \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/405](https\://github\.com/ansible\-collections/community\.docker/pull/405)\)\.
* docker\_image\_load \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/406](https\://github\.com/ansible\-collections/community\.docker/pull/406)\)\.
* docker\_login \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/407](https\://github\.com/ansible\-collections/community\.docker/pull/407)\)\.
* docker\_network \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/408](https\://github\.com/ansible\-collections/community\.docker/pull/408)\)\.
* docker\_network\_info \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/409](https\://github\.com/ansible\-collections/community\.docker/pull/409)\)\.
* docker\_plugin \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/429](https\://github\.com/ansible\-collections/community\.docker/pull/429)\)\.
* docker\_prune \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/410](https\://github\.com/ansible\-collections/community\.docker/pull/410)\)\.
* docker\_volume \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/411](https\://github\.com/ansible\-collections/community\.docker/pull/411)\)\.
* docker\_volume\_info \- no longer uses the Docker SDK for Python\. It requires <code>requests</code> to be installed\, and depending on the features used has some more requirements\. If the Docker SDK for Python is installed\, these requirements are likely met \([https\://github\.com/ansible\-collections/community\.docker/pull/412](https\://github\.com/ansible\-collections/community\.docker/pull/412)\)\.

<a id="minor-changes-22"></a>
### Minor Changes

* All software licenses are now in the <code>LICENSES/</code> directory of the collection root\. Moreover\, <code>SPDX\-License\-Identifier\:</code> is used to declare the applicable license for every file that is not automatically generated \([https\://github\.com/ansible\-collections/community\.docker/pull/430](https\://github\.com/ansible\-collections/community\.docker/pull/430)\)\.
* Remove vendored copy of <code>distutils\.version</code> in favor of vendored copy included with ansible\-core 2\.12\+\. For ansible\-core 2\.11\, uses <code>distutils\.version</code> for Python \< 3\.12\. There is no support for ansible\-core 2\.11 with Python 3\.12\+ \([https\://github\.com/ansible\-collections/community\.docker/pull/271](https\://github\.com/ansible\-collections/community\.docker/pull/271)\)\.
* docker\_container \- add a new parameter <code>image\_comparison</code> to control the behavior for which image will be used for idempotency checks \([https\://github\.com/ansible\-collections/community\.docker/issues/421](https\://github\.com/ansible\-collections/community\.docker/issues/421)\, [https\://github\.com/ansible\-collections/community\.docker/pull/428](https\://github\.com/ansible\-collections/community\.docker/pull/428)\)\.
* docker\_container \- add support for <code>cgroupns\_mode</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/338](https\://github\.com/ansible\-collections/community\.docker/issues/338)\, [https\://github\.com/ansible\-collections/community\.docker/pull/427](https\://github\.com/ansible\-collections/community\.docker/pull/427)\)\.
* docker\_container \- allow to specify <code>platform</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/123](https\://github\.com/ansible\-collections/community\.docker/issues/123)\, [https\://github\.com/ansible\-collections/community\.docker/pull/426](https\://github\.com/ansible\-collections/community\.docker/pull/426)\)\.
* modules and plugins communicating directly with the Docker daemon \- improve default TLS version selection for Python 3\.6 and newer\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.
* modules and plugins communicating directly with the Docker daemon \- simplify use of helper function that was removed in Docker SDK for Python to find executables \([https\://github\.com/ansible\-collections/community\.docker/pull/438](https\://github\.com/ansible\-collections/community\.docker/pull/438)\)\.
* socker\_handler and socket\_helper module utils \- improve Python forward compatibility\, create helper functions for file blocking/unblocking \([https\://github\.com/ansible\-collections/community\.docker/pull/415](https\://github\.com/ansible\-collections/community\.docker/pull/415)\)\.

<a id="breaking-changes--porting-guide-1"></a>
### Breaking Changes / Porting Guide

* This collection does not work with ansible\-core 2\.11 on Python 3\.12\+\. Please either upgrade to ansible\-core 2\.12\+\, or use Python 3\.11 or earlier \([https\://github\.com/ansible\-collections/community\.docker/pull/271](https\://github\.com/ansible\-collections/community\.docker/pull/271)\)\.
* docker\_container \- <code>exposed\_ports</code> is no longer ignored in <code>comparisons</code>\. Before\, its value was assumed to be identical with the value of <code>published\_ports</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container \- <code>log\_options</code> can no longer be specified when <code>log\_driver</code> is not specified \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container \- <code>publish\_all\_ports</code> is no longer ignored in <code>comparisons</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container \- <code>restart\_retries</code> can no longer be specified when <code>restart\_policy</code> is not specified \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* docker\_container \- <code>stop\_timeout</code> is no longer ignored for idempotency if told to be not ignored in <code>comparisons</code>\. So far it defaulted to <code>ignore</code> there\, and setting it to <code>strict</code> had no effect \([https\://github\.com/ansible\-collections/community\.docker/pull/422](https\://github\.com/ansible\-collections/community\.docker/pull/422)\)\.
* modules and plugins communicating directly with the Docker daemon \- when connecting by SSH and not using <code>use\_ssh\_client\=true</code>\, reject unknown host keys instead of accepting them\. This is only a breaking change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.

<a id="removed-features-previously-deprecated-1"></a>
### Removed Features \(previously deprecated\)

* Execution Environments built with community\.docker no longer include docker\-compose \< 2\.0\.0\. If you need to use it with the <code>docker\_compose</code> module\, please install that requirement manually \([https\://github\.com/ansible\-collections/community\.docker/pull/400](https\://github\.com/ansible\-collections/community\.docker/pull/400)\)\.
* Support for Ansible 2\.9 and ansible\-base 2\.10 has been removed\. If you need support for Ansible 2\.9 or ansible\-base 2\.10\, please use community\.docker 2\.x\.y \([https\://github\.com/ansible\-collections/community\.docker/pull/400](https\://github\.com/ansible\-collections/community\.docker/pull/400)\)\.
* Support for Docker API versions 1\.20 to 1\.24 has been removed\. If you need support for these API versions\, please use community\.docker 2\.x\.y \([https\://github\.com/ansible\-collections/community\.docker/pull/400](https\://github\.com/ansible\-collections/community\.docker/pull/400)\)\.
* Support for Python 2\.6 has been removed\. If you need support for Python 2\.6\, please use community\.docker 2\.x\.y \([https\://github\.com/ansible\-collections/community\.docker/pull/400](https\://github\.com/ansible\-collections/community\.docker/pull/400)\)\.
* Various modules \- the default of <code>tls\_hostname</code> \(<code>localhost</code>\) has been removed\. If you want to continue using <code>localhost</code>\, you need to specify it explicitly \([https\://github\.com/ansible\-collections/community\.docker/pull/363](https\://github\.com/ansible\-collections/community\.docker/pull/363)\)\.
* docker\_container \- the <code>all</code> value is no longer allowed in <code>published\_ports</code>\. Use <code>publish\_all\_ports\=true</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/399](https\://github\.com/ansible\-collections/community\.docker/pull/399)\)\.
* docker\_container \- the default of <code>command\_handling</code> was changed from <code>compatibility</code> to <code>correct</code>\. Older versions were warning for every invocation of the module when this would result in a change of behavior \([https\://github\.com/ansible\-collections/community\.docker/pull/399](https\://github\.com/ansible\-collections/community\.docker/pull/399)\)\.
* docker\_stack \- the return values <code>out</code> and <code>err</code> have been removed\. Use <code>stdout</code> and <code>stderr</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/363](https\://github\.com/ansible\-collections/community\.docker/pull/363)\)\.

<a id="security-fixes-1"></a>
### Security Fixes

* modules and plugins communicating directly with the Docker daemon \- when connecting by SSH and not using <code>use\_ssh\_client\=true</code>\, reject unknown host keys instead of accepting them\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.

<a id="bugfixes-45"></a>
### Bugfixes

* docker\_image \- when composing the build context\, trim trailing whitespace from <code>\.dockerignore</code> entries\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.
* docker\_plugin \- fix crash when handling plugin options \([https\://github\.com/ansible\-collections/community\.docker/issues/446](https\://github\.com/ansible\-collections/community\.docker/issues/446)\, [https\://github\.com/ansible\-collections/community\.docker/pull/447](https\://github\.com/ansible\-collections/community\.docker/pull/447)\)\.
* docker\_stack \- fix broken string formatting when reporting error in case <code>compose</code> was containing invalid values \([https\://github\.com/ansible\-collections/community\.docker/pull/448](https\://github\.com/ansible\-collections/community\.docker/pull/448)\)\.
* modules and plugins communicating directly with the Docker daemon \- do not create a subshell for SSH connections when using <code>use\_ssh\_client\=true</code>\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.
* modules and plugins communicating directly with the Docker daemon \- fix <code>ProxyCommand</code> handling for SSH connections when not using <code>use\_ssh\_client\=true</code>\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.
* modules and plugins communicating directly with the Docker daemon \- fix parsing of IPv6 addresses with a port in <code>docker\_host</code>\. This is only a change relative to older community\.docker 3\.0\.0 pre\-releases or with respect to Docker SDK for Python \< 6\.0\.0\. Docker SDK for Python 6\.0\.0 will also include this change \([https\://github\.com/ansible\-collections/community\.docker/pull/434](https\://github\.com/ansible\-collections/community\.docker/pull/434)\)\.
* modules and plugins communicating directly with the Docker daemon \- prevent crash when TLS is used \([https\://github\.com/ansible\-collections/community\.docker/pull/432](https\://github\.com/ansible\-collections/community\.docker/pull/432)\)\.

<a id="v2-7-0"></a>
## v2\.7\.0

<a id="release-summary-58"></a>
### Release Summary

Bugfix and deprecation release\. The next 2\.x\.y releases will only be bugfix releases\, the next expect minor/major release will be 3\.0\.0 with some major changes\.

<a id="minor-changes-23"></a>
### Minor Changes

* Move common utility functions from the <code>common</code> module\_util to a new module\_util called <code>util</code>\. This should not have any user\-visible effect \([https\://github\.com/ansible\-collections/community\.docker/pull/390](https\://github\.com/ansible\-collections/community\.docker/pull/390)\)\.

<a id="deprecated-features-4"></a>
### Deprecated Features

* Support for Docker API version 1\.20 to 1\.24 has been deprecated and will be removed in community\.docker 3\.0\.0\. The first Docker version supporting API version 1\.25 was Docker 1\.13\, released in January 2017\. This affects the modules <code>docker\_container</code>\, <code>docker\_container\_exec</code>\, <code>docker\_container\_info</code>\, <code>docker\_compose</code>\, <code>docker\_login</code>\, <code>docker\_image</code>\, <code>docker\_image\_info</code>\, <code>docker\_image\_load</code>\, <code>docker\_host\_info</code>\, <code>docker\_network</code>\, <code>docker\_network\_info</code>\, <code>docker\_node\_info</code>\, <code>docker\_swarm\_info</code>\, <code>docker\_swarm\_service</code>\, <code>docker\_swarm\_service\_info</code>\, <code>docker\_volume\_info</code>\, and <code>docker\_volume</code>\, whose minimally supported API version is between 1\.20 and 1\.24 \([https\://github\.com/ansible\-collections/community\.docker/pull/396](https\://github\.com/ansible\-collections/community\.docker/pull/396)\)\.
* Support for Python 2\.6 is deprecated and will be removed in the next major release \(community\.docker 3\.0\.0\)\. Some modules might still work with Python 2\.6\, but we will no longer try to ensure compatibility \([https\://github\.com/ansible\-collections/community\.docker/pull/388](https\://github\.com/ansible\-collections/community\.docker/pull/388)\)\.

<a id="bugfixes-46"></a>
### Bugfixes

* Docker SDK for Python based modules and plugins \- if the API version is specified as an option\, use that one to validate API version requirements of module/plugin options instead of the latest API version supported by the Docker daemon\. This also avoids one unnecessary API call per module/plugin \([https\://github\.com/ansible\-collections/community\.docker/pull/389](https\://github\.com/ansible\-collections/community\.docker/pull/389)\)\.

<a id="v2-6-0"></a>
## v2\.6\.0

<a id="release-summary-59"></a>
### Release Summary

Bugfix and feature release\.

<a id="minor-changes-24"></a>
### Minor Changes

* docker\_container \- added <code>image\_label\_mismatch</code> parameter \([https\://github\.com/ansible\-collections/community\.docker/issues/314](https\://github\.com/ansible\-collections/community\.docker/issues/314)\, [https\://github\.com/ansible\-collections/community\.docker/pull/370](https\://github\.com/ansible\-collections/community\.docker/pull/370)\)\.

<a id="deprecated-features-5"></a>
### Deprecated Features

* Support for Ansible 2\.9 and ansible\-base 2\.10 is deprecated\, and will be removed in the next major release \(community\.docker 3\.0\.0\)\. Some modules might still work with these versions afterwards\, but we will no longer keep compatibility code that was needed to support them \([https\://github\.com/ansible\-collections/community\.docker/pull/361](https\://github\.com/ansible\-collections/community\.docker/pull/361)\)\.
* The dependency on docker\-compose for Execution Environments is deprecated and will be removed in community\.docker 3\.0\.0\. The [Python docker\-compose library](https\://pypi\.org/project/docker\-compose/) is unmaintained and can cause dependency issues\. You can manually still install it in an Execution Environment when needed \([https\://github\.com/ansible\-collections/community\.docker/pull/373](https\://github\.com/ansible\-collections/community\.docker/pull/373)\)\.
* Various modules \- the default of <code>tls\_hostname</code> that was supposed to be removed in community\.docker 2\.0\.0 will now be removed in version 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/362](https\://github\.com/ansible\-collections/community\.docker/pull/362)\)\.
* docker\_stack \- the return values <code>out</code> and <code>err</code> that were supposed to be removed in community\.docker 2\.0\.0 will now be removed in version 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/362](https\://github\.com/ansible\-collections/community\.docker/pull/362)\)\.

<a id="bugfixes-47"></a>
### Bugfixes

* docker\_container \- fail with a meaningful message instead of crashing if a port is specified with more than three colon\-separated parts \([https\://github\.com/ansible\-collections/community\.docker/pull/367](https\://github\.com/ansible\-collections/community\.docker/pull/367)\, [https\://github\.com/ansible\-collections/community\.docker/issues/365](https\://github\.com/ansible\-collections/community\.docker/issues/365)\)\.
* docker\_container \- remove unused code that will cause problems with Python 3\.13 \([https\://github\.com/ansible\-collections/community\.docker/pull/354](https\://github\.com/ansible\-collections/community\.docker/pull/354)\)\.

<a id="v2-5-1"></a>
## v2\.5\.1

<a id="release-summary-60"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-48"></a>
### Bugfixes

* Include <code>PSF\-license\.txt</code> file for <code>plugins/module\_utils/\_version\.py</code>\.

<a id="v2-5-0"></a>
## v2\.5\.0

<a id="release-summary-61"></a>
### Release Summary

Regular feature release\.

<a id="minor-changes-25"></a>
### Minor Changes

* docker\_config \- add support for <code>template\_driver</code> with one option <code>golang</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/332](https\://github\.com/ansible\-collections/community\.docker/issues/332)\, [https\://github\.com/ansible\-collections/community\.docker/pull/345](https\://github\.com/ansible\-collections/community\.docker/pull/345)\)\.
* docker\_swarm \- adds <code>data\_path\_addr</code> parameter during swarm initialization or when joining \([https\://github\.com/ansible\-collections/community\.docker/issues/339](https\://github\.com/ansible\-collections/community\.docker/issues/339)\)\.

<a id="v2-4-0"></a>
## v2\.4\.0

<a id="release-summary-62"></a>
### Release Summary

Regular feature and bugfix release\.

<a id="minor-changes-26"></a>
### Minor Changes

* Prepare collection for inclusion in an Execution Environment by declaring its dependencies\. The <code>docker\_stack\*</code> modules are not supported \([https\://github\.com/ansible\-collections/community\.docker/pull/336](https\://github\.com/ansible\-collections/community\.docker/pull/336)\)\.
* current\_container\_facts \- add detection for GitHub Actions \([https\://github\.com/ansible\-collections/community\.docker/pull/336](https\://github\.com/ansible\-collections/community\.docker/pull/336)\)\.
* docker\_container \- support returning Docker container log output when using Docker\'s <code>local</code> logging driver\, an optimized local logging driver introduced in Docker 18\.09 \([https\://github\.com/ansible\-collections/community\.docker/pull/337](https\://github\.com/ansible\-collections/community\.docker/pull/337)\)\.

<a id="bugfixes-49"></a>
### Bugfixes

* docker connection plugin \- make sure that <code>docker\_extra\_args</code> is used for querying the Docker version\. Also ensures that the Docker version is only queried when needed\. This is currently the case if a remote user is specified \([https\://github\.com/ansible\-collections/community\.docker/issues/325](https\://github\.com/ansible\-collections/community\.docker/issues/325)\, [https\://github\.com/ansible\-collections/community\.docker/pull/327](https\://github\.com/ansible\-collections/community\.docker/pull/327)\)\.

<a id="v2-3-0"></a>
## v2\.3\.0

<a id="release-summary-63"></a>
### Release Summary

Regular feature and bugfix release\.

<a id="minor-changes-27"></a>
### Minor Changes

* docker connection plugin \- implement connection reset by clearing internal container user cache \([https\://github\.com/ansible\-collections/community\.docker/pull/312](https\://github\.com/ansible\-collections/community\.docker/pull/312)\)\.
* docker connection plugin \- simplify <code>actual\_user</code> handling code \([https\://github\.com/ansible\-collections/community\.docker/pull/311](https\://github\.com/ansible\-collections/community\.docker/pull/311)\)\.
* docker connection plugin \- the plugin supports new ways to define the timeout\. These are the <code>ANSIBLE\_DOCKER\_TIMEOUT</code> environment variable\, the <code>timeout</code> setting in the <code>docker\_connection</code> section of <code>ansible\.cfg</code>\, and the <code>ansible\_docker\_timeout</code> variable \([https\://github\.com/ansible\-collections/community\.docker/pull/297](https\://github\.com/ansible\-collections/community\.docker/pull/297)\)\.
* docker\_api connection plugin \- implement connection reset by clearing internal container user/group ID cache \([https\://github\.com/ansible\-collections/community\.docker/pull/312](https\://github\.com/ansible\-collections/community\.docker/pull/312)\)\.
* docker\_api connection plugin \- the plugin supports new ways to define the timeout\. These are the <code>ANSIBLE\_DOCKER\_TIMEOUT</code> environment variable\, the <code>timeout</code> setting in the <code>docker\_connection</code> section of <code>ansible\.cfg</code>\, and the <code>ansible\_docker\_timeout</code> variable \([https\://github\.com/ansible\-collections/community\.docker/pull/308](https\://github\.com/ansible\-collections/community\.docker/pull/308)\)\.

<a id="bugfixes-50"></a>
### Bugfixes

* docker connection plugin \- fix option handling to be compatible with ansible\-core 2\.13 \([https\://github\.com/ansible\-collections/community\.docker/pull/297](https\://github\.com/ansible\-collections/community\.docker/pull/297)\, [https\://github\.com/ansible\-collections/community\.docker/issues/307](https\://github\.com/ansible\-collections/community\.docker/issues/307)\)\.
* docker\_api connection plugin \- fix option handling to be compatible with ansible\-core 2\.13 \([https\://github\.com/ansible\-collections/community\.docker/pull/308](https\://github\.com/ansible\-collections/community\.docker/pull/308)\)\.

<a id="v2-2-1"></a>
## v2\.2\.1

<a id="release-summary-64"></a>
### Release Summary

Regular bugfix release\.

<a id="bugfixes-51"></a>
### Bugfixes

* docker\_compose \- fix Python 3 type error when extracting warnings or errors from docker\-compose\'s output \([https\://github\.com/ansible\-collections/community\.docker/pull/305](https\://github\.com/ansible\-collections/community\.docker/pull/305)\)\.

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-65"></a>
### Release Summary

Regular feature and bugfix release\.

<a id="minor-changes-28"></a>
### Minor Changes

* docker\_config \- add support for rolling update\, set <code>rolling\_versions</code> to <code>true</code> to enable \([https\://github\.com/ansible\-collections/community\.docker/pull/295](https\://github\.com/ansible\-collections/community\.docker/pull/295)\, [https\://github\.com/ansible\-collections/community\.docker/issues/109](https\://github\.com/ansible\-collections/community\.docker/issues/109)\)\.
* docker\_secret \- add support for rolling update\, set <code>rolling\_versions</code> to <code>true</code> to enable \([https\://github\.com/ansible\-collections/community\.docker/pull/293](https\://github\.com/ansible\-collections/community\.docker/pull/293)\, [https\://github\.com/ansible\-collections/community\.docker/issues/21](https\://github\.com/ansible\-collections/community\.docker/issues/21)\)\.
* docker\_swarm\_service \- add support for setting capabilities with the <code>cap\_add</code> and <code>cap\_drop</code> parameters\. Usage is the same as with the <code>capabilities</code> and <code>cap\_drop</code> parameters for <code>docker\_container</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/294](https\://github\.com/ansible\-collections/community\.docker/pull/294)\)\.

<a id="bugfixes-52"></a>
### Bugfixes

* docker\_container\, docker\_image \- adjust image finding code to peculiarities of <code>podman\-docker</code>\'s API emulation when Docker short names like <code>redis</code> are used \([https\://github\.com/ansible\-collections/community\.docker/issues/292](https\://github\.com/ansible\-collections/community\.docker/issues/292)\)\.

<a id="v2-1-1"></a>
## v2\.1\.1

<a id="release-summary-66"></a>
### Release Summary

Emergency release to amend breaking change in previous release\.

<a id="bugfixes-53"></a>
### Bugfixes

* Fix unintended breaking change caused by [an earlier fix](https\://github\.com/ansible\-collections/community\.docker/pull/258) by vendoring the deprecated Python standard library <code>distutils\.version</code> until this collection stops supporting Ansible 2\.9 and ansible\-base 2\.10 \([https\://github\.com/ansible\-collections/community\.docker/issues/267](https\://github\.com/ansible\-collections/community\.docker/issues/267)\, [https\://github\.com/ansible\-collections/community\.docker/pull/269](https\://github\.com/ansible\-collections/community\.docker/pull/269)\)\.

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-67"></a>
### Release Summary

Feature and bugfix release\.

<a id="minor-changes-29"></a>
### Minor Changes

* docker\_container\_exec \- add <code>detach</code> parameter \([https\://github\.com/ansible\-collections/community\.docker/issues/250](https\://github\.com/ansible\-collections/community\.docker/issues/250)\, [https\://github\.com/ansible\-collections/community\.docker/pull/255](https\://github\.com/ansible\-collections/community\.docker/pull/255)\)\.
* docker\_container\_exec \- add <code>env</code> option \([https\://github\.com/ansible\-collections/community\.docker/issues/248](https\://github\.com/ansible\-collections/community\.docker/issues/248)\, [https\://github\.com/ansible\-collections/community\.docker/pull/254](https\://github\.com/ansible\-collections/community\.docker/pull/254)\)\.

<a id="bugfixes-54"></a>
### Bugfixes

* Various modules and plugins \- use vendored version of <code>distutils\.version</code> included in ansible\-core 2\.12 if available\. This avoids breakage when <code>distutils</code> is removed from the standard library of Python 3\.12\. Note that ansible\-core 2\.11\, ansible\-base 2\.10 and Ansible 2\.9 are right now not compatible with Python 3\.12\, hence this fix does not target these ansible\-core/\-base/2\.9 versions \([https\://github\.com/ansible\-collections/community\.docker/pull/258](https\://github\.com/ansible\-collections/community\.docker/pull/258)\)\.
* docker connection plugin \- replace deprecated <code>distutils\.spawn\.find\_executable</code> with Ansible\'s <code>get\_bin\_path</code> to find the <code>docker</code> executable \([https\://github\.com/ansible\-collections/community\.docker/pull/257](https\://github\.com/ansible\-collections/community\.docker/pull/257)\)\.
* docker\_container\_exec \- disallow using the <code>chdir</code> option for Docker API before 1\.35 \([https\://github\.com/ansible\-collections/community\.docker/pull/253](https\://github\.com/ansible\-collections/community\.docker/pull/253)\)\.

<a id="v2-0-2"></a>
## v2\.0\.2

<a id="release-summary-68"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-55"></a>
### Bugfixes

* docker\_api connection plugin \- avoid passing an unnecessary argument to a Docker SDK for Python call that is only supported by version 3\.0\.0 or later \([https\://github\.com/ansible\-collections/community\.docker/pull/243](https\://github\.com/ansible\-collections/community\.docker/pull/243)\)\.
* docker\_container\_exec \- <code>chdir</code> is only supported since Docker SDK for Python 3\.0\.0\. Make sure that this option can only use when 3\.0\.0 or later is installed\, and prevent passing this parameter on when <code>chdir</code> is not provided to this module \([https\://github\.com/ansible\-collections/community\.docker/pull/243](https\://github\.com/ansible\-collections/community\.docker/pull/243)\, [https\://github\.com/ansible\-collections/community\.docker/issues/242](https\://github\.com/ansible\-collections/community\.docker/issues/242)\)\.
* nsenter connection plugin \- ensure the <code>nsenter\_pid</code> option is retrieved in <code>\_connect</code> instead of <code>\_\_init\_\_</code> to prevent a crash due to bad initialization order \([https\://github\.com/ansible\-collections/community\.docker/pull/249](https\://github\.com/ansible\-collections/community\.docker/pull/249)\)\.
* nsenter connection plugin \- replace the use of <code>\-\-all\-namespaces</code> with specific namespaces to support compatibility with Busybox nsenter \(used on\, for example\, Alpine containers\) \([https\://github\.com/ansible\-collections/community\.docker/pull/249](https\://github\.com/ansible\-collections/community\.docker/pull/249)\)\.

<a id="v2-0-1"></a>
## v2\.0\.1

<a id="release-summary-69"></a>
### Release Summary

Maintenance release with some documentation fixes\.

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-70"></a>
### Release Summary

New major release with some deprecations removed and a breaking change in the <code>docker\_compose</code> module regarding the <code>timeout</code> parameter\.

<a id="breaking-changes--porting-guide-2"></a>
### Breaking Changes / Porting Guide

* docker\_compose \- fixed <code>timeout</code> defaulting behavior so that <code>stop\_grace\_period</code>\, if defined in the compose file\, will be used if <code>timeout</code> is not specified \([https\://github\.com/ansible\-collections/community\.docker/pull/163](https\://github\.com/ansible\-collections/community\.docker/pull/163)\)\.

<a id="deprecated-features-6"></a>
### Deprecated Features

* docker\_container \- using the special value <code>all</code> in <code>published\_ports</code> has been deprecated\. Use <code>publish\_all\_ports\=true</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/210](https\://github\.com/ansible\-collections/community\.docker/pull/210)\)\.

<a id="removed-features-previously-deprecated-2"></a>
### Removed Features \(previously deprecated\)

* docker\_container \- the default value of <code>container\_default\_behavior</code> changed to <code>no\_defaults</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/210](https\://github\.com/ansible\-collections/community\.docker/pull/210)\)\.
* docker\_container \- the default value of <code>network\_mode</code> is now the name of the first network specified in <code>networks</code> if such are specified and <code>networks\_cli\_compatible\=true</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/210](https\://github\.com/ansible\-collections/community\.docker/pull/210)\)\.
* docker\_container \- the special value <code>all</code> can no longer be used in <code>published\_ports</code> next to other values\. Please use <code>publish\_all\_ports\=true</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/210](https\://github\.com/ansible\-collections/community\.docker/pull/210)\)\.
* docker\_login \- removed the <code>email</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/210](https\://github\.com/ansible\-collections/community\.docker/pull/210)\)\.

<a id="v1-10-0"></a>
## v1\.10\.0

<a id="release-summary-71"></a>
### Release Summary

Regular feature and bugfix release\.

<a id="minor-changes-30"></a>
### Minor Changes

* Add the modules docker\_container\_exec\, docker\_image\_load and docker\_plugin to the <code>docker</code> module defaults group \([https\://github\.com/ansible\-collections/community\.docker/pull/209](https\://github\.com/ansible\-collections/community\.docker/pull/209)\)\.
* docker\_config \- add option <code>data\_src</code> to read configuration data from target \([https\://github\.com/ansible\-collections/community\.docker/issues/64](https\://github\.com/ansible\-collections/community\.docker/issues/64)\, [https\://github\.com/ansible\-collections/community\.docker/pull/203](https\://github\.com/ansible\-collections/community\.docker/pull/203)\)\.
* docker\_secret \- add option <code>data\_src</code> to read secret data from target \([https\://github\.com/ansible\-collections/community\.docker/issues/64](https\://github\.com/ansible\-collections/community\.docker/issues/64)\, [https\://github\.com/ansible\-collections/community\.docker/pull/203](https\://github\.com/ansible\-collections/community\.docker/pull/203)\)\.

<a id="v1-9-1"></a>
## v1\.9\.1

<a id="release-summary-72"></a>
### Release Summary

Regular bugfix release\.

<a id="bugfixes-56"></a>
### Bugfixes

* docker\_compose \- fixed incorrect <code>changed</code> status for services with <code>profiles</code> defined\, but none enabled \([https\://github\.com/ansible\-collections/community\.docker/pull/192](https\://github\.com/ansible\-collections/community\.docker/pull/192)\)\.

<a id="v1-9-0"></a>
## v1\.9\.0

<a id="release-summary-73"></a>
### Release Summary

New bugfixes and features release\.

<a id="minor-changes-31"></a>
### Minor Changes

* docker\_\* modules \- include <code>ImportError</code> traceback when reporting that Docker SDK for Python could not be found \([https\://github\.com/ansible\-collections/community\.docker/pull/188](https\://github\.com/ansible\-collections/community\.docker/pull/188)\)\.
* docker\_compose \- added <code>env\_file</code> option for specifying custom environment files \([https\://github\.com/ansible\-collections/community\.docker/pull/174](https\://github\.com/ansible\-collections/community\.docker/pull/174)\)\.
* docker\_container \- added <code>publish\_all\_ports</code> option to publish all exposed ports to random ports except those explicitly bound with <code>published\_ports</code> \(this was already added in community\.docker 1\.8\.0\) \([https\://github\.com/ansible\-collections/community\.docker/pull/162](https\://github\.com/ansible\-collections/community\.docker/pull/162)\)\.
* docker\_container \- added new <code>command\_handling</code> option with current deprecated default value <code>compatibility</code> which allows to control how the module handles shell quoting when interpreting lists\, and how the module handles empty lists/strings\. The default will switch to <code>correct</code> in community\.docker 3\.0\.0 \([https\://github\.com/ansible\-collections/community\.docker/pull/186](https\://github\.com/ansible\-collections/community\.docker/pull/186)\)\.
* docker\_container \- lifted restriction preventing the creation of anonymous volumes with the <code>mounts</code> option \([https\://github\.com/ansible\-collections/community\.docker/pull/181](https\://github\.com/ansible\-collections/community\.docker/pull/181)\)\.

<a id="deprecated-features-7"></a>
### Deprecated Features

* docker\_container \- the new <code>command\_handling</code>\'s default value\, <code>compatibility</code>\, is deprecated and will change to <code>correct</code> in community\.docker 3\.0\.0\. A deprecation warning is emitted by the module in cases where the behavior will change\. Please note that ansible\-core will output a deprecation warning only once\, so if it is shown for an earlier task\, there could be more tasks with this warning where it is not shown \([https\://github\.com/ansible\-collections/community\.docker/pull/186](https\://github\.com/ansible\-collections/community\.docker/pull/186)\)\.

<a id="bugfixes-57"></a>
### Bugfixes

* docker\_compose \- fixes task failures when bringing up services while using <code>docker\-compose \<1\.17\.0</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/180](https\://github\.com/ansible\-collections/community\.docker/issues/180)\)\.
* docker\_container \- make sure to also return <code>container</code> on <code>detached\=false</code> when status code is non\-zero \([https\://github\.com/ansible\-collections/community\.docker/pull/178](https\://github\.com/ansible\-collections/community\.docker/pull/178)\)\.
* docker\_stack\_info \- make sure that module isn\'t skipped in check mode \([https\://github\.com/ansible\-collections/community\.docker/pull/183](https\://github\.com/ansible\-collections/community\.docker/pull/183)\)\.
* docker\_stack\_task\_info \- make sure that module isn\'t skipped in check mode \([https\://github\.com/ansible\-collections/community\.docker/pull/183](https\://github\.com/ansible\-collections/community\.docker/pull/183)\)\.

<a id="new-plugins"></a>
### New Plugins

<a id="connection"></a>
#### Connection

* community\.docker\.nsenter \- execute on host running controller container

<a id="v1-8-0"></a>
## v1\.8\.0

<a id="release-summary-74"></a>
### Release Summary

Regular bugfix and feature release\.

<a id="minor-changes-32"></a>
### Minor Changes

* Avoid internal ansible\-core module\_utils in favor of equivalent public API available since at least Ansible 2\.9 \([https\://github\.com/ansible\-collections/community\.docker/pull/164](https\://github\.com/ansible\-collections/community\.docker/pull/164)\)\.
* docker\_compose \- added <code>profiles</code> option to specify service profiles when starting services \([https\://github\.com/ansible\-collections/community\.docker/pull/167](https\://github\.com/ansible\-collections/community\.docker/pull/167)\)\.
* docker\_containers inventory plugin \- when <code>connection\_type\=docker\-api</code>\, now pass Docker daemon connection options from inventory plugin to connection plugin\. This can be disabled by setting <code>configure\_docker\_daemon\=false</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/157](https\://github\.com/ansible\-collections/community\.docker/pull/157)\)\.
* docker\_host\_info \- allow values for keys in <code>containers\_filters</code>\, <code>images\_filters</code>\, <code>networks\_filters</code>\, and <code>volumes\_filters</code> to be passed as YAML lists \([https\://github\.com/ansible\-collections/community\.docker/pull/160](https\://github\.com/ansible\-collections/community\.docker/pull/160)\)\.
* docker\_plugin \- added <code>alias</code> option to specify local names for docker plugins \([https\://github\.com/ansible\-collections/community\.docker/pull/161](https\://github\.com/ansible\-collections/community\.docker/pull/161)\)\.

<a id="bugfixes-58"></a>
### Bugfixes

* docker\_compose \- fix idempotence bug when using <code>stopped\: true</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/142](https\://github\.com/ansible\-collections/community\.docker/issues/142)\, [https\://github\.com/ansible\-collections/community\.docker/pull/159](https\://github\.com/ansible\-collections/community\.docker/pull/159)\)\.

<a id="v1-7-0"></a>
## v1\.7\.0

<a id="release-summary-75"></a>
### Release Summary

Small feature and bugfix release\.

<a id="minor-changes-33"></a>
### Minor Changes

* docker\_image \- allow to tag images by ID \([https\://github\.com/ansible\-collections/community\.docker/pull/149](https\://github\.com/ansible\-collections/community\.docker/pull/149)\)\.

<a id="v1-6-1"></a>
## v1\.6\.1

<a id="release-summary-76"></a>
### Release Summary

Bugfix release to reduce deprecation warning spam\.

<a id="bugfixes-59"></a>
### Bugfixes

* docker\_\* modules and plugins\, except <code>docker\_swarm</code> connection plugin and <code>docker\_compose</code> and <code>docker\_stack\*\` modules \- only emit \`\`tls\_hostname</code> deprecation message if TLS is actually used \([https\://github\.com/ansible\-collections/community\.docker/pull/143](https\://github\.com/ansible\-collections/community\.docker/pull/143)\)\.

<a id="v1-6-0"></a>
## v1\.6\.0

<a id="release-summary-77"></a>
### Release Summary

Regular bugfix and feature release\.

<a id="minor-changes-34"></a>
### Minor Changes

* common module utils \- correct error messages for guiding to install proper Docker SDK for Python module \([https\://github\.com/ansible\-collections/community\.docker/pull/125](https\://github\.com/ansible\-collections/community\.docker/pull/125)\)\.
* docker\_container \- allow <code>memory\_swap\: \-1</code> to set memory swap limit to unlimited\. This is useful when the user cannot set memory swap limits due to cgroup limitations or other reasons\, as by default Docker will try to set swap usage to two times the value of <code>memory</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/138](https\://github\.com/ansible\-collections/community\.docker/pull/138)\)\.

<a id="deprecated-features-8"></a>
### Deprecated Features

* docker\_\* modules and plugins\, except <code>docker\_swarm</code> connection plugin and <code>docker\_compose</code> and <code>docker\_stack\*\` modules \- the current default \`\`localhost</code> for <code>tls\_hostname</code> is deprecated\. In community\.docker 2\.0\.0 it will be computed from <code>docker\_host</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/134](https\://github\.com/ansible\-collections/community\.docker/pull/134)\)\.

<a id="bugfixes-60"></a>
### Bugfixes

* docker\-compose \- fix not pulling when <code>state\: present</code> and <code>stopped\: true</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/12](https\://github\.com/ansible\-collections/community\.docker/issues/12)\, [https\://github\.com/ansible\-collections/community\.docker/pull/119](https\://github\.com/ansible\-collections/community\.docker/pull/119)\)\.
* docker\_plugin \- also configure plugin after installing \([https\://github\.com/ansible\-collections/community\.docker/issues/118](https\://github\.com/ansible\-collections/community\.docker/issues/118)\, [https\://github\.com/ansible\-collections/community\.docker/pull/135](https\://github\.com/ansible\-collections/community\.docker/pull/135)\)\.
* docker\_swarm\_services \- avoid crash during idempotence check if <code>published\_port</code> is not specified \([https\://github\.com/ansible\-collections/community\.docker/issues/107](https\://github\.com/ansible\-collections/community\.docker/issues/107)\, [https\://github\.com/ansible\-collections/community\.docker/pull/136](https\://github\.com/ansible\-collections/community\.docker/pull/136)\)\.

<a id="v1-5-0"></a>
## v1\.5\.0

<a id="release-summary-78"></a>
### Release Summary

Regular feature release\.

<a id="minor-changes-35"></a>
### Minor Changes

* Add the <code>use\_ssh\_client</code> option to most docker modules and plugins \([https\://github\.com/ansible\-collections/community\.docker/issues/108](https\://github\.com/ansible\-collections/community\.docker/issues/108)\, [https\://github\.com/ansible\-collections/community\.docker/pull/114](https\://github\.com/ansible\-collections/community\.docker/pull/114)\)\.

<a id="bugfixes-61"></a>
### Bugfixes

* all modules \- use <code>to\_native</code> to convert exceptions to strings \([https\://github\.com/ansible\-collections/community\.docker/pull/121](https\://github\.com/ansible\-collections/community\.docker/pull/121)\)\.

<a id="new-modules-5"></a>
### New Modules

* community\.docker\.docker\_container\_exec \- Execute command in a docker container

<a id="v1-4-0"></a>
## v1\.4\.0

<a id="release-summary-79"></a>
### Release Summary

Security release to address another potential secret leak\. Also includes regular bugfixes and features\.

<a id="minor-changes-36"></a>
### Minor Changes

* docker\_swarm\_service \- change <code>publish\.published\_port</code> option from mandatory to optional\. Docker will assign random high port if not specified \([https\://github\.com/ansible\-collections/community\.docker/issues/99](https\://github\.com/ansible\-collections/community\.docker/issues/99)\)\.

<a id="breaking-changes--porting-guide-3"></a>
### Breaking Changes / Porting Guide

* docker\_swarm \- if <code>join\_token</code> is specified\, a returned join token with the same value will be replaced by <code>VALUE\_SPECIFIED\_IN\_NO\_LOG\_PARAMETER</code>\. Make sure that you do not blindly use the join tokens from the return value of this module when the module is invoked with <code>join\_token</code> specified\! This breaking change appears in a minor release since it is necessary to fix a security issue \([https\://github\.com/ansible\-collections/community\.docker/pull/103](https\://github\.com/ansible\-collections/community\.docker/pull/103)\)\.

<a id="security-fixes-2"></a>
### Security Fixes

* docker\_swarm \- the <code>join\_token</code> option is now marked as <code>no\_log</code> so it is no longer written into logs \([https\://github\.com/ansible\-collections/community\.docker/pull/103](https\://github\.com/ansible\-collections/community\.docker/pull/103)\)\.

<a id="bugfixes-62"></a>
### Bugfixes

* <code>docker\_swarm\_service</code> \- fix KeyError on caused by reference to deprecated option <code>update\_failure\_action</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/100](https\://github\.com/ansible\-collections/community\.docker/pull/100)\)\.
* docker\_swarm\_service \- mark <code>secrets</code> module option with <code>no\_log\=False</code> since it does not leak secrets \([https\://github\.com/ansible\-collections/community\.general/pull/2001](https\://github\.com/ansible\-collections/community\.general/pull/2001)\)\.

<a id="v1-3-0"></a>
## v1\.3\.0

<a id="release-summary-80"></a>
### Release Summary

Regular feature and bugfix release\.

<a id="minor-changes-37"></a>
### Minor Changes

* docker\_container \- add <code>storage\_opts</code> option to specify storage options \([https\://github\.com/ansible\-collections/community\.docker/issues/91](https\://github\.com/ansible\-collections/community\.docker/issues/91)\, [https\://github\.com/ansible\-collections/community\.docker/pull/93](https\://github\.com/ansible\-collections/community\.docker/pull/93)\)\.
* docker\_image \- allows to specify platform to pull for <code>source\=pull</code> with new option <code>pull\_platform</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/79](https\://github\.com/ansible\-collections/community\.docker/issues/79)\, [https\://github\.com/ansible\-collections/community\.docker/pull/89](https\://github\.com/ansible\-collections/community\.docker/pull/89)\)\.
* docker\_image \- properly support image IDs \(hashes\) for loading and tagging images \([https\://github\.com/ansible\-collections/community\.docker/issues/86](https\://github\.com/ansible\-collections/community\.docker/issues/86)\, [https\://github\.com/ansible\-collections/community\.docker/pull/87](https\://github\.com/ansible\-collections/community\.docker/pull/87)\)\.
* docker\_swarm\_service \- adding support for maximum number of tasks per node \(<code>replicas\_max\_per\_node</code>\) when running swarm service in replicated mode\. Introduced in API 1\.40 \([https\://github\.com/ansible\-collections/community\.docker/issues/7](https\://github\.com/ansible\-collections/community\.docker/issues/7)\, [https\://github\.com/ansible\-collections/community\.docker/pull/92](https\://github\.com/ansible\-collections/community\.docker/pull/92)\)\.

<a id="bugfixes-63"></a>
### Bugfixes

* docker\_container \- fix healthcheck disabling idempotency issue with strict comparison \([https\://github\.com/ansible\-collections/community\.docker/issues/85](https\://github\.com/ansible\-collections/community\.docker/issues/85)\)\.
* docker\_image \- prevent module failure when removing image that is removed between inspection and removal \([https\://github\.com/ansible\-collections/community\.docker/pull/87](https\://github\.com/ansible\-collections/community\.docker/pull/87)\)\.
* docker\_image \- prevent module failure when removing non\-existent image by ID \([https\://github\.com/ansible\-collections/community\.docker/pull/87](https\://github\.com/ansible\-collections/community\.docker/pull/87)\)\.
* docker\_image\_info \- prevent module failure when image vanishes between listing and inspection \([https\://github\.com/ansible\-collections/community\.docker/pull/87](https\://github\.com/ansible\-collections/community\.docker/pull/87)\)\.
* docker\_image\_info \- prevent module failure when querying non\-existent image by ID \([https\://github\.com/ansible\-collections/community\.docker/pull/87](https\://github\.com/ansible\-collections/community\.docker/pull/87)\)\.

<a id="new-modules-6"></a>
### New Modules

* community\.docker\.docker\_image\_load \- Load docker image\(s\) from archives
* community\.docker\.docker\_plugin \- Manage Docker plugins

<a id="v1-2-2"></a>
## v1\.2\.2

<a id="release-summary-81"></a>
### Release Summary

Security bugfix release to address CVE\-2021\-20191\.

<a id="security-fixes-3"></a>
### Security Fixes

* docker\_swarm \- enabled <code>no\_log</code> for the option <code>signing\_ca\_key</code> to prevent accidental disclosure \(CVE\-2021\-20191\, [https\://github\.com/ansible\-collections/community\.docker/pull/80](https\://github\.com/ansible\-collections/community\.docker/pull/80)\)\.

<a id="v1-2-1"></a>
## v1\.2\.1

<a id="release-summary-82"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-64"></a>
### Bugfixes

* docker connection plugin \- fix Docker version parsing\, as some docker versions have a leading <code>v</code> in the output of the command <code>docker version \-\-format \"\{\{\.Server\.Version\}\}\"</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/76](https\://github\.com/ansible\-collections/community\.docker/pull/76)\)\.

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-83"></a>
### Release Summary

Feature release with one new feature and two bugfixes\.

<a id="minor-changes-38"></a>
### Minor Changes

* docker\_container \- added <code>default\_host\_ip</code> option which allows to explicitly set the default IP string for published ports without explicitly specified IPs\. When using IPv6 binds with Docker 20\.10\.2 or newer\, this needs to be set to an empty string \(<code>\"\"</code>\) \([https\://github\.com/ansible\-collections/community\.docker/issues/70](https\://github\.com/ansible\-collections/community\.docker/issues/70)\, [https\://github\.com/ansible\-collections/community\.docker/pull/71](https\://github\.com/ansible\-collections/community\.docker/pull/71)\)\.

<a id="bugfixes-65"></a>
### Bugfixes

* docker\_container \- allow IPv6 zones \(RFC 4007\) in bind IPs \([https\://github\.com/ansible\-collections/community\.docker/pull/66](https\://github\.com/ansible\-collections/community\.docker/pull/66)\)\.
* docker\_image \- fix crash on loading images with versions of Docker SDK for Python before 2\.5\.0 \([https\://github\.com/ansible\-collections/community\.docker/issues/72](https\://github\.com/ansible\-collections/community\.docker/issues/72)\, [https\://github\.com/ansible\-collections/community\.docker/pull/73](https\://github\.com/ansible\-collections/community\.docker/pull/73)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-84"></a>
### Release Summary

Feature release with three new plugins and modules\.

<a id="minor-changes-39"></a>
### Minor Changes

* docker\_container \- support specifying <code>cgroup\_parent</code> \([https\://github\.com/ansible\-collections/community\.docker/issues/6](https\://github\.com/ansible\-collections/community\.docker/issues/6)\, [https\://github\.com/ansible\-collections/community\.docker/pull/59](https\://github\.com/ansible\-collections/community\.docker/pull/59)\)\.
* docker\_container \- when a container is started with <code>detached\=false</code>\, <code>status</code> is now also returned when it is 0 \([https\://github\.com/ansible\-collections/community\.docker/issues/26](https\://github\.com/ansible\-collections/community\.docker/issues/26)\, [https\://github\.com/ansible\-collections/community\.docker/pull/58](https\://github\.com/ansible\-collections/community\.docker/pull/58)\)\.
* docker\_image \- support <code>platform</code> when building images \([https\://github\.com/ansible\-collections/community\.docker/issues/22](https\://github\.com/ansible\-collections/community\.docker/issues/22)\, [https\://github\.com/ansible\-collections/community\.docker/pull/54](https\://github\.com/ansible\-collections/community\.docker/pull/54)\)\.

<a id="deprecated-features-9"></a>
### Deprecated Features

* docker\_container \- currently <code>published\_ports</code> can contain port mappings next to the special value <code>all</code>\, in which case the port mappings are ignored\. This behavior is deprecated for community\.docker 2\.0\.0\, at which point it will either be forbidden\, or this behavior will be properly implemented similar to how the Docker CLI tool handles this \([https\://github\.com/ansible\-collections/community\.docker/issues/8](https\://github\.com/ansible\-collections/community\.docker/issues/8)\, [https\://github\.com/ansible\-collections/community\.docker/pull/60](https\://github\.com/ansible\-collections/community\.docker/pull/60)\)\.

<a id="bugfixes-66"></a>
### Bugfixes

* docker\_image \- if <code>push\=true</code> is used with <code>repository</code>\, and the image does not need to be tagged\, still push\. This can happen if <code>repository</code> and <code>name</code> are equal \([https\://github\.com/ansible\-collections/community\.docker/issues/52](https\://github\.com/ansible\-collections/community\.docker/issues/52)\, [https\://github\.com/ansible\-collections/community\.docker/pull/53](https\://github\.com/ansible\-collections/community\.docker/pull/53)\)\.
* docker\_image \- report error when loading a broken archive that contains no image \([https\://github\.com/ansible\-collections/community\.docker/issues/46](https\://github\.com/ansible\-collections/community\.docker/issues/46)\, [https\://github\.com/ansible\-collections/community\.docker/pull/55](https\://github\.com/ansible\-collections/community\.docker/pull/55)\)\.
* docker\_image \- report error when the loaded archive does not contain the specified image \([https\://github\.com/ansible\-collections/community\.docker/issues/41](https\://github\.com/ansible\-collections/community\.docker/issues/41)\, [https\://github\.com/ansible\-collections/community\.docker/pull/55](https\://github\.com/ansible\-collections/community\.docker/pull/55)\)\.

<a id="new-plugins-1"></a>
### New Plugins

<a id="connection-1"></a>
#### Connection

* community\.docker\.docker\_api \- Run tasks in docker containers

<a id="inventory"></a>
#### Inventory

* community\.docker\.docker\_containers \- Ansible dynamic inventory plugin for Docker containers\.

<a id="new-modules-7"></a>
### New Modules

* community\.docker\.current\_container\_facts \- Return facts about whether the module runs in a Docker container

<a id="v1-0-1"></a>
## v1\.0\.1

<a id="release-summary-85"></a>
### Release Summary

Maintenance release with a bugfix for <code>docker\_container</code>\.

<a id="bugfixes-67"></a>
### Bugfixes

* docker\_container \- the validation for <code>capabilities</code> in <code>device\_requests</code> was incorrect \([https\://github\.com/ansible\-collections/community\.docker/issues/42](https\://github\.com/ansible\-collections/community\.docker/issues/42)\, [https\://github\.com/ansible\-collections/community\.docker/pull/43](https\://github\.com/ansible\-collections/community\.docker/pull/43)\)\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-86"></a>
### Release Summary

This is the first production \(non\-prerelease\) release of <code>community\.docker</code>\.

<a id="minor-changes-40"></a>
### Minor Changes

* Add collection\-side support of the <code>docker</code> action group / module defaults group \([https\://github\.com/ansible\-collections/community\.docker/pull/17](https\://github\.com/ansible\-collections/community\.docker/pull/17)\)\.
* docker\_image \- return docker build output \([https\://github\.com/ansible\-collections/community\.general/pull/805](https\://github\.com/ansible\-collections/community\.general/pull/805)\)\.
* docker\_secret \- add a warning when the secret does not have an <code>ansible\_key</code> label but the <code>force</code> parameter is not set \([https\://github\.com/ansible\-collections/community\.docker/issues/30](https\://github\.com/ansible\-collections/community\.docker/issues/30)\, [https\://github\.com/ansible\-collections/community\.docker/pull/31](https\://github\.com/ansible\-collections/community\.docker/pull/31)\)\.

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-87"></a>
### Release Summary

The <code>community\.docker</code> continues the work on the Ansible docker modules and plugins from their state in <code>community\.general</code> 1\.2\.0\. The changes listed here are thus relative to the modules and plugins <code>community\.general\.docker\*</code>\.

All deprecation removals planned for <code>community\.general</code> 2\.0\.0 have been applied\. All deprecation removals scheduled for <code>community\.general</code> 3\.0\.0 have been re\-scheduled for <code>community\.docker</code> 2\.0\.0\.

<a id="minor-changes-41"></a>
### Minor Changes

* docker\_container \- now supports the <code>device\_requests</code> option\, which allows to request additional resources such as GPUs \([https\://github\.com/ansible/ansible/issues/65748](https\://github\.com/ansible/ansible/issues/65748)\, [https\://github\.com/ansible\-collections/community\.general/pull/1119](https\://github\.com/ansible\-collections/community\.general/pull/1119)\)\.

<a id="removed-features-previously-deprecated-3"></a>
### Removed Features \(previously deprecated\)

* docker\_container \- no longer returns <code>ansible\_facts</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_container \- the default of <code>networks\_cli\_compatible</code> changed to <code>true</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_container \- the unused option <code>trust\_image\_content</code> has been removed \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- <code>state\=build</code> has been removed\. Use <code>present</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- the <code>container\_limits</code>\, <code>dockerfile</code>\, <code>http\_timeout</code>\, <code>nocache</code>\, <code>rm</code>\, <code>path</code>\, <code>buildargs</code>\, <code>pull</code> have been removed\. Use the corresponding suboptions of <code>build</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- the <code>force</code> option has been removed\. Use the more specific <code>force\_\*</code> options instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- the <code>source</code> option is now mandatory \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- the <code>use\_tls</code> option has been removed\. Use <code>tls</code> and <code>validate\_certs</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image \- the default of the <code>build\.pull</code> option changed to <code>false</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_image\_facts \- this alias is on longer available\, use <code>docker\_image\_info</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_network \- no longer returns <code>ansible\_facts</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_network \- the <code>ipam\_options</code> option has been removed\. Use <code>ipam\_config</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_service \- no longer returns <code>ansible\_facts</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm \- <code>state\=inspect</code> has been removed\. Use <code>docker\_swarm\_info</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>constraints</code> option has been removed\. Use <code>placement\.constraints</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>limit\_cpu</code> and <code>limit\_memory</code> options has been removed\. Use the corresponding suboptions in <code>limits</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>log\_driver</code> and <code>log\_driver\_options</code> options has been removed\. Use the corresponding suboptions in <code>logging</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>reserve\_cpu</code> and <code>reserve\_memory</code> options has been removed\. Use the corresponding suboptions in <code>reservations</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>restart\_policy</code>\, <code>restart\_policy\_attempts</code>\, <code>restart\_policy\_delay</code> and <code>restart\_policy\_window</code> options has been removed\. Use the corresponding suboptions in <code>restart\_config</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_swarm\_service \- the <code>update\_delay</code>\, <code>update\_parallelism</code>\, <code>update\_failure\_action</code>\, <code>update\_monitor</code>\, <code>update\_max\_failure\_ratio</code> and <code>update\_order</code> options has been removed\. Use the corresponding suboptions in <code>update\_config</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_volume \- no longer returns <code>ansible\_facts</code> \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.
* docker\_volume \- the <code>force</code> option has been removed\. Use <code>recreate</code> instead \([https\://github\.com/ansible\-collections/community\.docker/pull/1](https\://github\.com/ansible\-collections/community\.docker/pull/1)\)\.

<a id="bugfixes-68"></a>
### Bugfixes

* docker\_login \- fix internal config file storage to handle credentials for more than one registry \([https\://github\.com/ansible\-collections/community\.general/issues/1117](https\://github\.com/ansible\-collections/community\.general/issues/1117)\)\.
