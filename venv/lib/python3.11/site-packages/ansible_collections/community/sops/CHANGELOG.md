# Community SOPS Release Notes

**Topics**

- <a href="#v2-2-7">v2\.2\.7</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#known-issues">Known Issues</a>
- <a href="#v2-2-6">v2\.2\.6</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v2-2-5">v2\.2\.5</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v2-2-4">v2\.2\.4</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#bugfixes-2">Bugfixes</a>
- <a href="#v2-2-3">v2\.2\.3</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes-3">Bugfixes</a>
- <a href="#v2-2-2">v2\.2\.2</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v2-2-1">v2\.2\.1</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-8">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
- <a href="#v2-0-5">v2\.0\.5</a>
    - <a href="#release-summary-9">Release Summary</a>
- <a href="#v2-0-4">v2\.0\.4</a>
    - <a href="#release-summary-10">Release Summary</a>
    - <a href="#bugfixes-6">Bugfixes</a>
- <a href="#v2-0-3">v2\.0\.3</a>
    - <a href="#release-summary-11">Release Summary</a>
    - <a href="#bugfixes-7">Bugfixes</a>
- <a href="#v2-0-2">v2\.0\.2</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v2-0-1">v2\.0\.1</a>
    - <a href="#release-summary-13">Release Summary</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
- <a href="#v1-9-1">v1\.9\.1</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v1-9-0">v1\.9\.0</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#minor-changes-3">Minor Changes</a>
- <a href="#v1-8-2">v1\.8\.2</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#deprecated-features">Deprecated Features</a>
- <a href="#v1-8-1">v1\.8\.1</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v1-8-0">v1\.8\.0</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#minor-changes-4">Minor Changes</a>
    - <a href="#bugfixes-11">Bugfixes</a>
- <a href="#v1-7-0">v1\.7\.0</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#minor-changes-5">Minor Changes</a>
    - <a href="#bugfixes-12">Bugfixes</a>
- <a href="#v1-6-7">v1\.6\.7</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#bugfixes-13">Bugfixes</a>
- <a href="#v1-6-6">v1\.6\.6</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#bugfixes-14">Bugfixes</a>
- <a href="#v1-6-5">v1\.6\.5</a>
    - <a href="#release-summary-23">Release Summary</a>
    - <a href="#bugfixes-15">Bugfixes</a>
- <a href="#v1-6-4">v1\.6\.4</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#bugfixes-16">Bugfixes</a>
- <a href="#v1-6-3">v1\.6\.3</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#known-issues-1">Known Issues</a>
- <a href="#v1-6-2">v1\.6\.2</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#bugfixes-17">Bugfixes</a>
- <a href="#v1-6-1">v1\.6\.1</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#bugfixes-18">Bugfixes</a>
- <a href="#v1-6-0">v1\.6\.0</a>
    - <a href="#release-summary-28">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
- <a href="#v1-5-0">v1\.5\.0</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
    - <a href="#new-playbooks">New Playbooks</a>
    - <a href="#new-roles">New Roles</a>
- <a href="#v1-4-1">v1\.4\.1</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#bugfixes-19">Bugfixes</a>
- <a href="#v1-4-0">v1\.4\.0</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
- <a href="#v1-3-0">v1\.3\.0</a>
    - <a href="#release-summary-32">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
- <a href="#v1-2-3">v1\.2\.3</a>
    - <a href="#release-summary-33">Release Summary</a>
- <a href="#v1-2-2">v1\.2\.2</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#bugfixes-20">Bugfixes</a>
- <a href="#v1-2-1">v1\.2\.1</a>
    - <a href="#release-summary-35">Release Summary</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-36">Release Summary</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#bugfixes-21">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-37">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#filter">Filter</a>
- <a href="#v1-0-6">v1\.0\.6</a>
    - <a href="#release-summary-38">Release Summary</a>
    - <a href="#bugfixes-22">Bugfixes</a>
- <a href="#v1-0-5">v1\.0\.5</a>
    - <a href="#release-summary-39">Release Summary</a>
    - <a href="#bugfixes-23">Bugfixes</a>
- <a href="#v1-0-4">v1\.0\.4</a>
    - <a href="#release-summary-40">Release Summary</a>
    - <a href="#security-fixes">Security Fixes</a>
- <a href="#v1-0-3">v1\.0\.3</a>
    - <a href="#release-summary-41">Release Summary</a>
    - <a href="#bugfixes-24">Bugfixes</a>
- <a href="#v1-0-2">v1\.0\.2</a>
    - <a href="#release-summary-42">Release Summary</a>
- <a href="#v1-0-1">v1\.0\.1</a>
    - <a href="#release-summary-43">Release Summary</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-44">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
- <a href="#v0-2-0">v0\.2\.0</a>
    - <a href="#release-summary-45">Release Summary</a>
    - <a href="#minor-changes-13">Minor Changes</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-46">Release Summary</a>
    - <a href="#new-plugins-1">New Plugins</a>
        - <a href="#lookup">Lookup</a>
        - <a href="#vars">Vars</a>
    - <a href="#new-modules">New Modules</a>

<a id="v2-2-7"></a>
## v2\.2\.7

<a id="release-summary"></a>
### Release Summary

Maintenance release\.

<a id="known-issues"></a>
### Known Issues

* When using the <code>community\.sops\.load\_vars</code> with ansible\-core 2\.20\, note that the deprecation of <code>INJECT\_FACTS\_AS\_VARS</code> causes deprecation warnings to be shown every time a variable loaded with <code>community\.sops\.load\_vars</code> is used\. This is due to ansible\-core deprecating <code>INJECT\_FACTS\_AS\_VARS</code> without providing an alternative for modules like <code>community\.sops\.load\_vars</code> to use\. If you do not like these deprecation warnings\, you have to explicitly set <code>INJECT\_FACTS\_AS\_VARS</code> to <code>true</code>\. <strong>DO NOT</strong> change the use of SOPS encrypted variables to <code>ansible\_facts</code>\. The situation will hopefully improve in ansible\-core 2\.21 through the promised API that allows action plugins to set variables\; community\.sops will adapt to use it\, which will make the warning go away\. \(The API was originally promised for ansible\-core 2\.20\, but then delayed\.\)

<a id="v2-2-6"></a>
## v2\.2\.6

<a id="release-summary-1"></a>
### Release Summary

Bugfix and maintenance release\.

<a id="bugfixes"></a>
### Bugfixes

* Clean up plugin code that does not run on the target \([https\://github\.com/ansible\-collections/community\.sops/pull/275](https\://github\.com/ansible\-collections/community\.sops/pull/275)\)\.
* Note that the MIT licenced code in <code>plugins/module\_utils/\_six\.py</code> has been removed \([https\://github\.com/ansible\-collections/community\.sops/pull/275](https\://github\.com/ansible\-collections/community\.sops/pull/275)\)\.
* sops vars plugin \- ensure that loaded vars are evaluated also with ansible\-core 2\.19\+ \([https\://github\.com/ansible\-collections/community\.sops/pull/273](https\://github\.com/ansible\-collections/community\.sops/pull/273)\)\.

<a id="v2-2-5"></a>
## v2\.2\.5

<a id="release-summary-2"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-1"></a>
### Bugfixes

* load\_vars action \- avoid another deprecated module utils from ansible\-core \([https\://github\.com/ansible\-collections/community\.sops/pull/270](https\://github\.com/ansible\-collections/community\.sops/pull/270)\)\.
* load\_vars action \- avoid deprecated import from ansible\-core that will be removed in ansible\-core 2\.21 \([https\://github\.com/ansible\-collections/community\.sops/pull/272](https\://github\.com/ansible\-collections/community\.sops/pull/272)\)\.

<a id="v2-2-4"></a>
## v2\.2\.4

<a id="release-summary-3"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-2"></a>
### Bugfixes

* Fix accidental type extensions \([https\://github\.com/ansible\-collections/community\.sops/pull/269](https\://github\.com/ansible\-collections/community\.sops/pull/269)\)\.

<a id="v2-2-3"></a>
## v2\.2\.3

<a id="release-summary-4"></a>
### Release Summary

Maintenance release\.

<a id="minor-changes"></a>
### Minor Changes

* Note that some new code in <code>plugins/module\_utils/\_six\.py</code> is MIT licensed \([https\://github\.com/ansible\-collections/community\.sops/pull/268](https\://github\.com/ansible\-collections/community\.sops/pull/268)\)\.

<a id="bugfixes-3"></a>
### Bugfixes

* Avoid using <code>ansible\.module\_utils\.six</code> to avoid deprecation warnings with ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.sops/pull/268](https\://github\.com/ansible\-collections/community\.sops/pull/268)\)\.

<a id="v2-2-2"></a>
## v2\.2\.2

<a id="release-summary-5"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-4"></a>
### Bugfixes

* Avoid deprecated functionality in ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.sops/pull/260](https\://github\.com/ansible\-collections/community\.sops/pull/260)\)\.
* all modules and plugins \- the default of <code>enable\_local\_keyservice</code> changed from <code>false</code> to <code>true</code>\, and explicitly setting it to <code>false</code> now passes <code>\-\-enable\-local\-keyservice\=false</code>\. SOPS\' default has always been <code>true</code>\, and when setting this option to <code>true</code> so far it resulted in passing <code>\-\-enable\-local\-keyservice</code>\, which is equivalent to <code>\-\-enable\-local\-keyservice\=true</code> and had no effect\. This means that from now on\, setting <code>enable\_local\_keyservice</code> explicitly to <code>false</code> has an effect\. If <code>enable\_local\_keyservice</code> was not set before\, or was set to <code>true</code>\, nothing will change \([https\://github\.com/ansible\-collections/community\.sops/issues/261](https\://github\.com/ansible\-collections/community\.sops/issues/261)\, [https\://github\.com/ansible\-collections/community\.sops/pull/262](https\://github\.com/ansible\-collections/community\.sops/pull/262)\)\.

<a id="v2-2-1"></a>
## v2\.2\.1

<a id="release-summary-6"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-5"></a>
### Bugfixes

* install role \- avoid deprecated parameter value for the <code>ansible\.builtin\.uri</code> module \([https\://github\.com/ansible\-collections/community\.sops/pull/255](https\://github\.com/ansible\-collections/community\.sops/pull/255)\)\.

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-7"></a>
### Release Summary

Feature release\.

<a id="minor-changes-1"></a>
### Minor Changes

* load\_vars \- expressions can now be lazily evaluated when using ansible\-core 2\.19 or newer \([https\://github\.com/ansible\-collections/community\.sops/pull/229](https\://github\.com/ansible\-collections/community\.sops/pull/229)\)\.

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-8"></a>
### Release Summary

Feature release\.

<a id="minor-changes-2"></a>
### Minor Changes

* Now supports specifying SSH private keys for age with the new <code>age\_ssh\_private\_keyfile</code> option \([https\://github\.com/ansible\-collections/community\.sops/pull/241](https\://github\.com/ansible\-collections/community\.sops/pull/241)\)\.

<a id="v2-0-5"></a>
## v2\.0\.5

<a id="release-summary-9"></a>
### Release Summary

Maintenance release with updated SOPS version test coverage\.

<a id="v2-0-4"></a>
## v2\.0\.4

<a id="release-summary-10"></a>
### Release Summary

Maintenance release with Data Tagging support\.

<a id="bugfixes-6"></a>
### Bugfixes

* load\_vars \- make evaluation compatible with Data Tagging in upcoming ansible\-core release \([https\://github\.com/ansible\-collections/community\.sops/pull/225](https\://github\.com/ansible\-collections/community\.sops/pull/225)\)\.

<a id="v2-0-3"></a>
## v2\.0\.3

<a id="release-summary-11"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-7"></a>
### Bugfixes

* install role \- <code>sops\_install\_on\_localhost\=false</code> was not working properly if the role was running on more than one host due to a bug in ansible\-core \([https\://github\.com/ansible\-collections/community\.sops/issues/223](https\://github\.com/ansible\-collections/community\.sops/issues/223)\, [https\://github\.com/ansible\-collections/community\.sops/pull/224](https\://github\.com/ansible\-collections/community\.sops/pull/224)\)\.

<a id="v2-0-2"></a>
## v2\.0\.2

<a id="release-summary-12"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-8"></a>
### Bugfixes

* install role \- when used with Debian on ARM architecture\, the architecture name is now correctly translated from <code>aarch64</code> to <code>arm64</code> \([https\://github\.com/ansible\-collections/community\.sops/issues/220](https\://github\.com/ansible\-collections/community\.sops/issues/220)\, [https\://github\.com/ansible\-collections/community\.sops/pull/221](https\://github\.com/ansible\-collections/community\.sops/pull/221)\)\.

<a id="v2-0-1"></a>
## v2\.0\.1

<a id="release-summary-13"></a>
### Release Summary

Maintenance release with updated documentation\.

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-14"></a>
### Release Summary

Major verison that drops support for End of Life Ansible/ansible\-base/ansible\-core versions\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The collection no longer supports Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, ansible\-core 2\.13\, and ansible\-core 2\.14\. If you need to continue using End of Life versions of Ansible/ansible\-base/ansible\-core\, please use community\.sops 1\.x\.y \([https\://github\.com/ansible\-collections/community\.sops/pull/206](https\://github\.com/ansible\-collections/community\.sops/pull/206)\)\.

<a id="v1-9-1"></a>
## v1\.9\.1

<a id="release-summary-15"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-9"></a>
### Bugfixes

* sops\_encrypt \- pass absolute paths to <code>module\.atomic\_move\(\)</code> \([https\://github\.com/ansible/ansible/issues/83950](https\://github\.com/ansible/ansible/issues/83950)\, [https\://github\.com/ansible\-collections/community\.sops/pull/208](https\://github\.com/ansible\-collections/community\.sops/pull/208)\)\.

<a id="v1-9-0"></a>
## v1\.9\.0

<a id="release-summary-16"></a>
### Release Summary

Feature release\.

<a id="minor-changes-3"></a>
### Minor Changes

* decrypt filter plugin \- now supports the input and output type <code>ini</code> \([https\://github\.com/ansible\-collections/community\.sops/pull/204](https\://github\.com/ansible\-collections/community\.sops/pull/204)\)\.
* sops lookup plugin \- new option <code>extract</code> allows extracting a single key out of a JSON or YAML file\, equivalent to sops\' <code>decrypt \-\-extract</code> \([https\://github\.com/ansible\-collections/community\.sops/pull/200](https\://github\.com/ansible\-collections/community\.sops/pull/200)\)\.
* sops lookup plugin \- now supports the input and output type <code>ini</code> \([https\://github\.com/ansible\-collections/community\.sops/pull/204](https\://github\.com/ansible\-collections/community\.sops/pull/204)\)\.

<a id="v1-8-2"></a>
## v1\.8\.2

<a id="release-summary-17"></a>
### Release Summary

Maintenance release with updated documentation and changelog\.

<a id="deprecated-features"></a>
### Deprecated Features

* The collection deprecates support for all Ansible/ansible\-base/ansible\-core versions that are currently End of Life\, [according to the ansible\-core support matrix](https\://docs\.ansible\.com/ansible\-core/devel/reference\_appendices/release\_and\_maintenance\.html\#ansible\-core\-support\-matrix)\. This means that the next major release of the collection will no longer support Ansible 2\.9\, ansible\-base 2\.10\, ansible\-core 2\.11\, ansible\-core 2\.12\, ansible\-core 2\.13\, and ansible\-core 2\.14\.

<a id="v1-8-1"></a>
## v1\.8\.1

<a id="release-summary-18"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-10"></a>
### Bugfixes

* Pass <code>config\_path</code> on SOPS 3\.9\.0 before the subcommand instead of after it \([https\://github\.com/ansible\-collections/community\.sops/issues/195](https\://github\.com/ansible\-collections/community\.sops/issues/195)\, [https\://github\.com/ansible\-collections/community\.sops/pull/197](https\://github\.com/ansible\-collections/community\.sops/pull/197)\)\.

<a id="v1-8-0"></a>
## v1\.8\.0

<a id="release-summary-19"></a>
### Release Summary

Feature release for supporting improvements coming with SOPS 3\.9\.0\.

<a id="minor-changes-4"></a>
### Minor Changes

* Detect SOPS 3\.9\.0 and use new <code>decrypt</code> and <code>encrypt</code> subcommands \([https\://github\.com/ansible\-collections/community\.sops/pull/190](https\://github\.com/ansible\-collections/community\.sops/pull/190)\)\.
* sops vars plugin \- new option <code>handle\_unencrypted\_files</code> allows to control behavior when encountering unencrypted files with SOPS 3\.9\.0\+ \([https\://github\.com/ansible\-collections/community\.sops/pull/190](https\://github\.com/ansible\-collections/community\.sops/pull/190)\)\.

<a id="bugfixes-11"></a>
### Bugfixes

* sops\_encrypt \- properly support <code>path\_regex</code> in <code>\.sops\.yaml</code> when SOPS 3\.9\.0 or later is used \([https\://github\.com/ansible\-collections/community\.sops/issues/153](https\://github\.com/ansible\-collections/community\.sops/issues/153)\, [https\://github\.com/ansible\-collections/community\.sops/pull/190](https\://github\.com/ansible\-collections/community\.sops/pull/190)\)\.

<a id="v1-7-0"></a>
## v1\.7\.0

<a id="release-summary-20"></a>
### Release Summary

Bugfix and feature release to fix installation issues with SOPS 3\.9\.0\.

<a id="minor-changes-5"></a>
### Minor Changes

* sops vars plugin \- allow to configure the valid extensions with an <code>ansible\.cfg</code> entry or with an environment variable \([https\://github\.com/ansible\-collections/community\.sops/pull/185](https\://github\.com/ansible\-collections/community\.sops/pull/185)\)\.

<a id="bugfixes-12"></a>
### Bugfixes

* Fix RPM URL for the 3\.9\.0 release \([https\://github\.com/ansible\-collections/community\.sops/pull/188](https\://github\.com/ansible\-collections/community\.sops/pull/188)\)\.

<a id="v1-6-7"></a>
## v1\.6\.7

<a id="release-summary-21"></a>
### Release Summary

Bugfix release\.

<a id="bugfixes-13"></a>
### Bugfixes

* sops\_encrypt \- ensure that output\-type is set to <code>yaml</code> when the file extension <code>\.yml</code> is used\. Now both <code>\.yaml</code> and <code>\.yml</code> files use the SOPS <code>\-\-output\-type\=yaml</code> formatting \([https\://github\.com/ansible\-collections/community\.sops/issues/164](https\://github\.com/ansible\-collections/community\.sops/issues/164)\)\.

<a id="v1-6-6"></a>
## v1\.6\.6

<a id="release-summary-22"></a>
### Release Summary

Make fully compatible with and test against sops 3\.8\.0\.

<a id="bugfixes-14"></a>
### Bugfixes

* Fix RPM URL for the 3\.8\.0 release \([https\://github\.com/ansible\-collections/community\.sops/pull/161](https\://github\.com/ansible\-collections/community\.sops/pull/161)\)\.

<a id="v1-6-5"></a>
## v1\.6\.5

<a id="release-summary-23"></a>
### Release Summary

Make compatible with and test against sops 3\.8\.0\-rc\.1\.

<a id="bugfixes-15"></a>
### Bugfixes

* Avoid pre\-releases when picking the latest version when using the GitHub API method \([https\://github\.com/ansible\-collections/community\.sops/pull/159](https\://github\.com/ansible\-collections/community\.sops/pull/159)\)\.
* Fix changed DEB and RPM URLs for 3\.8\.0 and its prerelease\(s\) \([https\://github\.com/ansible\-collections/community\.sops/pull/159](https\://github\.com/ansible\-collections/community\.sops/pull/159)\)\.

<a id="v1-6-4"></a>
## v1\.6\.4

<a id="release-summary-24"></a>
### Release Summary

Maintenance/bugfix release for the move of sops to the new [getsops GitHub organization](https\://github\.com/getsops)\.

<a id="bugfixes-16"></a>
### Bugfixes

* install role \- fix <code>sops\_github\_latest\_detection\=latest\-release</code>\, which broke due to sops moving to another GitHub organization \([https\://github\.com/ansible\-collections/community\.sops/pull/151](https\://github\.com/ansible\-collections/community\.sops/pull/151)\)\.

<a id="v1-6-3"></a>
## v1\.6\.3

<a id="release-summary-25"></a>
### Release Summary

Maintenance release with updated documentation\.

From this version on\, community\.sops is using the new [Ansible semantic markup](https\://docs\.ansible\.com/ansible/devel/dev\_guide/developing\_modules\_documenting\.html\#semantic\-markup\-within\-module\-documentation)
in its documentation\. If you look at documentation with the ansible\-doc CLI tool
from ansible\-core before 2\.15\, please note that it does not render the markup
correctly\. You should be still able to read it in most cases\, but you need
ansible\-core 2\.15 or later to see it as it is intended\. Alternatively you can
look at [the devel docsite](https\://docs\.ansible\.com/ansible/devel/collections/community/sops/)
for the rendered HTML version of the documentation of the latest release\.

<a id="known-issues-1"></a>
### Known Issues

* Ansible markup will show up in raw form on ansible\-doc text output for ansible\-core before 2\.15\. If you have trouble deciphering the documentation markup\, please upgrade to ansible\-core 2\.15 \(or newer\)\, or read the HTML documentation on [https\://docs\.ansible\.com/ansible/devel/collections/community/sops/](https\://docs\.ansible\.com/ansible/devel/collections/community/sops/)\.

<a id="v1-6-2"></a>
## v1\.6\.2

<a id="release-summary-26"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-17"></a>
### Bugfixes

* install role \- make sure that the <code>pkg\_mgr</code> fact is definitely available when installing on <code>localhost</code>\. This can improve error messages in some cases \([https\://github\.com/ansible\-collections/community\.sops/issues/145](https\://github\.com/ansible\-collections/community\.sops/issues/145)\, [https\://github\.com/ansible\-collections/community\.sops/pull/146](https\://github\.com/ansible\-collections/community\.sops/pull/146)\)\.

<a id="v1-6-1"></a>
## v1\.6\.1

<a id="release-summary-27"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-18"></a>
### Bugfixes

* action plugin helper \- fix handling of deprecations for ansible\-core 2\.14\.2 \([https\://github\.com/ansible\-collections/community\.sops/pull/136](https\://github\.com/ansible\-collections/community\.sops/pull/136)\)\.
* various plugins \- remove unnecessary imports \([https\://github\.com/ansible\-collections/community\.sops/pull/133](https\://github\.com/ansible\-collections/community\.sops/pull/133)\)\.

<a id="v1-6-0"></a>
## v1\.6\.0

<a id="release-summary-28"></a>
### Release Summary

Feature release improving the installation role\.

<a id="minor-changes-6"></a>
### Minor Changes

* install role \- add <code>sops\_github\_latest\_detection</code> option that allows to configure which method to use for detecting the latest release on GitHub\. By default \(<code>auto</code>\) first tries to retrieve a list of recent releases using the API\, and if that fails due to rate limiting\, tries to obtain the latest GitHub release from a semi\-documented URL \([https\://github\.com/ansible\-collections/community\.sops/pull/133](https\://github\.com/ansible\-collections/community\.sops/pull/133)\)\.
* install role \- add <code>sops\_github\_token</code> option to allow passing a GitHub token\. This can for example be used to avoid rate limits when using the role in GitHub Actions \([https\://github\.com/ansible\-collections/community\.sops/pull/132](https\://github\.com/ansible\-collections/community\.sops/pull/132)\)\.
* install role \- implement another method to determine the latest release on GitHub than using the GitHub API\, which can make installation fail due to rate\-limiting \([https\://github\.com/ansible\-collections/community\.sops/pull/131](https\://github\.com/ansible\-collections/community\.sops/pull/131)\)\.

<a id="v1-5-0"></a>
## v1\.5\.0

<a id="release-summary-29"></a>
### Release Summary

Feature release\.

<a id="minor-changes-7"></a>
### Minor Changes

* Automatically install GNU Privacy Guard \(GPG\) in execution environments\. To install Mozilla sops a manual step needs to be added to the EE definition\, see the collection\'s documentation for details \([https\://github\.com/ansible\-collections/community\.sops/pull/98](https\://github\.com/ansible\-collections/community\.sops/pull/98)\)\.

<a id="new-playbooks"></a>
### New Playbooks

* community\.sops\.install \- Installs sops and GNU Privacy Guard on all remote hosts
* community\.sops\.install\_localhost \- Installs sops and GNU Privacy Guard on localhost

<a id="new-roles"></a>
### New Roles

* community\.sops\.install \- Install Mozilla sops

<a id="v1-4-1"></a>
## v1\.4\.1

<a id="release-summary-30"></a>
### Release Summary

Maintenance release to improve compatibility with future ansible\-core releases\.

<a id="bugfixes-19"></a>
### Bugfixes

* load\_vars \- ensure compatibility with newer versions of ansible\-core \([https\://github\.com/ansible\-collections/community\.sops/pull/121](https\://github\.com/ansible\-collections/community\.sops/pull/121)\)\.

<a id="v1-4-0"></a>
## v1\.4\.0

<a id="release-summary-31"></a>
### Release Summary

Feature release\.

<a id="minor-changes-8"></a>
### Minor Changes

* Allow to specify age keys as <code>age\_key</code>\, or age keyfiles as <code>age\_keyfile</code> \([https\://github\.com/ansible\-collections/community\.sops/issues/116](https\://github\.com/ansible\-collections/community\.sops/issues/116)\, [https\://github\.com/ansible\-collections/community\.sops/pull/117](https\://github\.com/ansible\-collections/community\.sops/pull/117)\)\.
* sops\_encrypt \- allow to specify age recipients \([https\://github\.com/ansible\-collections/community\.sops/issues/116](https\://github\.com/ansible\-collections/community\.sops/issues/116)\, [https\://github\.com/ansible\-collections/community\.sops/pull/117](https\://github\.com/ansible\-collections/community\.sops/pull/117)\)\.

<a id="v1-3-0"></a>
## v1\.3\.0

<a id="release-summary-32"></a>
### Release Summary

Feature release\.

<a id="minor-changes-9"></a>
### Minor Changes

* All software licenses are now in the <code>LICENSES/</code> directory of the collection root\, and the collection repository conforms to the [REUSE specification](https\://reuse\.software/spec/) except for the changelog fragments \([https\://github\.com/ansible\-collections/community\.crypto/sops/108](https\://github\.com/ansible\-collections/community\.crypto/sops/108)\, [https\://github\.com/ansible\-collections/community\.sops/pull/113](https\://github\.com/ansible\-collections/community\.sops/pull/113)\)\.
* sops vars plugin \- added a configuration option to temporarily disable the vars plugin \([https\://github\.com/ansible\-collections/community\.sops/pull/114](https\://github\.com/ansible\-collections/community\.sops/pull/114)\)\.

<a id="v1-2-3"></a>
## v1\.2\.3

<a id="release-summary-33"></a>
### Release Summary

Fix formatting bug in documentation\. No code changes\.

<a id="v1-2-2"></a>
## v1\.2\.2

<a id="release-summary-34"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-20"></a>
### Bugfixes

* Include <code>simplified\_bsd\.txt</code> license file for the <code>sops</code> module utils\.

<a id="v1-2-1"></a>
## v1\.2\.1

<a id="release-summary-35"></a>
### Release Summary

Maintenance release with updated documentation\.

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-36"></a>
### Release Summary

Collection release for inclusion in Ansible 4\.9\.0 and 5\.1\.0\.

This release contains a change allowing to configure generic plugin options with ansible\.cfg keys and env variables\.

<a id="minor-changes-10"></a>
### Minor Changes

* sops lookup and vars plugin \- allow to configure almost all generic options by ansible\.cfg entries and environment variables \([https\://github\.com/ansible\-collections/community\.sops/pull/81](https\://github\.com/ansible\-collections/community\.sops/pull/81)\)\.

<a id="bugfixes-21"></a>
### Bugfixes

* Fix error handling in calls of the <code>sops</code> binary when negative errors are returned \([https\://github\.com/ansible\-collections/community\.sops/issues/82](https\://github\.com/ansible\-collections/community\.sops/issues/82)\, [https\://github\.com/ansible\-collections/community\.sops/pull/83](https\://github\.com/ansible\-collections/community\.sops/pull/83)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-37"></a>
### Release Summary

A minor release for inclusion in Ansible 4\.2\.0\.

<a id="minor-changes-11"></a>
### Minor Changes

* Avoid internal ansible\-core module\_utils in favor of equivalent public API available since at least Ansible 2\.9 \([https\://github\.com/ansible\-collections/community\.sops/pull/73](https\://github\.com/ansible\-collections/community\.sops/pull/73)\)\.

<a id="new-plugins"></a>
### New Plugins

<a id="filter"></a>
#### Filter

* community\.sops\.decrypt \- Decrypt sops\-encrypted data

<a id="v1-0-6"></a>
## v1\.0\.6

<a id="release-summary-38"></a>
### Release Summary

This release makes the collection compatible to the latest beta release of ansible\-core 2\.11\.

<a id="bugfixes-22"></a>
### Bugfixes

* action\_module plugin helper \- make compatible with latest changes in ansible\-core 2\.11\.0b3 \([https\://github\.com/ansible\-collections/community\.sops/pull/58](https\://github\.com/ansible\-collections/community\.sops/pull/58)\)\.
* community\.sops\.load\_vars \- make compatible with latest changes in ansible\-core 2\.11\.0b3 \([https\://github\.com/ansible\-collections/community\.sops/pull/58](https\://github\.com/ansible\-collections/community\.sops/pull/58)\)\.

<a id="v1-0-5"></a>
## v1\.0\.5

<a id="release-summary-39"></a>
### Release Summary

This release fixes a bug that prevented correct YAML file to be created when the output was ending in <code>\.yaml</code>\.

<a id="bugfixes-23"></a>
### Bugfixes

* community\.sops\.sops\_encrypt \- use output type <code>yaml</code> when path ends with <code>\.yaml</code> \([https\://github\.com/ansible\-collections/community\.sops/pull/56](https\://github\.com/ansible\-collections/community\.sops/pull/56)\)\.

<a id="v1-0-4"></a>
## v1\.0\.4

<a id="release-summary-40"></a>
### Release Summary

This is a security release\, fixing a potential information leak in the <code>community\.sops\.sops\_encrypt</code> module\.

<a id="security-fixes"></a>
### Security Fixes

* community\.sops\.sops\_encrypt \- mark the <code>aws\_secret\_access\_key</code> and <code>aws\_session\_token</code> parameters as <code>no\_log</code> to avoid leakage of secrets \([https\://github\.com/ansible\-collections/community\.sops/pull/54](https\://github\.com/ansible\-collections/community\.sops/pull/54)\)\.

<a id="v1-0-3"></a>
## v1\.0\.3

<a id="release-summary-41"></a>
### Release Summary

This release include some fixes to Ansible docs and required changes for inclusion in Ansible\.

<a id="bugfixes-24"></a>
### Bugfixes

* community\.sops\.sops lookup plugins \- fix wrong format of Ansible variables so that these are actually used \([https\://github\.com/ansible\-collections/community\.sops/pull/51](https\://github\.com/ansible\-collections/community\.sops/pull/51)\)\.
* community\.sops\.sops vars plugins \- remove non\-working Ansible variables \([https\://github\.com/ansible\-collections/community\.sops/pull/51](https\://github\.com/ansible\-collections/community\.sops/pull/51)\)\.

<a id="v1-0-2"></a>
## v1\.0\.2

<a id="release-summary-42"></a>
### Release Summary

Fix of 1\.0\.1 release which had no changelog entry\.

<a id="v1-0-1"></a>
## v1\.0\.1

<a id="release-summary-43"></a>
### Release Summary

Re\-release of 1\.0\.0 to counteract error during release\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-44"></a>
### Release Summary

First stable release\. This release is expected to be included in Ansible 3\.0\.0\.

<a id="minor-changes-12"></a>
### Minor Changes

* All plugins and modules\: allow to pass generic sops options with new options <code>config\_path</code>\, <code>enable\_local\_keyservice</code>\, <code>keyservice</code>\. Also allow to pass AWS parameters with options <code>aws\_profile</code>\, <code>aws\_access\_key\_id</code>\, <code>aws\_secret\_access\_key</code>\, and <code>aws\_session\_token</code> \([https\://github\.com/ansible\-collections/community\.sops/pull/47](https\://github\.com/ansible\-collections/community\.sops/pull/47)\)\.
* community\.sops\.sops\_encrypt \- allow to pass encryption\-specific options <code>kms</code>\, <code>gcp\_kms</code>\, <code>azure\_kv</code>\, <code>hc\_vault\_transit</code>\, <code>pgp</code>\, <code>unencrypted\_suffix</code>\, <code>encrypted\_suffix</code>\, <code>unencrypted\_regex</code>\, <code>encrypted\_regex</code>\, <code>encryption\_context</code>\, and <code>shamir\_secret\_sharing\_threshold</code> to sops \([https\://github\.com/ansible\-collections/community\.sops/pull/47](https\://github\.com/ansible\-collections/community\.sops/pull/47)\)\.

<a id="v0-2-0"></a>
## v0\.2\.0

<a id="release-summary-45"></a>
### Release Summary

This release adds features for the lookup and vars plugins\.

<a id="minor-changes-13"></a>
### Minor Changes

* community\.sops\.sops lookup plugin \- add <code>empty\_on\_not\_exist</code> option which allows to return an empty string instead of an error when the file does not exist \([https\://github\.com/ansible\-collections/community\.sops/pull/33](https\://github\.com/ansible\-collections/community\.sops/pull/33)\)\.
* community\.sops\.sops vars plugin \- add option to control caching \([https\://github\.com/ansible\-collections/community\.sops/pull/32](https\://github\.com/ansible\-collections/community\.sops/pull/32)\)\.
* community\.sops\.sops vars plugin \- add option to determine when vars are loaded \([https\://github\.com/ansible\-collections/community\.sops/pull/32](https\://github\.com/ansible\-collections/community\.sops/pull/32)\)\.

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-46"></a>
### Release Summary

First release of the <code>community\.sops</code> collection\!
This release includes multiple plugins\: an <code>action</code> plugin\, a <code>lookup</code> plugin and a <code>vars</code> plugin\.

<a id="new-plugins-1"></a>
### New Plugins

<a id="lookup"></a>
#### Lookup

* community\.sops\.sops \- Read sops encrypted file contents

<a id="vars"></a>
#### Vars

* community\.sops\.sops \- Loading sops\-encrypted vars files

<a id="new-modules"></a>
### New Modules

* community\.sops\.load\_vars \- Load sops\-encrypted variables from files\, dynamically within a task
* community\.sops\.sops\_encrypt \- Encrypt data with sops
