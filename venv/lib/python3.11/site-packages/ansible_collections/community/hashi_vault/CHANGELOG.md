# community\.hashi\_vault Release Notes

**Topics**

- <a href="#v7-1-0">v7\.1\.0</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
- <a href="#v7-0-0">v7\.0\.0</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#breaking-changes--porting-guide">Breaking Changes / Porting Guide</a>
- <a href="#v6-2-1">v6\.2\.1</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#deprecated-features">Deprecated Features</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v6-2-0">v6\.2\.0</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#minor-changes-1">Minor Changes</a>
    - <a href="#new-modules">New Modules</a>
- <a href="#v6-1-0">v6\.1\.0</a>
    - <a href="#release-summary-4">Release Summary</a>
    - <a href="#major-changes">Major Changes</a>
- <a href="#v6-0-0">v6\.0\.0</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-1">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated">Removed Features \(previously deprecated\)</a>
- <a href="#v5-0-1">v5\.0\.1</a>
    - <a href="#release-summary-6">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v5-0-0">v5\.0\.0</a>
    - <a href="#release-summary-7">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-2">Breaking Changes / Porting Guide</a>
- <a href="#v4-2-1">v4\.2\.1</a>
    - <a href="#release-summary-8">Release Summary</a>
- <a href="#v4-2-0">v4\.2\.0</a>
    - <a href="#release-summary-9">Release Summary</a>
    - <a href="#deprecated-features-1">Deprecated Features</a>
    - <a href="#bugfixes-2">Bugfixes</a>
    - <a href="#new-modules-1">New Modules</a>
- <a href="#v4-1-0">v4\.1\.0</a>
    - <a href="#release-summary-10">Release Summary</a>
    - <a href="#deprecated-features-2">Deprecated Features</a>
    - <a href="#new-plugins">New Plugins</a>
        - <a href="#lookup">Lookup</a>
    - <a href="#new-modules-2">New Modules</a>
- <a href="#v4-0-0">v4\.0\.0</a>
    - <a href="#release-summary-11">Release Summary</a>
    - <a href="#minor-changes-2">Minor Changes</a>
    - <a href="#breaking-changes--porting-guide-3">Breaking Changes / Porting Guide</a>
- <a href="#v3-4-0">v3\.4\.0</a>
    - <a href="#release-summary-12">Release Summary</a>
    - <a href="#minor-changes-3">Minor Changes</a>
    - <a href="#bugfixes-3">Bugfixes</a>
    - <a href="#new-modules-3">New Modules</a>
- <a href="#v3-3-1">v3\.3\.1</a>
    - <a href="#release-summary-13">Release Summary</a>
- <a href="#v3-3-0">v3\.3\.0</a>
    - <a href="#release-summary-14">Release Summary</a>
    - <a href="#minor-changes-4">Minor Changes</a>
- <a href="#v3-2-0">v3\.2\.0</a>
    - <a href="#release-summary-15">Release Summary</a>
    - <a href="#minor-changes-5">Minor Changes</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v3-1-0">v3\.1\.0</a>
    - <a href="#release-summary-16">Release Summary</a>
    - <a href="#deprecated-features-3">Deprecated Features</a>
    - <a href="#bugfixes-5">Bugfixes</a>
- <a href="#v3-0-0">v3\.0\.0</a>
    - <a href="#release-summary-17">Release Summary</a>
    - <a href="#deprecated-features-4">Deprecated Features</a>
    - <a href="#removed-features-previously-deprecated-1">Removed Features \(previously deprecated\)</a>
- <a href="#v2-5-0">v2\.5\.0</a>
    - <a href="#release-summary-18">Release Summary</a>
    - <a href="#minor-changes-6">Minor Changes</a>
    - <a href="#deprecated-features-5">Deprecated Features</a>
    - <a href="#new-plugins-1">New Plugins</a>
        - <a href="#lookup-1">Lookup</a>
    - <a href="#new-modules-4">New Modules</a>
- <a href="#v2-4-0">v2\.4\.0</a>
    - <a href="#release-summary-19">Release Summary</a>
    - <a href="#new-plugins-2">New Plugins</a>
        - <a href="#lookup-2">Lookup</a>
    - <a href="#new-modules-5">New Modules</a>
- <a href="#v2-3-0">v2\.3\.0</a>
    - <a href="#release-summary-20">Release Summary</a>
    - <a href="#new-plugins-3">New Plugins</a>
        - <a href="#lookup-3">Lookup</a>
    - <a href="#new-modules-6">New Modules</a>
- <a href="#v2-2-0">v2\.2\.0</a>
    - <a href="#release-summary-21">Release Summary</a>
    - <a href="#minor-changes-7">Minor Changes</a>
    - <a href="#new-plugins-4">New Plugins</a>
        - <a href="#filter">Filter</a>
        - <a href="#lookup-4">Lookup</a>
    - <a href="#new-modules-7">New Modules</a>
- <a href="#v2-1-0">v2\.1\.0</a>
    - <a href="#release-summary-22">Release Summary</a>
    - <a href="#deprecated-features-6">Deprecated Features</a>
    - <a href="#removed-features-previously-deprecated-2">Removed Features \(previously deprecated\)</a>
- <a href="#v2-0-0">v2\.0\.0</a>
    - <a href="#release-summary-23">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-4">Breaking Changes / Porting Guide</a>
    - <a href="#removed-features-previously-deprecated-3">Removed Features \(previously deprecated\)</a>
- <a href="#v1-5-0">v1\.5\.0</a>
    - <a href="#release-summary-24">Release Summary</a>
    - <a href="#minor-changes-8">Minor Changes</a>
- <a href="#v1-4-1">v1\.4\.1</a>
    - <a href="#release-summary-25">Release Summary</a>
    - <a href="#bugfixes-6">Bugfixes</a>
- <a href="#v1-4-0">v1\.4\.0</a>
    - <a href="#release-summary-26">Release Summary</a>
    - <a href="#minor-changes-9">Minor Changes</a>
    - <a href="#deprecated-features-7">Deprecated Features</a>
    - <a href="#bugfixes-7">Bugfixes</a>
    - <a href="#new-plugins-5">New Plugins</a>
        - <a href="#lookup-5">Lookup</a>
    - <a href="#new-modules-8">New Modules</a>
- <a href="#v1-3-2">v1\.3\.2</a>
    - <a href="#release-summary-27">Release Summary</a>
    - <a href="#minor-changes-10">Minor Changes</a>
    - <a href="#deprecated-features-8">Deprecated Features</a>
- <a href="#v1-3-1">v1\.3\.1</a>
    - <a href="#release-summary-28">Release Summary</a>
- <a href="#v1-3-0">v1\.3\.0</a>
    - <a href="#release-summary-29">Release Summary</a>
    - <a href="#minor-changes-11">Minor Changes</a>
- <a href="#v1-2-0">v1\.2\.0</a>
    - <a href="#release-summary-30">Release Summary</a>
    - <a href="#minor-changes-12">Minor Changes</a>
    - <a href="#deprecated-features-9">Deprecated Features</a>
- <a href="#v1-1-3">v1\.1\.3</a>
    - <a href="#release-summary-31">Release Summary</a>
    - <a href="#bugfixes-8">Bugfixes</a>
- <a href="#v1-1-2">v1\.1\.2</a>
    - <a href="#release-summary-32">Release Summary</a>
- <a href="#v1-1-1">v1\.1\.1</a>
    - <a href="#release-summary-33">Release Summary</a>
    - <a href="#bugfixes-9">Bugfixes</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-34">Release Summary</a>
    - <a href="#minor-changes-13">Minor Changes</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-35">Release Summary</a>
    - <a href="#breaking-changes--porting-guide-5">Breaking Changes / Porting Guide</a>
- <a href="#v0-2-0">v0\.2\.0</a>
    - <a href="#release-summary-36">Release Summary</a>
    - <a href="#minor-changes-14">Minor Changes</a>
    - <a href="#deprecated-features-10">Deprecated Features</a>
    - <a href="#bugfixes-10">Bugfixes</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-37">Release Summary</a>

<a id="v7-1-0"></a>
## v7\.1\.0

<a id="release-summary"></a>
### Release Summary

This release adds support for Google Cloud Platform \(GCP\) auth\, and removes some Python 2 compatibility code\. Python 2 has long been unsupported in this collection but if you happened to be using it successfully anyway\, that will likely not work after this release\.

<a id="minor-changes"></a>
### Minor Changes

* community\.hashi\_vault collection \- add support for <code>gcp</code> auth method \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/442](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/442)\)\.

<a id="v7-0-0"></a>
## v7\.0\.0

<a id="release-summary-1"></a>
### Release Summary

This release removes support for older versions of <code>ansible\-core</code> and <code>python</code>\. It does not contain functional changes that cause the collection to stop working in earlier versions\, however we are no longer testing against those so compatibility will not be guaranteed from this version on\.

<a id="breaking-changes--porting-guide"></a>
### Breaking Changes / Porting Guide

* ansible\-core \- support for all end\-of\-life versions of <code>ansible\-core</code> has been dropped\. The collection is tested with <code>ansible\-core\>\=2\.17</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/470](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/470)\)\.
* python \- support for older versions of Python has been dropped\. The collection is tested with all supported controller\-side versions and a few lower target\-side versions depending on the tests \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/470](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/470)\)\.

<a id="v6-2-1"></a>
## v6\.2\.1

<a id="release-summary-2"></a>
### Release Summary

A quick bugfix release before the next major version\. Please take note of the upcoming deprecation of <code>ansible\-core</code> and <code>python</code> versions\.

<a id="deprecated-features"></a>
### Deprecated Features

* ansible\-core \- support for several <code>ansible\-core</code> versions will be dropped in <code>v7\.0\.0</code>\. The collection will focus on current supported versions of <code>ansible\-core</code> going forward and more agressively drop end\-of\-life or soon\-to\-be EOL versions \([https\://docs\.ansible\.com/ansible/devel/reference\_appendices/release\_and\_maintenance\.html](https\://docs\.ansible\.com/ansible/devel/reference\_appendices/release\_and\_maintenance\.html)\)\.
* python \- support for several <code>python</code> versions will be dropped in <code>v7\.0\.0</code>\. The collection will focus on <code>python</code> versions that are supported by the active versions of <code>ansible\-core</code> on the controller side at a minimum\, and some subset of target versions \([https\://docs\.ansible\.com/ansible/devel/reference\_appendices/release\_and\_maintenance\.html](https\://docs\.ansible\.com/ansible/devel/reference\_appendices/release\_and\_maintenance\.html)\)\.

<a id="bugfixes"></a>
### Bugfixes

* connection\_options \- the <code>validate\_certs</code> option had no effect if the <code>retries</code> option was set\. Fix now also sets the parameter correctly in the retry request session \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/461](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/461)\)\.

<a id="v6-2-0"></a>
## v6\.2\.0

<a id="release-summary-3"></a>
### Release Summary

This release contains a dozen\+ new modules for working with Vault\'s database secrets engine and some new <code>vars</code> entries for specifying public and private keys in <code>cert</code> auth\.

<a id="minor-changes-1"></a>
### Minor Changes

* cert auth \- add option to set the <code>cert\_auth\_public\_key</code> and <code>cert\_auth\_private\_key</code> parameters using the variables <code>ansible\_hashi\_vault\_cert\_auth\_public\_key</code> and <code>ansible\_hashi\_vault\_cert\_auth\_private\_key</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/428](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/428)\)\.

<a id="new-modules"></a>
### New Modules

* vault\_database\_connection\_configure \- Configures the database engine
* vault\_database\_connection\_delete \- Delete a Database Connection
* vault\_database\_connection\_read \- Returns the configuration settings for a O\(connection\_name\)
* vault\_database\_connection\_reset \- Closes a O\(connection\_name\) and its underlying plugin and restarts it with the configuration stored
* vault\_database\_connections\_list \- Returns a list of available connections
* vault\_database\_role\_create \- Creates or updates a \(dynamic\) role definition
* vault\_database\_role\_delete \- Delete a role definition
* vault\_database\_role\_read \- Queries a dynamic role definition
* vault\_database\_roles\_list \- Returns a list of available \(dynamic\) roles
* vault\_database\_rotate\_root\_credentials \- Rotates the root credentials stored for the database connection\. This user must have permissions to update its own password\.
* vault\_database\_static\_role\_create \- Create or update a static role
* vault\_database\_static\_role\_get\_credentials \- Returns the current credentials based on the named static role
* vault\_database\_static\_role\_read \- Queries a static role definition
* vault\_database\_static\_role\_rotate\_credentials \- Trigger the credential rotation for a static role
* vault\_database\_static\_roles\_list \- Returns a list of available static roles

<a id="v6-1-0"></a>
## v6\.1\.0

<a id="release-summary-4"></a>
### Release Summary

This release addresses some breaking changes in core that were backported\.

<a id="major-changes"></a>
### Major Changes

* requirements \- the <code>requests</code> package which is required by <code>hvac</code> now has a more restrictive range for this collection in certain use cases due to breaking security changes in <code>ansible\-core</code> that were backported \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/416](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/416)\)\.

<a id="v6-0-0"></a>
## v6\.0\.0

<a id="release-summary-5"></a>
### Release Summary

This major version of the collection has no functional changes from the previous version\, however the minimum versions of <code>hvac</code> and <code>ansible\-core</code> have been raised\. While the collection may still work with those earlier versions\, future changes will not test against them\.

<a id="breaking-changes--porting-guide-1"></a>
### Breaking Changes / Porting Guide

* The minimum required version of <code>hvac</code> is now <code>1\.2\.1</code> \([https\://docs\.ansible\.com/ansible/devel/collections/community/hashi\_vault/docsite/user\_guide\.html\#hvac\-version\-specifics](https\://docs\.ansible\.com/ansible/devel/collections/community/hashi\_vault/docsite/user\_guide\.html\#hvac\-version\-specifics)\)\.

<a id="removed-features-previously-deprecated"></a>
### Removed Features \(previously deprecated\)

* The minimum supported version of <code>ansible\-core</code> is now <code>2\.14</code>\, support for <code>2\.13</code> has been dropped \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/403](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/403)\)\.

<a id="v5-0-1"></a>
## v5\.0\.1

<a id="release-summary-6"></a>
### Release Summary

This release fixes a bug in <code>vault\_write</code> ahead of the collection\'s next major release\.

<a id="bugfixes-1"></a>
### Bugfixes

* vault\_write \- the <code>vault\_write</code> lookup and module were not able to write data containing keys named <code>path</code> or <code>wrap\_ttl</code> due to a bug in the <code>hvac</code> library\. These plugins have now been updated to take advantage of fixes in <code>hvac\>\=1\.2</code> to address this \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/389](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/389)\)\.

<a id="v5-0-0"></a>
## v5\.0\.0

<a id="release-summary-7"></a>
### Release Summary

This version makes some relatively minor but technically breaking changes\. Support for <code>ansible\-core</code> versions <code>2\.11</code> and <code>2\.12</code> have been dropped\, and there is now a minimum supported version of <code>hvac</code> which will be updated over time\. A warning in the <code>hashi\_vault</code> lookup on duplicate option specifications in the term string has been changed to a fatal error\.

<a id="breaking-changes--porting-guide-2"></a>
### Breaking Changes / Porting Guide

* Support for <code>ansible\-core</code> 2\.11 and 2\.12 has been removed \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/340](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/340)\)\.
* The minimum version of <code>hvac</code> for <code>community\.hashi\_vault</code> is now <code>1\.1\.0</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/324](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/324)\)\.
* hashi\_vault lookup \- duplicate option entries in the term string now raises an exception instead of a warning \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/356](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/356)\)\.

<a id="v4-2-1"></a>
## v4\.2\.1

<a id="release-summary-8"></a>
### Release Summary

This patch version updates the documentation for the <code>vault\_kv2\_write</code> module\. There are no functional changes\.

<a id="v4-2-0"></a>
## v4\.2\.0

<a id="release-summary-9"></a>
### Release Summary

This release contains a new module for KVv2 writes\, and a new warning for duplicated term string options in the <code>hashi\_vault</code> lookup\.

<a id="deprecated-features-1"></a>
### Deprecated Features

* hashi\_vault lookup \- in <code>v5\.0\.0</code> duplicate term string options will raise an exception instead of showing a warning \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/356](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/356)\)\.

<a id="bugfixes-2"></a>
### Bugfixes

* hashi\_vault lookup \- a term string with duplicate options would silently use the last value\. The lookup now shows a warning on option duplication \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/349](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/349)\)\.

<a id="new-modules-1"></a>
### New Modules

* vault\_kv2\_write \- Perform a write operation against a KVv2 secret in HashiCorp Vault

<a id="v4-1-0"></a>
## v4\.1\.0

<a id="release-summary-10"></a>
### Release Summary

This release brings new generic <code>vault\_list</code> plugins from a new contributor\!
There are also some deprecation notices for the next major version\, and some updates to documentation attributes\.

<a id="deprecated-features-2"></a>
### Deprecated Features

* ansible\-core \- support for <code>ansible\-core</code> versions <code>2\.11</code> and <code>2\.12</code> will be dropped in collection version <code>5\.0\.0</code>\, making <code>2\.13</code> the minimum supported version of <code>ansible\-core</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/340](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/340)\)\.
* hvac \- the minimum version of <code>hvac</code> to be supported in collection version <code>5\.0\.0</code> will be at least <code>1\.0\.2</code>\; this minimum may be raised before <code>5\.0\.0</code> is released\, so please subscribe to the linked issue and look out for new notices in the changelog \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/324](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/324)\)\.

<a id="new-plugins"></a>
### New Plugins

<a id="lookup"></a>
#### Lookup

* vault\_list \- Perform a list operation against HashiCorp Vault

<a id="new-modules-2"></a>
### New Modules

* vault\_list \- Perform a list operation against HashiCorp Vault

<a id="v4-0-0"></a>
## v4\.0\.0

<a id="release-summary-11"></a>
### Release Summary

The next major version of the collection includes previously announced breaking changes to some default values\, and improvements to module documentation with attributes that describe the use of action groups and check mode support\.

<a id="minor-changes-2"></a>
### Minor Changes

* modules \- all modules now document their action group and support for check mode in their attributes documentation \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/197](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/197)\)\.

<a id="breaking-changes--porting-guide-3"></a>
### Breaking Changes / Porting Guide

* auth \- the default value for <code>token\_validate</code> has changed from <code>true</code> to <code>false</code>\, as previously announced \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248)\)\.
* vault\_kv2\_get lookup \- as previously announced\, the default value for <code>engine\_mount\_point</code> in the <code>vault\_kv2\_get</code> lookup has changed from <code>kv</code> to <code>secret</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/279](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/279)\)\.

<a id="v3-4-0"></a>
## v3\.4\.0

<a id="release-summary-12"></a>
### Release Summary

This release includes a new module\, fixes \(another\) <code>requests</code> header issue\, and updates some inaccurate documentation\.
This is the last planned release before v4\.0\.0\.

<a id="minor-changes-3"></a>
### Minor Changes

* vault\_pki\_generate\_certificate \- the documentation has been updated to match the argspec for the default values of options <code>alt\_names</code>\, <code>ip\_sans</code>\, <code>other\_sans</code>\, and <code>uri\_sans</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/318](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/318)\)\.

<a id="bugfixes-3"></a>
### Bugfixes

* connection options \- the <code>namespace</code> connection option will be forced into a string to ensure cmpatibility with recent <code>requests</code> versions \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/309](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/309)\)\.

<a id="new-modules-3"></a>
### New Modules

* vault\_kv2\_delete \- Delete one or more versions of a secret from HashiCorp Vault\'s KV version 2 secret store

<a id="v3-3-1"></a>
## v3\.3\.1

<a id="release-summary-13"></a>
### Release Summary

No functional changes in this release\, this provides updated filter documentation for the public docsite\.

<a id="v3-3-0"></a>
## v3\.3\.0

<a id="release-summary-14"></a>
### Release Summary

With the release of <code>hvac</code> version <code>1\.0\.0</code>\, we needed to update <code>vault\_token\_create</code>\'s support for orphan tokens\.
The collection\'s changelog is now viewable in the Ansible documentation site\.

<a id="minor-changes-4"></a>
### Minor Changes

* vault\_token\_create \- creation or orphan tokens uses <code>hvac</code>\'s new v1 method for creating orphans\, or falls back to the v0 method if needed \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/301](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/301)\)\.

<a id="v3-2-0"></a>
## v3\.2\.0

<a id="release-summary-15"></a>
### Release Summary

This release brings support for the <code>azure</code> auth method\, adds <code>412</code> to the default list of HTTP status codes to be retried\, and fixes a bug that causes failures in token auth with <code>requests\>\=2\.28\.0</code>\.

<a id="minor-changes-5"></a>
### Minor Changes

* community\.hashi\_vault collection \- add support for <code>azure</code> auth method\, for Azure service principal\, managed identity\, or plain JWT access token \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/293](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/293)\)\.
* community\.hashi\_vault retries \- [HTTP status code 412](https\://www\.vaultproject\.io/api\-docs\#412) has been added to the default list of codes to be retried\, for the new [Server Side Consistent Token feature](https\://www\.vaultproject\.io/docs/faq/ssct\#q\-is\-there\-anything\-else\-i\-need\-to\-consider\-to\-achieve\-consistency\-besides\-upgrading\-to\-vault\-1\-10) in Vault Enterprise \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/290](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/290)\)\.

<a id="bugfixes-4"></a>
### Bugfixes

* community\.hashi\_vault plugins \- tokens will be cast to a string type before being sent to <code>hvac</code> to prevent errors in <code>requests</code> when values are <code>AnsibleUnsafe</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/289](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/289)\)\.
* modules \- fix a \"variable used before assignment\" that cannot be reached but causes sanity test failures \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/296](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/296)\)\.

<a id="v3-1-0"></a>
## v3\.1\.0

<a id="release-summary-16"></a>
### Release Summary

A default value that was set incorrectly will be corrected in <code>4\.0\.0</code>\.
A deprecation warning will be shown until then if the value is not specified explicitly\.
This version also includes some fixes and improvements to the licensing in the collection\, which does not affect any functionality\.

<a id="deprecated-features-3"></a>
### Deprecated Features

* vault\_kv2\_get lookup \- the <code>engine\_mount\_point option</code> in the <code>vault\_kv2\_get</code> lookup only will change its default from <code>kv</code> to <code>secret</code> in community\.hashi\_vault version 4\.0\.0 \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/279](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/279)\)\.

<a id="bugfixes-5"></a>
### Bugfixes

* Add SPDX license headers to individual files \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/282](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/282)\)\.
* Add missing <code>BSD\-2\-Clause\.txt</code> file for BSD licensed content \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/275](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/275)\)\.
* Use the correct GPL license for plugin\_utils \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/276](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/276)\)\.

<a id="v3-0-0"></a>
## v3\.0\.0

<a id="release-summary-17"></a>
### Release Summary

Version 3\.0\.0 of <code>community\.hashi\_vault</code> drops support for Ansible 2\.9 and ansible\-base 2\.10\.
Several deprecated features have been removed\. See the changelog for the full list\.

<a id="deprecated-features-4"></a>
### Deprecated Features

* token\_validate options \- the shared auth option <code>token\_validate</code> will change its default from <code>true</code> to <code>false</code> in community\.hashi\_vault version 4\.0\.0\. The <code>vault\_login</code> lookup and module will keep the default value of <code>true</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248)\)\.

<a id="removed-features-previously-deprecated-1"></a>
### Removed Features \(previously deprecated\)

* aws\_iam auth \- the deprecated alias <code>aws\_iam\_login</code> for the <code>aws\_iam</code> value of the <code>auth\_method</code> option has been removed \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/194](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/194)\)\.
* community\.hashi\_vault collection \- support for Ansible 2\.9 and ansible\-base 2\.10 has been removed \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/189](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/189)\)\.
* hashi\_vault lookup \- the deprecated <code>\[lookup\_hashi\_vault\]</code> INI config section has been removed in favor of the collection\-wide <code>\[hashi\_vault\_collection\]</code> section \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/179](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/179)\)\.

<a id="v2-5-0"></a>
## v2\.5\.0

<a id="release-summary-18"></a>
### Release Summary

This release finally contains dedicated KV plugins and modules\, and an exciting new lookup to help use plugin values in module calls\.
With that\, we also have a guide in the collection docsite for migrating away from the <code>hashi\_vault</code> lookup toward dedicated content\.
We are also announcing that the <code>token\_validate</code> option will change its default value in version 4\.0\.0\.
This is the last planned release before 3\.0\.0\. See the porting guide for breaking changes and removed features in the next version\.

<a id="minor-changes-6"></a>
### Minor Changes

* vault\_login module \& lookup \- no friendly error message was given when <code>hvac</code> was missing \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257)\)\.
* vault\_pki\_certificate \- add <code>vault\_pki\_certificate</code> to the <code>community\.hashi\_vault\.vault</code> action group \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251)\)\.
* vault\_read module \& lookup \- no friendly error message was given when <code>hvac</code> was missing \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257)\)\.
* vault\_token\_create \- add <code>vault\_token\_create</code> to the <code>community\.hashi\_vault\.vault</code> action group \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251)\)\.
* vault\_token\_create module \& lookup \- no friendly error message was given when <code>hvac</code> was missing \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/257)\)\.
* vault\_write \- add <code>vault\_write</code> to the <code>community\.hashi\_vault\.vault</code> action group \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/251)\)\.

<a id="deprecated-features-5"></a>
### Deprecated Features

* token\_validate options \- the shared auth option <code>token\_validate</code> will change its default from <code>True</code> to <code>False</code> in community\.hashi\_vault version 4\.0\.0\. The <code>vault\_login</code> lookup and module will keep the default value of <code>True</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/248)\)\.

<a id="new-plugins-1"></a>
### New Plugins

<a id="lookup-1"></a>
#### Lookup

* vault\_ansible\_settings \- Returns plugin settings \(options\)
* vault\_kv1\_get \- Get a secret from HashiCorp Vault\'s KV version 1 secret store
* vault\_kv2\_get \- Get a secret from HashiCorp Vault\'s KV version 2 secret store

<a id="new-modules-4"></a>
### New Modules

* vault\_kv1\_get \- Get a secret from HashiCorp Vault\'s KV version 1 secret store
* vault\_kv2\_get \- Get a secret from HashiCorp Vault\'s KV version 2 secret store

<a id="v2-4-0"></a>
## v2\.4\.0

<a id="release-summary-19"></a>
### Release Summary

Our first content for writing to Vault is now live\.

<a id="new-plugins-2"></a>
### New Plugins

<a id="lookup-2"></a>
#### Lookup

* vault\_write \- Perform a write operation against HashiCorp Vault

<a id="new-modules-5"></a>
### New Modules

* vault\_write \- Perform a write operation against HashiCorp Vault

<a id="v2-3-0"></a>
## v2\.3\.0

<a id="release-summary-20"></a>
### Release Summary

This release contains new plugins and modules for creating tokens and for generating certificates with Vault\'s PKI secrets engine\.

<a id="new-plugins-3"></a>
### New Plugins

<a id="lookup-3"></a>
#### Lookup

* vault\_token\_create \- Create a HashiCorp Vault token

<a id="new-modules-6"></a>
### New Modules

* vault\_pki\_generate\_certificate \- Generates a new set of credentials \(private key and certificate\) using HashiCorp Vault PKI
* vault\_token\_create \- Create a HashiCorp Vault token

<a id="v2-2-0"></a>
## v2\.2\.0

<a id="release-summary-21"></a>
### Release Summary

This release contains a new lookup/module combo for logging in to Vault\, and includes our first filter plugin\.

<a id="minor-changes-7"></a>
### Minor Changes

* The Filter guide has been added to the collection\'s docsite\.

<a id="new-plugins-4"></a>
### New Plugins

<a id="filter"></a>
#### Filter

* vault\_login\_token \- Extracts the client token from a Vault login response

<a id="lookup-4"></a>
#### Lookup

* vault\_login \- Perform a login operation against HashiCorp Vault

<a id="new-modules-7"></a>
### New Modules

* vault\_login \- Perform a login operation against HashiCorp Vault

<a id="v2-1-0"></a>
## v2\.1\.0

<a id="release-summary-22"></a>
### Release Summary

The most important change in this release is renaming the <code>aws\_iam\_login</code> auth method to <code>aws\_iam</code> and deprecating the old name\. This release also announces the deprecation of Ansible 2\.9 and ansible\-base 2\.10 support in 3\.0\.0\.

<a id="deprecated-features-6"></a>
### Deprecated Features

* Support for Ansible 2\.9 and ansible\-base 2\.10 is deprecated\, and will be removed in the next major release \(community\.hashi\_vault 3\.0\.0\) next spring \([https\://github\.com/ansible\-community/community\-topics/issues/50](https\://github\.com/ansible\-community/community\-topics/issues/50)\, [https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/189](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/189)\)\.
* aws\_iam\_login auth method \- the <code>aws\_iam\_login</code> method has been renamed to <code>aws\_iam</code>\. The old name will be removed in collection version <code>3\.0\.0</code>\. Until then both names will work\, and a warning will be displayed when using the old name \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/193](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/193)\)\.

<a id="removed-features-previously-deprecated-2"></a>
### Removed Features \(previously deprecated\)

* the \"legacy\" integration test setup has been removed\; this does not affect end users and is only relevant to contributors \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/191](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/191)\)\.

<a id="v2-0-0"></a>
## v2\.0\.0

<a id="release-summary-23"></a>
### Release Summary

Version 2\.0\.0 of the collection drops support for Python 2 \& Python 3\.5\, making Python 3\.6 the minimum supported version\.
Some deprecated features and settings have been removed as well\.

<a id="breaking-changes--porting-guide-4"></a>
### Breaking Changes / Porting Guide

* connection options \- there is no longer a default value for the <code>url</code> option \(the Vault address\)\, so a value must be supplied \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/83](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/83)\)\.

<a id="removed-features-previously-deprecated-3"></a>
### Removed Features \(previously deprecated\)

* drop support for Python 2 and Python 3\.5 \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81)\)\.
* support for the following deprecated environment variables has been removed\: <code>VAULT\_AUTH\_METHOD</code>\, <code>VAULT\_TOKEN\_PATH</code>\, <code>VAULT\_TOKEN\_FILE</code>\, <code>VAULT\_ROLE\_ID</code>\, <code>VAULT\_SECRET\_ID</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/173](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/173)\)\.

<a id="v1-5-0"></a>
## v1\.5\.0

<a id="release-summary-24"></a>
### Release Summary

This release includes a new action group for use with <code>module\_defaults</code>\, and additional ways of specifying the <code>mount\_point</code> option for plugins\.
This will be the last <code>1\.x</code> release\.

<a id="minor-changes-8"></a>
### Minor Changes

* add the <code>community\.hashi\_vault\.vault</code> action group \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/172](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/172)\)\.
* auth methods \- Add support for configuring the <code>mount\_point</code> auth method option in plugins via the <code>ANSIBLE\_HASHI\_VAULT\_MOUNT\_POINT</code> environment variable\, <code>ansible\_hashi\_vault\_mount\_point</code> ansible variable\, or <code>mount\_point</code> INI section \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/171](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/171)\)\.

<a id="v1-4-1"></a>
## v1\.4\.1

<a id="release-summary-25"></a>
### Release Summary

This release contains a bugfix for <code>aws\_iam\_login</code> authentication\.

<a id="bugfixes-6"></a>
### Bugfixes

* aws\_iam\_login auth method \- fix incorrect use of <code>boto3</code>/<code>botocore</code> that prevented proper loading of AWS IAM role credentials \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/167](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/167)\)\.

<a id="v1-4-0"></a>
## v1\.4\.0

<a id="release-summary-26"></a>
### Release Summary

This release includes bugfixes\, a new auth method \(<code>cert</code>\)\, and the first new content since the collection\'s formation\, the <code>vault\_read</code> module and lookup plugin\.
We\'re also announcing the deprecation of the <code>\[lookup\_hashi\_vault\]</code> INI section \(which will continue working up until its removal only for the <code>hashi\_vault</code> lookup\)\, to be replaced by the <code>\[hashi\_vault\_collection\]</code> section that will apply to all plugins in the collection\.

<a id="minor-changes-9"></a>
### Minor Changes

* community\.hashi\_vault collection \- add cert auth method \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/159](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/159)\)\.

<a id="deprecated-features-7"></a>
### Deprecated Features

* lookup hashi\_vault \- the <code>\[lookup\_hashi\_vault\]</code> section in the <code>ansible\.cfg</code> file is deprecated and will be removed in collection version <code>3\.0\.0</code>\. Instead\, the section <code>\[hashi\_vault\_collection\]</code> can be used\, which will apply to all plugins in the collection going forward \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/144](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/144)\)\.

<a id="bugfixes-7"></a>
### Bugfixes

* aws\_iam\_login auth \- the <code>aws\_security\_token</code> option was not used\, causing assumed role credentials to fail \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/160](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/160)\)\.
* hashi\_vault collection \- a fallback import supporting the <code>retries</code> option for <code>urllib3</code> via <code>requests\.packages\.urllib3</code> was not correctly formed \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/116](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/116)\)\.
* hashi\_vault collection \- unhandled exception with <code>token</code> auth when <code>token\_file</code> exists but is a directory \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/152](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/152)\)\.

<a id="new-plugins-5"></a>
### New Plugins

<a id="lookup-5"></a>
#### Lookup

* vault\_read \- Perform a read operation against HashiCorp Vault

<a id="new-modules-8"></a>
### New Modules

* vault\_read \- Perform a read operation against HashiCorp Vault

<a id="v1-3-2"></a>
## v1\.3\.2

<a id="release-summary-27"></a>
### Release Summary

This release adds requirements detection support for Ansible Execution Environments\. It also updates and adds new guides in our [collection docsite](https\://docs\.ansible\.com/ansible/devel/collections/community/hashi\_vault)\.
This release also announces the dropping of Python 3\.5 support in version <code>2\.0\.0</code> of the collection\, alongside the previous announcement dropping Python 2\.x in <code>2\.0\.0</code>\.

<a id="minor-changes-10"></a>
### Minor Changes

* hashi\_vault collection \- add <code>execution\-environment\.yml</code> and a python requirements file to better support <code>ansible\-builder</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/105](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/105)\)\.

<a id="deprecated-features-8"></a>
### Deprecated Features

* hashi\_vault collection \- support for Python 3\.5 will be dropped in version <code>2\.0\.0</code> of <code>community\.hashi\_vault</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81)\)\.

<a id="v1-3-1"></a>
## v1\.3\.1

<a id="release-summary-28"></a>
### Release Summary

This release fixes an error in the documentation\. No functionality is changed so it\'s not necessary to upgrade from <code>1\.3\.0</code>\.

<a id="v1-3-0"></a>
## v1\.3\.0

<a id="release-summary-29"></a>
### Release Summary

This release adds two connection\-based options for controlling timeouts and retrying failed Vault requests\.

<a id="minor-changes-11"></a>
### Minor Changes

* hashi\_vault lookup \- add <code>retries</code> and <code>retry\_action</code> to enable built\-in retry on failure \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/71](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/71)\)\.
* hashi\_vault lookup \- add <code>timeout</code> option to control connection timeouts \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/100](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/100)\)\.

<a id="v1-2-0"></a>
## v1\.2\.0

<a id="release-summary-30"></a>
### Release Summary

This release brings several new ways of accessing options\, like using Ansible vars\, and addng new environment variables and INI config entries\.
A special <code>none</code> auth type is also added\, for working with certain Vault Agent configurations\.
This release also announces the deprecation of Python 2 support in version <code>2\.0\.0</code> of the collection\.

<a id="minor-changes-12"></a>
### Minor Changes

* hashi\_vault lookup \- add <code>ANSIBLE\_HASHI\_VAULT\_CA\_CERT</code> env var \(with <code>VAULT\_CACERT</code> low\-precedence fallback\) for <code>ca\_cert</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97)\)\.
* hashi\_vault lookup \- add <code>ANSIBLE\_HASHI\_VAULT\_PASSWORD</code> env var and <code>ansible\_hashi\_vault\_password</code> ansible var for <code>password</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/96](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/96)\)\.
* hashi\_vault lookup \- add <code>ANSIBLE\_HASHI\_VAULT\_USERNAME</code> env var and <code>ansible\_hashi\_vault\_username</code> ansible var for <code>username</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/96](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/96)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_auth\_method</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_ca\_cert</code> ansible var for <code>ca\_cert</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_namespace</code> Ansible vars entry to the <code>namespace</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_proxies</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_role\_id</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_secret\_id</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_token\_file</code> Ansible vars entry to the <code>token\_file</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_token\_path</code> Ansible vars entry to the <code>token\_path</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_token\_validate</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_token</code> Ansible vars entry to the <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_url</code> and <code>ansible\_hashi\_vault\_addr</code> Ansible vars entries to the <code>url</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/86)\)\.
* hashi\_vault lookup \- add <code>ansible\_hashi\_vault\_validate\_certs</code> Ansible vars entry to the <code>validate\_certs</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/95)\)\.
* hashi\_vault lookup \- add <code>ca\_cert</code> INI config file key <code>ca\_cert</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/97)\)\.
* hashi\_vault lookup \- add <code>none</code> auth type which allows for passive auth via a Vault agent \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/80](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/80)\)\.

<a id="deprecated-features-9"></a>
### Deprecated Features

* hashi\_vault collection \- support for Python 2 will be dropped in version <code>2\.0\.0</code> of <code>community\.hashi\_vault</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/81)\)\.

<a id="v1-1-3"></a>
## v1\.1\.3

<a id="release-summary-31"></a>
### Release Summary

This release fixes a bug with <code>userpass</code> authentication and <code>hvac</code> versions 0\.9\.6 and higher\.

<a id="bugfixes-8"></a>
### Bugfixes

* hashi\_vault \- userpass authentication did not work with hvac 0\.9\.6 or higher \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/68](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/68)\)\.

<a id="v1-1-2"></a>
## v1\.1\.2

<a id="release-summary-32"></a>
### Release Summary

This release contains the same functionality as 1\.1\.1\. The only change is to mark some code as internal to the collection\. If you are already using 1\.1\.1 as an end user you do not need to update\.

<a id="v1-1-1"></a>
## v1\.1\.1

<a id="release-summary-33"></a>
### Release Summary

This bugfix release restores the use of the <code>VAULT\_ADDR</code> environment variable for setting the <code>url</code> option\.
See the PR linked from the changelog entry for details and workarounds if you cannot upgrade\.

<a id="bugfixes-9"></a>
### Bugfixes

* hashi\_vault \- restore use of <code>VAULT\_ADDR</code> environment variable as a low preference env var \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/61](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/61)\)\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-34"></a>
### Release Summary

This release contains a new <code>proxies</code> option for the <code>hashi\_vault</code> lookup\.

<a id="minor-changes-13"></a>
### Minor Changes

* hashi\_vault \- add <code>proxies</code> option \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/50](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/50)\)\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-35"></a>
### Release Summary

Our first major release contains a single breaking change that will affect only a small subset of users\. No functionality is removed\. See the details in the changelog to determine if you\'re affected and if so how to transition to remediate\.

<a id="breaking-changes--porting-guide-5"></a>
### Breaking Changes / Porting Guide

* hashi\_vault \- the <code>VAULT\_ADDR</code> environment variable is now checked last for the <code>url</code> parameter\. For details on which use cases are impacted\, see \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8)\)\.

<a id="v0-2-0"></a>
## v0\.2\.0

<a id="release-summary-36"></a>
### Release Summary

Several backwards\-compatible bugfixes and enhancements in this release\.
Some environment variables are deprecated and have standardized replacements\.

<a id="minor-changes-14"></a>
### Minor Changes

* Add optional <code>aws\_iam\_server\_id</code> parameter as the value for <code>X\-Vault\-AWS\-IAM\-Server\-ID</code> header \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/27](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/27)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_ADDR</code> environment variable added for option <code>url</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_AUTH\_METHOD</code> environment variable added for option <code>auth\_method</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/17](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/17)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_ROLE\_ID</code> environment variable added for option <code>role\_id</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_SECRET\_ID</code> environment variable added for option <code>secret\_id</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_TOKEN\_FILE</code> environment variable added for option <code>token\_file</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15)\)\.
* hashi\_vault \- <code>ANSIBLE\_HASHI\_VAULT\_TOKEN\_PATH</code> environment variable added for option <code>token\_path</code> \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15)\)\.
* hashi\_vault \- <code>namespace</code> parameter can be specified in INI or via env vars <code>ANSIBLE\_HASHI\_VAULT\_NAMESPACE</code> \(new\) and <code>VAULT\_NAMESPACE</code> \(lower preference\)  \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/14](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/14)\)\.
* hashi\_vault \- <code>token</code> parameter can now be specified via <code>ANSIBLE\_HASHI\_VAULT\_TOKEN</code> as well as via <code>VAULT\_TOKEN</code> \(the latter with lower preference\) \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/16](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/16)\)\.
* hashi\_vault \- add <code>token\_validate</code> option to control token validation \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/24](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/24)\)\.
* hashi\_vault \- uses new AppRole method in hvac 0\.10\.6 with fallback to deprecated method with warning \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/33](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/33)\)\.

<a id="deprecated-features-10"></a>
### Deprecated Features

* hashi\_vault \- <code>VAULT\_ADDR</code> environment variable for option <code>url</code> will have its precedence lowered in 1\.0\.0\; use <code>ANSIBLE\_HASHI\_VAULT\_ADDR</code> to intentionally override a config value \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/8)\)\.
* hashi\_vault \- <code>VAULT\_AUTH\_METHOD</code> environment variable for option <code>auth\_method</code> will be removed in 2\.0\.0\, use <code>ANSIBLE\_HASHI\_VAULT\_AUTH\_METHOD</code> instead \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/17](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/17)\)\.
* hashi\_vault \- <code>VAULT\_ROLE\_ID</code> environment variable for option <code>role\_id</code> will be removed in 2\.0\.0\, use <code>ANSIBLE\_HASHI\_VAULT\_ROLE\_ID</code> instead \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20)\)\.
* hashi\_vault \- <code>VAULT\_SECRET\_ID</code> environment variable for option <code>secret\_id</code> will be removed in 2\.0\.0\, use <code>ANSIBLE\_HASHI\_VAULT\_SECRET\_ID</code> instead \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/20)\)\.
* hashi\_vault \- <code>VAULT\_TOKEN\_FILE</code> environment variable for option <code>token\_file</code> will be removed in 2\.0\.0\, use <code>ANSIBLE\_HASHI\_VAULT\_TOKEN\_FILE</code> instead \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15)\)\.
* hashi\_vault \- <code>VAULT\_TOKEN\_PATH</code> environment variable for option <code>token\_path</code> will be removed in 2\.0\.0\, use <code>ANSIBLE\_HASHI\_VAULT\_TOKEN\_PATH</code> instead \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/15)\)\.

<a id="bugfixes-10"></a>
### Bugfixes

* hashi\_vault \- <code>mount\_point</code> parameter did not work with <code>aws\_iam\_login</code> auth method \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/7](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/7)\)
* hashi\_vault \- fallback logic for handling deprecated style of auth in hvac was not implemented correctly \([https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/33](https\://github\.com/ansible\-collections/community\.hashi\_vault/pull/33)\)\.
* hashi\_vault \- parameter <code>mount\_point</code> does not work with JWT auth \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/29](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/29)\)\.
* hashi\_vault \- tokens without <code>lookup\-self</code> ability can\'t be used because of validation \([https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/18](https\://github\.com/ansible\-collections/community\.hashi\_vault/issues/18)\)\.

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-37"></a>
### Release Summary

Our first release matches the <code>hashi\_vault</code> lookup functionality provided by <code>community\.general</code> version <code>1\.3\.0</code>\.
