# Community Inventory Filtering Library Collection Release Notes

**Topics**

- <a href="#v1-1-5">v1\.1\.5</a>
    - <a href="#release-summary">Release Summary</a>
    - <a href="#bugfixes">Bugfixes</a>
- <a href="#v1-1-4">v1\.1\.4</a>
    - <a href="#release-summary-1">Release Summary</a>
    - <a href="#bugfixes-1">Bugfixes</a>
- <a href="#v1-1-3">v1\.1\.3</a>
    - <a href="#release-summary-2">Release Summary</a>
    - <a href="#bugfixes-2">Bugfixes</a>
- <a href="#v1-1-2">v1\.1\.2</a>
    - <a href="#release-summary-3">Release Summary</a>
    - <a href="#bugfixes-3">Bugfixes</a>
- <a href="#v1-1-1">v1\.1\.1</a>
    - <a href="#release-summary-4">Release Summary</a>
- <a href="#v1-1-0">v1\.1\.0</a>
    - <a href="#release-summary-5">Release Summary</a>
    - <a href="#minor-changes">Minor Changes</a>
    - <a href="#bugfixes-4">Bugfixes</a>
- <a href="#v1-0-2">v1\.0\.2</a>
    - <a href="#release-summary-6">Release Summary</a>
- <a href="#v1-0-1">v1\.0\.1</a>
    - <a href="#release-summary-7">Release Summary</a>
- <a href="#v1-0-0">v1\.0\.0</a>
    - <a href="#release-summary-8">Release Summary</a>
- <a href="#v0-1-0">v0\.1\.0</a>
    - <a href="#release-summary-9">Release Summary</a>

<a id="v1-1-5"></a>
## v1\.1\.5

<a id="release-summary"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes"></a>
### Bugfixes

* Improve and stricten typing information \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/42](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/42)\)\.

<a id="v1-1-4"></a>
## v1\.1\.4

<a id="release-summary-1"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-1"></a>
### Bugfixes

* Fix accidental type extensions \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/40](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/40)\)\.

<a id="v1-1-3"></a>
## v1\.1\.3

<a id="release-summary-2"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-2"></a>
### Bugfixes

* Stop using <code>ansible\.module\_utils\.six</code> to avoid user\-facing deprecation messages with ansible\-core 2\.20\, while still supporting older ansible\-core versions \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/39](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/39)\)\.

<a id="v1-1-2"></a>
## v1\.1\.2

<a id="release-summary-3"></a>
### Release Summary

Maintenance release\.

<a id="bugfixes-3"></a>
### Bugfixes

* Avoid deprecated functionality in ansible\-core 2\.20 \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/38](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/38)\)\.

<a id="v1-1-1"></a>
## v1\.1\.1

<a id="release-summary-4"></a>
### Release Summary

Maintenance release\.

<a id="v1-1-0"></a>
## v1\.1\.0

<a id="release-summary-5"></a>
### Release Summary

Feature\, bugfix\, and maintenance release with support for Data Tagging\.

<a id="minor-changes"></a>
### Minor Changes

* Add typing information for the <code>inventory\_filter</code> plugin utils \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/22](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/22)\)\.

<a id="bugfixes-4"></a>
### Bugfixes

* inventory\_filter plugin utils \- make compatible with ansible\-core\'s Data Tagging feature \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/24](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/24)\)\.
* inventory\_plugin plugin util \- <code>parse\_filters</code> now filters <code>None</code> values with allowed keys \([https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/27](https\://github\.com/ansible\-collections/community\.library\_inventory\_filtering/pull/27)\)\.

<a id="v1-0-2"></a>
## v1\.0\.2

<a id="release-summary-6"></a>
### Release Summary

Maintenance release with updated links\.

<a id="v1-0-1"></a>
## v1\.0\.1

<a id="release-summary-7"></a>
### Release Summary

Maintenance release with documentation\.

<a id="v1-0-0"></a>
## v1\.0\.0

<a id="release-summary-8"></a>
### Release Summary

First production ready release\.

<a id="v0-1-0"></a>
## v0\.1\.0

<a id="release-summary-9"></a>
### Release Summary

Initial test release\.
