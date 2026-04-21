# Changelog

## [1.18.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.18.0) (2021-06-14)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.17.0...1.18.0)

**Merged pull requests:**

- add period to notification task [\#121](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/121) ([michaelamattes](https://github.com/michaelamattes))
- add info about documentation [\#120](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/120) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.17.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.17.0) (2021-05-09)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.16.0...1.17.0)

**Merged pull requests:**

- add timeperiod\_template and corresponding info module [\#118](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/118) ([rndmh3ro](https://github.com/rndmh3ro))
- add ansible-2.11 to CI [\#117](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/117) ([rndmh3ro](https://github.com/rndmh3ro))
- Improve Release Action [\#116](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/116) ([schurzi](https://github.com/schurzi))

## [1.16.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.16.0) (2021-03-05)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.15.0...1.16.0)

**Implemented enhancements:**

- add Usergroups modules [\#114](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/114) ([rndmh3ro](https://github.com/rndmh3ro))

**Closed issues:**

- Add support to specify user Groups in icinga Notifications [\#111](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/111)
- icinga\_notification | time period [\#109](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/109)

**Merged pull requests:**

- Update installation instructions in README.md [\#115](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/115) ([rndmh3ro](https://github.com/rndmh3ro))
- update notification modules - add option user\_groups [\#112](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/112) ([sgruber94](https://github.com/sgruber94))

## [1.15.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.15.0) (2021-02-12)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.14.0...1.15.0)

**Implemented enhancements:**

- Add support to change the check\_source / command\_endpoint parameter [\#107](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/107)
- add new options to notification and notification template [\#110](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/110) ([rndmh3ro](https://github.com/rndmh3ro))
- Add support to change the check\_source / command\_endpoint parameter [\#108](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/108) ([xFuture603](https://github.com/xFuture603))

**Fixed bugs:**

- fix naming for timeperiod test task [\#102](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/102) ([BenjaminBoehm](https://github.com/BenjaminBoehm))

**Closed issues:**

- Support Event Commands [\#100](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/100)

**Merged pull requests:**

- add more test executions to trigger all paths [\#106](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/106) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.14.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.14.0) (2021-02-02)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.13.0...1.14.0)

**Implemented enhancements:**

- Add event commands to modules that support this feature  [\#101](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/101) ([xFuture603](https://github.com/xFuture603))

**Merged pull requests:**

- make it possible to run the script from the root dir and hacking dir [\#105](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/105) ([rndmh3ro](https://github.com/rndmh3ro))
- Fix zone [\#104](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/104) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.13.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.13.0) (2021-02-01)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.12.0...1.13.0)

**Implemented enhancements:**

- add info modules for Director objects [\#98](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/98) ([schurzi](https://github.com/schurzi))

**Closed issues:**

- Append properties [\#96](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/96)
- Provide modules to get information from Icinga Director [\#89](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/89)
- Parameters for check execution at Service Apply level are ignored [\#65](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/65)

**Merged pull requests:**

- update readme with new stuff [\#103](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/103) ([rndmh3ro](https://github.com/rndmh3ro))
- use version for github action, short sha is no longer supported [\#99](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/99) ([schurzi](https://github.com/schurzi))
- remove unneeded return values for host [\#97](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/97) ([schurzi](https://github.com/schurzi))

## [1.12.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.12.0) (2021-01-14)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.11.0...1.12.0)

**Implemented enhancements:**

- Add check\_interval parameter to host\_template [\#95](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/95) ([mmslkr](https://github.com/mmslkr))
- spelling fixes, add notes-section, remove useless sections [\#94](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/94) ([rndmh3ro](https://github.com/rndmh3ro))
- Add execution params [\#67](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/67) ([AnBenn](https://github.com/AnBenn))

## [1.11.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.11.0) (2021-01-12)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.10.1...1.11.0)

**Fixed bugs:**

- add back url parameter [\#92](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/92) ([rndmh3ro](https://github.com/rndmh3ro))

**Merged pull requests:**

- remove period from short description [\#93](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/93) ([rndmh3ro](https://github.com/rndmh3ro))
- remove unneeded return values [\#88](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/88) ([schurzi](https://github.com/schurzi))

## [1.10.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.10.1) (2021-01-11)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.10.0...1.10.1)

**Implemented enhancements:**

- Update tests [\#86](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/86) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.10.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.10.0) (2021-01-11)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.9.1...1.10.0)

**Implemented enhancements:**

- change class to make compatible for python2 [\#84](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/84) ([rndmh3ro](https://github.com/rndmh3ro))
- add version\_added to modules and module options [\#82](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/82) ([rndmh3ro](https://github.com/rndmh3ro))
- add docstrings to the functions of the icinga class [\#81](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/81) ([rndmh3ro](https://github.com/rndmh3ro))
- add name alias for object\_name [\#80](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/80) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- Fix url spec [\#85](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/85) ([rndmh3ro](https://github.com/rndmh3ro))
- fix spelling in module docs [\#83](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/83) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.9.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.9.1) (2021-01-06)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.9.0...1.9.1)

**Implemented enhancements:**

- use doc\_fragments for modules documentation [\#78](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/78) ([rndmh3ro](https://github.com/rndmh3ro))
- added wished files and directories to build\_ignore list [\#77](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/77) ([xFuture603](https://github.com/xFuture603))

**Closed issues:**

- Update module docs with FQCN [\#61](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/61)
- Add meta directory with runtime.yml to collection [\#60](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/60)
- Remove unwanted files from release-tarball [\#58](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/58)

**Merged pull requests:**

- fix copyright notice in all files [\#79](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/79) ([rndmh3ro](https://github.com/rndmh3ro))
- use fqcn in all examples, fix example and test generation [\#76](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/76) ([rndmh3ro](https://github.com/rndmh3ro))
- Create CONTRIBUTING.md [\#74](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/74) ([rndmh3ro](https://github.com/rndmh3ro))
- Create runtime.yml [\#72](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/72) ([rndmh3ro](https://github.com/rndmh3ro))
- Create LICENSE [\#71](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/71) ([rndmh3ro](https://github.com/rndmh3ro))
- run tests on a schedule [\#70](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/70) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.9.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.9.0) (2020-12-14)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.8.1...1.9.0)

**Implemented enhancements:**

- add vars option to icinga\_notification [\#68](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/68) ([rndmh3ro](https://github.com/rndmh3ro))
- improve support for API parameters [\#66](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/66) ([schurzi](https://github.com/schurzi))
- Notification templates [\#64](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/64) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- fixed "command is missing" while trying to create a command [\#69](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/69) ([xFuture603](https://github.com/xFuture603))

**Closed issues:**

- icinga\_commands with "imports" not working [\#63](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/63)
- Add ability to create notification\_template [\#62](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/62)
- Can't use fields available in API - e.g. host\_template - has\_agent [\#59](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/59)

## [1.8.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.8.1) (2020-11-05)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.8.0...1.8.1)

**Implemented enhancements:**

- Unsupported parameter "Notes" for icinga\_host [\#50](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/50)
- added vsc code snippets [\#57](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/57) ([xFuture603](https://github.com/xFuture603))

## [1.8.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.8.0) (2020-10-28)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.7.1...1.8.0)

**Implemented enhancements:**

- Add support for notes and notes\_url to all relevant objects [\#56](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/56) ([mmslkr](https://github.com/mmslkr))

## [1.7.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.7.1) (2020-10-26)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.7.0...1.7.1)

**Fixed bugs:**

- Icinga Object "Service" rerun - failed to recreate if object\_name contains spaces [\#52](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/52)
- allow using whitespaces in object names [\#55](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/55) ([schurzi](https://github.com/schurzi))

**Merged pull requests:**

- improve coverage of new service module [\#51](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/51) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.7.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.7.0) (2020-10-23)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.6.0...1.7.0)

**Implemented enhancements:**

- update examples and tests so they can actually be deployed [\#54](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/54) ([rndmh3ro](https://github.com/rndmh3ro))
- add check\_command arg to service\_apply module [\#53](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/53) ([rndmh3ro](https://github.com/rndmh3ro))

**Closed issues:**

- Add object "Service" for a Host [\#42](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/42)

## [1.6.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.6.0) (2020-10-22)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.5.0...1.6.0)

**Implemented enhancements:**

- add new service module [\#32](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/32) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.5.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.5.0) (2020-10-02)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.4.3...1.5.0)

**Implemented enhancements:**

- Add Support for Zones and Endpoints [\#48](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/48) ([arbu](https://github.com/arbu))
- Create codeql-analysis.yml [\#47](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/47) ([rndmh3ro](https://github.com/rndmh3ro))

**Merged pull requests:**

- add example and test for command without args [\#46](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/46) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.4.3](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.4.3) (2020-10-01)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.4.2...1.4.3)

**Fixed bugs:**

- Hosts in state absent don't require import parameter [\#44](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/44)
- when deleting objects, only the object\_name is required  [\#45](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/45) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.4.2](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.4.2) (2020-09-25)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.4.1...1.4.2)

**Implemented enhancements:**

- add timeout parameter to icinga\_command.yml [\#43](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/43) ([AnBenn](https://github.com/AnBenn))

## [1.4.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.4.1) (2020-09-02)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.4.0...1.4.1)

**Implemented enhancements:**

- make local testing without ansible-test work [\#41](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/41) ([rndmh3ro](https://github.com/rndmh3ro))
- Add more Integrationtests [\#39](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/39) ([rndmh3ro](https://github.com/rndmh3ro))
- Testing update [\#38](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/38) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- No IPv6-Address Variable for Hosts [\#36](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/36)

**Merged pull requests:**

- add badge to readme [\#40](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/40) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.4.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.4.0) (2020-08-04)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.3.2...1.4.0)

**Implemented enhancements:**

- add support for address6 on host object [\#37](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/37) ([schurzi](https://github.com/schurzi))

## [1.3.2](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.3.2) (2020-07-15)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.3.1...1.3.2)

**Implemented enhancements:**

- make local testing without ansible-test easier [\#33](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/33) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- added code in icinga\_command.yml to make it work like the other tasks in our role [\#35](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/35) ([xFuture603](https://github.com/xFuture603))

**Merged pull requests:**

- update examples and bash script for new testing paths [\#31](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/31) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.3.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.3.1) (2020-07-07)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.3.0...1.3.1)

**Merged pull requests:**

- replace hyphen in role name with underscore [\#29](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/29) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.3.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.3.0) (2020-07-07)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.2.2...1.3.0)

**Implemented enhancements:**

- Ansible icinga role [\#28](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/28) ([michaelamattes](https://github.com/michaelamattes))

## [1.2.2](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.2.2) (2020-06-26)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.2.1...1.2.2)

**Implemented enhancements:**

- Use ansible-test to run integration tests [\#27](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/27) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- zone: defaults to master but i do not want to configure zone at all. [\#25](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/25)

**Merged pull requests:**

- do not set zone to master in host and hosttemplate [\#26](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/26) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.2.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.2.1) (2020-06-25)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.2.0...1.2.1)

**Implemented enhancements:**

- Integration testing [\#24](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/24) ([rndmh3ro](https://github.com/rndmh3ro))
- Add proper linting [\#22](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/22) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.2.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.2.0) (2020-06-24)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.1.4...1.2.0)

**Implemented enhancements:**

- add gitattributes because of windows line endings [\#21](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/21) ([rndmh3ro](https://github.com/rndmh3ro))
- add icinga\_host\_template [\#20](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/20) ([michaelamattes](https://github.com/michaelamattes))
- add troubleshooting section [\#19](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/19) ([rndmh3ro](https://github.com/rndmh3ro))

**Fixed bugs:**

- do not require import and check\_command in host\_template [\#23](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/23) ([rndmh3ro](https://github.com/rndmh3ro))

**Closed issues:**

- Error creating servicegroups [\#13](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/13)

## [1.1.4](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.1.4) (2020-06-12)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.1.3...1.1.4)

**Implemented enhancements:**

- further improve error messages for different errors [\#18](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/18) ([rndmh3ro](https://github.com/rndmh3ro))
- added required ansible version to readme.md [\#17](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/17) ([xFuture603](https://github.com/xFuture603))

## [1.1.3](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.1.3) (2020-06-09)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.1.2...1.1.3)

**Implemented enhancements:**

- try to improve error messages [\#16](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/16) ([rndmh3ro](https://github.com/rndmh3ro))
- add steps to update galaxy.yml in publish action [\#15](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/15) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.1.2](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.1.2) (2020-06-09)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.1.1...1.1.2)

**Implemented enhancements:**

- add action to publish to galaxy [\#14](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/14) ([rndmh3ro](https://github.com/rndmh3ro))
- github-action to automatically create release-drafts [\#12](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/12) ([rndmh3ro](https://github.com/rndmh3ro))
- remove unused intermediate assignments [\#11](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/11) ([schurzi](https://github.com/schurzi))

**Fixed bugs:**

- assign\_filter variable in icinga\_notification module should be a string [\#9](https://github.com/telekom-mms/ansible-collection-icinga-director/issues/9)

## [1.1.1](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.1.1) (2020-06-04)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.1.0...1.1.1)

**Implemented enhancements:**

- fix issue \#9 - define assign\_filter as string [\#10](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/10) ([FLiPp3r90](https://github.com/FLiPp3r90))

## [1.1.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.1.0) (2020-05-25)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/1.0.0...1.1.0)

**Implemented enhancements:**

- Add icinga command template [\#8](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/8) ([mmslkr](https://github.com/mmslkr))

**Fixed bugs:**

- fix name of imports [\#7](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/7) ([rndmh3ro](https://github.com/rndmh3ro))

## [1.0.0](https://github.com/telekom-mms/ansible-collection-icinga-director/tree/1.0.0) (2020-05-15)

[Full Changelog](https://github.com/telekom-mms/ansible-collection-icinga-director/compare/2492296965515a9ac885c6a4874acba8a7475895...1.0.0)

**Merged pull requests:**

- update urls, lowercase name [\#6](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/6) ([rndmh3ro](https://github.com/rndmh3ro))
- replace - with \_ [\#5](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/5) ([rndmh3ro](https://github.com/rndmh3ro))
- alter readme to accommodate for collection [\#4](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/4) ([rndmh3ro](https://github.com/rndmh3ro))
- Linting fixes [\#3](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/3) ([rndmh3ro](https://github.com/rndmh3ro))
- Create main.yml [\#2](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/2) ([rndmh3ro](https://github.com/rndmh3ro))
- Create ansible-lint.yml [\#1](https://github.com/telekom-mms/ansible-collection-icinga-director/pull/1) ([rndmh3ro](https://github.com/rndmh3ro))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
