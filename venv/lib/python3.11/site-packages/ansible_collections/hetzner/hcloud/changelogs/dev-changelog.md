# Changelog

## [5.4.0](https://github.com/ansible-collections/hetzner.hcloud/compare/5.3.1...5.4.0) (2025-10-07)


### Features

* support the new DNS API ([#703](https://github.com/ansible-collections/hetzner.hcloud/issues/703)) ([adddef5](https://github.com/ansible-collections/hetzner.hcloud/commit/adddef5fc07d13fca0b7ff8cf883d84850d9dc14))


### Bug Fixes

* add experimental features maturity ([#698](https://github.com/ansible-collections/hetzner.hcloud/issues/698)) ([1251ee0](https://github.com/ansible-collections/hetzner.hcloud/commit/1251ee0e6f2f0b16cc598b328cd4f4662bef6476))

## [5.3.1](https://github.com/ansible-collections/hetzner.hcloud/compare/5.3.0...5.3.1) (2025-09-29)


### Bug Fixes

* also check server type deprecation after server creation ([#696](https://github.com/ansible-collections/hetzner.hcloud/issues/696)) ([c4dc19c](https://github.com/ansible-collections/hetzner.hcloud/commit/c4dc19c6750afa26269f77b8bc855175fcc01516))

## [5.3.0](https://github.com/ansible-collections/hetzner.hcloud/compare/5.2.0...5.3.0) (2025-09-26)


### Features

* per location server types ([#692](https://github.com/ansible-collections/hetzner.hcloud/issues/692)) ([826e6a5](https://github.com/ansible-collections/hetzner.hcloud/commit/826e6a5309b3b46d1a0a1d43933efe2439ff1fd3))
* return server type category ([#687](https://github.com/ansible-collections/hetzner.hcloud/issues/687)) ([3d809cb](https://github.com/ansible-collections/hetzner.hcloud/commit/3d809cbc6f21d26085e7dd6aaa7768599456f845))


### Bug Fixes

* wait for floating ip assign action ([#694](https://github.com/ansible-collections/hetzner.hcloud/issues/694)) ([c3ec5d1](https://github.com/ansible-collections/hetzner.hcloud/commit/c3ec5d1dcc9e0662c690da06d7f22e7121c46ec0))

## [5.2.0](https://github.com/ansible-collections/hetzner.hcloud/compare/5.1.0...5.2.0) (2025-08-14)


### Features

* allow renaming a volume ([#683](https://github.com/ansible-collections/hetzner.hcloud/issues/683)) ([8c8a52c](https://github.com/ansible-collections/hetzner.hcloud/commit/8c8a52ceed3bb26c0dfcb0aaf4b9bdb9359b0609))
* warn when experimental features are used ([#669](https://github.com/ansible-collections/hetzner.hcloud/issues/669)) ([36053c7](https://github.com/ansible-collections/hetzner.hcloud/commit/36053c7ee802d26dabcc97bf88013966f8f6411a))


### Bug Fixes

* add `volume_attachment` module to meta ([#655](https://github.com/ansible-collections/hetzner.hcloud/issues/655)) ([e6e4ce1](https://github.com/ansible-collections/hetzner.hcloud/commit/e6e4ce1d5f4117262bc234b14ab87d6e753474d8))

## [5.1.0](https://github.com/ansible-collections/hetzner.hcloud/compare/5.0.1...5.1.0) (2025-06-11)


### Features

* allow recreating ssh key when public key in the API does not match  ([#634](https://github.com/ansible-collections/hetzner.hcloud/issues/634)) ([4fc2003](https://github.com/ansible-collections/hetzner.hcloud/commit/4fc2003f304971ace64be27581b117aa5ad09378))


### Bug Fixes

* ensure returned resource ids are integers ([#651](https://github.com/ansible-collections/hetzner.hcloud/issues/651)) ([579b34e](https://github.com/ansible-collections/hetzner.hcloud/commit/579b34e754a53a10522e5edcd5994133ba653f42))

## [5.0.1](https://github.com/ansible-collections/hetzner.hcloud/compare/5.0.0...5.0.1) (2025-05-21)


### Bug Fixes

* remove deprecated force_upgrade argument ([#637](https://github.com/ansible-collections/hetzner.hcloud/issues/637)) ([88f84e7](https://github.com/ansible-collections/hetzner.hcloud/commit/88f84e7d7c41fec1a01aee1229212443472aa591))

## [5.0.0](https://github.com/ansible-collections/hetzner.hcloud/compare/4.3.0...5.0.0) (2025-05-21)


### ⚠ BREAKING CHANGES

* do not detach volume if `server` is not provided ([#632](https://github.com/ansible-collections/hetzner.hcloud/issues/632))
* prevent host variable name collision with ansible reserved names ([#617](https://github.com/ansible-collections/hetzner.hcloud/issues/617))
* drop support for ansible-core 2.16 ([#612](https://github.com/ansible-collections/hetzner.hcloud/issues/612))
* drop support for ansible-core 2.15 ([#611](https://github.com/ansible-collections/hetzner.hcloud/issues/611))

### Features

* add volume_attachment module ([#622](https://github.com/ansible-collections/hetzner.hcloud/issues/622)) ([c37cdf0](https://github.com/ansible-collections/hetzner.hcloud/commit/c37cdf0bc654eeeb987e6407648ce8e6a0aed599))
* allow renaming a server ([#619](https://github.com/ansible-collections/hetzner.hcloud/issues/619)) ([e59e787](https://github.com/ansible-collections/hetzner.hcloud/commit/e59e787d9927041d1c50261476e6df6c58d71869))
* drop support for ansible-core 2.15 ([#611](https://github.com/ansible-collections/hetzner.hcloud/issues/611)) ([92f1354](https://github.com/ansible-collections/hetzner.hcloud/commit/92f135456fa6caff29e832d99db9870ae9c61aaf))
* drop support for ansible-core 2.16 ([#612](https://github.com/ansible-collections/hetzner.hcloud/issues/612)) ([140d150](https://github.com/ansible-collections/hetzner.hcloud/commit/140d1508ccb8adb1d8fc2f64e446e993bfc02336))
* drop support for python 3.8 ([#615](https://github.com/ansible-collections/hetzner.hcloud/issues/615)) ([b82e18f](https://github.com/ansible-collections/hetzner.hcloud/commit/b82e18ffbdf8a584b89d43970f6f0cb63d5ac3b8))


### Bug Fixes

* do not detach volume if `server` is not provided ([#632](https://github.com/ansible-collections/hetzner.hcloud/issues/632)) ([e8fda35](https://github.com/ansible-collections/hetzner.hcloud/commit/e8fda3557cf835e4e711a934b46d4f672f9b517c))
* prevent host variable name collision with ansible reserved names ([#617](https://github.com/ansible-collections/hetzner.hcloud/issues/617)) ([5de425c](https://github.com/ansible-collections/hetzner.hcloud/commit/5de425c90c3ea365ebd24527cce5828a1debd35b))

## [4.3.0](https://github.com/ansible-collections/hetzner.hcloud/compare/4.2.2...4.3.0) (2025-03-21)


### Features

* add new `created` state for idempotent server creation ([#606](https://github.com/ansible-collections/hetzner.hcloud/issues/606)) ([4534cf6](https://github.com/ansible-collections/hetzner.hcloud/commit/4534cf6b9d0fc422e77192d6994b86afb7d4b1df))


### Bug Fixes

* only update load balancer service when changed ([#603](https://github.com/ansible-collections/hetzner.hcloud/issues/603)) ([6956596](https://github.com/ansible-collections/hetzner.hcloud/commit/6956596fd2a4a570834fbfb42fb6194ed5271d59))

## [4.2.2](https://github.com/ansible-collections/hetzner.hcloud/compare/4.2.1...4.2.2) (2024-11-22)


### Bug Fixes

* improve unknown certificate error in `load_balancer_service` ([#570](https://github.com/ansible-collections/hetzner.hcloud/issues/570)) ([fe3bfa9](https://github.com/ansible-collections/hetzner.hcloud/commit/fe3bfa9020323034817013ffb5dc318532cfad20))
* only rebuild existing servers, skip rebuild if it was just created ([#581](https://github.com/ansible-collections/hetzner.hcloud/issues/581)) ([06718d0](https://github.com/ansible-collections/hetzner.hcloud/commit/06718d0db0f928c476d5ca294d1a977b7b8e69f6))

## [4.2.1](https://github.com/ansible-collections/hetzner.hcloud/compare/4.2.0...4.2.1) (2024-09-23)


### Bug Fixes

* **server:** timeout in server creation when waiting on next actions ([#561](https://github.com/ansible-collections/hetzner.hcloud/issues/561)) ([98e9c52](https://github.com/ansible-collections/hetzner.hcloud/commit/98e9c52c74d2ceaa53dfc1c7e5c9f77e166dd865))

## [4.2.0](https://github.com/ansible-collections/hetzner.hcloud/compare/4.1.0...4.2.0) (2024-08-30)


### Features

* compute load balancer targets status using a filter ([#550](https://github.com/ansible-collections/hetzner.hcloud/issues/550)) ([fce8bc9](https://github.com/ansible-collections/hetzner.hcloud/commit/fce8bc9bb971e87cacfeca115fe7be01b0f908d9))


### Bug Fixes

* check label_selector child targets with load_balancer_status filter ([#552](https://github.com/ansible-collections/hetzner.hcloud/issues/552)) ([abdf722](https://github.com/ansible-collections/hetzner.hcloud/commit/abdf72212b73ad1fc67856e88df97b5173ed1767))

## [4.1.0](https://github.com/ansible-collections/hetzner.hcloud/compare/4.0.1...4.1.0) (2024-07-25)


### Features

* deprecate `server_type_info` `included_traffic` return value ([#532](https://github.com/ansible-collections/hetzner.hcloud/issues/532)) ([39aa356](https://github.com/ansible-collections/hetzner.hcloud/commit/39aa356c4c8a8c47b0c510bf3bc217b5bb58dbf5))
* use exponential backoff algorithm when polling actions ([#524](https://github.com/ansible-collections/hetzner.hcloud/issues/524)) ([19e586f](https://github.com/ansible-collections/hetzner.hcloud/commit/19e586fa22708348eca056377d9b8c51401c7cbb))

## [4.0.1](https://github.com/ansible-collections/hetzner.hcloud/compare/4.0.0...4.0.1) (2024-06-11)


### Bug Fixes

* keep deprecated alias for another major version ([#515](https://github.com/ansible-collections/hetzner.hcloud/issues/515)) ([49e21ae](https://github.com/ansible-collections/hetzner.hcloud/commit/49e21ae4febe18c62e44c9abf365fa2feee7e7cc))

## [4.0.0](https://github.com/ansible-collections/hetzner.hcloud/compare/3.1.1...4.0.0) (2024-06-11)


### ⚠ BREAKING CHANGES

* drop support for ansible-core 2.14 ([#512](https://github.com/ansible-collections/hetzner.hcloud/issues/512))

### Features

* drop support for ansible-core 2.14 ([#512](https://github.com/ansible-collections/hetzner.hcloud/issues/512)) ([8157f9a](https://github.com/ansible-collections/hetzner.hcloud/commit/8157f9a250947a7a9b7b3acdb50f78ed28a22903))

## [3.1.1](https://github.com/ansible-collections/hetzner.hcloud/compare/3.1.0...3.1.1) (2024-04-16)


### Bug Fixes

* **inventory:** ensure host ipv6 variable is json serializable ([#496](https://github.com/ansible-collections/hetzner.hcloud/issues/496)) ([a98cf72](https://github.com/ansible-collections/hetzner.hcloud/commit/a98cf72f927bf36ec9745a03bba16c13728154e2))

## [3.1.0](https://github.com/ansible-collections/hetzner.hcloud/compare/3.0.0...3.1.0) (2024-04-15)


### Features

* assign primary ip to a server on create ([#465](https://github.com/ansible-collections/hetzner.hcloud/issues/465)) ([51afb23](https://github.com/ansible-collections/hetzner.hcloud/commit/51afb2316639d3b996b29544534aaeff6122904c))
* rename server `image_allow_deprecated` option ([#487](https://github.com/ansible-collections/hetzner.hcloud/issues/487)) ([d88ecdb](https://github.com/ansible-collections/hetzner.hcloud/commit/d88ecdbccc0da0a61338d23673adf6a6fded211c))
* use resources name or ID in server module arguments ([#484](https://github.com/ansible-collections/hetzner.hcloud/issues/484)) ([7fdefcf](https://github.com/ansible-collections/hetzner.hcloud/commit/7fdefcfa0243b84a3edb58566ec710e4f4a6db8d))


### Bug Fixes

* improve actions waiting timeout based on data ([#488](https://github.com/ansible-collections/hetzner.hcloud/issues/488)) ([0709552](https://github.com/ansible-collections/hetzner.hcloud/commit/07095529a4a23dc380ab4678963da9dceb665fd4))
* return sorted `alias_ips` in `server_network` module ([#458](https://github.com/ansible-collections/hetzner.hcloud/issues/458)) ([1ae6769](https://github.com/ansible-collections/hetzner.hcloud/commit/1ae6769210b1a845084c88c58a545bebc067ca48))
* use empty string to remove server from its placement group ([#489](https://github.com/ansible-collections/hetzner.hcloud/issues/489)) ([00a4fdd](https://github.com/ansible-collections/hetzner.hcloud/commit/00a4fdd58aba74ab7e8e1a26ff59beea452c2add))

## [3.0.0](https://github.com/ansible-collections/hetzner.hcloud/compare/2.5.0...3.0.0) (2024-02-05)


### ⚠ BREAKING CHANGES

* drop support for ansible-core 2.13 ([#450](https://github.com/ansible-collections/hetzner.hcloud/issues/450))
* always return iso-8601 formatted date time ([#453](https://github.com/ansible-collections/hetzner.hcloud/issues/453))
* remove inventory `api_token_env` option ([#454](https://github.com/ansible-collections/hetzner.hcloud/issues/454))

### Features

* drop support for ansible-core 2.13 ([#450](https://github.com/ansible-collections/hetzner.hcloud/issues/450)) ([96f8009](https://github.com/ansible-collections/hetzner.hcloud/commit/96f8009214d5d57357cf165bfa5e7c3507d0d6e1)), closes [#400](https://github.com/ansible-collections/hetzner.hcloud/issues/400)
* **inventory:** allow templating instances hostname ([#455](https://github.com/ansible-collections/hetzner.hcloud/issues/455)) ([be404ef](https://github.com/ansible-collections/hetzner.hcloud/commit/be404ef18165c933fbdd7de92773d38e3426efec))
* remove inventory `api_token_env` option ([#454](https://github.com/ansible-collections/hetzner.hcloud/issues/454)) ([d0c82ae](https://github.com/ansible-collections/hetzner.hcloud/commit/d0c82aec86f844ccb1dcc07ec4acf9eedc87730d))


### Bug Fixes

* allow renaming networks ([#449](https://github.com/ansible-collections/hetzner.hcloud/issues/449)) ([742cfe6](https://github.com/ansible-collections/hetzner.hcloud/commit/742cfe6d7446d0b54240de5342ef8bb9679cff64))
* always return iso-8601 formatted date time ([#453](https://github.com/ansible-collections/hetzner.hcloud/issues/453)) ([55d2616](https://github.com/ansible-collections/hetzner.hcloud/commit/55d26162b329cbb5bcff8ed63e5960bef4a897c8))
* load balancer invalid cookie lifetime value returned ([#452](https://github.com/ansible-collections/hetzner.hcloud/issues/452)) ([86b7662](https://github.com/ansible-collections/hetzner.hcloud/commit/86b76620daf9684edffefcb0f3d3d0220bbe5f2c))

## [2.5.0](https://github.com/ansible-collections/hetzner.hcloud/compare/2.4.1...2.5.0) (2024-02-02)


### Features

* add `hostvars_prefix` and `hostvars_suffix` options to inventory hostvars ([#423](https://github.com/ansible-collections/hetzner.hcloud/issues/423)) ([4e3f89a](https://github.com/ansible-collections/hetzner.hcloud/commit/4e3f89aed3be6f040e304521d69329c313616df5))
* allow forcing the deletion of firewalls that are still in use ([#447](https://github.com/ansible-collections/hetzner.hcloud/issues/447)) ([559d315](https://github.com/ansible-collections/hetzner.hcloud/commit/559d31561ad1e0fcf8dd14523bd3eb4262a8a3c1))
* improve firewall resources management ([#324](https://github.com/ansible-collections/hetzner.hcloud/issues/324)) ([2757fe7](https://github.com/ansible-collections/hetzner.hcloud/commit/2757fe745fcd80409290a453db72e9e6e4016f8f))
* replace `ansible.netcommon` utils with python3 `ipaddress` module ([#416](https://github.com/ansible-collections/hetzner.hcloud/issues/416)) ([4cfdf50](https://github.com/ansible-collections/hetzner.hcloud/commit/4cfdf50b26536c468705c729cdb48d4b2d421571))

## [2.4.1](https://github.com/ansible-collections/hetzner.hcloud/compare/2.4.0...2.4.1) (2023-11-27)


### Bug Fixes

* **inventory:** always use fresh cache on new cached session ([#404](https://github.com/ansible-collections/hetzner.hcloud/issues/404)) ([df7fa04](https://github.com/ansible-collections/hetzner.hcloud/commit/df7fa041494eb3609fcdbe65517a58a6396e0a84))

## [2.4.0](https://github.com/ansible-collections/hetzner.hcloud/compare/2.3.0...2.4.0) (2023-11-24)


### Features

* add `hetzner.hcloud.all` action group ([#396](https://github.com/ansible-collections/hetzner.hcloud/issues/396)) ([6581ed5](https://github.com/ansible-collections/hetzner.hcloud/commit/6581ed50db8fd7a3e7525cb364acd63fec256c3a))
* **inventory:** improve api options ([#397](https://github.com/ansible-collections/hetzner.hcloud/issues/397)) ([9905bd0](https://github.com/ansible-collections/hetzner.hcloud/commit/9905bd0e01ca5a21bb2db94f29a4c5276ffc638b))
* remove `hcloud_` prefix from all modules names ([#390](https://github.com/ansible-collections/hetzner.hcloud/issues/390)) ([933a162](https://github.com/ansible-collections/hetzner.hcloud/commit/933a16249bc224ee135fcf28a2ebb9ad34978d85))
* rename api_endpoint module argument ([#395](https://github.com/ansible-collections/hetzner.hcloud/issues/395)) ([7c9fbf8](https://github.com/ansible-collections/hetzner.hcloud/commit/7c9fbf85a734bc7884ff967680beb1fe422dc0ff))


### Bug Fixes

* **inventory:** improve performance ([#402](https://github.com/ansible-collections/hetzner.hcloud/issues/402)) ([f85d8f4](https://github.com/ansible-collections/hetzner.hcloud/commit/f85d8f4492f5c400dfcc4601f8212b6310f5c691))

## [2.3.0](https://github.com/ansible-collections/hetzner.hcloud/compare/2.2.0...2.3.0) (2023-11-07)

### Features

- add `created` field to server and server_info modules ([#381](https://github.com/ansible-collections/hetzner.hcloud/issues/381)) ([c3e4c0e](https://github.com/ansible-collections/hetzner.hcloud/commit/c3e4c0ea0a77bec26b83476af99d35078ed9cf6d))
- add server_types to datacenter info module ([#379](https://github.com/ansible-collections/hetzner.hcloud/issues/379)) ([084e04d](https://github.com/ansible-collections/hetzner.hcloud/commit/084e04d576798e7b49c5c3101803e7b8d2e80181))

## [2.2.0](https://github.com/ansible-collections/hetzner.hcloud/compare/2.1.2...2.2.0) (2023-10-23)

### Features

- add deprecation field to hcloud_iso_info ([#357](https://github.com/ansible-collections/hetzner.hcloud/issues/357)) ([76ef636](https://github.com/ansible-collections/hetzner.hcloud/commit/76ef636f07feb91daa91ecaa17619d10fea7d6e4))
- add load_balancer algorithm option ([#368](https://github.com/ansible-collections/hetzner.hcloud/issues/368)) ([a93dbaa](https://github.com/ansible-collections/hetzner.hcloud/commit/a93dbaa428a128555d71a9ef36a1a6c211e09952))
- allow selecting a resource using its ID ([#361](https://github.com/ansible-collections/hetzner.hcloud/issues/361)) ([5e425c5](https://github.com/ansible-collections/hetzner.hcloud/commit/5e425c56c2643f7c0c68b7c6feb8d3e098d4bcdb))

## [2.1.2](https://github.com/ansible-collections/hetzner.hcloud/compare/2.1.1...v2.1.2) (2023-10-05)

### Bug Fixes

- firewall port argument is required with udp or tcp ([#345](https://github.com/ansible-collections/hetzner.hcloud/issues/345)) ([76c1abf](https://github.com/ansible-collections/hetzner.hcloud/commit/76c1abf44764778aa6e11bae57df5ee5f69a947b))
- invalid field in load_balancer_service health_check.http return data ([#333](https://github.com/ansible-collections/hetzner.hcloud/issues/333)) ([fb35516](https://github.com/ansible-collections/hetzner.hcloud/commit/fb35516e7609fad4dd3fa75138dbc603f83d9aa0))

## Dev Changelog

> [!WARNING]
> For the user changelog, please check out [CHANGELOG.rst](../CHANGELOG.rst) instead.

This file contains a list of changes intended towards developers. It is auto-generated by release-please.

We would prefer to not generate this file, but disabling this is not supported currently: https://github.com/googleapis/release-please/issues/2007
