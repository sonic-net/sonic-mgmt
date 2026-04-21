=============================
Grafana.Grafana Release Notes
=============================

.. contents:: Topics

v6.0.6
======

Major Changes
-------------

- Restore default listen address and port in Mimir by @56quarters in https://github.com/grafana/grafana-ansible-collection/pull/456
- fix broken Grafana apt repository addition by @kleini in https://github.com/grafana/grafana-ansible-collection/pull/454

v6.0.5
======

Major Changes
-------------

- Fallback to empty dict in case grafana_ini is undefined by @root-expert in https://github.com/grafana/grafana-ansible-collection/pull/403
- Fix Mimir config file validation task by @Windos in https://github.com/grafana/grafana-ansible-collection/pull/428
- Fixes issue by @digiserg in https://github.com/grafana/grafana-ansible-collection/pull/421
- Import custom dashboards only when directory exists by @mahendrapaipuri in https://github.com/grafana/grafana-ansible-collection/pull/430
- Updated YUM repo urls from `packages.grafana.com` to `rpm.grafana.com` by @DejfCold in https://github.com/grafana/grafana-ansible-collection/pull/414
- Use credentials from grafana_ini when importing dashboards by @root-expert in https://github.com/grafana/grafana-ansible-collection/pull/402
- do not skip scrape latest github version even in check_mode by @cmehat in https://github.com/grafana/grafana-ansible-collection/pull/408
- fix datasource documentation by @jeremad in https://github.com/grafana/grafana-ansible-collection/pull/437
- fix mimir_download_url_deb & mimir_download_url_rpm by @germebl in https://github.com/grafana/grafana-ansible-collection/pull/400
- update catalog info by @Duologic in https://github.com/grafana/grafana-ansible-collection/pull/434
- use deb822 for newer debian versions by @Lukas-Heindl in https://github.com/grafana/grafana-ansible-collection/pull/440

v6.0.4
======

Major Changes
-------------

- Add SUSE support to Alloy role by @pozsa in https://github.com/grafana/grafana-ansible-collection/pull/423
- Fixes to foldersFromFilesStructure option by @root-expert in https://github.com/grafana/grafana-ansible-collection/pull/351
- Migrate RedHat install to ansible.builtin.package by @r65535 in https://github.com/grafana/grafana-ansible-collection/pull/431
- add macOS support to alloy role by @l50 in https://github.com/grafana/grafana-ansible-collection/pull/418
- replace None with [] for safe length checks by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/426

v6.0.3
======

Major Changes
-------------

- Bump ansible-lint from 24.9.2 to 25.6.1 by @dependabot[bot] in https://github.com/grafana/grafana-ansible-collection/pull/391
- Bump brace-expansion from 1.1.11 to 1.1.12 in the npm_and_yarn group across 1 directory by @dependabot[bot] in https://github.com/grafana/grafana-ansible-collection/pull/396
- Changes for issue
- Update Mimir README.md by @Gufderald in https://github.com/grafana/grafana-ansible-collection/pull/397
- declare collection dependencies by @ishanjainn in https://github.com/grafana/grafana-ansible-collection/pull/390
- declare collection dependencies by @kleini in https://github.com/grafana/grafana-ansible-collection/pull/392
- ensure IP assert returns boolean result by @aardbol in https://github.com/grafana/grafana-ansible-collection/pull/398
- improve mimir/alloy examples playbook by @smCloudInTheSky in https://github.com/grafana/grafana-ansible-collection/pull/369
- store APT key with .asc extension by @derhuerst in https://github.com/grafana/grafana-ansible-collection/pull/394

v6.0.2
======

Major Changes
-------------

- Add delete protection by @KucicM in https://github.com/grafana/grafana-ansible-collection/pull/381
- Don't override defaults by @56quarters in https://github.com/grafana/grafana-ansible-collection/pull/382
- Don't use a proxy when doing Alloy readiness check by @benoitc-croesus in https://github.com/grafana/grafana-ansible-collection/pull/375
- Fix Mimir URL verify task by @parcimonic in https://github.com/grafana/grafana-ansible-collection/pull/358
- Fix some regression introduced by v6 by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/376
- Update when statement to test for dashboard files found by @hal58th in https://github.com/grafana/grafana-ansible-collection/pull/363
- Use become false in find task by @santilococo in https://github.com/grafana/grafana-ansible-collection/pull/368
- alloy_readiness_check_use_https by @piotr-g in https://github.com/grafana/grafana-ansible-collection/pull/359
- declare collection dependencies by @kleini in https://github.com/grafana/grafana-ansible-collection/pull/386
- ensure alerting provisioning directory exists by @derhuerst in https://github.com/grafana/grafana-ansible-collection/pull/364
- mark configuration deployment task with `no_log` by @kkantonop in https://github.com/grafana/grafana-ansible-collection/pull/380
- properly validate config by @pieterlexis-tomtom in https://github.com/grafana/grafana-ansible-collection/pull/354
- template ingester and querier section by @Gufderald in https://github.com/grafana/grafana-ansible-collection/pull/371
- use ansible_facts instead of variables by @kleini in https://github.com/grafana/grafana-ansible-collection/pull/365

v6.0.1
======

Minor Changes
-------------

- Remove Node modules from Ansible Collection build

v6.0.0
======

Major Changes
-------------

- Add foldersFromFilesStructure option by @root-expert in https://github.com/grafana/grafana-ansible-collection/pull/326
- Add tempo role by @CSTDev in https://github.com/grafana/grafana-ansible-collection/pull/323
- Do not log grafana.ini contents when setting facts by @root-expert in https://github.com/grafana/grafana-ansible-collection/pull/325
- Fix loki_operational_config section not getting rendered in config.yml by @olegkaspersky in https://github.com/grafana/grafana-ansible-collection/pull/330
- Fix sectionless items edge case by @santilococo in https://github.com/grafana/grafana-ansible-collection/pull/303
- Fix tags Inherit default vars by @MJurayev in https://github.com/grafana/grafana-ansible-collection/pull/341
- Fix the markdown code fences for install command by @benmatselby in https://github.com/grafana/grafana-ansible-collection/pull/306
- Grafana fix facts in main.yml by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/315
- Make dashboard imports more flexible by @torfbolt in https://github.com/grafana/grafana-ansible-collection/pull/308
- Make systemd create /var/lib/otel-collector by @pieterlexis-tomtom in https://github.com/grafana/grafana-ansible-collection/pull/336
- Validate config by @pieterlexis-tomtom in https://github.com/grafana/grafana-ansible-collection/pull/327
- add catalog-info file for internal dev catalog by @theSuess in https://github.com/grafana/grafana-ansible-collection/pull/317
- add publish step to GitHub Actions workflow for Ansible Galaxy by @thelooter in https://github.com/grafana/grafana-ansible-collection/pull/340
- add user module to create/update/delete grafana users by @mvalois in https://github.com/grafana/grafana-ansible-collection/pull/178
- force temporary directory even in check mode for  dashboards.yml by @cmehat in https://github.com/grafana/grafana-ansible-collection/pull/339
- integrate sles legacy init-script support by @floerica in https://github.com/grafana/grafana-ansible-collection/pull/184
- management of the config.river with the conversion of the config.yaml by @lbrule in https://github.com/grafana/grafana-ansible-collection/pull/149
- use ansible_facts instead of ansible_* variables by @kleini in https://github.com/grafana/grafana-ansible-collection/pull/296

v5.7.0
======

Major Changes
-------------

- Ability to set custom directory path for \*.alloy config files by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/294
- Add tests and support version latest by @pieterlexis-tomtom in https://github.com/grafana/grafana-ansible-collection/pull/299
- Fix 'dict object' has no attribute 'path' when running with --check by @JMLX42 in https://github.com/grafana/grafana-ansible-collection/pull/283
- Update grafana template by @santilococo in https://github.com/grafana/grafana-ansible-collection/pull/300
- add loki bloom support by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/298
- grafana.ini yaml syntax by @intermittentnrg in https://github.com/grafana/grafana-ansible-collection/pull/232

v5.6.0
======

Major Changes
-------------

- Adding "distributor" section support to mimir config file by @HamzaKhait in https://github.com/grafana/grafana-ansible-collection/pull/247
- Allow alloy_user_groups variable again by @pjezek in https://github.com/grafana/grafana-ansible-collection/pull/276
- Alloy Role Improvements by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/281
- Bump ansible-lint from 24.6.0 to 24.9.2 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/270
- Bump pylint from 3.2.5 to 3.3.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/273
- Ensure check-mode works for otel collector by @pieterlexis-tomtom in https://github.com/grafana/grafana-ansible-collection/pull/264
- Fix message argument of dashboard task by @Nemental in https://github.com/grafana/grafana-ansible-collection/pull/256
- Update Alloy variables to use the `grafana_alloy_` namespace so they are unique by @Aethylred in https://github.com/grafana/grafana-ansible-collection/pull/209
- Update README.md by @aioue in https://github.com/grafana/grafana-ansible-collection/pull/272
- Update README.md by @aioue in https://github.com/grafana/grafana-ansible-collection/pull/275
- Update main.yml by @aioue in https://github.com/grafana/grafana-ansible-collection/pull/274
- add grafana_plugins_ops to defaults and docs by @weakcamel in https://github.com/grafana/grafana-ansible-collection/pull/251
- add option to populate google_analytics_4_id value by @copolycube in https://github.com/grafana/grafana-ansible-collection/pull/249
- fix ansible-lint warnings on Forbidden implicit octal value "0640" by @copolycube in https://github.com/grafana/grafana-ansible-collection/pull/279

v5.5.1
======

Bugfixes
--------

- Add check_mode: false to Loki "Scrape GitHub" Task by @winsmith in https://github.com/grafana/grafana-ansible-collection/pull/262

v5.5.0
======

Major Changes
-------------

- add support for extra args by @harryfinbow in https://github.com/grafana/grafana-ansible-collection/pull/259
- mimir molecule should use ansible core 2.16 by @GVengelen in https://github.com/grafana/grafana-ansible-collection/pull/254

v5.4.1
======

Major Changes
-------------

- Updated promtail arch map for aarch64 matching by @gianmarco-mameli in https://github.com/grafana/grafana-ansible-collection/pull/257

v5.4.0
======

Major Changes
-------------

- Use a variable to control uninstall behavior instead of tags by @dobbi84 in https://github.com/grafana/grafana-ansible-collection/pull/253

v5.3.0
======

Major Changes
-------------

- Add a config check before restarting mimir by @panfantastic in https://github.com/grafana/grafana-ansible-collection/pull/198
- Add support for configuring feature_toggles in grafana role by @LexVar in https://github.com/grafana/grafana-ansible-collection/pull/173
- Backport post-setup healthcheck from agent to alloy by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/213
- Bump ansible-lint from 24.2.3 to 24.5.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/207
- Bump ansible-lint from 24.5.0 to 24.6.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/216
- Bump braces from 3.0.2 to 3.0.3 in the npm_and_yarn group across 1 directory by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/218
- Bump pylint from 3.1.0 to 3.1.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/200
- Bump pylint from 3.1.1 to 3.2.2 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/208
- Bump pylint from 3.2.2 to 3.2.3 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/217
- Bump pylint from 3.2.3 to 3.2.5 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/234
- Change from config.river to config.alloy by @cardasac in https://github.com/grafana/grafana-ansible-collection/pull/225
- Fix Grafana Configuration for Unified and Legacy Alerting Based on Version by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/215
- Fix env file location by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/211
- Support adding alloy user to extra groups by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/212
- Updated result.json['message'] to result.json()['message'] by @CPreun in https://github.com/grafana/grafana-ansible-collection/pull/223
- readme styling & language improvements by @tigattack in https://github.com/grafana/grafana-ansible-collection/pull/214

v5.2.0
======

Major Changes
-------------

- Add a new config part to configure KeyCloak based auth by @he0s in https://github.com/grafana/grafana-ansible-collection/pull/191
- Add promtail role by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/197
- Bump ansible-lint from 24.2.2 to 24.2.3 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/195

v5.1.0
======

Major Changes
-------------

- Uninstall Step for Loki and Mimir by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/193

v5.0.0
======

Major Changes
-------------

- Add Grafana Loki role by @voidquark in https://github.com/grafana/grafana-ansible-collection/pull/188
- Add Grafana Mimir role by @GVengelen in https://github.com/grafana/grafana-ansible-collection/pull/183

v4.0.0
======

Major Changes
-------------

- Add an Ansible role for Grafana Alloy by @ishanjainn in https://github.com/grafana/grafana-ansible-collection/pull/169

Minor Changes
-------------

- Apply correct uid + gid for imported dashboards by @hypery2k in https://github.com/grafana/grafana-ansible-collection/pull/167
- Bump ansible-lint from 24.2.0 to 24.2.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/164
- Bump ansible-lint from 24.2.0 to 24.2.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/168
- Bump black from 24.1.1 to 24.3.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/165
- Clarify grafana-server configuration in README by @VGerris in https://github.com/grafana/grafana-ansible-collection/pull/177
- Update description to match module by @brmurphy in https://github.com/grafana/grafana-ansible-collection/pull/179

v3.0.0
======

Major Changes
-------------

- Add an Ansible role for OpenTelemetry Collector by @ishanjainn in https://github.com/grafana/grafana-ansible-collection/pull/138

Minor Changes
-------------

- Bump pylint from 3.0.3 to 3.1.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/158
- Bump pylint from 3.0.3 to 3.1.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/161
- Bump the pip group across 1 directories with 1 update by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/156
- Bump yamllint from 1.33.0 to 1.35.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/155
- Bump yamllint from 1.33.0 to 1.35.1 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/159
- ExecStartPre and EnvironmentFile settings to system unit file by @fabiiw05 in https://github.com/grafana/grafana-ansible-collection/pull/157
- datasources url parameter fix by @dergudzon in https://github.com/grafana/grafana-ansible-collection/pull/162

v2.2.5
======

Release Summary
---------------

Grafana and Agent Role bug fixes and security updates

Minor Changes
-------------

- Add 'run_once' to download&unzip tasks by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/136
- Adding `oauth_allow_insecure_email_lookup` to fix oauth user sync error by @hypery2k in https://github.com/grafana/grafana-ansible-collection/pull/132
- Bump ansible-core from 2.15.4 to 2.15.8 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/137
- Bump ansible-lint from 6.13.1 to 6.14.3 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/139
- Bump ansible-lint from 6.14.3 to 6.22.2 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/142
- Bump ansible-lint from 6.22.2 to 24.2.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/150
- Bump jinja2 from 3.1.2 to 3.1.3 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/129
- Bump pylint from 2.16.2 to 3.0.3 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/141
- Bump yamllint from 1.29.0 to 1.33.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/140
- Bump yamllint from 1.29.0 to 1.33.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/143
- Bump yamllint from 1.33.0 to 1.34.0 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/151
- Change handler to systemd by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/135
- Fix links in grafana_agent/defaults/main.yaml by @PabloCastellano in https://github.com/grafana/grafana-ansible-collection/pull/134
- Topic/grafana agent idempotency by @ohdearaugustin in https://github.com/grafana/grafana-ansible-collection/pull/147

v2.2.4
======

Release Summary
---------------

Grafana and Agent Role bug fixes and security updates

Minor Changes
-------------

- Bump cryptography from 41.0.4 to 41.0.6 by @dependabot in https://github.com/grafana/grafana-ansible-collection/pull/126
- Drop curl check by @v-zhuravlev in https://github.com/grafana/grafana-ansible-collection/pull/120
- Fix check mode for grafana role by @Boschung-Mecatronic-AG-Infrastructure in https://github.com/grafana/grafana-ansible-collection/pull/125
- Fix check mode in Grafana Agent by @AmandaCameron in https://github.com/grafana/grafana-ansible-collection/pull/124
- Update tags in README by @ishanjainn in https://github.com/grafana/grafana-ansible-collection/pull/121

v2.2.3
======

Release Summary
---------------

Remove dependency on local-fs.target from Grafana Agent role

Minor Changes
-------------

- Remove dependency on local-fs.target from Grafana Agent role

v2.2.2
======

Release Summary
---------------

Grafana Role bug fixes and security updates

Minor Changes
-------------

- Bump cryptography from 41.0.3 to 41.0.4
- Create missing notification directory in Grafana Role
- Remove check_mode from create local directory task in Grafana Role

v2.2.1
======

Release Summary
---------------

Allow alert resource provisioning in Grafana Role

Minor Changes
-------------

- Allow alert resource provisioning in Grafana Role

v2.2.0
======

Release Summary
---------------

Grafana Agent Role Updates

Minor Changes
-------------

- Use 'ansible_system' env variable to detect os typ in Grafana Agent Role
- hange grafana Agent Wal and Positions Directory in Grafana Agent Role

v2.1.9
======

Release Summary
---------------

Security Updates and Grafana Agent Version failure fixes

Minor Changes
-------------

- Add check for Curl and failure step if Agent Version is not retrieved
- Bump cryptography from 39.0.2 to 41.0.3
- Bump semver from 5.7.1 to 5.7.2
- Bump word-wrap from 1.2.3 to 1.2.5
- Create local dashboard directory in check mode
- Update CI Testing
- Update Cloud Stack Module failures

v2.1.8
======

Release Summary
---------------

Fix grafana dashboard import in Grafana Role

Minor Changes
-------------

- Fix grafana dashboard import in Grafana Role

v2.1.7
======

Release Summary
---------------

YAML Fixes

Minor Changes
-------------

- YAML Fixes

v2.1.6
======

Release Summary
---------------

Grafana and Grafana Agent role updates

Minor Changes
-------------

- Add overrides.conf with CAP_NET_BIND_SERVICE for grafana-server unit
- Fix Grafana Dashboard Import for Grafana Role
- Make grafana_agent Idempotent
- Provisioning errors in YAML
- Use new standard to configure Grafana APT source for Grafana Role

v2.1.5
======

Release Summary
---------------

Update Grafana Agent Download varibale and ZIP file

Minor Changes
-------------

- Add Grafana Agent Version and CPU Arch to Downloaded ZIP in Grafana Agent Role
- Move _grafana_agent_base_download_url from /vars to /defaults in Grafana Agent Role

v2.1.4
======

Release Summary
---------------

Update Datasource Tests and minor fixes

Minor Changes
-------------

- Datasource test updates and minor fixes

v2.1.3
======

Release Summary
---------------

Update modules to fix failing Sanity Tests

Minor Changes
-------------

- indentation and Lint fixes to modules

v2.1.2
======

Release Summary
---------------

Idempotency Updates and minor api_url fixes

Minor Changes
-------------

- Fix Deleting datasources
- Fix alert_notification_policy failing on fresh instance
- Making Deleting folders idempotent
- Remove trailing slash automatically from grafana_url

v2.1.1
======

Release Summary
---------------

Update Download tasks in Grafana Agent Role

Minor Changes
-------------

- Update Download tasks in Grafana Agent Role

v2.1.0
======

Release Summary
---------------

Add Grafana Server role and plugins support on-prem Grafana

Major Changes
-------------

- Addition of Grafana Server role by @gardar
- Configurable agent user groups by @NormanJS
- Grafana Plugins support on-prem Grafana installation by @ishanjainn
- Updated Service for flow mode by @bentonam

Minor Changes
-------------

- Ability to configure date format in grafana server role by @RomainMou
- Avoid using shell for fetching latest version in Grafana Agent Role by @gardar
- Fix for invalid yaml with datasources list enclosed in quotes by @elkozmon
- Remove agent installation custom check by @VLZZZ
- Remove explicit user creation check by @v-zhuravlev

v2.0.0
======

Release Summary
---------------

Updated Grafana Agent Role

Major Changes
-------------

- Added Lint support
- Configs for server, metrics, logs, traces, and integrations
- Installation of the latest version
- Local installations when internet connection is not allowed
- Only download binary to controller once instead of hosts
- Skip install if the agent is already installed and the version is the same as the requested version
- Support for Grafana Agent Flow
- Validation of variables

v1.1.1
======

Release Summary
---------------

Updated return description and value for grafana.grafana.folder module

Minor Changes
-------------

- Updated the return message in grafana.grafana.folder module

v1.1.0
======

Release Summary
---------------

Added Role to deploy Grafana Agent on linux hosts

Major Changes
-------------

- Added Role for Grafana Agent

v1.0.5
======

Release Summary
---------------

Add Note to modules which don't support Idempotency

Minor Changes
-------------

- Added Note to datasource and dashboard module about not supporting Idempotency

v1.0.4
======

Release Summary
---------------

Bug fixes and idempotency fixes for modules

Major Changes
-------------

- All modules except dashboard and datasource modules now support idempotency

Minor Changes
-------------

- All modules use `missing_required_lib`` to compose the message for module.fail_json() when required library is missing from host

Bugfixes
--------

- Fixed cases where cloud_stack and alert_contact_point modules do not return a tuple when nothing in loop matches

v1.0.3
======

Minor Changes
-------------

- Add a fail method to modules source code if `requests` library is not present
- Fixed markup for arg option in Documentation
- Updated Documentation with `notes` to specify if the check_mode feature is supported by modules
- removed `supports_check_mode=True` from source code of modules

v1.0.2
======

Release Summary
---------------

Documentation updates with updated description for modules

v1.0.1
======

Release Summary
---------------

Documentation updates with updated examples

v1.0.0
======

Release Summary
---------------

CI and testing improvements

v0.0.7
======

Release Summary
---------------

Documentation update for return values in `grafana.grafana.dashboard`

v0.0.6
======

Minor Changes
-------------

- Idempotency updates to cloud_api_key and datasource modules

v0.0.5
======

Release Summary
---------------

Documentation update and code cleanup

v0.0.4
======

Bugfixes
--------

- Fix an issue with `cloud_stack` idempotency

v0.0.3
======

Release Summary
---------------

Documentation update and code cleanup

v0.0.2
======

Release Summary
---------------

Updated input parameters description for all modules

v0.0.1
======

Release Summary
---------------

It's a release! First version to publish to Ansible Galaxy
