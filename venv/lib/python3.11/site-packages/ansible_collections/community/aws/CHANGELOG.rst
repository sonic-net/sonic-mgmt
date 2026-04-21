===========================
community.aws Release Notes
===========================

.. contents:: Topics

v10.0.0
=======

Release Summary
---------------

In this major release, the ``connection/aws_ssm`` connection plugin has been fully migrated out of this collection and into ``amazon.aws`` (https://forum.ansible.com/t/aws-ssm-connection-refactoring-plugin-promotion/39930). Playbooks or Inventory using the Fully Qualified Collection Name (FQCN) for this connection plugin should be updated to use ``amazon.aws.aws_ssm``. Additionally, ``botocore<1.31.0`` and ``boto3<1.28.0`` are no longer supported; most modules will continue to work with older versions of the AWS SDK, however, compatibility with older versions of the SDK is not guaranteed.


Major Changes
-------------

- community.aws collection - The ``community.aws`` collection has dropped support for ``botocore<1.34.0`` and ``boto3<1.34.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/amazon.aws/pull/2426).

Breaking Changes / Porting Guide
--------------------------------

- Support for ``ansible-core<2.17`` has been dropped (https://github.com/ansible-collections/community.aws/pull/2303).
- The ``community.aws`` collection has dropped support for ``botocore<1.31.0`` and ``boto3<1.28.0``. Most modules will continue to work with older versions of the AWS SDK.  However, compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/2195).
- connection/aws_ssm - The connection plugin has been migrated from the ``community.aws`` collection. Playbooks or Inventory using the Fully Qualified Collection Name for this connection plugin should be updated to use ``amazon.aws.aws_ssm``.

Deprecated Features
-------------------

- community.aws collection - Due to the AWS SDKs announcing the end of support for Python less than 3.8 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.8 by this collection has been deprecated and was removed in this 10.0.0 release (https://github.com/ansible-collections/community.aws/pull/2195).

v9.3.0
======

Release Summary
---------------

This release includes several improvements for the ``community.aws.aws_ssm`` connection plugin in preparation for its promotion to amazon.aws and bumps version of ansible-lint to ``25.1.0``.

Minor Changes
-------------

- Bump version of ``ansible-lint`` to 25.1.2 (https://github.com/ansible-collections/community.aws/pull/2295).
- aws_ssm - Move the ``aws_ssm`` connection plugin's plugin_utils into a dedicated folder (https://github.com/ansible-collections/community.aws/pull/2279).
- aws_ssm - Refactor S3 operations methods for improved clarity (https://github.com/ansible-collections/community.aws/pull/2275).
- aws_ssm - Refactor connection/aws_ssm to add new TerminalManager class and move relevant methods to the new class (https://github.com/ansible-collections/community.aws/pull/2270).
- aws_ssm - Refactor connection/aws_ssm to add new ``FileTransferManager`` class and move relevant methods to the new class (https://github.com/ansible-collections/community.aws/pull/2273).
- aws_ssm - Refactor connection/aws_ssm to add new ``SSMSessionManager`` and ``ProcessManager`` classes and move relevant methods to the new class (https://github.com/ansible-collections/community.aws/pull/2272).

v9.2.0
======

Release Summary
---------------

This release includes several improvements for the ``community.aws.aws_ssm`` connection plugin in preparation for its promotion to amazon.aws in the ucoming major release.

Minor Changes
-------------

- aws_ssm - Refactor ``_exec_transport_commands``, ``_generate_commands``, and ``_exec_transport_commands`` methods for improved clarity (https://github.com/ansible-collections/community.aws/pull/2248).
- aws_ssm - Refactor connection/aws_ssm to add new S3ClientManager class and move relevant methods to the new class (https://github.com/ansible-collections/community.aws/pull/2255).
- aws_ssm - Refactor display/verbosity-related methods in aws_ssm to simplify the code and avoid repetition (https://github.com/ansible-collections/community.aws/pull/2264).

v9.1.0
======

Release Summary
---------------

Preparation for the promotion of the ``aws_ssm.py`` plugin (https://forum.ansible.com/t/aws-ssm-connection-refactoring-plugin-promotion/39930) is under way in this release; this effort includes the refactoring work for methods like ``exec_command`` (https://github.com/ansible-collections/community.aws/pull/2224) as well as new methods such as ``generate_mark()`` (https://github.com/ansible-collections/community.aws/pull/2235) which generates random strings for SSM CLI delimitation.


Minor Changes
-------------

- aws_ssm -  Refactor ``_init_clients`` Method for Improved Clarity and Efficiency (https://github.com/ansible-collections/community.aws/pull/2223).
- aws_ssm -  Refactor ``_prepare_terminal()`` Method for Improved Clarity and Efficiency (https://github.com/ansible-collections/community.aws/pull/).
- aws_ssm -  Refactor ``exec_command`` Method for Improved Clarity and Efficiency (https://github.com/ansible-collections/community.aws/pull/2224).
- aws_ssm - Add the possibility to define ``aws_ssm plugin`` variable via environment variable and by default use the version found on the $PATH rather than require that you provide an absolute path (https://github.com/ansible-collections/community.aws/issues/1990).
- dms_endpoint - Improve resilience of parameter comparison (https://github.com/ansible-collections/community.aws/pull/2221).
- s3_lifecycle - Support for min and max object size when applying the filter rules (https://github.com/ansible-collections/community.aws/pull/2205).
- aws_ssm - Add function to generate random strings for SSM CLI delimitation (https://github.com/ansible-collections/community.aws/pull/2235).
- various modules - Linting fixups (https://github.com/ansible-collections/community.aws/pull/2221).
- waf_condition - Add missing options validation to filters (https://github.com/ansible-collections/community.aws/pull/2220).

Bugfixes
--------

- aws_ssm - Use ``head_bucket`` to access bucket locations in foreign AWS accounts (https://github.com/ansible-collections/community.aws/pull/1987).
- aws_ssm - Strip Powershell ``CLIXML`` from ``stdout`` (https://github.com/ansible-collections/community.aws/issues/1952).

v9.0.0
======

Release Summary
---------------

This release includes some new features, bugfixes and breaking changes. Several modules have been migrated to amazon.aws and the Fully Qualified Collection Name for these modules needs to be updated. The community.aws collection has dropped support for botocore<1.31.0 and boto3<1.28.0. Due to the AWS SDKs announcing Python less than 3.8 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/), support for Python less than 3.8 by this collection was deprecated in this release and will be removed in release 10.0.0 (https://github.com/ansible-collections/community.aws/pull/2194).

Minor Changes
-------------

- autoscaling_instance_refresh - Add support for ``skip_matching`` and ``max_healthy_percentage`` in ``preference`` (https://github.com/ansible-collections/community.aws/pull/2150).
- autoscaling_instance_refresh - refactor module to use shared code from ``ansible_collections.amazon.aws.plugins.module_utils.autoscaling`` and add type hinting (https://github.com/ansible-collections/community.aws/pull/2150).
- autoscaling_instance_refresh_info - refactor module to use shared code from ``ansible_collections.amazon.aws.plugins.module_utils.autoscaling`` and add type hinting (https://github.com/ansible-collections/community.aws/pull/2150).
- ec2_launch_template - Add option ``tag_specifications`` to define tags to be applied to the resources created with the launch template (https://github.com/ansible-collections/community.aws/issues/176).
- ec2_launch_template - Add suboption ``throughput`` to ``block_device_mappings`` argument (https://github.com/ansible-collections/community.aws/issues/1944).
- ec2_launch_template - Add support ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/issues/176).
- ec2_launch_template - Add the possibility to delete specific versions of a launch template using ``versions_to_delete`` (https://github.com/ansible-collections/community.aws/pull/2164).
- ec2_launch_template - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2164).
- ec2_placement_group - Added support for creating with ``tags`` (https://github.com/ansible-collections/community.aws/pull/2081).
- ec2_placement_group - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2167).
- ec2_transit_gateway - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2158).
- ec2_transit_gateway - Support for enable multicast on Transit Gateway (https://github.com/ansible-collections/community.aws/pull/2063).
- ec2_transit_gateway_info - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2158).
- ec2_transit_gateway_vpc_attachment - Modify doumentation and refactor to adhere to coding guidelines (https://github.com/ansible-collections/community.aws/pull/2157).
- ec2_vpc_egress_igw - Add the possibility to update/add tags on Egress only internet gateway (https://github.com/ansible-collections/community.aws/pull/2152).
- ec2_vpc_egress_igw - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` util (https://github.com/ansible-collections/community.aws/pull/2152).
- ec2_vpc_nacl - Refactor module to use shared code from `amazon.aws.plugins.module_utils.ec2` (https://github.com/ansible-collections/community.aws/pull/2159).
- ec2_vpc_nacl_info - Refactor module to use shared code from `amazon.aws.plugins.module_utils.ec2` (https://github.com/ansible-collections/community.aws/pull/2159).
- ec2_vpc_peer - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` (https://github.com/ansible-collections/community.aws/pull/2153).
- ec2_vpc_peering_info - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` (https://github.com/ansible-collections/community.aws/pull/2153).
- ec2_vpc_vgw - Fix call to parent static method in class ``VGWRetry`` (https://github.com/ansible-collections/community.aws/pull/2140).
- ec2_vpc_vgw - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2171).
- ec2_vpc_vgw_info - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` and update ``RETURN`` block (https://github.com/ansible-collections/community.aws/pull/2171).
- ec2_vpc_vpn - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` (https://github.com/ansible-collections/community.aws/pull/2160).
- ec2_vpc_vpn_info - Refactor module to use shared code from ``amazon.aws.plugins.module_utils.ec2`` (https://github.com/ansible-collections/community.aws/pull/2160).
- elb_classic_lb_info - Refactor elb_classic_lb_info module (https://github.com/ansible-collections/community.aws/pull/2139).

Breaking Changes / Porting Guide
--------------------------------

- The community.aws collection has dropped support for ``botocore<1.31.0`` and ``boto3<1.28.0``. Most modules will continue to work with older versions of the AWS SDK.  However, compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/2195).
- autoscaling_instance_refresh - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.autoscaling_instance_refresh`` (https://github.com/ansible-collections/community.aws/pull/2177).
- autoscaling_instance_refresh_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.autoscaling_instance_refresh_info`` (https://github.com/ansible-collections/community.aws/pull/2177).
- ec2_launch_template - Tags defined using option ``tags`` are now applied to the launch template resources not the resource created using this launch template (https://github.com/ansible-collections/community.aws/issues/176).
- ec2_launch_template - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_launch_template`` (https://github.com/ansible-collections/community.aws/pull/2185).
- ec2_placement_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_placement_group``.
- ec2_placement_group_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_placement_group_info``.
- ec2_transit_gateway - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_transit_gateway``.
- ec2_transit_gateway_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_transit_gateway_info``.
- ec2_transit_gateway_vpc_attachment - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_transit_gateway_vpc_attachment``.
- ec2_transit_gateway_vpc_attachment_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_transit_gateway_vpc_attachment_info``.
- ec2_vpc_egress_igw - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_egress_igw`` (https://api.github.com/repos/ansible-collections/community.aws/pulls/2169).
- ec2_vpc_nacl - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_nacl`` (https://github.com/ansible-collections/community.aws/pull/2178).
- ec2_vpc_nacl_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_nacl_info`` (https://github.com/ansible-collections/community.aws/pull/2178).
- ec2_vpc_peer - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_peer``.
- ec2_vpc_peering_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_peering_info``.
- ec2_vpc_vgw - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_vgw``.
- ec2_vpc_vgw_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_vgw_info``.
- ec2_vpc_vpn - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_vpn``.
- ec2_vpc_vpn_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_vpn_info``.
- ecs_cluster - the parameter ``purge_capacity_providers`` defaults to true. (https://github.com/ansible-collections/community.aws/pull/2165).
- elb_classic_lb_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.elb_classic_lb_info``.
- iam_policy - the ``connection_properties`` return key was previously deprecated and has been removed, please use ``raw_connection_properties`` instead (https://github.com/ansible-collections/community.aws/pull/2165).

Deprecated Features
-------------------

- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.8 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.8 by this collection has been deprecated and will removed in release 10.0.0 (https://github.com/ansible-collections/community.aws/pull/2195).

Bugfixes
--------

- autoscaling_instance_refresh - Fix typo in module ``exit_json`` (https://github.com/ansible-collections/community.aws/issues/2019).
- ecs_taskdefinition - avoid throttling exceptions on task definitions with a large number of revisions by using the retry mechanism (https://github.com/ansible-collections/community.aws/issues/2123).

v8.1.0
======

Release Summary
---------------

This minor release brings several new features and bug fixes.

Minor Changes
-------------

- ec2_placement_group - Added support for creating with ``tags`` (https://github.com/ansible-collections/community.aws/pull/2081).
- ec2_transit_gateway - Support for enabling multicast on Transit Gateway (https://github.com/ansible-collections/community.aws/pull/2063).
- ec2_vpc_vgw - Fix call to parent static method in class ``VGWRetry`` (https://github.com/ansible-collections/community.aws/pull/2140).

Bugfixes
--------

- ecs_taskdefinition - Avoid throttling exceptions on task definitions with a large number of revisions by using the retry mechanism (https://github.com/ansible-collections/community.aws/issues/2123).

v8.0.0
======

Release Summary
---------------

This major release brings several new features, bug fixes, and deprecated features. It also includes the removal of several modules that have been migrated to the ``amazon.aws`` collection. We have also removed support for ``ansible-core<2.15``.

Minor Changes
-------------

- api_gateway - use fstrings where appropriate (https://github.com/ansible-collections/amazon.aws/pull/1962).
- api_gateway_info - use fstrings where appropriate (https://github.com/ansible-collections/amazon.aws/pull/1962).
- community.aws collection - apply isort code formatting to ensure consistent formatting of code (https://github.com/ansible-collections/community.aws/pull/1962)
- ecs_taskdefinition - Add parameter ``runtime_platform`` (https://github.com/ansible-collections/community.aws/issues/1891).
- eks_nodegroup - ensure wait also waits for deletion to complete when ``wait==True`` (https://github.com/ansible-collections/community.aws/pull/1994).
- elb_network_lb - add support for Application-Layer Protocol Negotiation (ALPN) policy ``AlpnPolicy`` for TLS listeners (https://github.com/ansible-collections/community.aws/issues/1566).
- elb_network_lb - add the possibly to update ``SslPolicy`` and ``Certificates`` for TLS listeners ().

Breaking Changes / Porting Guide
--------------------------------

- The community.aws collection has dropped support for ``botocore<1.29.0`` and ``boto3<1.26.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/amazon.aws/pull/1763).
- aws_region_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.aws_region_info``.
- aws_s3_bucket_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.aws_s3_bucket_info``.
- community.aws collection - Support for ansible-core < 2.15 has been dropped (https://github.com/ansible-collections/community.aws/pull/2074).
- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.7 by this collection wss been deprecated in release 6.0.0 and removed in release 7.0.0. (https://github.com/ansible-collections/amazon.aws/pull/1763).
- iam_access_key - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_access_key``.
- iam_access_key_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_access_key_info``.
- iam_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_group`` (https://github.com/ansible-collections/community.aws/pull/1945).
- iam_managed_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_managed_policy`` (https://github.com/ansible-collections/community.aws/pull/1954).
- iam_mfa_device_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_mfa_device_info`` (https://github.com/ansible-collections/community.aws/pull/1953).
- iam_password_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_password_policy``.
- iam_role - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_role`` (https://github.com/ansible-collections/community.aws/pull/1948).
- iam_role_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_role_info`` (https://github.com/ansible-collections/community.aws/pull/1948).
- s3_bucket_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.s3_bucket_info``.
- sts_assume_role - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.sts_assume_role``.

Deprecated Features
-------------------

- aws_glue_connection - updated the deprecation for removal of the ``connection_parameters`` return key from ``after 2024-06-01`` to release version ``9.0.0``, it is being replaced by the ``raw_connection_parameters`` key (https://github.com/ansible-collections/community.aws/pull/518).
- ecs_cluster - updated the deprecation for updated default of ``purge_capacity_providers``, the current default of ``False`` will be changed to ``True`` in release ``9.0.0``.  To maintain the current behaviour explicitly set ``purge_capacity_providers=False`` (https://github.com/ansible-collections/community.aws/pull/1640).
- ecs_service - updated the deprecation for updated default of ``purge_placement_constraints``, the current default of ``False`` will be changed to ``True`` in release ``9.0.0``.  To maintain the current behaviour explicitly set ``purge_placement_constraints=False`` (https://github.com/ansible-collections/community.aws/pull/1716).
- ecs_service - updated the deprecation for updated default of ``purge_placement_strategy``, the current default of ``False`` will be changed to ``True`` in release ``9.0.0``.  To maintain the current behaviour explicitly set ``purge_placement_strategy=False`` (https://github.com/ansible-collections/community.aws/pull/1716).

Bugfixes
--------

- mq_broker - ensure broker is created with ``tags`` when passed (https://github.com/ansible-collections/community.aws/issues/1832).
- opensearch - Don't try to read a non existing key from the domain config (https://github.com/ansible-collections/community.aws/pull/1910).

v7.2.0
======

Release Summary
---------------

This release includes a new module ``dynamodb_table_info``, new features for the ``glue_job`` and ``msk_cluster`` modules, and a bugfix for the ``aws_ssm`` connection plugin.

Minor Changes
-------------

- glue_job - add support for 2 new instance types which are G.4X and G.8X (https://github.com/ansible-collections/community.aws/pull/2048).
- msk_cluster - Support for additional ``m5`` and ``m7g`` types of MSK clusters (https://github.com/ansible-collections/community.aws/pull/1947).

Bugfixes
--------

- ssm(connection) - fix bucket region logic when region is ``us-east-1`` (https://github.com/ansible-collections/community.aws/pull/1908).

New Modules
-----------

- dynamodb_table_info - Returns information about a Dynamo DB table

v7.1.0
======

Release Summary
---------------

This release includes new features for the ``cloudfront_distribution`` and ``mq_broker`` modules, as well as a bugfix for the ``aws_ssm`` connection plugin needed when connecting to hosts with Bash 5.1.0 and later.

Minor Changes
-------------

- aws_ssm - Updated the documentation to explicitly state that an S3 bucket is required, the behavior of the files in that bucket, and requirements around that. (https://github.com/ansible-collections/community.aws/issues/1775).
- cloudfront_distribution - added support for ``cache_policy_id`` and ``origin_request_policy_id`` for behaviors (https://github.com/ansible-collections/community.aws/pull/1589)
- mq_broker - add support to wait for broker state via ``wait`` and ``wait_timeout`` parameter values (https://github.com/ansible-collections/community.aws/pull/1879).

Bugfixes
--------

- aws_ssm - disable ``enable-bracketed-paste`` to fix issue with amazon linux 2023 and other OSes (https://github.com/ansible-collections/community.aws/issues/1756)

v7.0.0
======

Release Summary
---------------

This release includes some new features, bugfixes and breaking changes. Several modules have been migrated to amazon.aws and the Fully Qualified Collection Name for these modules needs to be updated. The community.aws collection has dropped support for ``botocore<1.29.0`` and ``boto3<1.26.0``. Due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/), support for Python less than 3.7 by this collection was deprecated in release 6.0.0 and removed in release 7.0.0. (https://github.com/ansible-collections/amazon.aws/pull/1763).

Minor Changes
-------------

- api_gateway - use fstrings where appropriate (https://github.com/ansible-collections/amazon.aws/pull/1962).
- api_gateway_info - use fstrings where appropriate (https://github.com/ansible-collections/amazon.aws/pull/1962).
- community.aws collection - apply isort code formatting to ensure consistent formatting of code (https://github.com/ansible-collections/community.aws/pull/1962)
- ecs_taskdefinition - Add parameter ``runtime_platform`` (https://github.com/ansible-collections/community.aws/issues/1891).
- eks_nodegroup - ensure wait also waits for deletion to complete when ``wait==True`` (https://github.com/ansible-collections/community.aws/pull/1994).

Breaking Changes / Porting Guide
--------------------------------

- The community.aws collection has dropped support for ``botocore<1.29.0`` and ``boto3<1.26.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/amazon.aws/pull/1763).
- aws_region_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.aws_region_info``.
- aws_s3_bucket_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.aws_s3_bucket_info``.
- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.7 by this collection wss been deprecated in release 6.0.0 and removed in release 7.0.0. (https://github.com/ansible-collections/amazon.aws/pull/1763).
- iam_access_key - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_access_key``.
- iam_access_key_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_access_key_info``.
- iam_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_group`` (https://github.com/ansible-collections/community.aws/pull/1945).
- iam_managed_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_managed_policy`` (https://github.com/ansible-collections/community.aws/pull/1954).
- iam_mfa_device_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_mfa_device_info`` (https://github.com/ansible-collections/community.aws/pull/1953).
- iam_password_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_password_policy``.
- iam_role - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_role`` (https://github.com/ansible-collections/community.aws/pull/1948).
- iam_role_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_role_info`` (https://github.com/ansible-collections/community.aws/pull/1948).
- s3_bucket_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.s3_bucket_info``.
- sts_assume_role - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.sts_assume_role``.

Bugfixes
--------

- mq_broker - ensure broker is created with ``tags`` when passed (https://github.com/ansible-collections/community.aws/issues/1832).
- opensearch - Don't try to read a non existing key from the domain config (https://github.com/ansible-collections/community.aws/pull/1910).

v6.2.0
======

Release Summary
---------------

This release includes some new features for the ``community.aws.ec2_vpc_vpn`` and ``community.aws.api_gateway`` modules.

Minor Changes
-------------

- api_gateway - add support for parameters ``name``, ``lookup``, ``tags`` and ``purge_tags`` (https://github.com/ansible-collections/community.aws/pull/1845).
- ec2_vpc_vpn - add support for connecting VPNs to a transit gateway (https://github.com/ansible-collections/community.aws/pull/1877).

Bugfixes
--------

- Remove ``apigateway`` and ``apigateway_deployment`` from meta/runtime.yml (https://github.com/ansible-collections/community.aws/pull/1905).

v6.1.0
======

Release Summary
---------------

This release brings a new inventory plugin, some new features, and several bugfixes.

Minor Changes
-------------

- dynamodb_table - added waiter when updating indexes to avoid concurrency issues (https://github.com/ansible-collections/community.aws/pull/1866).
- dynamodb_table - increased default timeout based on time to update indexes in CI (https://github.com/ansible-collections/community.aws/pull/1866).
- iam_group - refactored ARN validation handling (https://github.com/ansible-collections/community.aws/pull/1848).
- iam_role - refactored ARN validation handling (https://github.com/ansible-collections/community.aws/pull/1848).
- sns_topic - refactored ARN validation handling (https://github.com/ansible-collections/community.aws/pull/1848).

Bugfixes
--------

- batch_compute_environment - fixed incorrect handling of Gov Cloud ARNs in ``compute_environment_name`` parameter (https://github.com/ansible-collections/community.aws/issues/1846).
- cloudfront_distribution - The origins  recognises the s3 domains with region part now (https://github.com/ansible-collections/community.aws/issues/1819).
- cloudfront_distribution - no longer crashes when waiting for completion of creation (https://github.com/ansible-collections/community.aws/issues/255).
- cloudfront_distribution - now honours the ``enabled`` setting (https://github.com/ansible-collections/community.aws/issues/1823).
- dynamodb_table - secondary indexes are now created (https://github.com/ansible-collections/community.aws/issues/1825).
- ec2_launch_template - fixed incorrect handling of Gov Cloud ARNs in ``compute_environment_name`` parameter (https://github.com/ansible-collections/community.aws/issues/1846).
- elasticache_info - remove hard coded use of ``aws`` partition (https://github.com/ansible-collections/community.aws/issues/1846).
- iam_role - fixed incorrect rejection of Gov Cloud ARNs in ``boundary`` parameter (https://github.com/ansible-collections/community.aws/issues/1846).
- msk_cluster - remove hard coded use of ``aws`` partition (https://github.com/ansible-collections/community.aws/issues/1846).
- redshift - fixed hard coded use of ``aws`` partition (https://github.com/ansible-collections/community.aws/issues/1846).

New Plugins
-----------

Inventory
~~~~~~~~~

- aws_mq - MQ broker inventory source

v6.0.0
======

Release Summary
---------------

This release brings some new plugins and features. Several bugfixes, breaking changes and deprecated features are also included.
The community.aws collection has dropped support for ``botocore<1.25.0`` and ``boto3<1.22.0``.
Support for Python 3.6 has also been dropped.

Minor Changes
-------------

- The ``black`` code formatter has been run across the collection to improve code consistency (https://github.com/ansible-collections/community.aws/pull/1784).
- aws_config_delivery_channel - add support for encrypted objects in S3 via KMS key (https://github.com/ansible-collections/community.aws/pull/1786).
- aws_ssm - Updated the documentation to explicitly mention that the ``ansible_user`` and ``remote_user`` variables are not supported by the plugin (https://github.com/ansible-collections/community.aws/pull/1682).
- bulk migration of ``%`` and ``.format()`` to fstrings (https://github.com/ansible-collections/community.aws/pull/1810).
- cloudfront_distribution - add ``http3`` support via parameter value ``http2and3`` for parameter ``http_version`` (https://github.com/ansible-collections/community.aws/pull/1753).
- cloudfront_distribution - add ``origin_shield`` options (https://github.com/ansible-collections/community.aws/pull/1557).
- cloudfront_distribution - documented ``connection_attempts`` and ``connection_timeout`` the module was already capable of using them
- community.aws - updated document fragments based on changes in amazon.aws (https://github.com/ansible-collections/community.aws/pull/1738).
- community.aws - updated imports based on changes in amazon.aws (https://github.com/ansible-collections/community.aws/pull/1738).
- ecs_ecr - use ``compare_policies`` when comparing lifecycle policies instead of naive ``sort_json_policy_dict`` comparisons (https://github.com/ansible-collections/community.aws/pull/1551).
- elasticache - Use the ``cache.t3.small`` node type in the example. ``cache.m1.small`` is not deprecated.
- minor code fixes and enable integration tests for modules cloudfront_distribution, cloudfront_invalidation and cloudfront_origin_access_identity (https://github.com/ansible-collections/community.aws/pull/1596).
- module_utils.botocore - Add Ansible AWS User-Agent identification (https://github.com/ansible-collections/community.aws/pull/1632).
- wafv2_rule_group_info - remove unused and deprecated ``state`` parameter (https://github.com/ansible-collections/community.aws/pull/1555).

Breaking Changes / Porting Guide
--------------------------------

- The community.aws collection has dropped support for ``botocore<1.25.0`` and ``boto3<1.22.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/1743).
- aws_ssm - the AWS SSM plugin was incorrectly prepending ``sudo`` to most commands.  This behaviour was incorrect and has been removed. To execute commands as a specific user, including the ``root`` user, the ``become`` and ``become_user`` directives should be used.  See the `Ansible documentation for more information <https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html>`_ (https://github.com/ansible-collections/community.aws/issues/853).
- codebuild_project - ``tags`` parameter now accepts a dict representing the tags, rather than the boto3 format (https://github.com/ansible-collections/community.aws/pull/1643).

Deprecated Features
-------------------

- community.aws collection - due to the AWS SDKs Python support policies (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.8 by this collection is expected to be removed in a release after 2024-12-01 (https://github.com/ansible-collections/community.aws/pull/1743).
- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.7 by this collection has been deprecated and will be removed in release 7.0.0. (https://github.com/ansible-collections/community.aws/pull/1743).

Bugfixes
--------

- opensearch_info - Fix the name of the domain_name key in the example (https://github.com/ansible-collections/community.aws/pull/1811).
- ses_identity - fix clearing notification topic (https://github.com/ansible-collections/community.aws/issues/150).

New Modules
-----------

- ec2_carrier_gateway - Manage an AWS VPC Carrier gateway
- ec2_carrier_gateway_info - Gather information about carrier gateways in AWS
- lightsail_snapshot - Creates snapshots of AWS Lightsail instances
- mq_broker - MQ broker management
- mq_broker_config - Update Amazon MQ broker configuration
- mq_broker_info - Retrieve MQ Broker details
- mq_user - Manage users in existing Amazon MQ broker
- mq_user_info - List users of an Amazon MQ broker
- ssm_inventory_info - Get SSM inventory information for EC2 instance

v5.5.1
======

Release Summary
---------------

This release brings several bugfixes.

Bugfixes
--------

- cloudfront_distribution - no longer crashes when waiting for completion of creation (https://github.com/ansible-collections/community.aws/issues/255).
- cloudfront_distribution - now honours the ``enabled`` setting (https://github.com/ansible-collections/community.aws/issues/1823).

v5.5.0
======

Release Summary
---------------

This release contains a number of bugfixes for various modules, as well as new features for the ``ec2_launch_template`` and ``msk_cluster`` modules.  This is the last planned minor release prior to the release of version 6.0.0.

Minor Changes
-------------

- ec2_launch_template - Add parameter ``version_description`` (https://github.com/ansible-collections/community.aws/pull/1763).
- msk_cluster - add option for SASL/IAM authentication and add support to disable unauthenticated clients (https://github.com/ansible-collections/community.aws/issues/1761).

Bugfixes
--------

- cloudformation_stack_set - add a waiter to ensure that update operation complete before adding stack instances (https://github.com/ansible-collections/community.aws/issues/1608).
- eks_nodegroup - fix handling of ``remote_access`` option (https://github.com/ansible-collections/community.aws/issues/1771).
- elasticache_info - ignore the ``CacheClusterNotFound`` exception when collecting tags (https://github.com/ansible-collections/community.aws/pull/1777).
- elb_target_group - ensure ``AvailabilityZone`` is kept in target definitions when ``Id`` and ``Port`` are passed (https://github.com/ansible-collections/community.aws/issues/1736).
- elb_target_group - get ``ProtocolVersion`` key from ``target_group`` attributes only when exists (https://github.com/ansible-collections/community.aws/pull/1800).
- msk_cluster - fix creating a cluster with SASL/SCRAM authentication (https://github.com/ansible-collections/community.aws/issues/1761).
- s3_lifecycle - fix invalid value type for transitions list (https://github.com/ansible-collections/community.aws/issues/1774)

v5.4.0
======

Release Summary
---------------

This minor release brings minor new features to the ``sns`` and ``ecs_service`` modules.

Minor Changes
-------------

- ecs_service - added new parameter ``enable_execute_command`` (https://github.com/ansible-collections/community.aws/pull/488).
- ecs_service - handle SDK errors more cleanly on update failures (https://github.com/ansible-collections/community.aws/pull/488).
- sns - Add support for ``message_group_id`` and ``message_deduplication_id`` (https://github.com/ansible-collections/community.aws/pull/1733).

v5.3.0
======

Release Summary
---------------

This release brings some minor changes, bugfixes and deprecations.

Minor Changes
-------------

- aws_ssm - added support for specifying the endpoint to use when connecting to the S3 API (https://github.com/ansible-collections/community.aws/pull/1619).
- aws_ssm - remove unused imports (https://github.com/ansible-collections/community.aws/pull/1707).
- aws_ssm - rework environment variable handling to use built in Ansible plugin support (https://github.com/ansible-collections/community.aws/pull/514).
- batch_job_definition - make trailing comma tuple explicitly a tuple (https://github.com/ansible-collections/community.aws/pull/1707).
- ecs_service - ``task_definition`` is now optional when ``force_new_deployment`` is ``True`` (https://github.com/ansible-collections/community.aws/pull/1680).
- ecs_service - new parameter ``purge_placement_constraints``  to have the ability to remove the placement constraints of an ECS Service (https://github.com/ansible-collections/community.aws/pull/1716).
- ecs_service - new parameter ``purge_placement_strategy`` to have the ability to remove the placement strategy of an ECS Service (https://github.com/ansible-collections/community.aws/pull/1716).
- iam_role - added ``assume_role_policy_document_raw`` to the role return values, this doesn't convert policy document contents from CamelCase to snake_case (https://github.com/ansible-collections/community.aws/issues/551).
- iam_role_info - added ``assume_role_policy_document_raw`` to the role return values, this doesn't convert policy document contents from CamelCase to snake_case (https://github.com/ansible-collections/community.aws/issues/551).
- inspector_target - minor linting fix (https://github.com/ansible-collections/community.aws/pull/1707).
- s3_lifecycle - add parameter ``noncurrent_version_keep_newer`` to set the number of newest noncurrent versions to retain (https://github.com/ansible-collections/community.aws/pull/1606).
- secretsmanager_secret - added support for region replication using the ``replica`` parameter (https://github.com/ansible-collections/community.aws/pull/827).
- secretsmanager_secret - added the ``overwrite`` parameter to support only setting the secret if it doesn't exist (https://github.com/ansible-collections/community.aws/pull/1628).
- sns_topic - add support for ``content_based_deduplication`` parameter (https://github.com/ansible-collections/community.aws/pull/1693).
- sns_topic - add support for ``tags`` and ``purge_tags`` (https://github.com/ansible-collections/community.aws/pull/972).
- sqs_queue - add support for ``deduplication_scope`` parameter (https://github.com/ansible-collections/community.aws/pull/1603).
- sqs_queue - add support for ``fifo_throughput_limit`` parameter (https://github.com/ansible-collections/community.aws/pull/1603).
- ssm_parameter - add support for tags in ssm parameters (https://github.com/ansible-collections/community.aws/issues/1573).

Deprecated Features
-------------------

- ecs_service -  In a release after 2024-06-01, tha default value of ``purge_placement_constraints`` will be change from ``false`` to ``true`` (https://github.com/ansible-collections/community.aws/pull/1716).
- ecs_service -  In a release after 2024-06-01, tha default value of ``purge_placement_strategy`` will be change from ``false`` to ``true`` (https://github.com/ansible-collections/community.aws/pull/1716).
- iam_role - All top level return values other than ``iam_role`` and ``changed`` have been deprecated and will be removed in a release after 2023-12-01 (https://github.com/ansible-collections/community.aws/issues/551).
- iam_role - In a release after 2023-12-01 the contents of ``assume_role_policy_document`` will no longer be converted from CamelCase to snake_case.  The ``assume_role_policy_document_raw`` return value already returns the policy document in this future format (https://github.com/ansible-collections/community.aws/issues/551).
- iam_role_info - In a release after 2023-12-01 the contents of ``assume_role_policy_document`` will no longer be converted from CamelCase to snake_case.  The ``assume_role_policy_document_raw`` return value already returns the policy document in this future format (https://github.com/ansible-collections/community.aws/issues/551).

Bugfixes
--------

- aws_ssm - fix copying empty file with older curl versions (https://github.com/ansible-collections/community.aws/issues/1686).
- eks_cluster - adding tags to eks cluster creation (https://github.com/ansible-collections/community.aws/pull/1591).
- sns_topic - avoid fetching attributes from subscribers when not setting them, this can cause permissions issues (https://github.com/ansible-collections/community.aws/pull/1418).

New Modules
-----------

- eks_nodegroup - Manage EKS Nodegroup module

v5.2.0
======

Release Summary
---------------

A minor release containing bugfixes for the ``aws_ssm`` connection
plugin and the ``ecs_service``, ``s3_lifecycle`` and  ``ssm_parameter``
modules.
As well as improvements to the ``ecs_cluster``, ``ec2_ecr``,
``ecs_service``, ``iam_role`` and ``ssm_parameter`` plugins.

Minor Changes
-------------

- aws_ssm - add ``ansible_aws_ssm_s3_addressing_style`` to allow setting the S3 addressing style (https://github.com/ansible-collections/community.aws/pull/1633).
- aws_ssm - add support for custom SSM documents (https://github.com/ansible-collections/community.aws/pull/876).
- aws_ssm - avoid overloading ``subprocess`` (https://github.com/ansible-collections/community.aws/pull/1660).
- aws_ssm - cleanup logging output (https://github.com/ansible-collections/community.aws/pull/1660).
- aws_ssm - minor refactoring (https://github.com/ansible-collections/community.aws/pull/1660).
- aws_ssm - refactor boto3 client initialization (https://github.com/ansible-collections/community.aws/pull/1663).
- aws_ssm - refactor remote command generation (https://github.com/ansible-collections/community.aws/pull/1664).
- ecs_cluster - add support for ``capacity_providers`` and ``capacity_provider_strategy`` features (https://github.com/ansible-collections/community.aws/pull/1640).
- ecs_cluster - append default value to documentation (https://github.com/ansible-collections/community.aws/pull/1636).
- ecs_ecr - add ``encryption_configuration`` option (https://github.com/ansible-collections/community.aws/pull/1623).
- ecs_service - support load balancer update for existing ECS services (https://github.com/ansible-collections/community.aws/pull/1625).
- iam_role - Drop deprecation warning, because the standard value for purge parameters is ``true`` (https://github.com/ansible-collections/community.aws/pull/1636).
- ssm_parameter - fix typo in examples ``paramater`` (https://github.com/ansible-collections/community.aws/issues/1642).

Bugfixes
--------

- aws_ssm - fix ``invalid literal for int`` error on some operating systems (https://github.com/ansible-collections/community.aws/issues/113).
- aws_ssm - fixes bug with presigned S3 URLs in post-2019 AWS regions (https://github.com/ansible-collections/community.aws/issues/1616).
- ecs_service - respect ``placement_constraints`` for existing ECS services (https://github.com/ansible-collections/community.aws/pull/1601).
- s3_lifecycle - module no longer calls ``put_lifecycle_configuration`` if there is no change (https://github.com/ansible-collections/community.aws/issues/1624).
- ssm_parameter - fix a ``KeyError`` when adding a description to an existing parameter (https://github.com/ansible-collections/community.aws/issues/1471).

v5.1.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- elasticache_parameter_group - add ``redis6.x`` group family on the module input choices (https://github.com/ansible-collections/community.aws/pull/1476).
- elb_target_group - add support for ``protocol_version`` parameter (https://github.com/ansible-collections/community.aws/pull/1496).

Bugfixes
--------

- aws_ssm - fixes S3 bucket region detection by ensuring boto client has correct credentials and exists in correct partition (https://github.com/ansible-collections/community.aws/pull/1428).
- ec2_snapshot_copy - including tags caused the erorr ``Tag specification resource type must have a value``. Fix sets the ResourceType to snapshot to resolve this issue (https://github.com/ansible-collections/community.aws/pull/1419).
- ecs_ecr - fix a ``RepositoryNotFound`` exception when trying to create repositories in check mode (https://github.com/ansible-collections/community.aws/pull/1550).
- opensearch - Fix cluster creation when using advanced security options (https://github.com/ansible-collections/community.aws/pull/1613).

v5.0.0
======

Release Summary
---------------

In this release many community modules have been promoted to Red Hat
supported status. Those modules have been moved from the commuity.aws to amazon.aws
collection.

The community.aws collection has dropped support for ``botocore<1.21.0`` and ``boto3<1.18.0``.
Support for ``ansible-core<2.11`` has also been dropped.

This release also brings some new features, bugfixes, breaking changes and deprecated features.

Minor Changes
-------------

- acm_certificate - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).
- acm_certificate_info - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).
- api_gateway_domain - Move to jittered backoff (https://github.com/ansible-collections/community.aws/pull/1386).
- autoscaling_group_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- aws_acm - the ``aws_acm`` module has been renamed to ``acm_certificate``, ``aws_acm`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1263).
- aws_acm_info - the ``aws_acm_info`` module has been renamed to ``acm_certificate_info``, ``aws_acm_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1263).
- aws_api_gateway - the ``aws_api_gateway`` module has been renamed to ``api_gateway``, ``aws_api_gateway`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1288).
- aws_api_gateway_domain - the ``aws_api_gateway_domain`` module has been renamed to ``api_gateway_domain``, ``aws_api_gateway_domain`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1288).
- aws_application_scaling_policy - the ``aws_application_scaling_policy`` module has been renamed to ``application_autoscaling_policy``, ``aws_application_scaling_policy`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1314).
- aws_batch_compute_environment - the ``aws_batch_compute_environment`` module has been renamed to ``batch_compute_environment``, ``aws_batch_compute_environment`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1272).
- aws_batch_job_definition - the ``aws_batch_job_definition`` module has been renamed to ``batch_job_definition``, ``aws_batch_job_definition`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1272).
- aws_batch_job_queue - the ``aws_batch_job_queue`` module has been renamed to ``batch_job_queue``, ``aws_batch_job_queue`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1272).
- aws_codebuild - the ``aws_codebuild`` module has been renamed to ``codebuild_project``, ``aws_codebuild`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1308).
- aws_codecommit - the ``aws_codecommit`` module has been renamed to ``codecommit_repository``, ``aws_codecommit`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1308).
- aws_codepipeline - the ``aws_codepipeline`` module has been renamed to ``codepipeline``, ``aws_codepipeline`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1308).
- aws_config_aggregation_authorization - the ``aws_config_aggregation_authorization`` module has been renamed to ``config_aggregation_authorization``, ``aws_config_aggregation_authorization`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1305).
- aws_config_aggregator - the ``aws_config_aggregator`` module has been renamed to ``config_aggregator``, ``aws_config_aggregator`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1305).
- aws_config_delivery_channel - the ``aws_config_delivery_channel`` module has been renamed to ``config_delivery_channel``, ``aws_config_delivery_channel`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1305).
- aws_config_recorder - the ``aws_config_recorder`` module has been renamed to ``config_recorder``, ``aws_config_recorder`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1305).
- aws_config_rule - the ``aws_config_rule`` module has been renamed to ``config_rule``, ``aws_config_rule`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1305).
- aws_direct_connect_confirm_connection - the ``aws_direct_connect_confirm_connection`` module has been renamed to ``directconnect_confirm_connection``, ``aws_direct_connect_confirm_connection`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1286).
- aws_direct_connect_connection - the ``aws_direct_connect_connection`` module has been renamed to ``directconnect_connection``, ``aws_direct_connect_connection`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1286).
- aws_direct_connect_gateway - the ``aws_direct_connect_gateway`` module has been renamed to ``directconnect_gateway``, ``aws_direct_connect_gateway`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1286).
- aws_direct_connect_link_aggregation_group - the ``aws_direct_connect_link_aggregation_group`` module has been renamed to ``directconnect_link_aggregation_group``, ``aws_direct_connect_link_aggregation_group`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1286).
- aws_direct_connect_virtual_interface - the ``aws_direct_connect_virtual_interface`` module has been renamed to ``directconnect_virtual_interface``, ``aws_direct_connect_virtual_interface`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1286).
- aws_eks_cluster - the ``aws_eks_cluster`` module has been renamed to ``eks_cluster``, ``aws_eks_cluster`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1269).
- aws_glue_connection - the ``aws_glue_connection`` module has been renamed to ``glue_connection``, ``aws_glue_connection`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1300).
- aws_glue_crawler - the ``aws_glue_crawler`` module has been renamed to ``glue_crawler``, ``aws_glue_crawler`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1300).
- aws_glue_job - the ``aws_glue_job`` module has been renamed to ``glue_job``, ``aws_glue_job`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1300).
- aws_inspector_target - the ``aws_inspector_target`` module has been renamed to ``inspector_target``, ``aws_inspector_target`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1318).
- aws_kms - the ``aws_kms`` module has been renamed to ``kms_key``, ``aws_kms`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1284).
- aws_kms_info - the ``aws_kms_info`` module has been renamed to ``kms_key_info``, ``aws_kms_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1284).
- aws_msk_cluster - the ``aws_msk_cluster`` module has been renamed to ``msk_cluster``, ``aws_msk_cluster`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1311).
- aws_msk_config - the ``aws_msk_config`` module has been renamed to ``msk_config``, ``aws_msk_config`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1311).
- aws_s3_bucket_info - the ``aws_s3_bucket_info`` module has been renamed to ``s3_bucket_info``, ``aws_s3_bucket_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1271).
- aws_s3_cors - the ``aws_s3_cors`` module has been renamed to ``s3_cors``, ``aws_s3_cors`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1271).
- aws_secret - the ``aws_secret`` module has been renamed to ``secretsmanager_secret``, ``aws_secret`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1315).
- aws_ses_identity - the ``aws_ses_identity`` module has been renamed to ``ses_identity``, ``aws_ses_identity`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1264).
- aws_ses_identity_policy - the ``aws_ses_identity_policy`` module has been renamed to ``ses_identity_policy``, ``aws_ses_identity_policy`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1264).
- aws_ses_rule_set - the ``aws_ses_rule_set`` module has been renamed to ``ses_rule_set``, ``aws_ses_rule_set`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1264).
- aws_sgw_info - the ``aws_sgw_info`` module has been renamed to ``storagegateway_info``, ``aws_sgw_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1301).
- aws_ssm_parameter_store - the ``aws_ssm_parameter_store`` module has been renamed to ``ssm_parameter``, ``aws_ssm_parameter_store`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1313).
- aws_step_functions_state_machine - the ``aws_step_functions_state_machine`` module has been renamed to ``stepfunctions_state_machine``, ``aws_step_functions_state_machine`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1310).
- aws_step_functions_state_machine_execution - the ``aws_step_functions_state_machine_execution`` module has been renamed to ``stepfunctions_state_machine_execution``, ``aws_step_functions_state_machine_execution`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1310).
- aws_waf_condition - the ``aws_waf_condition`` module has been renamed to ``waf_condition``, ``aws_waf_condition`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1299).
- aws_waf_info - the ``aws_waf_info`` module has been renamed to ``waf_info``, ``aws_waf_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1299).
- aws_waf_rule - the ``aws_waf_rule`` module has been renamed to ``waf_rule``, ``aws_waf_rule`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1299).
- aws_waf_web_acl - the ``aws_waf_web_acl`` module has been renamed to ``waf_web_acl``, ``aws_waf_web_acl`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1299).
- cloudfront_distribution - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudfront_info - the ``cloudfront_info`` module has been renamed to ``cloudfront_distribution_info``, ``cloudfront_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1352).
- cloudfront_origin_access_identity - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudtrail - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- community.aws modules - the ``ec2_url`` parameter has been renamed to ``endpoint_url`` for consistency, ``ec2_url`` remains as an alias (https://github.com/ansible-collections/amazon.aws/pull/992).
- ec2_asg - the ``ec2_asg`` module has been renamed to ``autoscaling_group``, ``ec2_asg`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_asg_info - the ``ec2_asg_info`` module has been renamed to ``autoscaling_group_info``, ``ec2_asg_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_asg_instance_refresh - the ``ec2_asg_instance_refresh`` module has been renamed to ``autoscaling_instance_refresh``, ``ec2_asg_instance_refresh`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_asg_instance_refresh_info - the ``ec2_asg_instance_refresh_info`` module has been renamed to ``autoscaling_instance_refresh_info``, ``ec2_asg_instance_refresh_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_asg_lifecycle_hook - the ``ec2_asg_lifecycle_hook`` module has been renamed to ``autoscaling_lifecycle_hool``, ``ec2_asg_lifecycle_hook`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_asg_scheduled_action - the ``ec2_asg_scheduled_action`` module has been renamed to ``autoscaling_scheduled_action``, ``ec2_asg_scheduled_action`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_lc - the ``ec2_lc`` module has been renamed to ``autoscaling_launch_config``, ``ec2_lc`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_lc_find - the ``ec2_lc_find`` module has been renamed to ``autoscaling_launch_config_find``, ``ec2_lc_find`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_lc_info - the ``ec2_lc_info`` module has been renamed to ``autoscaling_launch_config_info``, ``ec2_lc_info`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_metric_alarm - the ``ec2_metric_alarm`` module has been renamed to ``cloudwatch_metric_alarm``, ``ec2_metric_alarm`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1304).
- ec2_scaling_policy - the ``ec2_scaling_policy`` module has been renamed to ``autoscaling_policy``, ``ec2_scaling_policy`` remains as an alias (https://github.com/ansible-collections/community.aws/pull/1294).
- ec2_vpc_nacl - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- ec2_vpc_vpn - minor tweak to ``VPNConnectionException`` to pass message through to the superclass (https://github.com/ansible-collections/community.aws/pull/1407).
- eks_fargate_profile - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- elb_target_group - instead of completely ignoring ``health_check_path`` and ``successful_response_codes`` if ``health_check_protocol`` is not supplied, now raises an error (https://github.com/ansible-collections/community.aws/issues/29).
- redshift - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- s3_bucket_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- waf_condition - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).
- waf_info - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).
- waf_rule - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).
- waf_web_acl - Move to jittered backoff (https://github.com/ansible-collections/amazon.aws/pull/946).

Breaking Changes / Porting Guide
--------------------------------

- acm_certificate - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- autoscaling_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.autoscaling_group``.
- autoscaling_group_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.autoscaling_group_info``.
- cloudfront_distribution - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- cloudtrail - The module has been migrated to the ``amazon.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudtrail``.
- cloudwatch_metric_alarm - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudwatch_metric_alarm``.
- cloudwatchevent_rule - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudwatchevent_rule``.
- cloudwatchlogs_log_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudwatchlogs_log_group``.
- cloudwatchlogs_log_group_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudwatchlogs_log_group_info``.
- cloudwatchlogs_log_group_metric_filter - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.cloudwatchlogs_log_group_metric_filter``.
- community.aws collection - Support for ansible-core < 2.11 has been dropped (https://github.com/ansible-collections/community.aws/pull/1541).
- community.aws collection - The community.aws collection has dropped support for ``botocore<1.21.0`` and ``boto3<1.18.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/1362).
- ec2_eip - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_eip``.
- ec2_eip_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_eip_info``.
- ec2_vpc_vpn - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- elb_application_lb - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.elb_application_lb``.
- elb_application_lb_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.elb_application_lb_info``.
- execute_lambda - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.execute_lambda``.
- iam_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_policy``.
- iam_policy_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_policy_info``.
- iam_server_certificate - Passing file names to the ``cert``, ``chain_cert`` and ``key`` parameters has been removed. We recommend using a lookup plugin to read the files instead, see the documentation for an example (https://github.com/ansible-collections/community.aws/pull/1265).
- iam_server_certificate - the default value for the ``dup_ok`` parameter has been changed to ``true``. To preserve the original behaviour explicitly set the ``dup_ok`` parameter to ``false`` (https://github.com/ansible-collections/community.aws/pull/1265).
- iam_user - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_user``.
- iam_user_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.iam_user_info``.
- kms_key - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.kms_key``.
- kms_key - managing the KMS IAM Policy via ``policy_mode`` and ``policy_grant_types`` was previously deprecated and has been removed in favor of the ``policy`` option (https://github.com/ansible-collections/community.aws/pull/1344).
- kms_key - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- kms_key_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.kms_key_info``.
- lambda - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda``.
- lambda_alias - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda_alias``.
- lambda_event - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda_event``.
- lambda_execute - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda_execute``.
- lambda_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda_info``.
- lambda_policy - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.lambda_policy``.
- rds_cluster - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_cluster``.
- rds_cluster_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_cluster_info``.
- rds_cluster_snapshot - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_cluster_snapshot``.
- rds_instance - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_instance``.
- rds_instance_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_instance_info``.
- rds_instance_snapshot - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_instance_snapshot``.
- rds_option_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_option_group``.
- rds_option_group_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_option_group_info``.
- rds_param_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_param_group``.
- rds_param_group - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- rds_snapshot_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_snapshot_info``.
- rds_subnet_group - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.rds_subnet_group``.
- route53 - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.route53``.
- route53_health_check - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.route53_health_check``.
- route53_health_check - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- route53_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.route53_info``.
- route53_zone - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.route53_zone``.
- route53_zone - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).
- sqs_queue - the previously deprecated default value of ``purge_tags=False`` has been updated to ``purge_tags=True`` (https://github.com/ansible-collections/community.aws/pull/1343).

Deprecated Features
-------------------

- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.7 by this collection has been deprecated and will be removed in a release after 2023-05-31 (https://github.com/ansible-collections/community.aws/pull/1361).

Bugfixes
--------

- ec2_placement_group - Handle a potential race creation during the creation of a new Placement Group (https://github.com/ansible-collections/community.aws/pull/1477).
- elb_network_lb - fixes bug where ``ip_address_type`` in return value was not updated (https://github.com/ansible-collections/community.aws/pull/1365).
- rds_cluster - fixes bug where specifiying an rds cluster parameter group raises a ``KeyError`` (https://github.com/ansible-collections/community.aws/pull/1417).
- s3_sync - fix etag generation when running in FIPS mode (https://github.com/ansible-collections/community.aws/issues/757).

New Modules
-----------

- accessanalyzer_validate_policy_info - Performs validation of IAM policies

v4.5.1
======

Release Summary
---------------

This release contains a minor bugfix for the ``sns_topic`` module as well as corrections to the documentation for various modules.  This is the last planned release of the 4.x series.

Bugfixes
--------

- sns_topic - avoid fetching attributes from subscribers when not setting them, this can cause permissions issues (https://github.com/ansible-collections/community.aws/pull/1418).

v4.5.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.

Minor Changes
-------------

- ecs_service - support load balancer update for existing ecs services(https://github.com/ansible-collections/community.aws/pull/1625).
- iam_role - Drop deprecation warning, because the standard value for purge parametes is ``true`` (https://github.com/ansible-collections/community.aws/pull/1636).

Bugfixes
--------

- aws_ssm - fix ``invalid literal for int`` error on some operating systems (https://github.com/ansible-collections/community.aws/issues/113).
- ecs_service - respect ``placement_constraints`` for existing ecs services (https://github.com/ansible-collections/community.aws/pull/1601).
- s3_lifecycle - Module no longer calls ``put_lifecycle_configuration`` if there is no change. (https://github.com/ansible-collections/community.aws/issues/1624)
- ssm_parameter - Fix a ``KeyError`` when adding a description to an existing parameter (https://github.com/ansible-collections/community.aws/issues/1471).

v4.4.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- elasticache_parameter_group - add ``redis6.x`` group family on the module input choices (https://github.com/ansible-collections/community.aws/pull/1476).

Bugfixes
--------

- aws_ssm - fixes S3 bucket region detection by ensuring boto client has correct credentials and exists in correct partition (https://github.com/ansible-collections/community.aws/pull/1428).
- ecs_ecr - fix a ``RepositoryNotFound`` exception when trying to create repositories in check mode (https://github.com/ansible-collections/community.aws/pull/1550).
- opensearch - Fix cluster creation when using advanced security options (https://github.com/ansible-collections/community.aws/pull/1613).

v4.3.0
======

Release Summary
---------------

The community.aws 4.3.0 release includes a number of minor bug fixes and improvements.
Following the release of amazon.aws 5.0.0, backports to the 4.x series will be limited to security issues and bugfixes.

Minor Changes
-------------

- autoscaling_group_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudfront_distribution - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudfront_origin_access_identity - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudtrail - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- ec2_vpc_nacl - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- eks_fargate_profile - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- redshift - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- s3_bucket_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).

Bugfixes
--------

- ec2_placement_group - Handle a potential race creation during the creation of a new Placement Group (https://github.com/ansible-collections/community.aws/pull/1477).
- rds_cluster - fixes bug where specifiying an rds cluster parameter group raises a ``KeyError`` (https://github.com/ansible-collections/community.aws/pull/1417).

v4.2.0
======

Bugfixes
--------

- s3_lifecycle - fix bug when deleting rules with an empty prefix (https://github.com/ansible-collections/community.aws/pull/1398).

v4.1.1
======

Bugfixes
--------

- ecs_service - fixes KeyError for ``deployment_controller`` parameter (https://github.com/ansible-collections/community.aws/pull/1393).

v4.1.0
======

Minor Changes
-------------

- aws_glue_connection - added new ``raw_connection_parameters`` return key which doesn't snake case the connection parameters (https://github.com/ansible-collections/community.aws/pull/518).
- aws_ssm_parameter_store - added support for check_mode (https://github.com/ansible-collections/community.aws/pull/1309).
- cloudwatchevent_rule - Added ``targets.input_transformer.input_paths_map`` and ``targets.input_transformer.input_template`` parameters to support configuring on CloudWatch event rule input transformation (https://github.com/ansible-collections/community.aws/pull/623).
- cloudwatchevent_rule - Applied validation of ``targets`` arguments (https://github.com/ansible-collections/community.aws/issues/201).
- cloudwatchlogs_log_group - Added check_mode support (https://github.com/ansible-collections/community.aws/pull/1373).
- ec2_launch_template - Adds support for specifying the ``source_version`` upon which template updates are based (https://github.com/ansible-collections/community.aws/pull/239).
- ec2_scaling_policy - add TargetTrackingScaling as a scaling policy option (https://github.com/ansible-collections/community.aws/pull/771)
- ec2_vpc_vgw_info - updated to not throw an error when run in check_mode (https://github.com/ansible-collections/community.aws/issues/137).
- ecs_ecr - add ``force_absent`` parameter for removing repositories that contain images (https://github.com/ansible-collections/community.aws/pull/1316).
- ecs_service - add ``wait`` parameter and waiter for deleting services (https://github.com/ansible-collections/community.aws/pull/1209).
- ecs_service - added ``tags`` and ``tag_propagation`` support to the module (https://github.com/ansible-collections/community.aws/pull/543).
- ecs_service - added parameter ``deployment_controller`` so service can be controlled by Code Deploy (https://github.com/ansible-collections/community.aws/pull/340).
- ecs_task - add ``wait`` parameter and waiter for running and stopping tasks (https://github.com/ansible-collections/community.aws/pull/1209).
- elasticache_info - added ``replication_group`` to the returned information for an elasticache cluster (https://github.com/ansible-collections/community.aws/pull/646).
- iam_policy - added support for ``--diff`` mode (https://github.com/ansible-collections/community.aws/issues/560).
- iam_policy - attempts to continue when read requests are denied by IAM policy (https://github.com/ansible-collections/community.aws/pull/1375).
- iam_server_certificate - the deprecation for the ``iam_cert`` alias has been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1257).
- iam_server_certificate - the deprecations for ``cert_chain``, ``cert``, ``key`` and ``dup_ok`` have been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1256).
- lambda_info - add return key ``functions`` which returns a list of dictionaries instead of the previously returned ``function``, which returned a dictionary of dictionaries (https://github.com/ansible-collections/community.aws/pull/1239).
- lambda_info - now returns basic configuration information of each lambda function, regardless of query (https://github.com/ansible-collections/community.aws/pull/1239).
- rds_instance_snapshot - the deprecation for the ``rds_snapshot`` alias has been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1257).
- route53_health_check - Added new parameter ``health_check_id`` with alias ``id`` to allow update and delete health check by ID (https://github.com/ansible-collections/community.aws/pull/1143).
- route53_health_check - Added new parameter ``use_unique_names`` used with new parameter ``health_check_name`` with alias ``name`` to set health check name as unique identifier (https://github.com/ansible-collections/community.aws/pull/1143).
- s3_sync - improves error handling during ``HEAD`` operation to compare existing files (https://github.com/ansible-collections/community.aws/issues/58).
- secretsmanager_secret - add support for storing JSON in secrets (https://github.com/ansible-collections/community.aws/issues/656).
- sns_topic - Added ``attributes`` parameter to ``subscriptions`` items with support for RawMessageDelievery (SQS)

Deprecated Features
-------------------

- aws_glue_connection - the ``connection_parameters`` return key has been deprecated and will be removed in a release after 2024-06-01, it is being replaced by the ``raw_connection_parameters`` key (https://github.com/ansible-collections/community.aws/pull/518).
- community.aws collection - due to the AWS SDKs announcing the end of support for Python less than 3.7 (https://aws.amazon.com/blogs/developer/python-support-policy-updates-for-aws-sdks-and-tools/) support for Python less than 3.7 by this collection has been deprecated and will be removed in a release after 2023-05-31 (https://github.com/ansible-collections/community.aws/pull/1361).
- iam_policy - the ``policies`` return value has been renamed ``policy_names`` and will be removed in a release after 2024-08-01, both values are currently returned (https://github.com/ansible-collections/community.aws/pull/1375).
- lambda_info - The ``function`` return key returns a dictionary of dictionaries and has been deprecated. In a release after 2025-01-01, this key will be removed in favor of ``functions``, which returns a list of dictionaries (https://github.com/ansible-collections/community.aws/pull/1239).
- route53_info - The CamelCase return values for ``DelegationSets``, ``CheckerIpRanges``, and ``HealthCheck`` have been deprecated, in the future release you must use snake_case return values ``delegation_sets``, ``checker_ip_ranges``, and ``health_check`` instead respectively (https://github.com/ansible-collections/community.aws/pull/1322).

Bugfixes
--------

- aws_api_gateway_domain - added the ``aws_api_gateway_domain`` module to the aws module_defaults group (https://github.com/ansible-collections/community.aws/pull/1283).
- aws_config_aggregator - Fix ``KeyError`` when updating existing aggregator (https://github.com/ansible-collections/community.aws/pull/645).
- aws_config_aggregator - Fix idempotency when ``account_sources`` parameter is not specified (https://github.com/ansible-collections/community.aws/pull/645).
- aws_ssm - pull S3 bucket region for session generated for file transfer during playbooks (https://github.com/ansible-collections/community.aws/issues/1190).
- aws_ssm_parameter_store - fixed bug where module wasn't consistently idempotent (https://github.com/ansible-collections/community.aws/pull/1309).
- cloudfront_response_headers_policy - added the ``cloudfront_response_headers_policy`` module to the aws module_defaults group (https://github.com/ansible-collections/community.aws/pull/1283).
- ec2_vpc_peer - fix idempotency when requester/accepter is reversed (https://github.com/ansible-collections/community.aws/issues/580).
- kms_key_info - handle access denied errors more liberally (https://github.com/ansible-collections/community.aws/issues/206).
- route53 - fixes bug preventing creating a DNS record with a weight of zero (https://github.com/ansible-collections/community.aws/issues/1378)
- route53_info - fix ``max_items`` parameter when used with non-paginated commands (https://github.com/ansible-collections/community.aws/issues/1383).
- sns_topic - fix bug which prevented the module being used in GovCloud (https://github.com/ansible-collections/community.aws/issues/836).

New Modules
-----------

- autoscaling_complete_lifecycle_action - Completes the lifecycle action of an instance
- aws_glue_crawler - Manage an AWS Glue crawler
- lightsail_static_ip - Manage static IP addresses in AWS Lightsail

v4.0.0
======

Major Changes
-------------

- community.aws collection - The amazon.aws collection has dropped support for ``botocore<1.20.0`` and ``boto3<1.17.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/956).

Minor Changes
-------------

- aws_acm - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- aws_glue_job - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- aws_kms - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- aws_kms - add extra key/value pair to return data (key_policies) to return each policy as a dictionary rather than json string (https://github.com/ansible-collections/community.aws/pull/1052).
- aws_kms - fix some bugs in integration tests and add check mode support for key rotation as well as document issues with time taken for requested changes to be reflected on AWS (https://github.com/ansible-collections/community.aws/pull/1052).
- aws_kms - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1183).
- aws_msk_cluster - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- aws_secret - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- aws_secret - addition of the ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/issues/1146).
- aws_ssm_parameter_store - add parameter_metadata to the returned values (https://github.com/ansible-collections/community.aws/pull/1241).
- aws_step_functions_state_machine - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- cloudfront_distribution - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- cloudfront_distribution - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1183).
- cloudtrail - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1219).
- cloudtrail - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` (https://github.com/ansible-collections/community.aws/pull/1219).
- cloudtrail - updated to pass tags as part of the create API call rather than tagging the trail after creation (https://github.com/ansible-collections/community.aws/pull/1219).
- cloudwatchlogs_log_group - adds support for returning tags (https://github.com/ansible-collections/community.aws/pull/1233).
- cloudwatchlogs_log_group - adds support for updating tags (https://github.com/ansible-collections/community.aws/pull/1233).
- cloudwatchlogs_log_group - now consistently returns the values as defined in the return documentation (https://github.com/ansible-collections/community.aws/pull/1233).
- cloudwatchlogs_log_group_info - adds support for returning tags (https://github.com/ansible-collections/community.aws/pull/1233).
- data_pipeline - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1204).
- dms_endpoint - ``endpointtype`` and ``enginename`` no longer required when deleting an endpoint (https://github.com/ansible-collections/community.aws/pull/1234).
- dms_endpoint - ``resource_tags`` added as an alias for ``tags`` (https://github.com/ansible-collections/community.aws/pull/1234).
- dms_endpoint - added support for ``purge_tags`` (https://github.com/ansible-collections/community.aws/pull/1234).
- dms_endpoint - now returns details of the endpoint (https://github.com/ansible-collections/community.aws/pull/1234).
- dynamodb_table - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1199).
- ec2_ami_copy - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1204).
- ec2_asg - add check mode support (https://github.com/ansible-collections/community.aws/pull/1033).
- ec2_asg - bugfix to make test setup run once (https://github.com/ansible-collections/community.aws/pull/1061).
- ec2_asg_lifecycle_hook - Added check_mode support (https://github.com/ansible-collections/community.aws/pull/1060).
- ec2_asg_lifecycle_hook - add integration tests (https://github.com/ansible-collections/community.aws/pull/1048).
- ec2_asg_lifecycle_hook - module now returns info about Life Cycle Hook (https://github.com/ansible-collections/community.aws/pull/1048).
- ec2_eip - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- ec2_launch_template - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1204).
- ec2_snapshot_copy - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1201).
- ec2_snapshot_copy - updated to pass tags as part of the copy API call rather than tagging the snapshot after creation (https://github.com/ansible-collections/community.aws/pull/1201).
- ec2_transit_gateway - code updated to use common ``ensure_ec2_tags`` helper (https://github.com/ansible-collections/community.aws/pull/1183).
- ec2_transit_gateway - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` (https://github.com/ansible-collections/community.aws/pull/1183).
- ec2_transit_gateway - wait and retry if API returns an IncorrectState error.
- ec2_vpc_nacl - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1189).
- ec2_vpc_nacl - add support for ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1189).
- ec2_vpc_nacl - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1189).
- ec2_vpc_peer - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- ec2_vpc_vgw - add support for ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1232).
- ec2_vpc_vgw - the default behaviour for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1232).
- ec2_vpc_vgw - updated to set tags as part of VGW creation instead of tagging the VGW after creation (https://github.com/ansible-collections/community.aws/pull/1232).
- ec2_vpc_vgw_info - added ``resource_tags`` to the return values (https://github.com/ansible-collections/community.aws/pull/1232).
- ec2_vpc_vpn - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- ec2_vpc_vpn - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1183).
- ecs_ecr - Will now return repository permission policy if it exists, even if we did not create or modify it. (https://github.com/ansible-collections/community.aws/pull/1171).
- ecs_service - Now allows for a ``capacity_provider_strategy`` to be utilized when creating/updating a service (https://github.com/ansible-collections/community.aws/pull/1181).
- ecs_task - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1204).
- efs - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` (https://github.com/ansible-collections/community.aws/pull/1183).
- eks_fargate_profile - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` (https://github.com/ansible-collections/community.aws/pull/1183).
- elb_application_lb - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- elb_network_lb - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- elb_target_group - explicitly setting the ``tags`` parameter to the empty dict ``{}`` will now remove all tags unles ``purge_tags`` is explicitly set to ``False`` (https://github.com/ansible-collections/community.aws/pull/1183).
- iam_policy - update broken examples and add RETURN section to documentation; add extra integration tests for idempotency check mode runs (https://github.com/ansible-collections/community.aws/pull/1093).
- iam_role - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- iam_role - delete inline policies prior to deleting role (https://github.com/ansible-collections/community.aws/pull/1054).
- iam_role - remove global vars and refactor accordingly (https://github.com/ansible-collections/community.aws/pull/1054).
- iam_user - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- iam_user - add ``user`` value to return data structure to deprecate old ``iam_user`` (https://github.com/ansible-collections/community.aws/pull/1059).
- lambda - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1202).
- lambda - add kms_key_arn parameter (https://github.com/ansible-collections/community.aws/pull/1108).
- lambda - the behavior for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1202).
- rds_cluster - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- rds_instance - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- rds_instance - add ``deletion_protection`` parameter (https://github.com/ansible-collections/community.aws/pull/1105).
- rds_instance - add support for addition/removal of iam roles to db instance (https://github.com/ansible-collections/community.aws/pull/1002).
- rds_instance_snapshot - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1200).
- rds_instance_snapshot - add ``check_mode`` (https://github.com/ansible-collections/community.aws/pull/789).
- rds_instance_snapshot - add copy_db_snapshot functionality (https://github.com/ansible-collections/community.aws/pull/1078).
- rds_instance_snapshot - add integration tests (https://github.com/ansible-collections/community.aws/pull/789).
- rds_instance_snapshot - update module to use handlers defined in module_utils/rds.py (https://github.com/ansible-collections/community.aws/pull/789).
- rds_option_group - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- rds_param_group - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- rds_param_group - the default value for ``tags`` has been updated, to remove all tags the ``tags`` parameter must be explicitly set to the empty dict ``{}`` and ``purge_tags`` to ``True`` (https://github.com/ansible-collections/community.aws/pull/1183).
- rds_subnet_group - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- redshift - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1182).
- route53 - add support for GeoLocation param (https://github.com/ansible-collections/amazon.aws/pull/1117).
- route53_health_check - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- route53_info - add RETURN section to documentation (https://github.com/ansible-collections/community.aws/pull/1240).
- route53_zone - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- sqs_queue - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1185).
- wafv2_ip_set - Added support for ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1205).
- wafv2_ip_set - Added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1205).
- wafv2_ip_set - Added support for updating tags (https://github.com/ansible-collections/community.aws/pull/1205).
- wafv2_ip_set_info - Added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1205).
- wafv2_rule_group - Added support for ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1210).
- wafv2_rule_group - Added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1210).
- wafv2_rule_group - Added support for updating tags (https://github.com/ansible-collections/community.aws/pull/1210).
- wafv2_rule_group_info - Added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1210).
- wafv2_web_acl - Added support for ``purge_tags`` (https://github.com/ansible-collections/community.aws/pull/1218).
- wafv2_web_acl - Added support for updating tags (https://github.com/ansible-collections/community.aws/pull/1218).
- wafv2_web_acl - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1218).
- wafv2_web_acl - added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1218).
- wafv2_web_acl_info - added support for returning tags (https://github.com/ansible-collections/community.aws/pull/1218).

Breaking Changes / Porting Guide
--------------------------------

- Tags beginning with ``aws:`` will not be removed when purging tags, these tags are reserved by Amazon and may not be updated or deleted (https://github.com/ansible-collections/amazon.aws/issues/817).
- aws_secret - tags are no longer removed when the ``tags`` parameter is not set.  To remove all tags set ``tags={}`` (https://github.com/ansible-collections/community.aws/issues/1146).
- community.aws collection - The ``community.aws`` collection has now dropped support for and any requirements upon the original ``boto`` AWS SDK, and now uses the ``boto3``/``botocore`` AWS SDK (https://github.com/ansible-collections/community.aws/pull/898).
- community.aws collection - the ``profile`` parameter is now mutually exclusive with the ``aws_access_key``, ``aws_secret_key`` and ``security_token`` parameters (https://github.com/ansible-collections/amazon.aws/pull/834).
- ec2_vpc_route_table - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_route_table``.
- ec2_vpc_route_table_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_route_table_info``.
- elb_instance - the ``ec2_elbs`` fact has been removed, ``updated_elbs`` has been added the return values and includes the same information (https://github.com/ansible-collections/community.aws/pull/1173).
- elb_network_lb - the default value of ``state`` has changed from ``absent`` to ``present`` (https://github.com/ansible-collections/community.aws/pull/1167).
- script_inventory_ec2 - The ec2.py inventory script has been moved to a new repository. The script can now be downloaded from https://github.com/ansible-community/contrib-scripts/blob/main/inventory/ec2.py and has been removed from this collection. We recommend migrating from the script to the amazon.aws.ec2 inventory plugin.  (https://github.com/ansible-collections/community.aws/pull/898)

Deprecated Features
-------------------

- aws_acm - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- aws_kms - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- cloudfront_distribution - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- ec2_vpc_vpn - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- rds_param_group - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- route53_health_check - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- route53_zone - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.
- sqs_queue - the current default value of ``False`` for ``purge_tags`` has been deprecated and will be updated in release 5.0.0 to ``True``.

Removed Features (previously deprecated)
----------------------------------------

- aws_kms_info - the unused and deprecated ``keys_attr`` parameter has been removed (https://github.com/ansible-collections/amazon.aws/pull/1172).
- data_pipeline - the ``version`` option has always been ignored and has been removed (https://github.com/ansible-collections/community.aws/pull/1160
- ec2_eip - The ``wait_timeout`` option has been removed. It has always been ignored by the module (https://github.com/ansible-collections/community.aws/pull/1159).
- ec2_lc - the ``associate_public_ip_address`` option has been removed. It has always been ignored by the module (https://github.com/ansible-collections/community.aws/pull/1158).
- ec2_metric_alarm - support for using the ``<=``, ``<``, ``>`` and ``>=`` operators for comparison has been dropped. Please use ``LessThanOrEqualToThreshold``, ``LessThanThreshold``, ``GreaterThanThreshold`` or ``GreaterThanOrEqualToThreshold`` instead (https://github.com/ansible-collections/amazon.aws/pull/1164).
- ecs_ecr - The deprecated alias ``delete_policy`` has been removed.  Please use ``purge_policy`` instead (https://github.com/ansible-collections/community.aws/pull/1161).
- iam_managed_policy - the unused ``fail_on_delete`` parameter has been removed (https://github.com/ansible-collections/community.aws/pull/1168)
- s3_lifecycle - the unused parameter ``requester_pays`` has been removed (https://github.com/ansible-collections/community.aws/pull/1165).
- s3_sync - remove unused ``retries`` parameter (https://github.com/ansible-collections/community.aws/pull/1166).

Bugfixes
--------

- aws_ssm connection plugin - fix linting errors in documentation data (https://github.com/ansible-collections/community.aws/pull/965).
- aws_ssm_parameter_store - fix exception when description was set without value (https://github.com/ansible-collections/community.aws/pull/1241).
- don't require ``db_instance_identifier`` on state = present (https://github.com/ansible-collections/community.aws/pull/1078).
- dynamodb_table - fix an issue when creating secondary indexes with global_keys_only (https://github.com/ansible-collections/community.aws/issues/967).
- ec2_asg - Change the default value of ``purge_tags`` to ``false``. Restores previous behaviour (https://github.com/ansible-collections/community.aws/pull/1064).
- ec2_vpc_vpn - fix exception when no tags are passed in check mode (https://github.com/ansible-collections/community.aws/pull/1242).
- ecs_service - add missing change detect of ``health_check_grace_period_seconds`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix broken compare of ``task_definition`` that results always in a changed task (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix validation for ``placement_constraints``. It's possible to use ``distinctInstance`` placement constraint now (https://github.com/ansible-collections/community.aws/issues/1058)
- ecs_taskdefinition - fix broken change detect of ``launch_type`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- elb_application_lb_info - Up default value AWS backoff retries for paginated calls. (https://github.com/ansible-collections/community.aws/pull/1113).
- elb_target_group_info - Up default value AWS backoff retries for paginated calls. (https://github.com/ansible-collections/community.aws/pull/1113).
- execute_lamba - add waiter for function_updated (https://github.com/ansible-collections/community.aws/pull/1108).
- execute_lambda - fix check mode and update RETURN documentation (https://github.com/ansible-collections/community.aws/pull/1115).
- iam_policy - require one of ``policy_document`` and ``policy_json`` when state is present to prevent MalformedPolicyDocumentException from being thrown (https://github.com/ansible-collections/community.aws/pull/1093).
- iam_user - don't delete user login profile on check mode (https://github.com/ansible-collections/community.aws/pull/1059).
- iam_user_info - gracefully handle when no users are found (https://github.com/ansible-collections/community.aws/pull/1059).
- lambda - fix bug where tag keys were mangled in the return values (https://github.com/ansible-collections/community.aws/pull/1202).
- lambda - fix bug where the lambda module was modifying tags in check mode (https://github.com/ansible-collections/community.aws/pull/1202).
- lambda - fix check mode on creation (https://github.com/ansible-collections/community.aws/pull/1108).
- rds_instance - fix check_mode and idempotency issues and added integration tests for all tests in suite (https://github.com/ansible-collections/community.aws/pull/1002).
- s3_lifecycle - add support of value *0* for ``transition_days`` (https://github.com/ansible-collections/community.aws/pull/1077).
- s3_lifecycle - check that configuration is complete before returning (https://github.com/ansible-collections/community.aws/pull/1085).
- wafv2_rule_group - fix bug where description of resource state was missing when rule groups were updated (https://github.com/ansible-collections/community.aws/pull/1210).
- wafv2_rule_group - fix bug where updating just the description did not update the changed state (https://github.com/ansible-collections/community.aws/pull/1210).

New Modules
-----------

- ec2_transit_gateway_vpc_attachment - Create and delete AWS Transit Gateway VPC attachments
- ec2_transit_gateway_vpc_attachment_info - describes AWS Transit Gateway VPC attachments
- eks_fargate_profile - Manage EKS Fargate Profile
- networkfirewall - manage AWS Network Firewall firewalls
- networkfirewall_info - describe AWS Network Firewall firewalls
- networkfirewall_policy - manage AWS Network Firewall policies
- networkfirewall_policy_info - describe AWS Network Firewall policies
- networkfirewall_rule_group - create, delete and modify AWS Network Firewall rule groups
- networkfirewall_rule_group_info - describe AWS Network Firewall rule groups
- opensearch - Creates OpenSearch or ElasticSearch domain
- opensearch_info - obtain information about one or more OpenSearch or ElasticSearch domain
- rds_cluster_snapshot - Manage Amazon RDS snapshots of DB clusters

v3.6.0
======

Release Summary
---------------

Following the release of community.aws 5.0.0, 3.6.0 is a bugfix release and the final planned release for the 3.x series.

Minor Changes
-------------

- autoscaling_group_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudfront_distribution - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudfront_origin_access_identity - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- cloudtrail - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- ec2_asg_lifecycle_hook - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- ec2_vpc_nacl - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- redshift - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).
- s3_bucket_info - minor sanity test fixes (https://github.com/ansible-collections/community.aws/pull/1410).

Bugfixes
--------

- ec2_placement_group - Handle a potential race creation during the creation of a new Placement Group (https://github.com/ansible-collections/community.aws/pull/1477).
- s3_lifecycle - fix bug when deleting rules with an empty prefix (https://github.com/ansible-collections/community.aws/pull/1398).

v3.5.0
======

Minor Changes
-------------

- iam_server_certificate - the deprecation for the ``iam_cert`` alias has been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1257).
- iam_server_certificate - the deprecations for ``cert_chain``, ``cert``, ``key`` and ``dup_ok`` have been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1256).
- rds_instance_snapshot - the deprecation for the ``rds_snapshot`` alias has been extended from release 4.0.0 to release 5.0.0 (https://github.com/ansible-collections/community.aws/pull/1257).
- s3_sync - improves error handling during ``HEAD`` operation to compare existing files (https://github.com/ansible-collections/community.aws/issues/58).

Bugfixes
--------

- aws_api_gateway_domain - added the ``aws_api_gateway_domain`` module to the aws module_defaults group (https://github.com/ansible-collections/community.aws/pull/1283).
- aws_config_aggregator - Fix ``KeyError`` when updating existing aggregator (https://github.com/ansible-collections/community.aws/pull/645).
- aws_config_aggregator - Fix idempotency when ``account_sources`` parameter is not specified (https://github.com/ansible-collections/community.aws/pull/645).
- aws_ssm - pull S3 bucket region for session generated for file transfer during playbooks (https://github.com/ansible-collections/community.aws/issues/1190).
- cloudfront_response_headers_policy - added the ``cloudfront_response_headers_policy`` module to the aws module_defaults group (https://github.com/ansible-collections/community.aws/pull/1283).
- ec2_vpc_peer - fix idempotency when requester/accepter is reversed (https://github.com/ansible-collections/community.aws/issues/580).
- kms_key_info - handle access denied errors more liberally (https://github.com/ansible-collections/community.aws/issues/206).
- route53 - fixes bug preventing creating a DNS record with a weight of zero (https://github.com/ansible-collections/community.aws/issues/1378)
- route53_info - fix ``max_items`` parameter when used with non-paginated commands (https://github.com/ansible-collections/community.aws/issues/1383).

v3.4.0
======

Minor Changes
-------------

- aws_codebuild - add support for ``purge_tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1221).
- aws_codebuild - add the ``resource_tags`` parameter which takes the dictionary format for tags instead of the list of dictionaries format (https://github.com/ansible-collections/community.aws/pull/1221).
- aws_codebuild - add the ``resource_tags`` return value which returns the standard dictionary format for tags instead of the list of dictionaries format (https://github.com/ansible-collections/community.aws/pull/1221).
- aws_codebuild - the ``source`` and ``artifacts`` parameters are now optional unless creating a new project (https://github.com/ansible-collections/community.aws/pull/1221).
- ecs_service - ``deployment_circuit_breaker`` has been added as a supported feature (https://github.com/ansible-collections/community.aws/pull/1215).
- ecs_service - add ``service`` alias to address the ecs service name with the same parameter as the ecs_service_info module is doing (https://github.com/ansible-collections/community.aws/pull/1187).
- ecs_service_info - add ``name`` alias to address the ecs service name with the same parameter as the ecs_service module is doing (https://github.com/ansible-collections/community.aws/pull/1187).
- ecs_tag - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1184).
- efs_tag - ``resource_tags`` has been added as an alias for the ``tags`` parameter (https://github.com/ansible-collections/community.aws/pull/1184).
- rds_instance - add snapshot tests to test suite to test restoring db from snapshot (https://github.com/ansible-collections/community.aws/pull/1081).
- rds_instance_info - add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/1026).
- wafv2_web_acl - relax botocore requirement to bare minimum required (https://github.com/ansible-collections/community.aws/pull/1216).

Deprecated Features
-------------------

- aws_codebuild - The ``tags`` parameter currently uses a non-standard format and has been deprecated.  In release 6.0.0 this parameter will accept a simple key/value pair dictionary instead of the current list of dictionaries.  It is recommended to migrate to using the resource_tags parameter which already accepts the simple dictionary format (https://github.com/ansible-collections/community.aws/pull/1221).
- route53_info - The CamelCase return values for ``HostedZones``, ``ResourceRecordSets``, and ``HealthChecks`` have been deprecated, in the future release you must use snake_case return values ``hosted_zones``, ``resource_record_sets``, and ``health_checks`` instead respectively.

Bugfixes
--------

- aws_codebuild - fix bug where the result may be spuriously flagged as ``changed`` when multiple tags were set on the project (https://github.com/ansible-collections/community.aws/pull/1221).
- ecs_service - fix broken change detect of ``health_check_grace_period_seconds`` parameter when not specified (https://github.com/ansible-collections/community.aws/pull/1212).
- ecs_service - use default cluster name of ``default`` when not input (https://github.com/ansible-collections/community.aws/pull/1212).
- ecs_task - dont require ``cluster`` and use name of ``default`` when not input (https://github.com/ansible-collections/community.aws/pull/1212).
- lambda_info - fix bug that forces query=config when getting info for all lambdas. Now, if function name is specified, query will default to all.  This may have a performance impact when querying a large number of lambdas. If function name is not specified, query will default to config (https://github.com/ansible-collections/community.aws/pull/1152).
- rds_instance - fix bugs associated with restoring db instance from snapshot (https://github.com/ansible-collections/community.aws/pull/1081).
- wafv2_ip_set - fix bug where incorrect changed state was returned when only changing the description (https://github.com/ansible-collections/community.aws/pull/1211).
- wafv2_web_acl - consistently return web ACL info as described in module documentation (https://github.com/ansible-collections/community.aws/pull/1216).
- wafv2_web_acl - fix ``changed`` status when description not specified (https://github.com/ansible-collections/community.aws/pull/1216).

v3.3.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.

Minor Changes
-------------

- aws_kms - add extra key/value pair to return data (key_policies) to return each policy as a dictionary rather than json string (https://github.com/ansible-collections/community.aws/pull/1052).
- aws_kms - fix some bugs in integration tests and add check mode support for key rotation as well as document issues with time taken for requested changes to be reflected on AWS (https://github.com/ansible-collections/community.aws/pull/1052).
- ec2_asg - add check mode support (https://github.com/ansible-collections/community.aws/pull/1033).
- iam_policy - update broken examples and add RETURN section to documentation; add extra integration tests for idempotency check mode runs (https://github.com/ansible-collections/community.aws/pull/1093).
- iam_user - add ``user`` value to return data structure to deprecate old ``iam_user`` (https://github.com/ansible-collections/community.aws/pull/1059).
- lambda - add kms_key_arn parameter (https://github.com/ansible-collections/community.aws/pull/1108).
- rds_instance - add ``deletion_protection`` parameter (https://github.com/ansible-collections/community.aws/pull/1105).
- rds_instance - add support for addition/removal of iam roles to db instance (https://github.com/ansible-collections/community.aws/pull/1002).
- rds_instance_snapshot - add ``check_mode`` (https://github.com/ansible-collections/community.aws/pull/789).
- rds_instance_snapshot - add copy_db_snapshot functionality (https://github.com/ansible-collections/community.aws/pull/1078).
- rds_instance_snapshot - add integration tests (https://github.com/ansible-collections/community.aws/pull/789).
- rds_instance_snapshot - update module to use handlers defined in module_utils/rds.py (https://github.com/ansible-collections/community.aws/pull/789).
- route53 - add support for GeoLocation param (https://github.com/ansible-collections/amazon.aws/pull/1117).

Bugfixes
--------

- dynamodb_table - fix an issue when creating secondary indexes with global_keys_only (https://github.com/ansible-collections/community.aws/issues/967).
- ecs_service - add missing change detect of ``health_check_grace_period_seconds`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix broken compare of ``task_definition`` that results always in a changed task (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix validation for ``placement_constraints``. It's possible to use ``distinctInstance`` placement constraint now (https://github.com/ansible-collections/community.aws/issues/1058)
- ecs_taskdefinition - fix broken change detect of ``launch_type`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- execute_lambda - add waiter for function_updated (https://github.com/ansible-collections/community.aws/pull/1108).
- execute_lambda - fix check mode and update RETURN documentation (https://github.com/ansible-collections/community.aws/pull/1115).
- iam_policy - require one of ``policy_document`` and ``policy_json`` when state is present to prevent MalformedPolicyDocumentException from being thrown (https://github.com/ansible-collections/community.aws/pull/1093).
- iam_user - don't delete user login profile on check mode (https://github.com/ansible-collections/community.aws/pull/1059).
- iam_user_info - gracefully handle when no users are found (https://github.com/ansible-collections/community.aws/pull/1059).
- lambda - fix check mode on creation (https://github.com/ansible-collections/community.aws/pull/1108).
- rds_instance - fix check_mode and idempotency issues and added integration tests for all tests in suite (https://github.com/ansible-collections/community.aws/pull/1002).
- rds_instance_snapshot - don't require ``db_instance_identifier`` on state = present (https://github.com/ansible-collections/community.aws/pull/1078).
- s3_lifecycle - add support of value *0* for ``transition_days`` (https://github.com/ansible-collections/community.aws/pull/1077).
- s3_lifecycle - check that configuration is complete before returning (https://github.com/ansible-collections/community.aws/pull/1085).

New Modules
-----------

- aws_api_gateway_domain - Manage AWS API Gateway custom domains

v3.2.1
======

Release Summary
---------------

This is a bugfix release of the ``community.aws`` collection.
The new parameter ``purge_tags`` in ``ec2_asg`` module, that
was introduced in ``community.aws 3.2.0`` with its default
value ``true``, possibly breaks existing playbooks for users
if they don't update their playbooks and specify
``purge_tags: false``. However, this release restores the
previous behaviour.

Minor Changes
-------------

- iam_role - delete inline policies prior to deleting role (https://github.com/ansible-collections/community.aws/pull/1054).
- iam_role - remove global vars and refactor accordingly (https://github.com/ansible-collections/community.aws/pull/1054).

Bugfixes
--------

- ec2_asg - Change the default value of ``purge_tags`` to ``false``. Restores previous behaviour (https://github.com/ansible-collections/community.aws/pull/1064).

v3.2.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Major Changes
-------------

- s3_bucket_notifications - refactor module to support SNS / SQS targets as well as the existing support for Lambda functions (https://github.com/ansible-collections/community.aws/issues/140).

Minor Changes
-------------

- aws_acm - Add ``tags`` and ``purge_tags`` parameters to tag certificates in ACM (https://github.com/ansible-collections/community.aws/pull/870).
- cloudfront_distribution - Added support for retries (AWSRetry.jittered_backoff) (https://github.com/ansible-collections/community.aws/issues/296)
- ec2_asg - Added functionality to detach specific instances and/or decrement desired capacity from ASG without terminating instances (https://github.com/ansible-collections/community.aws/pull/933).
- ec2_asg - Restructure integration tests to run in parallel and reduce runtime (https://github.com/ansible-collections/community.aws/pull/1036).
- ec2_asg - add support for ``purge_tags`` to ec2_asg (https://github.com/ansible-collections/community.aws/pull/960).
- ec2_eip - refactor module by fixing check_mode and more clear return obj. added integration tests (https://github.com/ansible-collections/community.aws/pull/936)
- elb_application_lb - Add support for alb specific attributes and check_mode support for modifying them (https://github.com/ansible-collections/community.aws/pull/963).
- elb_application_lb - add check_mode support and refactor integration tests (https://github.com/ansible-collections/community.aws/pull/894)
- elb_application_lb_info - update documentation and refactor integration tests (https://github.com/ansible-collections/community.aws/pull/894)
- elb_target_group - add support for alb target_type and update documentation (https://github.com/ansible-collections/community.aws/pull/966).
- elb_target_group - add support for setting load_balancing_algorithm_type (https://github.com/ansible-collections/community.aws/pull/1016).
- rds_instance - add ``choices`` for valid engine value (https://github.com/ansible-collections/community.aws/pull/1034).
- rds_subnet_group - add ``check_mode`` (https://github.com/ansible-collections/community.aws/pull/562).
- rds_subnet_group - add ``tags`` feature (https://github.com/ansible-collections/community.aws/pull/562).

Bugfixes
--------

- ecs_taskdefinition - include launch_type comparison when comparing task definitions (https://github.com/ansible-collections/community.aws/pull/840)
- elb_application_lb - Fix empty security groups list behaves inconsistently on create/update by treating empty security group as VPC's defaault (https://github.com/ansible-collections/community.aws/pull/971).
- elb_application_lb_info - Add backoff retry logic (https://github.com/ansible-collections/community.aws/pull/977)
- elb_target_group_info - Add backoff retry logic (https://github.com/ansible-collections/community.aws/pull/1001)
- iam_role - Removes unnecessary removal of permission boundary from a role when deleting a role. Unlike inline policies, permission boundaries do not need to be removed from an IAM role before deleting the IAM role. This behavior causes issues when a permission boundary is inherited that prevents removal of the permission boundary. (https://github.com/ansible-collections/community.aws/pull/961)
- redshift_info - fix invalid import path for botocore exceptions (https://github.com/ansible-collections/community.aws/issues/968).
- wafv2_web_acl - fix exception when a rule contains lists values (https://github.com/ansible-collections/community.aws/pull/962).

New Modules
-----------

- cloudfront_response_headers_policy - Create, update and delete response headers policies to be used in a Cloudfront distribution
- ec2_asg_instance_refresh - Start or cancel an EC2 Auto Scaling Group (ASG) instance refresh in AWS
- ec2_asg_instance_refresh_info - Gather information about ec2 Auto Scaling Group (ASG) Instance Refreshes in AWS
- rds_cluster - rds_cluster module
- rds_cluster_info - Obtain information about one or more RDS clusters
- sns_topic_info - sns_topic_info module

v3.1.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- aws_secret - Add ``resource_policy`` parameter (https://github.com/ansible-collections/community.aws/pull/843).
- aws_ssm connection plugin - add parameters to explicitly specify SSE mode and KMS key id for uploads on the file transfer bucket. (https://github.com/ansible-collections/community.aws/pull/763)
- dynamodb_table - the ``table_class`` parameter has been added (https://github.com/ansible-collections/community.aws/pull/880).
- ec2_launch_template - Add metadata options parameter ``http_protocol_ipv6`` and ``instance_metadata_tags`` (https://github.com/ansible-collections/community.aws/pull/917).
- ec2_lc - add support for throughput parameter (https://github.com/ansible-collections/community.aws/pull/790).
- ec2_placement_group - add support for partition strategy and partition count (https://github.com/ansible-collections/community.aws/pull/872).
- elb_instance - ``wait`` parameter is no longer ignored (https://github.com/ansible-collections/community.aws/pull/826)
- elb_target_group - add support for parameter ``deregistration_connection_termination`` (https://github.com/ansible-collections/community.aws/pull/913).
- iam_managed_policy - refactor module adding ``check_mode`` and better AWSRetry backoff logic (https://github.com/ansible-collections/community.aws/pull/893).
- iam_user - add parameter ``password_reset_required`` (https://github.com/ansible-collections/community.aws/pull/860).
- wafv2_web_acl - Documentation updates wafv2_web_acl and aws_waf_web_acl (https://github.com/ansible-collections/community.aws/pull/721).
- wafv2_web_acl - Extended the wafv2_web_acl module to also take the ``custom_response_bodies`` argument (https://github.com/ansible-collections/community.aws/pull/721).

Bugfixes
--------

- Add backoff retry logic to route53_info (https://github.com/ansible-collections/community.aws/pull/865).
- Add backoff retry logic to route53_zone (https://github.com/ansible-collections/community.aws/pull/865).
- cloudfront_distribution - Dont pass ``s3_origin_access_identity_enabled`` to API request (https://github.com/ansible-collections/community.aws/pull/881).
- execute_lambda - Wait for Lambda function State = Active before executing (https://github.com/ansible-collections/community.aws/pull/857)
- lambda - Wait for Lambda function State = Active & LastUpdateStatus = Successful before updating (https://github.com/ansible-collections/community.aws/pull/857)
- rds_instance - Fix updates of ``iops`` or ``allocated_storage`` for ``io1`` DB instances when only one value is changing (https://github.com/ansible-collections/community.aws/pull/878).

v3.0.1
======

Release Summary
---------------

This is a path release of the ``community.aws`` collection.

Minor Changes
-------------

- aws_msk_config - remove duplicated and unspecific requirements (https://github.com/ansible-collections/community.aws/pull/863).
- ecs_taskdefinition - remove duplicated and unspecific requirements (https://github.com/ansible-collections/community.aws/pull/863).
- s3_lifecycle - Add ``abort_incomplete_multipart_upload_days`` and ``expire_object_delete_marker`` parameters (https://github.com/ansible-collections/community.aws/pull/794).

v3.0.0
======

Major Changes
-------------

- community.aws collection - The community.aws collection has dropped support for ``botocore<1.19.0`` and ``boto3<1.16.0``. Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/community.aws/pull/809).

Minor Changes
-------------

- aws_glue_job - Added ``command_python_version`` parameter (https://github.com/ansible-collections/community.aws/pull/480).
- aws_glue_job - Added ``glue_version`` parameter (https://github.com/ansible-collections/community.aws/pull/480).
- aws_glue_job - Added support for check mode (https://github.com/ansible-collections/community.aws/pull/480).
- aws_glue_job - Added support for tags (https://github.com/ansible-collections/community.aws/pull/480).
- aws_ssm connection plugin - add parameters to explicitly specify SSE mode and KMS key id for uploads on the file transfer bucket. (https://github.com/ansible-collections/community.aws/pull/763)
- iam_user - add boto3 waiter for iam user creation (https://github.com/ansible-collections/community.aws/pull/822).
- iam_user - add password management support bringing parity with ``iam`` module (https://github.com/ansible-collections/community.aws/pull/822).
- route53 - ``ttl``  and ``value`` are not required for deleting records (https://github.com/ansible-collections/community.aws/pull/801).
- route53_info - ``max_items`` and ``type`` are no longer ignored fixing a regression (https://github.com/ansible-collections/community.aws/pull/813).

Breaking Changes / Porting Guide
--------------------------------

- aws_acm_facts -  Remove deprecated alias ``aws_acm_facts``.  Please use ``aws_acm_info`` instead.
- aws_kms_facts -  Remove deprecated alias ``aws_kms_facts``.  Please use ``aws_kms_info`` instead.
- aws_kms_info - Deprecated ``keys_attr`` field is now ignored (https://github.com/ansible-collections/community.aws/pull/838).
- aws_region_facts -  Remove deprecated alias ``aws_region_facts``.  Please use ``aws_region_info`` instead.
- aws_s3_bucket_facts -  Remove deprecated alias ``aws_s3_bucket_facts``.  Please use ``aws_s3_bucket_info`` instead.
- aws_sgw_facts -  Remove deprecated alias ``aws_sgw_facts``.  Please use ``aws_sgw_info`` instead.
- aws_waf_facts -  Remove deprecated alias ``aws_waf_facts``.  Please use ``aws_waf_info`` instead.
- cloudfront_facts -  Remove deprecated alias ``cloudfront_facts``.  Please use ``cloudfront_info`` instead.
- cloudwatchlogs_log_group_facts -  Remove deprecated alias ``cloudwatchlogs_log_group_facts``.  Please use ``cloudwatchlogs_log_group_info`` instead.
- dynamodb_table - deprecated updates currently ignored for primary keys and global_all indexes will now result in a failure. (https://github.com/ansible-collections/community.aws/pull/837).
- ec2_asg_facts -  Remove deprecated alias ``ec2_asg_facts``.  Please use ``ec2_asg_info`` instead.
- ec2_customer_gateway_facts -  Remove deprecated alias ``ec2_customer_gateway_facts``.  Please use ``ec2_customer_gateway_info`` instead.
- ec2_eip_facts -  Remove deprecated alias ``ec2_eip_facts``.  Please use ``ec2_eip_info`` instead.
- ec2_elb_facts -  Remove deprecated alias ``ec2_elb_facts``.  Please use ``ec2_elb_info`` instead.
- ec2_elb_info -  The ``ec2_elb_info`` module has been removed.  Please use ``the ``elb_classic_lb_info`` module.
- ec2_lc_facts -  Remove deprecated alias ``ec2_lc_facts``.  Please use ``ec2_lc_info`` instead.
- ec2_placement_group_facts -  Remove deprecated alias ``ec2_placement_group_facts``.  Please use ``ec2_placement_group_info`` instead.
- ec2_vpc_nacl_facts -  Remove deprecated alias ``ec2_vpc_nacl_facts``.  Please use ``ec2_vpc_nacl_info`` instead.
- ec2_vpc_peering_facts -  Remove deprecated alias ``ec2_vpc_peering_facts``.  Please use ``ec2_vpc_peering_info`` instead.
- ec2_vpc_route_table_facts -  Remove deprecated alias ``ec2_vpc_route_table_facts``.  Please use ``ec2_vpc_route_table_info`` instead.
- ec2_vpc_vgw_facts -  Remove deprecated alias ``ec2_vpc_vgw_facts``.  Please use ``ec2_vpc_vgw_info`` instead.
- ec2_vpc_vpn_facts -  Remove deprecated alias ``ec2_vpc_vpn_facts``.  Please use ``ec2_vpc_vpn_info`` instead.
- ecs_service_facts -  Remove deprecated alias ``ecs_service_facts``.  Please use ``ecs_service_info`` instead.
- ecs_taskdefinition_facts -  Remove deprecated alias ``ecs_taskdefinition_facts``.  Please use ``ecs_taskdefinition_info`` instead.
- efs_facts -  Remove deprecated alias ``efs_facts``.  Please use ``efs_info`` instead.
- elasticache_facts -  Remove deprecated alias ``elasticache_facts``.  Please use ``elasticache_info`` instead.
- elb_application_lb_facts -  Remove deprecated alias ``elb_application_lb_facts``.  Please use ``elb_application_lb_info`` instead.
- elb_classic_lb_facts -  Remove deprecated alias ``elb_classic_lb_facts``.  Please use ``elb_classic_lb_info`` instead.
- elb_target_facts -  Remove deprecated alias ``elb_target_facts``.  Please use ``elb_target_info`` instead.
- elb_target_group_facts -  Remove deprecated alias ``elb_target_group_facts``.  Please use ``elb_target_group_info`` instead.
- iam - Removed deprecated ``community.aws.iam`` module. Please use ``community.aws.iam_user``, ``community.aws.iam_access_key`` or ``community.aws.iam_group`` (https://github.com/ansible-collections/community.aws/pull/839).
- iam_cert_facts -  Remove deprecated alias ``iam_cert_facts``.  Please use ``iam_cert_info`` instead.
- iam_mfa_device_facts -  Remove deprecated alias ``iam_mfa_device_facts``.  Please use ``iam_mfa_device_info`` instead.
- iam_role_facts -  Remove deprecated alias ``iam_role_facts``.  Please use ``iam_role_info`` instead.
- iam_server_certificate_facts -  Remove deprecated alias ``iam_server_certificate_facts``.  Please use ``iam_server_certificate_info`` instead.
- lambda_facts -  Remove deprecated module lambda_facts``.  Please use ``lambda_info`` instead.
- rds - Removed deprecated ``community.aws.rds`` module. Please use ``community.aws.rds_instance`` (https://github.com/ansible-collections/community.aws/pull/839).
- rds_instance_facts -  Remove deprecated alias ``rds_instance_facts``.  Please use ``rds_instance_info`` instead.
- rds_snapshot_facts -  Remove deprecated alias ``rds_snapshot_facts``.  Please use ``rds_snapshot_info`` instead.
- redshift_facts -  Remove deprecated alias ``redshift_facts``.  Please use ``redshift_info`` instead.
- route53_facts -  Remove deprecated alias ``route53_facts``.  Please use ``route53_info`` instead.

Bugfixes
--------

- aws_eks - Fix EKS cluster creation with short names (https://github.com/ansible-collections/community.aws/pull/818).

v2.6.1
======

Release Summary
---------------

Bump collection from 2.6.0 to 2.6.1 due to a publishing error with 2.6.0.  This release supersedes 2.6.0 entirely, users should skip 2.6.0.

v2.6.0
======

Release Summary
---------------

This is the last planned 2.x release of the ``community.aws`` collection.
Consider upgrading to the latest version of ``community.aws`` soon.

Minor Changes
-------------

- ecs_service - ``deployment_circuit_breaker`` has been added as a supported feature (https://github.com/ansible-collections/community.aws/pull/1215).
- ecs_service - add ``service`` alias to address the ecs service name with the same parameter as the ecs_service_info module is doing (https://github.com/ansible-collections/community.aws/pull/1187).
- ecs_service_info - add ``name`` alias to address the ecs service name with the same parameter as the ecs_service module is doing (https://github.com/ansible-collections/community.aws/pull/1187).

Bugfixes
--------

- ecs_service - fix broken change detect of ``health_check_grace_period_seconds`` parameter when not specified (https://github.com/ansible-collections/community.aws/pull/1212).
- ecs_service - use default cluster name of ``default`` when not input (https://github.com/ansible-collections/community.aws/pull/1212).
- ecs_task - dont require ``cluster`` and use name of ``default`` when not input (https://github.com/ansible-collections/community.aws/pull/1212).
- wafv2_ip_set - fix bug where incorrect changed state was returned when only changing the description (https://github.com/ansible-collections/community.aws/pull/1211).

v2.5.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.

Minor Changes
-------------

- iam_policy - update broken examples and add RETURN section to documentation; add extra integration tests for idempotency check mode runs (https://github.com/ansible-collections/community.aws/pull/1093).
- iam_role - delete inline policies prior to deleting role (https://github.com/ansible-collections/community.aws/pull/1054).
- iam_role - remove global vars and refactor accordingly (https://github.com/ansible-collections/community.aws/pull/1054).

Bugfixes
--------

- ecs_service - add missing change detect of ``health_check_grace_period_seconds`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix broken compare of ``task_definition`` that results always in a changed task (https://github.com/ansible-collections/community.aws/pull/1145).
- ecs_service - fix validation for ``placement_constraints``. It's possible to use ``distinctInstance`` placement constraint now (https://github.com/ansible-collections/community.aws/issues/1058)
- ecs_taskdefinition - fix broken change detect of ``launch_type`` parameter (https://github.com/ansible-collections/community.aws/pull/1145).
- execute_lambda - fix check mode and update RETURN documentation (https://github.com/ansible-collections/community.aws/pull/1115).
- iam_policy - require one of ``policy_document`` and ``policy_json`` when state is present to prevent MalformedPolicyDocumentException from being thrown (https://github.com/ansible-collections/community.aws/pull/1093).
- s3_lifecycle - add support of value *0* for ``transition_days`` (https://github.com/ansible-collections/community.aws/pull/1077).
- s3_lifecycle - check that configuration is complete before returning (https://github.com/ansible-collections/community.aws/pull/1085).

v2.4.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- Added suport for retries (AWSRetry.jittered_backoff) for cloudfront_distribution (https://github.com/ansible-collections/community.aws/issues/296)

Bugfixes
--------

- Add backoff retry logic to elb_application_lb_info (https://github.com/ansible-collections/community.aws/pull/977)
- ecs_taskdefinition - include launch_type comparison when comparing task definitions (https://github.com/ansible-collections/community.aws/pull/840)
- elb_target_group_info - Add backoff retry logic (https://github.com/ansible-collections/community.aws/pull/1001)
- iam_role - Removes unnecessary removal of permission boundary from a role when deleting a role. Unlike inline policies, permission boundaries do not need to be removed from an IAM role before deleting the IAM role. This behavior causes issues when a permission boundary is inherited that prevents removal of the permission boundary. (https://github.com/ansible-collections/community.aws/pull/961)
- redshift_info - fix invalid import path for botocore exceptions (https://github.com/ansible-collections/community.aws/issues/968).
- wafv2_web_acl - fix exception when a rule contains lists values (https://github.com/ansible-collections/community.aws/pull/962).

v2.3.0
======

Release Summary
---------------

This is the minor release of the ``community.aws`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- elb_instance - ``wait`` parameter is no longer ignored (https://github.com/ansible-collections/community.aws/pull/826)

Bugfixes
--------

- cloudfront_distribution - Dont pass ``s3_origin_access_identity_enabled`` to API request (https://github.com/ansible-collections/community.aws/pull/881).
- execute_lambda - Wait for Lambda function State = Active before executing (https://github.com/ansible-collections/community.aws/pull/857)
- lambda - Wait for Lambda function State = Active & LastUpdateStatus = Successful before updating (https://github.com/ansible-collections/community.aws/pull/857)

v2.2.0
======

Release Summary
---------------

This is a backport release of the ``community.aws`` collection.

Minor Changes
-------------

- aws_msk_config - remove duplicated and unspecific requirements (https://github.com/ansible-collections/community.aws/pull/863).
- aws_ssm connection plugin - add parameters to explicitly specify SSE mode and KMS key id for uploads on the file transfer bucket. (https://github.com/ansible-collections/community.aws/pull/763)
- ecs_taskdefinition - remove duplicated and unspecific requirements (https://github.com/ansible-collections/community.aws/pull/863).
- iam_user - add boto3 waiter for iam user creation (https://github.com/ansible-collections/community.aws/pull/822).
- iam_user - add password management support bringing parity with ``iam`` module (https://github.com/ansible-collections/community.aws/pull/822).
- s3_lifecycle - Add ``abort_incomplete_multipart_upload_days`` and ``expire_object_delete_marker`` parameters (https://github.com/ansible-collections/community.aws/pull/794).

Bugfixes
--------

- aws_eks - Fix EKS cluster creation with short names (https://github.com/ansible-collections/community.aws/pull/818).

New Modules
-----------

- ec2_asg_scheduled_action - Create, modify and delete ASG scheduled scaling actions.

v2.1.0
======

Minor Changes
-------------

- aws_config_delivery_channel - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_direct_connect_confirm_connection - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_direct_connect_connection - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_direct_connect_link_aggregation_group - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_direct_connect_virtual_interface - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_inspector_target - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_kms - add support for ``kms_spec`` and ``kms_usage`` parameter (https://github.com/ansible-collections/community.aws/pull/774).
- aws_kms - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- aws_kms_info - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- cloudformation_stack_set - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- cloudfront_distribution - add ``TLSv1.2_2021`` security policy for viewer connections (https://github.com/ansible-collections/community.aws/pull/707).
- dms_endpoint - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- dms_replication_subnet_group - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- dynamodb_table - add support for setting the ``billing_mode`` option (https://github.com/ansible-collections/community.aws/pull/753).
- dynamodb_table - the module has been updated to use the boto3 AWS SDK (https://github.com/ansible-collections/community.aws/pull/726).
- ec2_asg - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- ec2_eip - added support for tagging EIPs (https://github.com/ansible-collections/community.aws/pull/332).
- ec2_eip_info - added automatic retries for common temporary API failures (https://github.com/ansible-collections/community.aws/pull/332).
- ec2_eip_info - added support for tagging EIPs (https://github.com/ansible-collections/community.aws/pull/332).
- ec2_elb_info - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- ec2_win_password - module updated to use the boto3 AWS SDK (https://github.com/ansible-collections/community.aws/pull/759).
- ecs_service - added support for forcing deletion of a service (https://github.com/ansible-collections/community.aws/pull/228).
- ecs_service_info - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- ecs_taskdefinition - add ``placement_constraints`` option (https://github.com/ansible-collections/community.aws/pull/741).
- efs - add ``transition_to_ia`` parameter to support specifying the number of days before transitioning data to inactive storage (https://github.com/ansible-collections/community.aws/pull/522).
- elb_instance - added new ``updated_elbs`` return value (https://github.com/ansible-collections/community.aws/pull/773).
- elb_instance - the module has been migrated to the boto3 AWS SDK (https://github.com/ansible-collections/community.aws/pull/773).
- elb_target_group - add ``preserve_client_ip_enabled`` option (https://github.com/ansible-collections/community.aws/pull/670).
- elb_target_group - add ``proxy_protocol_v2_enabled`` option (https://github.com/ansible-collections/community.aws/pull/670).
- iam_managed_policy - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- iam_role - Added ``wait`` option for IAM role creation / updates (https://github.com/ansible-collections/community.aws/pull/767).
- iam_saml_federation - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- iam_server_certificate - add support for check_mode (https://github.com/ansible-collections/community.aws/pull/737).
- iam_server_certificate - migrate module to using the boto3 SDK (https://github.com/ansible-collections/community.aws/pull/737).
- lambda_info - add automatic retries for recoverable errors (https://github.com/ansible-collections/community.aws/pull/777).
- lambda_info - add support for tags (https://github.com/ansible-collections/community.aws/pull/375).
- lambda_info - use paginator for list queries (https://github.com/ansible-collections/community.aws/pull/777).
- rds - replaced use of deprecated backoff decorator (https://github.com/ansible-collections/community.aws/pull/764).
- redshift_subnet_group - added support for check_mode (https://github.com/ansible-collections/community.aws/pull/724).
- redshift_subnet_group - the ``group_description`` option has been renamed to ``description`` and is now optional. The old parameter name will continue to work (https://github.com/ansible-collections/community.aws/pull/724).
- redshift_subnet_group - the ``group_subnets`` option has been renamed to ``subnets`` and is now only required when creating a new group. The old parameter name will continue to work (https://github.com/ansible-collections/community.aws/pull/724).
- redshift_subnet_group - the module has been migrated to the boto3 AWS SDK (https://github.com/ansible-collections/community.aws/pull/724).
- route53_health_check - add support for tagging health checks (https://github.com/ansible-collections/community.aws/pull/765).
- route53_health_check - added support for check_mode (https://github.com/ansible-collections/community.aws/pull/734).
- route53_health_check - added support for disabling health checks (https://github.com/ansible-collections/community.aws/pull/756).
- route53_health_check - migrated to boto3 SDK (https://github.com/ansible-collections/community.aws/pull/734).
- route53_zone - add support for tagging Route 53 zones (https://github.com/ansible-collections/community.aws/pull/565).
- sqs_queue - Providing a kms_master_key_id will now enable SSE properly (https://github.com/ansible-collections/community.aws/pull/762)

Deprecated Features
-------------------

- dynamodb_table - DynamoDB does not support specifying non-key-attributes when creating an ``ALL`` index.  Passing ``includes`` for such indexes is currently ignored but will result in failures after version 3.0.0 (https://github.com/ansible-collections/community.aws/pull/726).
- dynamodb_table - DynamoDB does not support updating the primary indexes on a table.  Attempts to make such changes are currently ignored but will result in failures after version 3.0.0 (https://github.com/ansible-collections/community.aws/pull/726).
- elb_instance - setting of the ``ec2_elb`` fact has been deprecated and will be removed in release 4.0.0 of the collection. See the module documentation for an alternative example using the register keyword (https://github.com/ansible-collections/community.aws/pull/773).
- iam_cert - the iam_cert module has been renamed to iam_server_certificate for consistency with the companion iam_server_certificate_info module. The usage of the module has not changed.  The iam_cert alias will be removed in version 4.0.0 (https://github.com/ansible-collections/community.aws/pull/728).
- iam_server_certificate - Passing file names to the ``cert``, ``chain_cert`` and ``key`` parameters has been deprecated. We recommend using a lookup plugin to read the files instead, see the documentation for an example (https://github.com/ansible-collections/community.aws/pull/735).
- iam_server_certificate - the default value for the ``dup_ok`` parameter is currently ``false``, in version 4.0.0 this will be updated to ``true``.  To preserve the current behaviour explicitly set the ``dup_ok`` parameter to ``false`` (https://github.com/ansible-collections/community.aws/pull/737).
- rds_snapshot - the rds_snapshot module has been renamed to rds_instance_snapshot. The usage of the module has not changed. The rds_snapshot alias will be removed in version 4.0.0 (https://github.com/ansible-collections/community.aws/pull/783).

Bugfixes
--------

- AWS action group - added missing ``aws_direct_connect_confirm_connection`` and ``efs_tag`` entries (https://github.com/ansible-collections/amazon.aws/issues/557).
- cloudfront_info - Switch to native boto3 paginators to fix reported bug when over 100 distributions exist (https://github.com/ansible-collections/community.aws/issues/769).
- ec2_eip - fix bug when allocating an EIP but not associating it to a VPC (https://github.com/ansible-collections/community.aws/pull/731).
- elb_classic_lb_info - fix empty list returned when names not defined (https://github.com/ansible-collections/community.aws/pull/693).
- elb_instance - Python 3 compatibility fix (https://github.com/ansible-collections/community.aws/issues/384).
- iam_role_info - switch to jittered backoff to reduce rate limiting failures (https://github.com/ansible-collections/community.aws/pull/748).
- rds_instance - Fixed issue with enabling enhanced monitoring on a pre-existing RDS instance (https://github.com/ansible-collections/community.aws/pull/747).
- route53 - add missing set identifier in resource_record_set (https://github.com/ansible-collections/community.aws/pull/595).
- route53 - fix diff mode when deleting records (https://github.com/ansible-collections/community.aws/pull/802).
- route53 - return empty result for nonexistent records (https://github.com/ansible-collections/community.aws/pull/799).
- sns_topic - define suboptions for delivery_policy option (https://github.com/ansible-collections/community.aws/issues/713).

New Modules
-----------

- iam_access_key - Manage AWS IAM User access keys
- iam_access_key_info - fetch information about AWS IAM User access keys
- rds_option_group - rds_option_group module
- rds_option_group_info - rds_option_group_info module

v2.0.0
======

Major Changes
-------------

- community.aws collection - The community.aws collection has dropped support for ``botocore<1.18.0`` and ``boto3<1.15.0`` (https://github.com/ansible-collections/community.aws/pull/711). Most modules will continue to work with older versions of the AWS SDK, however compatibility with older versions of the SDK is not guaranteed and will not be tested. When using older versions of the SDK a warning will be emitted by Ansible (https://github.com/ansible-collections/amazon.aws/pull/442).

Minor Changes
-------------

- aws_eks_cluster - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- aws_kms_info - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- aws_s3_bucket_info - added test for botocore>=1.18.11 when attempting to fetch bucket ownership controls (https://github.com/ansible-collections/community.aws/pull/682)
- aws_ses_rule_set - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- aws_sgw_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- cloudformation_exports_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- cloudformation_stack_set - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- cloudfront_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- cloudwatchevent_rule - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- dynamodb_table - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- dynamodb_ttl - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_ami_copy - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_asg - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_asg_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- ec2_launch_template - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_lc_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- ec2_transit_gateway - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_transit_gateway_info - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_vpc_peer - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ec2_vpc_peer - use shared code for tagging peering connections (https://github.com/ansible-collections/community.aws/pull/614).
- ec2_vpc_route_table - use shared code for tagging route tables (https://github.com/ansible-collections/community.aws/pull/616).
- ec2_vpc_vgw - fix arguments-renamed pylint issue (https://github.com/ansible-collections/community.aws/pull/686).
- ec2_vpc_vpn - fix arguments-renamed pylint issue (https://github.com/ansible-collections/community.aws/pull/686).
- ecs_ecr - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ecs_service - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ecs_task - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- ecs_task - remove unused import (https://github.com/ansible-collections/community.aws/pull/686).
- ecs_taskdefinition - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- efs - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- efs_info - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- elasticache_subnet_group - add return values (https://github.com/ansible-collections/community.aws/pull/723).
- elasticache_subnet_group - add support for check_mode (https://github.com/ansible-collections/community.aws/pull/723).
- elasticache_subnet_group - module migrated to boto3 AWS SDK (https://github.com/ansible-collections/community.aws/pull/723).
- elb_application_lb - added ``ip_address_type`` parameter to support changing application load balancer configuration (https://github.com/ansible-collections/community.aws/pull/499).
- elb_application_lb_info - added ``ip_address_type`` in output when gathering application load balancer parameters (https://github.com/ansible-collections/community.aws/pull/499).
- elb_instance - make elb_instance idempotent when deregistering instances.  Merged from ec2_elb U(https://github.com/ansible/ansible/pull/31660).
- elb_network_lb - added ``ip_address_type`` parameter to support changing network load balancer configuration (https://github.com/ansible-collections/community.aws/pull/499).
- elb_target_group - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- elb_target_group - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- iam - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- iam_group - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- iam_mfa_device_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- iam_role - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- iam_role - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- iam_server_certificate_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- iam_user - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- kms_info - added a new ``keys_attr`` parameter to continue returning the key details in the ``keys`` attribute as well as the ``kms_keys`` attribute (https://github.com/ansible-collections/community.aws/pull/648).
- lambda - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- rds_instance - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- rds_instance - convert ``preferred_maintenance_window`` days into lowercase so changed returns properly (https://github.com/ansible-collections/community.aws/pull/516).
- rds_instance - use a generator rather than list comprehension (https://github.com/ansible-collections/community.aws/pull/688).
- route53 - add rate-limiting retries while waiting for changes to propagate (https://github.com/ansible-collections/community.aws/pull/564).
- route53 - add retries on ``PriorRequestNotComplete`` errors (https://github.com/ansible-collections/community.aws/pull/564).
- route53 - update retry ``max_delay`` setting so that it can be set above 60 seconds (https://github.com/ansible-collections/community.aws/pull/564).
- sns_topic - Added ``topic_type`` parameter to select type of SNS topic (either FIFO or Standard) (https://github.com/ansible-collections/community.aws/pull/599).
- sqs_queue - Tests for compatibility with older versions of the AWS SDKs have been removed (https://github.com/ansible-collections/community.aws/pull/675).
- various community.aws modules - remove unused imports (https://github.com/ansible-collections/community.aws/pull/629)
- wafv2_resources_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).
- wafv2_web_acl_info - ensure module runs in check_mode (https://github.com/ansible-collections/community.aws/issues/659).

Breaking Changes / Porting Guide
--------------------------------

- ec2_instance - The module has been migrated to the ``amazon.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_instance``.
- ec2_instance_info - The module has been migrated to the ``amazon.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_instance_info``.
- ec2_vpc_endpoint - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_endpoint``.
- ec2_vpc_endpoint_facts - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_endpoint_info``.
- ec2_vpc_endpoint_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_endpoint_info``.
- ec2_vpc_endpoint_service_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_endpoint_service_info``.
- ec2_vpc_igw - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_igw``.
- ec2_vpc_igw_facts - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_igw_info``.
- ec2_vpc_igw_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_igw_info``.
- ec2_vpc_nat_gateway - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_nat_gateway``.
- ec2_vpc_nat_gateway_facts - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_nat_gateway_info``.
- ec2_vpc_nat_gateway_info - The module has been migrated from the ``community.aws`` collection. Playbooks using the Fully Qualified Collection Name for this module should be updated to use ``amazon.aws.ec2_vpc_nat_gateway_info``.
- kms_info - key details are now returned in the ``kms_keys`` attribute rather than the ``keys`` attribute (https://github.com/ansible-collections/community.aws/pull/648).

Deprecated Features
-------------------

- ec2_elb - the ``ec2_elb`` module has been removed and redirected to the ``elb_instance`` module which functions identically. The original ``ec2_elb`` name is now deprecated and will be removed in release 3.0.0 (https://github.com/ansible-collections/community.aws/pull/586).
- ec2_elb_info - the boto based ``ec2_elb_info`` module has been deprecated in favour of the boto3 based ``elb_classic_lb_info`` module. The ``ec2_elb_info`` module will be removed in release 3.0.0 (https://github.com/ansible-collections/community.aws/pull/586).
- elb_classic_lb - the ``elb_classic_lb`` module has been removed and redirected to the ``amazon.aws.ec2_elb_lb`` module which functions identically.
- iam - the boto based ``iam`` module has been deprecated in favour of the boto3 based ``iam_user``, ``iam_group`` and ``iam_role`` modules. The ``iam`` module will be removed in release 3.0.0 (https://github.com/ansible-collections/community.aws/pull/664).
- rds - the boto based ``rds`` module has been deprecated in favour of the boto3 based ``rds_instance`` module. The ``rds`` module will be removed in release 3.0.0 (https://github.com/ansible-collections/community.aws/pull/663).
- script_inventory_ec2 - The ec2.py inventory script is being moved to a new repository. The script can now be downloaded from https://github.com/ansible-community/contrib-scripts/blob/main/inventory/ec2.py and will be removed from this collection in the 3.0 release. We recommend migrating from the script to the ``amazon.aws.ec2`` inventory plugin.

Bugfixes
--------

- aws_secret - fix deletion idempotency when not using instant deletion (https://github.com/ansible-collections/community.aws/pull/681).
- aws_ssm - rename ``retries`` to ``reconnection_retries`` to avoid conflict with task retries
- ec2_vpc_peer - automatically retry when attempting to tag freshly created peering connections (https://github.com/ansible-collections/community.aws/pull/614).
- ec2_vpc_route_table - automatically retry when attempting to modify freshly created route tables (https://github.com/ansible-collections/community.aws/pull/616).
- ecs_taskdefinition - ensure cast to integer (https://github.com/ansible-collections/community.aws/pull/574).
- ecs_taskdefinition - fix idempotency (https://github.com/ansible-collections/community.aws/pull/574).
- ecs_taskdefinition - fix typo in ecs task defination for env file validations (https://github.com/ansible-collections/community.aws/pull/600).
- iam_role - Modified iam_role internal code to replace update_role_description with update_role (https://github.com/ansible-collections/community.aws/pull/697).
- route53 - fix typo in waiter configuration that prevented management of the delays (https://github.com/ansible-collections/community.aws/pull/564).
- s3_sync - fix handling individual file path to upload a individual file to s3 bucket (https://github.com/ansible-collections/community.aws/pull/692).
- sqs_queue - fix queue attribute comparison to make module idempotent (https://github.com/ansible-collections/community.aws/pull/592).

New Modules
-----------

- aws_msk_cluster - Manage Amazon MSK clusters.
- aws_msk_config - Manage Amazon MSK cluster configurations.
- efs_tag - create and remove tags on Amazon EFS resources

v1.5.0
======

Minor Changes
-------------

- aws_config_aggregator - Fix typos in attribute names (https://github.com/ansible-collections/community.aws/pull/553).
- aws_glue_connection - Added multple connection types (https://github.com/ansible-collections/community.aws/pull/503).
- aws_glue_connection - Added support for check mode (https://github.com/ansible-collections/community.aws/pull/503).
- aws_glue_job - added ``number_of_workers``, ``worker_type`` and ``glue_version`` attributes to the module (https://github.com/ansible-collections/community.aws/pull/370).
- aws_region_info - Add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/422).
- aws_s3_bucket_info - new module options ``name``, ``name_filter``, ``bucket_facts`` and ``transform_location`` (https://github.com/ansible-collections/community.aws/pull/260).
- aws_ssm connection plugin - add support for specifying a profile to be used when connecting (https://github.com/ansible-collections/community.aws/pull/278).
- aws_ssm_parameter_store - added tier parameter option (https://github.com/ansible/ansible/issues/59738).
- ec2_asg module - add support for all mixed_instances_policy parameters (https://github.com/ansible-collections/community.aws/issues/231).
- ec2_asg_info - gather information about asg lifecycle hooks (https://github.com/ansible-collections/community.aws/pull/233).
- ec2_instance - wait for new instances to return a status before attempting to set additional parameters (https://github.com/ansible-collections/community.aws/pull/533).
- ec2_instance_info - add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/521).
- ec2_launch_template - added ``metadata_options`` parameter to support changing the IMDS configuration for instances (https://github.com/ansible-collections/community.aws/pull/322).
- ec2_metric_alarm - Added support for check mode (https://github.com/ansible-collections/community.aws/pull/470).
- ec2_metric_alarm - Made ``unit`` parameter optional (https://github.com/ansible-collections/community.aws/pull/470).
- ec2_vpc_egress_igw - Add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/421).
- ec2_vpc_endpoint - Add retries on common AWS failures. (https://github.com/ansible-collections/community.aws/pull/473)
- ec2_vpc_endpoint - Added support for specifying ``vpc_endpoint_type`` (https://github.com/ansible-collections/community.aws/pull/460).
- ec2_vpc_endpoint - The module now supports tagging endpoints. (https://github.com/ansible-collections/community.aws/pull/473)
- ec2_vpc_endpoint - The module will now lookup existing endpoints and try to match on the provided parameters before creating a new endpoint for better idempotency.  (https://github.com/ansible-collections/community.aws/pull/473)
- ec2_vpc_endpoint_info - ensure paginated endpoint description is retried on common AWS failures (https://github.com/ansible-collections/community.aws/pull/537).
- ec2_vpc_endpoint_info - use boto3 paginator when fetching services (https://github.com/ansible-collections/community.aws/pull/537).
- ec2_vpc_endpoint_service_info - new module added for fetching information about available VPC endpoint services (https://github.com/ansible-collections/community.aws/pull/346).
- ec2_vpc_nacl - add support for IPv6 (https://github.com/ansible-collections/community.aws/pull/398).
- ec2_vpc_nat_gateway - add AWSRetry decorators to improve reliability (https://github.com/ansible-collections/community.aws/pull/427).
- ec2_vpc_nat_gateway - code cleaning (https://github.com/ansible-collections/community.aws/pull/445)
- ec2_vpc_nat_gateway - imporove documentation (https://github.com/ansible-collections/community.aws/pull/445)
- ec2_vpc_nat_gateway - improve error handling (https://github.com/ansible-collections/community.aws/pull/445)
- ec2_vpc_nat_gateway - use custom waiters to manage NAT gateways states (deleted and available) (https://github.com/ansible-collections/community.aws/pull/445)
- ec2_vpc_nat_gateway - use pagination on describe calls to ensure all results are fetched (https://github.com/ansible-collections/community.aws/pull/427).
- ec2_vpc_nat_gateway_info - Add paginator (https://github.com/ansible-collections/community.aws/pull/472).
- ec2_vpc_nat_gateway_info - Improve documentation (https://github.com/ansible-collections/community.aws/pull/472).
- ec2_vpc_nat_gateway_info - Improve error handling (https://github.com/ansible-collections/community.aws/pull/472)
- ec2_vpc_nat_gateway_info - Use normalize_boto3_result (https://github.com/ansible-collections/community.aws/pull/472)
- ec2_vpc_nat_gateway_info - solve RequestLimitExceeded error by adding retry decorator (https://github.com/ansible-collections/community.aws/pull/446)
- ec2_vpc_peer - More return info added, also simplified module code a bit and extended tests (https://github.com/ansible-collections/community.aws/pull/355)
- ec2_vpc_peer - add support for waiting on state changes (https://github.com/ansible-collections/community.aws/pull/501).
- ec2_vpc_peering_info - add ``vpc_peering_connections`` return value to be consistent with boto3 modules (https://github.com/ansible-collections/community.aws/pull/501).
- ec2_vpc_peering_info - add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/536).
- ec2_vpc_route_table - add AWSRetry decorators to improve reliability (https://github.com/ansible-collections/community.aws/pull/442).
- ec2_vpc_route_table - add boto3 pagination for some searches (https://github.com/ansible-collections/community.aws/pull/442).
- ec2_vpc_route_table_info - migrate to boto3 (https://github.com/ansible-collections/community.aws/pull/442).
- ec2_vpc_vgw - Add automatic retries for recoverable errors (https://github.com/ansible-collections/community.aws/pull/162).
- ec2_vpc_vpn - Add automatic retries for recoverable errors (https://github.com/ansible-collections/community.aws/pull/162).
- ecs_service - Add ``platform_version`` parameter to ``ecs_service`` (https://github.com/ansible-collections/community.aws/pull/353).
- ecs_task - added ``assign_public_ip`` option for network_configuration (https://github.com/ansible-collections/community.aws/pull/395).
- ecs_taskdefinition - Documentation improvement (https://github.com/ansible-collections/community.aws/issues/520)
- elasticache - Improve docs a little, add intgration tests (https://github.com/ansible-collections/community.aws/pull/410).
- elb_classic_info - If the provided load balancer doesn't exist, return an empty list instead of throwing an error. (https://github.com/ansible-collections/community.aws/pull/215).
- elb_target_group - Add elb target group attributes ``stickiness_app_cookie_name`` and ``stickiness_app_cookie_duration_seconds``. Also update docs for stickiness_type to mention application cookie (https://github.com/ansible-collections/community.aws/pull/548)
- iam - Make iam module more predictable when returning the ``user_name`` it creates or deletes (https://github.com/ansible-collections/community.aws/pull/369).
- iam_saml_federation - module now returns the state of the provider when no changes are made (https://github.com/ansible-collections/community.aws/pull/419).
- kinesis_stream - check_mode is now based on the live settings rather than comparisons with a hard coded/fake stream definition (https://github.com/ansible-collections/community.aws/pull/27).
- kinesis_stream - now returns changed more accurately (https://github.com/ansible-collections/community.aws/pull/27).
- kinesis_stream - now returns tags consistently (https://github.com/ansible-collections/community.aws/pull/27).
- kinesis_stream - return values are now the same format when working with both encrypted and un-encrypted streams (https://github.com/ansible-collections/community.aws/pull/27).
- lambda_alias - add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/396).
- lambda_alias - use common helper functions to create AWS connections (https://github.com/ansible-collections/community.aws/pull/396).
- lambda_alias - use common helper functions to perform snake_case to CamelCase conversions (https://github.com/ansible-collections/community.aws/pull/396).
- rds_instance - new ``purge_security_groups`` parameter (https://github.com/ansible-collections/community.aws/issues/385).
- rds_param_group - Add AWSRetry (https://github.com/ansible-collections/community.aws/pull/532).
- rds_param_group - Fix integration tests (https://github.com/ansible-collections/community.aws/pull/532).
- rds_param_group - Support check_mode (https://github.com/ansible-collections/community.aws/pull/532).
- rds_snapshot - added to the aws module_defaults group (https://github.com/ansible-collections/community.aws/pull/515).
- route53 - fixes AWS API error when attempting to create Alias records (https://github.com/ansible-collections/community.aws/issues/434).
- s3_lifecycle - Add a ``wait`` parameter to wait for changes to propagate after being set (https://github.com/ansible-collections/community.aws/pull/448).
- s3_lifecycle - Add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/448).
- s3_lifecycle - Fix idempotency when using dates instead of days (https://github.com/ansible-collections/community.aws/pull/448).
- s3_logging - added support for check_mode (https://github.com/ansible-collections/community.aws/pull/447).
- s3_logging - migrated from boto to boto3 (https://github.com/ansible-collections/community.aws/pull/447).
- s3_sync - new ``storage_class`` feature allowing to specify the storage class when any object is added to an S3 bucket (https://github.com/ansible-collections/community.aws/issues/358).
- sanity tests - add ignore.txt for 2.12 (https://github.com/ansible-collections/community.aws/pull/527).
- state_machine_arn - return ``state_machine_arn`` when state is unchanged (https://github.com/ansible-collections/community.aws/pull/302).

Deprecated Features
-------------------

- ec2_vpc_endpoint_info - the ``query`` option has been deprecated and will be removed after 2022-12-01 (https://github.com/ansible-collections/community.aws/pull/346). The ec2_vpc_endpoint_info now defaults to listing information about endpoints. The ability to search for information about available services has been moved to the dedicated module ``ec2_vpc_endpoint_service_info``.

Security Fixes
--------------

- aws_direct_connect_virtual_interface - mark the ``authentication_key`` parameter as ``no_log`` to avoid accidental leaking of secrets in logs (https://github.com/ansible-collections/community.aws/pull/475).
- aws_secret - flag the ``secret`` parameter as containing sensitive data which shouldn't be logged (https://github.com/ansible-collections/community.aws/pull/471).
- sts_assume_role - mark the ``mfa_token`` parameter as ``no_log`` to avoid accidental leaking of secrets in logs (https://github.com/ansible-collections/community.aws/pull/475).
- sts_session_token - mark the ``mfa_token`` parameter as ``no_log`` to avoid accidental leaking of secrets in logs (https://github.com/ansible-collections/community.aws/pull/475).

Bugfixes
--------

- aws_ssm - Adds destructor to SSM connection plugin to ensure connections are properly cleaned up after usage (https://github.com/ansible-collections/community.aws/pull/542).
- aws_ssm - enable aws ssm connections if **AWS_SESSION_TOKEN** is missing (https://github.com/ansible-collections/community.aws/pull/535).
- cloudtrail - fix always reporting changed = true when kms alias used (https://github.com/ansible-collections/community.aws/pull/506).
- cloudtrail - fix lower casing of tag keys (https://github.com/ansible-collections/community.aws/pull/506).
- ec2_asg - fix target group update logic (https://github.com/ansible-collections/community.aws/pull/493).
- ec2_instance - ensure that termination protection isn't modified when using check_mode (https://github.com/ansible/ansible/issues/67716).
- ec2_instance - fix key errors when instance has no tags (https://github.com/ansible-collections/community.aws/pull/476).
- ec2_launch_template - ensure that empty parameters are properly removed before passing to AWS (https://github.com/ansible-collections/community.aws/issues/230).
- ec2_launch_template - fixes parameter validation failure when passing a instance profile ARN instead of just the role name (https://github.com/ansible-collections/community.aws/pull/371).
- ec2_vpc_peer - fix idempotency when rejecting and deleting peering connections (https://github.com/ansible-collections/community.aws/pull/501).
- ec2_vpc_route_table - catch RouteAlreadyExists error when rerunning same task twice to make module idempotent (https://github.com/ansible-collections/community.aws/issues/357).
- elasticache - Fix ``KeyError`` issue when updating security group (https://github.com/ansible-collections/community.aws/pull/410).
- kinesis_stream - fixed issue where streams get marked as changed even if no encryption actions were necessary (https://github.com/ansible/ansible/issues/65928).
- rds_instance - fixes bug preventing the use of tags when creating an RDS instance from a snapshot (https://github.com/ansible-collections/community.aws/issues/530).
- route53 - ensure that the old return values are re-added along side the new ones (https://github.com/ansible-collections/community.aws/issues/523).
- route53 - fix ``AttributeError`` in ``get_zone_id_by_name`` when a vpc_id on a private zone is provided (https://github.com/ansible-collections/community.aws/issues/509).
- route53 - fix handling for characters escaped by AWS in record names, like ``*`` and ``@``. This fixes idempotency for such record names (https://github.com/ansible-collections/community.aws/issues/524).
- route53 - fix when using ``state=get`` on private DNS zones and add tests to cover this scenario (https://github.com/ansible-collections/community.aws/pull/424).
- route53 - make sure that CAA values order is again ignored during idempotency comparsion (https://github.com/ansible-collections/community.aws/issues/524).
- sns_topic - Add ``+`` to allowable characters in SMS endpoints (https://github.com/ansible-collections/community.aws/pull/454).
- sqs_queue - fix UnboundLocalError when passing a boolean parameter (https://github.com/ansible-collections/community.aws/issues/172).

New Modules
-----------

- ec2_vpc_endpoint_service_info - retrieves AWS VPC endpoint service details
- wafv2_ip_set - wafv2_ip_set
- wafv2_ip_set_info - Get information about wafv2 ip sets
- wafv2_resources - wafv2_web_acl
- wafv2_resources_info - wafv2_resources_info
- wafv2_rule_group - wafv2_web_acl
- wafv2_rule_group_info - wafv2_web_acl_info
- wafv2_web_acl - wafv2_web_acl
- wafv2_web_acl_info - wafv2_web_acl

v1.4.0
======

Minor Changes
-------------

- aws_kms - add support for setting the deletion window using ``pending_window`` (PendingWindowInDays) (https://github.com/ansible-collections/community.aws/pull/200).
- aws_kms_info - Add ``key_id`` and ``alias`` parameters to support fetching a single key (https://github.com/ansible-collections/community.aws/pull/200).
- dynamodb_ttl - use ``botocore_at_least`` helper for checking the available botocore version (https://github.com/ansible-collections/community.aws/pull/280).
- ec2_instance - add automatic retries on all paginated queries for temporary errors (https://github.com/ansible-collections/community.aws/pull/373).
- ec2_instance - migrate to shared implementation of get_ec2_security_group_ids_from_names. The module will now return an error if the subnet provided isn't in the requested VPC. (https://github.com/ansible-collections/community.aws/pull/214)
- ec2_instance_info - added ``minimum_uptime`` option with alias ``uptime`` for filtering instances that have only been online for certain duration of time in minutes (https://github.com/ansible-collections/community.aws/pull/356).
- ec2_launch_template - Add retries on common AWS failures (https://github.com/ansible-collections/community.aws/pull/326).
- ec2_vpc_peer - use ``botocore_at_least`` helper for checking the available botocore version (https://github.com/ansible-collections/community.aws/pull/280).
- ecs_task - use ``botocore_at_least`` helper for checking the available botocore version (https://github.com/ansible-collections/community.aws/pull/280).
- route53 - migrated from boto to boto3 (https://github.com/ansible-collections/community.aws/pull/405).
- various community.aws modules - cleanup error handling to use ``is_boto3_error_code`` and ``is_boto3_error_message`` helpers (https://github.com/ansible-collections/community.aws/pull/268).
- various community.aws modules - cleanup of Python imports (https://github.com/ansible-collections/community.aws/pull/360).
- various community.aws modules - improve consistency of handling Boto3 exceptions (https://github.com/ansible-collections/community.aws/pull/268).
- various community.aws modules - migrate exception error message handling from fail_json to fail_json_aws (https://github.com/ansible-collections/community.aws/pull/361).

Deprecated Features
-------------------

- ec2_eip - formally deprecate the ``instance_id`` alias for ``device_id`` (https://github.com/ansible-collections/community.aws/pull/349).
- ec2_vpc_endpoint - deprecate the policy_file option and recommend using policy with a lookup (https://github.com/ansible-collections/community.aws/pull/366).

Bugfixes
--------

- aws_kms - fixes issue where module execution fails without the kms:GetKeyRotationStatus permission. (https://github.com/ansible-collections/community.aws/pull/200).
- aws_kms_info - ensure that searching by tag works when tag only exists on some CMKs (https://github.com/ansible-collections/community.aws/issues/276).
- aws_s3_cors - fix element type for rules parameter. (https://github.com/ansible-collections/community.aws/pull/408).
- aws_ssm - fix the generation of CURL URL used to download Ansible Python file from S3 bucket by ``_get_url()`` due to due to non-assignment of aws region in the URL and not using V4 signature as specified for AWS S3 signature URL by ``_get_boto_client()`` in (https://github.com/ansible-collections/community.aws/pull/352).
- aws_ssm - fixed ``UnicodeEncodeError`` error when using unicode file names (https://github.com/ansible-collections/community.aws/pull/295).
- ec2_eip - fix eip association by instance id & private ip address due to case-sensitivity of the ``PrivateIpAddress`` parameter (https://github.com/ansible-collections/community.aws/pull/328).
- ec2_vpc_endpoint - ensure ``changed`` is correctly set when deleting an endpoint (https://github.com/ansible-collections/community.aws/pull/362).
- ec2_vpc_endpoint - fix exception when attempting to delete an endpoint which has already been deleted (https://github.com/ansible-collections/community.aws/pull/362).
- ecs_task - use ``required_if`` to enforce mandatory parameters based on specified operation (https://github.com/ansible-collections/community.aws/pull/402).
- elb_application_lb - during the removal of an instance, the associated listeners are also removed.

v1.3.0
======

Minor Changes
-------------

- ec2_vpc_igw - Add AWSRetry decorators to improve reliability (https://github.com/ansible-collections/community.aws/pull/318).
- ec2_vpc_igw - Add ``purge_tags`` parameter so that tags can be added without purging existing tags to match the collection standard tagging behaviour (https://github.com/ansible-collections/community.aws/pull/318).
- ec2_vpc_igw_info - Add AWSRetry decorators to improve reliability (https://github.com/ansible-collections/community.aws/pull/318).
- ec2_vpc_igw_info - Add ``convert_tags`` parameter so that tags can be returned in standard dict format rather than the both list of dict format (https://github.com/ansible-collections/community.aws/pull/318).
- rds_instance - set ``no_log=False`` on ``force_update_password`` to clear warning (https://github.com/ansible-collections/community.aws/issues/241).
- redshift - add support for setting tags.
- s3_lifecycle - Add support for intelligent tiering and deep archive storage classes (https://github.com/ansible-collections/community.aws/issues/270)

Deprecated Features
-------------------

- ec2_vpc_igw_info - After 2022-06-22 the ``convert_tags`` parameter default value will change from ``False`` to ``True`` to match the collection standard behavior (https://github.com/ansible-collections/community.aws/pull/318).

Bugfixes
--------

- aws_kms_info - fixed incompatibility with external and custom key-store keys. The module was attempting to call  ``GetKeyRotationStatus``, which raises ``UnsupportedOperationException`` for these key types (https://github.com/ansible-collections/community.aws/pull/311).
- ec2_win_password - on success return state as not changed (https://github.com/ansible-collections/community.aws/issues/145)
- ec2_win_password - return failed if unable to decode the password (https://github.com/ansible-collections/community.aws/issues/142)
- ecs_service - fix element type for ``load_balancers`` parameter (https://github.com/ansible-collections/community.aws/issues/265).
- ecs_taskdefinition - fixes elements type for ``containers`` parameter (https://github.com/ansible-collections/community.aws/issues/264).
- iam_policy - Added jittered_backoff to handle AWS rate limiting (https://github.com/ansible-collections/community.aws/pull/324).
- iam_policy_info - Added jittered_backoff to handle AWS rate limiting (https://github.com/ansible-collections/community.aws/pull/324).
- kinesis_stream - fixes issue where kinesis streams with > 100 shards get stuck in an infinite loop (https://github.com/ansible-collections/community.aws/pull/93)
- s3_sync - fix chunk_size calculation (https://github.com/ansible-collections/community.aws/issues/272)

New Modules
-----------

- s3_metrics_configuration - Manage s3 bucket metrics configuration in AWS

v1.2.1
======

Minor Changes
-------------

- aws_ssm connection plugin - Change the (internal) variable name from timeout to plugin_timeout to avoid conflicts with ansible/ansible default timeout (#69284,
- aws_ssm connection plugin - add STS token options to aws_ssm connection plugin.
- ec2_scaling_policy - Add support for step_adjustments
- ec2_scaling_policy - Migrate from boto to boto3
- rds_subnet_group module - Add Boto3 support and remove Boto support.

Bugfixes
--------

- aws_ssm connection plugin - namespace file uploads to S3 into unique folders per host, to prevent name collisions. Also deletes files from S3 to ensure temp files are not left behind. (https://github.com/ansible-collections/community.aws/issues/221, https://github.com/ansible-collections/community.aws/issues/222)
- rds_instance - fixed tag type conversion issue for creating read replicas.

v1.2.0
======

Minor Changes
-------------

- Add retries for aws_api_gateway when AWS throws ``TooManyRequestsException``
- Migrate the remaning boto3 based modules to the module based helpers for creating AWS connections.

Bugfixes
--------

- aws_codecommit - fixes issue where module execution would fail if an existing repository has empty description (https://github.com/ansible-collections/community.aws/pull/195)
- aws_kms_info - fixes issue where module execution fails because certain AWS KMS keys (e.g. aws/acm) do not permit the calling the API kms:GetKeyRotationStatus (example - https://forums.aws.amazon.com/thread.jspa?threadID=312992) (https://github.com/ansible-collections/community.aws/pull/199)
- ec2_instance - Fix a bug where tags were updated in check_mode.
- ec2_instance - fixes issue where security groups were not changed if the instance already existed.  https://github.com/ansible-collections/community.aws/pull/22
- iam - Fix false positive warning regarding use of ``no_log`` on ``update_password``

v1.1.0
======

Minor Changes
-------------

- Remaining community.aws AnsibleModule based modules migrated to AnsibleAWSModule.
- sanity - add future imports in all missing places.

Deprecated Features
-------------------

- data_pipeline - the ``version`` option has been deprecated and will be removed in a later release. It has always been ignored by the module.
- ec2_eip - the ``wait_timeout`` option has been deprecated and will be removed in a later release. It has had no effect since Ansible 2.3.
- ec2_lc - the ``associate_public_ip_address`` option has been deprecated and will be removed after a later release. It has always been ignored by the module.
- elb_network_lb - in a later release, the default behaviour for the ``state`` option will change from ``absent`` to ``present``.  To maintain the existing behavior explicitly set state to ``absent``.
- iam_managed_policy - the ``fail_on_delete`` option has been deprecated and will be removed after a later release.  It has always been ignored by the module.
- iam_policy - in a later release, the default value for the ``skip_duplicates`` option will change from ``true`` to ``false``.  To maintain the existing behavior explicitly set it to ``true``.
- iam_policy - the ``policy_document`` option has been deprecated and will be removed after a later release. To maintain the existing behavior use the ``policy_json`` option and read the file with the ``lookup`` plugin.
- iam_role - in a later release, the ``purge_policies`` option (also know as ``purge_policy``) default value will change from ``true`` to ``false``
- s3_lifecycle - the ``requester_pays`` option has been deprecated and will be removed after a later release. It has always been ignored by the module.
- s3_sync - the ``retries`` option has been deprecated and will be removed after 2022-06-01. It has always been ignored by the module.

v1.0.0
======

Minor Changes
-------------

- Allow all params that boto support in aws_api_gateway module
- aws_acm - Add the module to group/aws for module_defaults.
- aws_acm - Update automatic retries to stabilize the integration tests.
- aws_codecommit - Support updating the description
- aws_kms - Adds the ``enable_key_rotation`` option to enable or disable automatically key rotation.
- aws_kms - code refactor, some error messages updated
- aws_kms_info - Adds the ``enable_key_rotation`` info to the return value.
- ec2_asg - Add support for Max Instance Lifetime
- ec2_asg - Add the ability to use mixed_instance_policy in launch template driven autoscaling groups
- ec2_asg - Migrated to AnsibleAWSModule
- ec2_placement_group - make ``name`` a required field.
- ecs_task_definition - Add network_mode=default to support Windows ECS tasks.
- elb_network_lb - added support to UDP and TCP_UDP protocols
- elb_target - add awsretry to prevent rate exceeded errors (https://github.com/ansible/ansible/issues/51108)
- elb_target_group - allow UDP and TCP_UDP protocols; permit only HTTP/HTTPS health checks using response codes and paths
- iam - make ``name`` a required field.
- iam_cert - make ``name`` a required field.
- iam_policy - The iam_policy module has been migrated from boto to boto3.
- iam_policy - make ``iam_name`` a required field.
- iam_role - Add support for managing the maximum session duration
- iam_role - Add support for removing the related instance profile when we delete the role
- iam_role, iam_user and iam_group - the managed_policy option has been renamed to managed_policies (with an alias added)
- iam_role, iam_user and iam_group - the purge_policy option has been renamed to purge_policies (with an alias added)
- lambda - add a tracing_mode parameter to set the TracingConfig for AWS X-Ray. Also allow updating Lambda runtime.
- purefa_volume - Change I(qos) parameter to I(bw_iops), but retain I(qos) as an alias for backwards compatibility (https://github.com/ansible/ansible/pull/61577).
- redshift - Add AWSRetry calls for errors outside our control
- route53 - the module now has diff support.
- sns_topic - Add backoff when we get Topic ``NotFound`` exceptions while listing the subscriptions.
- sqs_queue - Add support for tagging, KMS and FIFO queues
- sqs_queue - updated to use boto3 instead of boto

Deprecated Features
-------------------

- cloudformation - The ``template_format`` option had no effect since Ansible 2.3 and will be removed after 2022-06-01
- data_pipeline - The ``version`` option had no effect and will be removed after 2022-06-01
- ec2_eip - The ``wait_timeout`` option had no effect and will be removed after 2022-06-01
- ec2_key - The ``wait_timeout`` option had no effect and will be removed after 2022-06-01
- ec2_key - The ``wait`` option had no effect and will be removed after 2022-06-01
- ec2_lc - The ``associate_public_ip_address`` option had no effect and will be removed after 2022-06-01
- elb_network_lb - The current default value of the ``state`` option has been deprecated and will change from absent to present after 2022-06-01
- iam_managed_policy - The ``fail_on_delete`` option had no effect and will be removed after 2022-06-01
- iam_policy - The ``policy_document`` will be removed after 2022-06-01.  To maintain the existing behavior use the ``policy_json`` option and read the file with the ``lookup`` plugin.
- iam_policy - The default value of ``skip_duplicates`` will change after 2022-06-01 from ``true`` to ``false``.
- iam_role - The default value of the purge_policies has been deprecated and will change from true to false after 2022-06-01
- s3_lifecycle - The ``requester_pays`` option had no effect and will be removed after 2022-06-01
- s3_sync - The ``retries`` option had no effect and will be removed after 2022-06-01

Bugfixes
--------

- **security issue** - Convert CLI provided passwords to text initially, to prevent unsafe context being lost when converting from bytes->text during post processing of PlayContext. This prevents CLI provided passwords from being incorrectly templated (CVE-2019-14856)
- **security issue** - Update ``AnsibleUnsafeText`` and ``AnsibleUnsafeBytes`` to maintain unsafe context by overriding ``.encode`` and ``.decode``. This prevents future issues with ``to_text``, ``to_bytes``, or ``to_native`` removing the unsafe wrapper when converting between string types (CVE-2019-14856)
- azure_rm_dnsrecordset_info - no longer returns empty ``azure_dnsrecordset`` facts when called as ``_info`` module.
- azure_rm_resourcegroup_info - no longer returns ``azure_resourcegroups`` facts when called as ``_info`` module.
- azure_rm_storageaccount_info - no longer returns empty ``azure_storageaccounts`` facts when called as ``_info`` module.
- azure_rm_virtualmachineimage_info - no longer returns empty ``azure_vmimages`` facts when called as ``_info`` module.
- azure_rm_virtualmachinescaleset_info - fix wrongly empty result, or ``ansible_facts`` result, when called as ``_info`` module.
- azure_rm_virtualnetwork_info - no longer returns empty ``azure_virtualnetworks`` facts when called as ``_info`` module.
- cloudfront_distribution - Always add field_level_encryption_id to cache behaviour to match AWS requirements
- cloudwatchlogs_log_group - Fix a KeyError when updating a log group that does not have a retention period (https://github.com/ansible/ansible/issues/47945)
- cloudwatchlogs_log_group_info - remove limitation of max 50 results
- ec2_asg - Ensure ``wait`` is honored during replace operations
- ec2_launch_template - Update output to include latest_version and default_version, matching the documentation
- ec2_transit_gateway - Use AWSRetry before ClientError is handled when describing transit gateways
- ec2_transit_gateway - fixed issue where auto_attach set to yes was not being honored (https://github.com/ansible/ansible/issues/61907)
- edgeos_config - fix issue where module would silently filter out encrypted passwords
- fixed issue with sns_topic's delivery_policy option resulting in changed always being true
- lineinfile - properly handle inserting a line when backrefs are enabled and the line already exists in the file (https://github.com/ansible/ansible/issues/63756)
- route53 - improve handling of octal encoded characters
- win_credential - Fix issue that errors when trying to add a ``name`` with wildcards.

New Modules
-----------

- aws_acm - Upload and delete certificates in the AWS Certificate Manager service
- aws_acm_info - Retrieve certificate information from AWS Certificate Manager service
- aws_api_gateway - Manage AWS API Gateway APIs
- aws_application_scaling_policy - Manage Application Auto Scaling Scaling Policies
- aws_batch_compute_environment - Manage AWS Batch Compute Environments
- aws_batch_job_definition - Manage AWS Batch Job Definitions
- aws_batch_job_queue - Manage AWS Batch Job Queues
- aws_codebuild - Create or delete an AWS CodeBuild project
- aws_codecommit - Manage repositories in AWS CodeCommit
- aws_codepipeline - Create or delete AWS CodePipelines
- aws_config_aggregation_authorization - Manage cross-account AWS Config authorizations
- aws_config_aggregator - Manage AWS Config aggregations across multiple accounts
- aws_config_delivery_channel - Manage AWS Config delivery channels
- aws_config_recorder - Manage AWS Config Recorders
- aws_config_rule - Manage AWS Config resources
- aws_direct_connect_connection - Creates, deletes, modifies a DirectConnect connection
- aws_direct_connect_gateway - Manage AWS Direct Connect gateway
- aws_direct_connect_link_aggregation_group - Manage Direct Connect LAG bundles
- aws_direct_connect_virtual_interface - Manage Direct Connect virtual interfaces
- aws_eks_cluster - Manage Elastic Kubernetes Service Clusters
- aws_elasticbeanstalk_app - Create, update, and delete an elastic beanstalk application
- aws_glue_connection - Manage an AWS Glue connection
- aws_glue_job - Manage an AWS Glue job
- aws_inspector_target - Create, Update and Delete Amazon Inspector Assessment Targets
- aws_kms - Perform various KMS management tasks.
- aws_kms_info - Gather information about AWS KMS keys
- aws_region_info - Gather information about AWS regions.
- aws_s3_bucket_info - Lists S3 buckets in AWS
- aws_s3_cors - Manage CORS for S3 buckets in AWS
- aws_secret - Manage secrets stored in AWS Secrets Manager.
- aws_ses_identity - Manages SES email and domain identity
- aws_ses_identity_policy - Manages SES sending authorization policies
- aws_ses_rule_set - Manages SES inbound receipt rule sets
- aws_sgw_info - Fetch AWS Storage Gateway information
- aws_ssm_parameter_store - Manage key-value pairs in aws parameter store.
- aws_step_functions_state_machine - Manage AWS Step Functions state machines
- aws_step_functions_state_machine_execution - Start or stop execution of an AWS Step Functions state machine.
- aws_waf_condition - Create and delete WAF Conditions
- aws_waf_info - Retrieve information for WAF ACLs, Rule , Conditions and Filters.
- aws_waf_rule - Create and delete WAF Rules
- aws_waf_web_acl - Create and delete WAF Web ACLs.
- cloudformation_exports_info - Read a value from CloudFormation Exports
- cloudformation_stack_set - Manage groups of CloudFormation stacks
- cloudfront_distribution - Create, update and delete AWS CloudFront distributions.
- cloudfront_info - Obtain facts about an AWS CloudFront distribution
- cloudfront_invalidation - create invalidations for AWS CloudFront distributions
- cloudfront_origin_access_identity - Create, update and delete origin access identities for a CloudFront distribution
- cloudtrail - manage CloudTrail create, delete, update
- cloudwatchevent_rule - Manage CloudWatch Event rules and targets
- cloudwatchlogs_log_group - create or delete log_group in CloudWatchLogs
- cloudwatchlogs_log_group_info - Get information about log_group in CloudWatchLogs
- cloudwatchlogs_log_group_metric_filter - Manage CloudWatch log group metric filter
- data_pipeline - Create and manage AWS Datapipelines
- dms_endpoint - Creates or destroys a data migration services endpoint
- dms_replication_subnet_group - creates or destroys a data migration services subnet group
- dynamodb_table - Create, update or delete AWS Dynamo DB tables
- dynamodb_ttl - Set TTL for a given DynamoDB table
- ec2_ami_copy - copies AMI between AWS regions, return new image id
- ec2_asg - Create or delete AWS AutoScaling Groups (ASGs)
- ec2_asg_info - Gather information about ec2 Auto Scaling Groups (ASGs) in AWS
- ec2_asg_lifecycle_hook - Create, delete or update AWS ASG Lifecycle Hooks.
- ec2_customer_gateway - Manage an AWS customer gateway
- ec2_customer_gateway_info - Gather information about customer gateways in AWS
- ec2_eip - manages EC2 elastic IP (EIP) addresses.
- ec2_eip_info - List EC2 EIP details
- ec2_elb - De-registers or registers instances from EC2 ELBs
- ec2_elb_info - Gather information about EC2 Elastic Load Balancers in AWS
- ec2_instance - Create & manage EC2 instances
- ec2_instance_info - Gather information about ec2 instances in AWS
- ec2_launch_template - Manage EC2 launch templates
- ec2_lc - Create or delete AWS Autoscaling Launch Configurations
- ec2_lc_find - Find AWS Autoscaling Launch Configurations
- ec2_lc_info - Gather information about AWS Autoscaling Launch Configurations.
- ec2_metric_alarm - Create/update or delete AWS Cloudwatch 'metric alarms'
- ec2_placement_group - Create or delete an EC2 Placement Group
- ec2_placement_group_info - List EC2 Placement Group(s) details
- ec2_scaling_policy - Create or delete AWS scaling policies for Autoscaling groups
- ec2_snapshot_copy - Copies an EC2 snapshot and returns the new Snapshot ID.
- ec2_transit_gateway - Create and delete AWS Transit Gateways
- ec2_transit_gateway_info - Gather information about ec2 transit gateways in AWS
- ec2_vpc_egress_igw - Manage an AWS VPC Egress Only Internet gateway
- ec2_vpc_endpoint - Create and delete AWS VPC Endpoints.
- ec2_vpc_endpoint_info - Retrieves AWS VPC endpoints details using AWS methods.
- ec2_vpc_igw - Manage an AWS VPC Internet gateway
- ec2_vpc_igw_info - Gather information about internet gateways in AWS
- ec2_vpc_nacl - create and delete Network ACLs.
- ec2_vpc_nacl_info - Gather information about Network ACLs in an AWS VPC
- ec2_vpc_nat_gateway - Manage AWS VPC NAT Gateways.
- ec2_vpc_nat_gateway_info - Retrieves AWS VPC Managed Nat Gateway details using AWS methods.
- ec2_vpc_peer - create, delete, accept, and reject VPC peering connections between two VPCs.
- ec2_vpc_peering_info - Retrieves AWS VPC Peering details using AWS methods.
- ec2_vpc_route_table - Manage route tables for AWS virtual private clouds
- ec2_vpc_route_table_info - Gather information about ec2 VPC route tables in AWS
- ec2_vpc_vgw - Create and delete AWS VPN Virtual Gateways.
- ec2_vpc_vgw_info - Gather information about virtual gateways in AWS
- ec2_vpc_vpn - Create, modify, and delete EC2 VPN connections.
- ec2_vpc_vpn_info - Gather information about VPN Connections in AWS.
- ec2_win_password - Gets the default administrator password for ec2 windows instances
- ecs_attribute - manage ecs attributes
- ecs_cluster - Create or terminate ECS clusters.
- ecs_ecr - Manage Elastic Container Registry repositories
- ecs_service - Create, terminate, start or stop a service in ECS
- ecs_service_info - List or describe services in ECS
- ecs_tag - create and remove tags on Amazon ECS resources
- ecs_task - Run, start or stop a task in ecs
- ecs_taskdefinition - register a task definition in ecs
- ecs_taskdefinition_info - Describe a task definition in ECS
- efs - create and maintain EFS file systems
- efs_info - Get information about Amazon EFS file systems
- elasticache - Manage cache clusters in Amazon ElastiCache
- elasticache_info - Retrieve information for AWS ElastiCache clusters
- elasticache_parameter_group - Manage cache parameter groups in Amazon ElastiCache.
- elasticache_snapshot - Manage cache snapshots in Amazon ElastiCache
- elasticache_subnet_group - manage ElastiCache subnet groups
- elb_application_lb - Manage an Application load balancer
- elb_application_lb_info - Gather information about application ELBs in AWS
- elb_classic_lb - Creates or destroys Amazon ELB.
- elb_classic_lb_info - Gather information about EC2 Elastic Load Balancers in AWS
- elb_instance - De-registers or registers instances from EC2 ELBs
- elb_network_lb - Manage a Network Load Balancer
- elb_target - Manage a target in a target group
- elb_target_group - Manage a target group for an Application or Network load balancer
- elb_target_group_info - Gather information about ELB target groups in AWS
- elb_target_info - Gathers which target groups a target is associated with.
- execute_lambda - Execute an AWS Lambda function
- iam - Manage IAM users, groups, roles and keys
- iam_cert - Manage server certificates for use on ELBs and CloudFront
- iam_group - Manage AWS IAM groups
- iam_managed_policy - Manage User Managed IAM policies
- iam_mfa_device_info - List the MFA (Multi-Factor Authentication) devices registered for a user
- iam_password_policy - Update an IAM Password Policy
- iam_policy - Manage inline IAM policies for users, groups, and roles
- iam_policy_info - Retrieve inline IAM policies for users, groups, and roles
- iam_role - Manage AWS IAM roles
- iam_role_info - Gather information on IAM roles
- iam_saml_federation - Maintain IAM SAML federation configuration.
- iam_server_certificate_info - Retrieve the information of a server certificate
- iam_user - Manage AWS IAM users
- iam_user_info - Gather IAM user(s) facts in AWS
- kinesis_stream - Manage a Kinesis Stream.
- lambda - Manage AWS Lambda functions
- lambda_alias - Creates, updates or deletes AWS Lambda function aliases
- lambda_event - Creates, updates or deletes AWS Lambda function event mappings
- lambda_facts - Gathers AWS Lambda function details as Ansible facts
- lambda_info - Gathers AWS Lambda function details
- lambda_policy - Creates, updates or deletes AWS Lambda policy statements.
- lightsail - Manage instances in AWS Lightsail
- rds - create, delete, or modify Amazon rds instances, rds snapshots, and related facts
- rds_instance - Manage RDS instances
- rds_instance_info - obtain information about one or more RDS instances
- rds_param_group - manage RDS parameter groups
- rds_snapshot - manage Amazon RDS snapshots.
- rds_snapshot_info - obtain information about one or more RDS snapshots
- rds_subnet_group - manage RDS database subnet groups
- redshift_cross_region_snapshots - Manage Redshift Cross Region Snapshots
- redshift_info - Gather information about Redshift cluster(s)
- route53 - add or delete entries in Amazons Route53 DNS service
- route53_health_check - Add or delete health-checks in Amazons Route53 DNS service
- route53_info - Retrieves route53 details using AWS methods
- route53_zone - add or delete Route53 zones
- s3_bucket_notification - Creates, updates or deletes S3 Bucket notification for lambda
- s3_lifecycle - Manage s3 bucket lifecycle rules in AWS
- s3_logging - Manage logging facility of an s3 bucket in AWS
- s3_sync - Efficiently upload multiple files to S3
- s3_website - Configure an s3 bucket as a website
- sns - Send Amazon Simple Notification Service messages
- sns_topic - Manages AWS SNS topics and subscriptions
- sqs_queue - Creates or deletes AWS SQS queues.
- sts_assume_role - Assume a role using AWS Security Token Service and obtain temporary credentials
- sts_session_token - Obtain a session token from the AWS Security Token Service
