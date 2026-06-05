# Overview

This document captures the GPINs test plan for image upgrade/downgrade. It also covers the testing of image upgrade/downgrade using the gNOI OS API.

# Objective

-   Test GPINs image upgrade/downgrade with gNOI OS API.
-   Test GPINs image upgrade support from N-1 release.
-   Test GPINs image downgrade support to N-1 release.
-   Non-stack image components (Haven FW, bootloader, FPGA, optic FW etc) upgrade/downgrade testing is not in the scope of this document.

# Background

## Chemia Upgrade Test

As part of the system integration test workflow, the chemia update test performs an image update by making a "chemia update" call. The existing test updates the IUT to itself. We will expand this test to cover real upgrade/downgrade scenarios.

Currently chemia update is not using the gNOI OS API, but it will migrate to the API in the near future. Once chemia completes the gNOI migration. The test will cover gNOI OS testing in the stack.

## GPINs Release Process

For each production GPINs release image, we would like to have test coverage in +1/-1 upgrade/downgrade. For a daily image or release candidate, we would like to perform:

-   Upgrade test from last production release and all production release candidates.
-   Downgrade test to last production release and all production release candidates.

The GPINs image release processis yet to be defined. a release candidate will typically go through the following stages:

<table>
  <thead>
    <tr>
      <th><strong>Stage</strong></th>
      <th><strong>MPM Label (TBD)</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Qual</td>
      <td>IN_QUAL</td>
    </tr>
    <tr>
      <td>Staging</td>
      <td>IN_STAGING</td>
    </tr>
    <tr>
      <td>Canary/Prod</td>
      <td>IN_PROD</td>
    </tr>
  </tbody>
</table>

In SandCastle, a release candidate was never skipped to go to prod since NSF was introduced. The release cadence for SandCastle is 6-12 weeks, which gives enough time for fixing issues in qual or staging. However, the GPINs release cadence is planned to be 2 weeks. This gives less time to fix issues in qual or staging before the next release cut of. So in GPINs, we might need to skip a release candidate in prod. Ideally:

-   Upgrade test will test upgrade from [IN_QUAL, IN_STAGING, IN_PROD] to IUT.
-   Downgrade test will test downgrade from IUT to [IN_QUAL, IN_STAGING, IN_PROD].

Currently, GPINs has a biweekly release schedule. And there is no 3 release staging as SandCastle. At this early stage, we can test upgrade/downgrade with LAST_RELEASE.

Update on May 2022:\
 Currently, the upgrade/downgrade tests use the LAST_RELEASE image for testing. The LAST_RELEASE image MPM label can be:

-   "release_latest", if IUT is a daily image.
-   "release_previous", if IUT is a release image.

Due to the biweekly release schedule, GPINs does not have a "in qual" release stage as SandCastle. Also, GPINs is not in production yet.

## Manufacture Image

The GPINs manufacture image process is yet to be defined. To add test coverage for the manufacture image, we will expand the existing chemia installation test to perform chemia install from manufacture image to IUT. Chemia install does not use gNOI OS API.

## GNOI OS API

The gNOI OS API provides an open interface for image installation.:


In the end-to-end testing, the test will exercise the gNOI install for different supported images. The details are defined in the OsUpdate proto. Example image type can be:

-   switch stack + containers
-   netlo
-   bootloader

The test will also test certain error scenarios. They can be:

-   Invalid remote link.
-   Missing container images.
-   gNOI OS proto sequence error.

# Testbed Requirements

Any hardware standalone testbed setup can run the upgrade/downgrade tests. They can be:

-   Single switch (with or without Ixia/hosts).
-   Mirror switches.

Upgrade/downgrade should not run in virtual environments such as vGPINs.

# Test Cases

## Chemia Test

### Upgrade Test

This test should do chemia update from [IN_QUAL, IN_STAGING, IN_PROD] to IUT. At the early stage, it can do chemia update from LAST_RELEASE to IUT.

Procedure:

-   Fast install the IN_QUAL/IN_STAGING/IN_PROD/LAST_RELEASE image into SUT.
-   Verify the image version that has been installed.
-   Perform chemia update to IUT.

Expected results:

-   Switch image has the expected version.
-   Validation should pass.

### Downgrade Test

This test should do chemia update from IUT to [IN_QUAL, IN_STAGING, IN_PROD]. At the early stage, it can do chemia update from IUT to LAST_RELEASE.

Procedure:

-   Perform chemia update to IN_QUAL/IN_STAGING/IN_PROD/LAST_RELEASE.
-   Revert switch image to IUT after finish using fast install.

Expected results:

-   Switch image has the expected version.
-   Validation should pass.

## GNOI Install Test

The following tests will directly call the gNOI OS API to install various images. We will update the image from IUT to IUT in the following tests.

### GNOI Install Switch Stack & Containers

This test should perform a stack image install using the gNOI OS API.

Procedure:

-   Perform gNOI OS install sequence for switch stack & containers using LAST_RELEASE image.
-   Measure time taken for the gNOI install operations (install + activate + verify).
-   Revert switch image to IUT after finish using fast install.

Expected results:

-   Switch stack image has the expected version.

### GNOI Install Netlo Image

This test should perform a netlo image install using the gNOI OS API.

Procedure:

-   Perform gNOI OS install sequence for the netlo image using LAST_RELEASE image.
-   Measure time taken for the gNOI install operations (install + activate + verify).
-   Revert netlo image to IUT after finish using fast install.

Expected results:

-   Netlo image has the expected version.

### GNOI Install Bootloader Image

This test should perform a bootloader image install using the gNOI OS API.

Procedure:

-   Perform gNOI OS install sequence for the bootloader image using LAST_RELEASE image.
-   Measure time taken for the gNOI install operations (install + activate + verify).
-   Revert bootloader image to IUT after finish using fast install.

Expected results:

-   Bootloader image has the expected version.

### Invalid Stack Image Link

This test will perform a gNOI OS install on stack image with an OsUpdate proto that contains an invalid remote stack image link.

Procedure:

-   Perform gNOI OS install sequence on stack image with an invalid remote stack image link.

Expected results:

-   The gNOI OS install should fail.
-   The gNOI OS version should not be updated.

### Missing Container Images

This test will perform a gNOI OS install on stack image with a few missing containers.

Procedure:

-   Perform gNOI OS install sequence on stack image with a few missing containers.

Expected results:

-   The gNOI OS install should succeed.
-   The gNOI OS version should be successfully updated.
-   SUT should be in critical state as some containers are missing.

### Activate Without Install

The test will perform a gNOI OS activate without completing the gNOI OS install.

Procedure:

-   Perform a gNOI OS activate directly without a gNOI OS install. Then perform gNOI OS verify.

Expected results:

-   The gNOI OS activate should fail.
-   The gNOI OS version should not be updated.

### Reboot Before Activate

The test will test the case where the switch will reboot after the gNOI OS install but before the gNOI OS activate.

Procedure:

-   Send a gNOI OS install to the switch.
-   Reboot the switch via ssh.
-   Send a gNOI OS activate & verify.

Expected results:

-   The gNOI OS activate should fail.
-   The gNOI OS version should not be updated.
