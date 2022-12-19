 - [Overview](#overview)
     - [Scope](#scope)
 - [Test Procedure](#test-procedure)

## Overview
The purpose of this test is to ensure that the DUT is able to fetch from an external SCP server without loss of file integrity. The file used by the test is close to half a gigabyte in order to ensure integrity even for large file sizes.

### Scope
This test was verified on a t0 topology, but should work on any other topology since the only interaction is between the host computer, DUT and the PTF.

## Test Procedure

1. The PTF container generates a 0.5 GB file with random bytes.
2. AN MD5 checksum is generated for the generated file.
3. The DUT requests this file from the PTF via scp started from the DUT.
4. An MD5 checksum is generated for the file on the DUT.
5. The checksums are compared, failing if they differ.
6. The DUT copies over a copy of the same file back to the PTF via SCP initiated from the PTF.
7. An MD5 checksum is generated for the copy sent to the PTF.
8. The checksums are compared again, failing if they differ.
9. Both systems are cleaned of the large file.

