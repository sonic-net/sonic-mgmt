- [Overview](#overview)
    - [Scope](#scope)
- [Test Procedure](#test-procedure)

## Overview
The purpose for this test is to ensure that the DUT is able to fetch files from an external HTTP server without loss of file integrity. The file used by the test exceeds a gigabyte in order to ensure integrity even for large file sizes.

### Scope
This test was verified on a t0 topology, but should work on any other topology since the only interaction is between the host computer running the HTTP server and the DUT.

## Test Procedure

1. An HTTP server is started on the PTF container
2. The PTF container generates a 1 GB file with random bytes
3. An MD5 checksum is generated for the generated file
4. The DUT requests this file from the HTTP server
5. An MD5 checksum is generated for the file on the DUT
6. The checksums are compared, failing if they differ
7. Both systems are cleaned of the large file