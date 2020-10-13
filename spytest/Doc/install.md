**PLEASE REFER TO intro.md FIRST BEFORE THIS DOCUMENT**

* Prerequisites for executing SpyTest
    * Server/Laptop or VM running Red Hat or Ubuntu with minimum 10GB HDD.
      We have tested on Red Hat 4.4.7-9 and Ubuntu 16.04.10

* Tools Installation
    * Create a folder install under the /projects/scid folder
    * Download following files from [ActiveState](https://www.activestate.com/products/)
        * ActiveTcl-8.5.19.8519-x86_64-linux-glibc-2.5-403583.tar.gz
        * ActivePython-2.7.14.2717-linux-x86_64-glibc-2.12-404899.tar.gz
    * Install them to /projects/scid folder. After installation the folder structure should look like below

            /projects/scid/tools/ActivPython/2.7.14
            /projects/scid/tools/ActivPython/2.7.14/lib
            /projects/scid/tools/ActivPython/2.7.14/etc
            /projects/scid/tools/ActivPython/2.7.14/licenses
            /projects/scid/tools/ActivPython/2.7.14/include
            /projects/scid/tools/ActivPython/2.7.14/doc
            /projects/scid/tools/ActivPython/2.7.14/bin
            /projects/scid/tools/ActivPython/2.7.14/share
            /projects/scid/tools/ActivPython/current -> 2.7.14

            /projects/scid/tools/ActivTcl/
            /projects/scid/tools/ActivTcl/8.5.19
            /projects/scid/tools/ActivTcl/8.5.19/lib
            /projects/scid/tools/ActivTcl/8.5.19/8.5.19
            /projects/scid/tools/ActivTcl/8.5.19/licenses
            /projects/scid/tools/ActivTcl/8.5.19/MANIFEST_at8.5.txt
            /projects/scid/tools/ActivTcl/8.5.19/demos
            /projects/scid/tools/ActivTcl/8.5.19/include
            /projects/scid/tools/ActivTcl/8.5.19/doc
            /projects/scid/tools/ActivTcl/8.5.19/bin
            /projects/scid/tools/ActivTcl/8.5.19/man
            /projects/scid/tools/ActivTcl/8.5.19/share
            /projects/scid/tools/ActivTcl/8.5.19/README-8.5-thread.txt
            /projects/scid/tools/ActivTcl/8.5.19/license-at8.5-thread.terms
            /projects/scid/tools/ActivTcl/current -> 8.5.19
    * SPyTest may also work fine with native Linux packages for python2, pip2, tcl and tclx
      but this is not exercised well. Similarly it may work well in virtual python environment also.

* TGen Installation
    * SPyTest needs traffic generator client libraries
        * Please contact Ixia and STC to get the required APIs for these libraries
    * The exact files used for validating SPyTest are:
        * [IxNetwork 8.42](http://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/IxNetworkAPI8.42.1250.2Linux64.bin.tgz)
        * [STC 4.91](https://support.spirent.com/SpirentCSC/SpirentDownloadsAppPage?rid=10492)
    * Once installed, create symbolic links so that folder structure looks same as given in
        [SPYTEST-ROOT]/bin/tgen_folders.txt
    * IxOS TCL libraries need to be installed before installing the IxNetwork libraries
    * SPyTest needs IxNetwork to installed on an intermediate server/VM
        * The exact file used for validating SPyTest is:  [IxNetwork 8.42](http://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/IxNetwork8.42EA.exe)
    * The IxNetwork Server IP address needs to be given in testbed file as "ix_server"
    * The IxNetwork API Server needs to be launched before launching SPyTest
    * For Scapy traffic generator refer to [README.testbed.Setup.md](https://github.com/Azure/sonic-mgmt/blob/master/ansible/doc/README.testbed.Setup.md)

