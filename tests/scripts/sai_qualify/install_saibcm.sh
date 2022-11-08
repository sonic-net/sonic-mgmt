#!/bin/bash
#Internal-used-only shell
#Use to uninstall libsaibcm package from a environment(could be inside a container), without uninstall other dependencies
#This shell need to place the new libsaibcm package into /download folder in the environment

dpkg -r --force-depends libsaibcm
dpkg -i /download/libsaibcm_*.deb
