#!/bin/bash

source ./demo_env.sh

# Here we force install the swss and swss-dbg packages for debugging, because we will never run them locally.
echo "Installing debug files from buildimage ..."
sudo dpkg --force-all -i $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/swss_1.0.0_amd64.deb
sudo dpkg --force-all -i $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/swss-dbg_1.0.0_amd64.deb
sudo dpkg --force-all -i $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/syncd-vs_1.0.0_amd64.deb
sudo dpkg --force-all -i $DEMO_BUILDIMAGE_DIR/target/debs/bookworm/syncd-vs-dbgsym_1.0.0_amd64.deb

echo "Download dump file from DPU ..."
$DPU_PW $SSH admin@$DPU_IP "rm -f /home/admin/sonic-dump.tar.gz"
$DPU_PW $SSH admin@$DPU_IP "for f in \`ls -1 /var/dump/*.tar.gz | sort -r\`; do cp \$f /home/admin/sonic-dump.tar.gz; break; done"
$DPU_PW $SCP admin@$DPU_IP:/home/admin/sonic-dump.tar.gz .
echo ""

echo "Extract dump file ..."
rm -rf sonic-dump
mkdir sonic-dump && tar xvf sonic-dump.tar.gz -C sonic-dump --strip-components=1
echo ""

echo "Unzip all core files ..."
for f in `ls -1 sonic-dump/core/*.core.gz`; do
    echo "Unzipping $f ..."
    gzip -d $f
done

# After finished
# gdb /usr/bin/orchagent sonic-dump/core/orchagent.1728169080.61.core
