#!/bin/sh

# By this script, SONiC switch moving to ONIE with specific boot_mode
# The examples of usage:
#     onie_install.sh

onie_mount=/mnt/onie-boot
os_boot=/host
onie_partition=
onie_entry=0

enable_onie_access()
{
	onie_partition=$(fdisk -l | grep "ONIE boot" | awk '{print $1}')
	if [ ! -d $onie_mount ]; then
		mkdir /mnt/onie-boot
	fi
	mount $onie_partition /mnt/onie-boot
	if [ ! -e /lib/onie ]; then
		ln -s /mnt/onie-boot/onie/tools/lib/onie /lib/onie
	fi
	PATH=/sbin:/usr/sbin:/bin:/usr/bin:$onie_mount/onie/tools/bin/
	export PATH
}

clean_onie_access()
{
	rm -f /lib/onie
	umount $onie_partition
}

# ONIE entry must exist in grub config
find_onie_menuentry()
{
	onie_entry="$(cat $os_boot/grub/grub.cfg | grep -e 'menuentry' | cat -n | awk '$0~/ONIE/ {print $1-1}')"
	entries_num="$(echo "$onie_entry" | grep -E '^[0-9]+$' | wc -l)"
	if [ $entries_num -eq 1 ] && [ $onie_entry -ge 1 ]; then
		return 0
	fi
	return 1
}


change_onie_grub_boot_order()
{
	find_onie_menuentry
	rc=$?
	if [ $rc -eq 0 ]; then
		grub-reboot --boot-directory=$os_boot $onie_entry
	else
		echo "ERROR: ONIE entry wasn't found in grub config"
		return 1
	fi

	echo "Set onie mode to install"
	grub-editenv $onie_mount/grub/grubenv set onie_mode=install
	return 0
}


system_reboot()
{
    	echo "Reboot will be done after 3 sec."
    	sleep 3
    	/sbin/reboot
}



rc=$?
enable_onie_access
change_onie_grub_boot_order
clean_onie_access

if [ $rc -eq 0 ]; then
	system_reboot
fi

exit $rc
