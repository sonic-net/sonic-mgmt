RC_SSH_SUCCESS = 0
RC_SSH_FAILED = 1
RC_PASSWORD_FAILED = 2

# Here we will get a screen like
#
#                              GNU GRUB  version 2.02
#
#  +----------------------------------------------------------------------------+
#  |*SONiC-OS-20220531.48                                                       |
#  | ONIE                                                                       |
#  |                                                                            |
#  |                                                                            |
#  +----------------------------------------------------------------------------+
#       Use the ^ and v keys to select which entry is highlighted.
#       Press enter to boot the selected OS, `e' to edit the commands
#       before booting or `c' for a command-line.

# The buffer maybe small and can not hold all characters
# So we select typical characters
OS_VERSION_IN_GRUB = "-OS-"
ONIE_ENTRY_IN_GRUB = "*ONIE"

# After enter into ONIE, we we get the screen like
#
#                              GNU GRUB  version 2.02
#
#  +----------------------------------------------------------------------------+
#  |*ONIE: Install OS                                                           |
#  | ONIE: Rescue                                                               |
#  | ONIE: Uninstall OS                                                         |
#  | ONIE: Update ONIE                                                          |
#  | ONIE: Embed ONIE                                                           |
#  |                                                                            |
#  |                                                                            |
#  +----------------------------------------------------------------------------+
#       Use the ^ and v keys to select which entry is highlighted.
#       Press enter to boot the selected OS, `e' to edit the commands
#       before booting or `c' for a command-line.

ONIE_INSTALL_MODEL = "Install"
ONIE_RESCUE_MODEL = "Rescue"

# While entering into ONIE, we will get some output like
# " Booting `ONIE: Install OS' "
# " OS Install Mode"
BOOTING_INSTALL_OS = "Booting"

# After enter into the installation in ONIE, it will discover some configuration
# And finally, we will get the string "ONIE: Starting ONIE Service Discovery"
# To fit the scenario of Celestica, we finally use the string "covery"
ONIE_START_TO_DISCOVERY = "covery"

# At last, if installation successes in ONIE, we will get the prompt
SONIC_PROMPT = "sonic login:"

# For Nokia testbeds, we will get the string "Hit any key to stop autoboot" to enter into Marvell
MARVELL_ENTRY = "stop autoboot"
