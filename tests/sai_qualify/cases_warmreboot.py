
"""
Test cases list under ptf/warm_boot
"""
PRE_REBOOT_TEST_CASE = [
    # "warm_saisanity.WarmL2SanityTest",
    "sai_vlan_test.Vlan_Domain_Forwarding_Test",
    "sai_vlan_test.UntagAccessToAccessTest",
    "sai_vlan_test.MismatchDropTest",
    "sai_vlan_test.TaggedFrameFilteringTest",
    "sai_vlan_test.UnTaggedFrameFilteringTest",
    "sai_vlan_test.TaggedVlanFloodingTest",
    "sai_vlan_test.UnTaggedVlanFloodingTest",
    "sai_vlan_test.BroadcastTest",
    "sai_vlan_test.UntaggedMacLearningTest",
    "sai_vlan_test.TaggedMacLearningTest",
    "sai_vlan_test.VlanMemberListTest",
    "sai_vlan_test.VlanMemberInvalidTest",
    "sai_vlan_test.DisableMacLearningTaggedTest",
    "sai_vlan_test.DisableMacLearningUntaggedTest",
    "sai_vlan_test.ArpRequestFloodingTest",
    "sai_vlan_test.ArpRequestLearningTest",
    "sai_vlan_test.TaggedVlanStatusTest",
    "sai_vlan_test.UntaggedVlanStatusTest",
]

REBOOTING_TEST_CASE = [
    # "warm_saisanity.WarmL2SanityTest",
    "sai_vlan_test.Vlan_Domain_Forwarding_Test",
    "sai_vlan_test.UntagAccessToAccessTest",
    "sai_vlan_test.MismatchDropTest",
    "sai_vlan_test.TaggedVlanFloodingTest",
    "sai_vlan_test.UnTaggedVlanFloodingTest",
    "sai_vlan_test.BroadcastTest",
    "sai_vlan_test.ArpRequestFloodingTest",
]

POST_REBOOT_TEST_CASE = PRE_REBOOT_TEST_CASE
