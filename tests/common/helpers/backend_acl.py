import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = "/tmp"
TEMPLATE_DIR = os.path.join(BASE_DIR, '../templates')
ACL_TEMPLATE = 'backend_acl_update_config.j2'

def apply_acl_rules(duthost, tbinfo, intf_list=None):
    if "t0-backend" not in tbinfo["topo"]["name"]:
        return

    dst_acl_template = os.path.join(DUT_TMP_DIR, ACL_TEMPLATE)
    dst_acl_file = os.path.join(DUT_TMP_DIR, 'backend_new_acl.json')
    add_var = ''

    if intf_list:
        duthost.copy(src=os.path.join(TEMPLATE_DIR, ACL_TEMPLATE), dest=dst_acl_template)
        intfs = ",".join(intf_list)
        confvar = '{{"intf_list" : "{}"}}'.format(intfs)
        add_var = "-a '{}' ".format(confvar)
    else:
        dst_acl_template = "/usr/share/sonic/templates/backend_acl.j2"

    duthost.shell("sonic-cfggen {}-d -t {} > {}".format(add_var, dst_acl_template, dst_acl_file))
    tmp = duthost.stat(path=dst_acl_file)
    if tmp['stat']['exists']:
        duthost.command("acl-loader update incremental {}".format(dst_acl_file))


def bind_acl_table(duthost, tbinfo):
    if "t0-backend" not in tbinfo["topo"]["name"]:
        return

    vlan_intfs = duthost.get_vlan_intfs()
    duthost.command("config acl add table DATAACL L3 -p {}".format(",".join(vlan_intfs)))
