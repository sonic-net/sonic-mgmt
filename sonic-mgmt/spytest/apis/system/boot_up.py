from spytest.utils import filter_and_select
from spytest import st
import sys
import re

def sonic_installer_cleanup(dut):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer cleanup -y"
    output = st.config(dut, command)
    retval = re.search(r".*No image\(s\) to remove.*", output)
    if retval is None:
        return True
    else:
        st.log("No image(s) to remove")
        return False
    return True

def sonic_installer_remove(dut,image):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer remove {} -y".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False
    return True

def sonic_installer_set_default(dut,image):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer set_default {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False
    return True

def sonic_installer_set_next_boot(dut,image):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer set_next_boot {}".format(image)
    output = st.config(dut, command)
    retval = re.search(".*Image does not exist.*", output)
    if retval is None:
        return True
    else:
        st.log("Image does not exist")
        return False
    return True

def sonic_installer_install(dut,image_path):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer install {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False
    return True

def sonic_installer_binary_version(dut,image_path):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer binary_version {} -y".format(image_path)
    output = st.config(dut, command)
    retval = re.search(".*File does not appear to be a vaild SONiC image file.*", output)
    if retval is None:
        return True
    else:
        st.log("File does not appear to be a vaild SONiC image file")
        return False
    return True

def sonic_installer_upgrade_docker(dut,container_name,image_path):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer upgrade_docker {} {} -y".format(container_name,image_path)
    output = st.config(dut, command)
    retval = re.search(".*No such file or directory.*|.*Image file '.*' does not exist or is not a regular file. Aborting.*", output)
    if retval is None:
        return True
    else:
        st.log("No such file or directory | Image file does not exist or is not a regular file. Aborting")
        return False
    return True

def sonic_installer_list(dut):
    st.log(sys._getframe(  ).f_code.co_name.replace('_',' '))
    command = "sudo sonic_installer list"
    output = st.show(dut, command)
    entries = filter_and_select(output, ["current","next","available"])

    retval = dict()
    currentList = []
    nextList = []
    availableList = []
    for ent in entries:
        if ent["current"]: currentList.append(ent["current"])
        if ent["next"]: nextList.append(ent["next"])
        if ent["available"]: availableList.append(ent["available"])
    retval["Current"] = currentList
    retval["Next"] = nextList
    retval["Available"] = availableList
    return retval

