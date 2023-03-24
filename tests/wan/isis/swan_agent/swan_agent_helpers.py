import os
import re
import glob


DUT_SWAN_AGANT_PATH = '~'
SWAN_AGENT_PATH = '/data/swan_agent'
SWAN_AGENT_NAME = 'SwanAgentSonic'
SWAN_AGENT_INIT = 'sonicswanagent_init.sh'
SWAN_AGENT_UNINIT = 'sonicswanagent_uninit.sh'


def get_latest_file(regex):
    file_iter = glob.glob(os.path.join(SWAN_AGENT_PATH, regex))
    return max(file_iter, key=os.path.getctime)


def get_swan_agent_file():
    regex_swan_agent = "swanagentsonic-*.x64.tar"
    return get_latest_file(regex_swan_agent)


def extract_swan_agent_file(localhost):
    regex_swan_agent_tar = "swanagentsonic-*.x86_64.tar"
    target = get_latest_file(regex_swan_agent_tar)
    localhost.shell("tar -xf {}".format(target))


def get_containerid(dut_host):
    regex_containerid = re.compile(r'^(\S+)\s+.*')
    output = dut_host.shell("docker ps | grep '{}'".format(SWAN_AGENT_NAME))
    return regex_containerid.match(output["stdout_lines"][0]).group(1)


def load_swan_agent(dut_host, localhost):
    extract_swan_agent_file(localhost)

    agent_file = get_swan_agent_file()
    dest_file = os.path.join(DUT_SWAN_AGANT_PATH, os.path.basename(agent_file))
    init_script = os.path.join(DUT_SWAN_AGANT_PATH, SWAN_AGENT_INIT)
    uninit_script = os.path.join(DUT_SWAN_AGANT_PATH, SWAN_AGENT_UNINIT)

    dut_host.file(path=init_script, state='absent')
    dut_host.copy(src=os.path.join(SWAN_AGENT_PATH, SWAN_AGENT_INIT), dest=init_script)
    dut_host.shell("chmod +x {}".format(init_script))

    dut_host.file(path=uninit_script, state='absent')
    dut_host.copy(src=os.path.join(SWAN_AGENT_PATH, SWAN_AGENT_UNINIT), dest=uninit_script)
    dut_host.shell("chmod +x {}".format(uninit_script))

    dut_host.file(path=dest_file, state='absent')
    dut_host.copy(src=agent_file, dest=dest_file)
    dut_host.shell("sudo docker load -i {}".format(dest_file))

    output = dut_host.shell("sudo docker images | grep 'swanagent'")["stdout_lines"]
    regex_imageid = re.compile(r'(\S+)\s+(\S+)\s+(\S+).*')
    if regex_imageid.match(output[0]):
        dut_host.shell("sudo docker run --name {} -itd --network host --cap-add=SYS_ADMIN {}".format(
            SWAN_AGENT_NAME, regex_imageid.match(output[0]).group(3)))
        time.sleep(5)
        dut_host.shell("{}/{} {}".format(DUT_SWAN_AGANT_PATH, SWAN_AGENT_INIT, get_containerid(dut_host)))
        time.sleep(10)


def remove_swan_agent(dut_host):
    agent_file = get_swan_agent_file()
    dest_file = os.path.join(DUT_SWAN_AGANT_PATH, os.path.basename(agent_file))
    dut_host.file(path=dest_file, state='absent')

    init_script = os.path.join(DUT_SWAN_AGANT_PATH, SWAN_AGENT_INIT)
    dut_host.file(path=init_script, state='absent')

    dut_host.shell("{}/{} {}".format(DUT_SWAN_AGANT_PATH, SWAN_AGENT_UNINIT, get_containerid(dut_host)))
    uninit_script = os.path.join(DUT_SWAN_AGANT_PATH, SWAN_AGENT_UNINIT)
    dut_host.file(path=uninit_script, state='absent')

    output = dut_host.shell("sudo docker images | grep 'swanagent'")["stdout_lines"]
    regex_imageid = re.compile(r'(\S+)\s+(\S+)\s+(\S+).*')
    if regex_imageid.match(output[0]):
        dut_host.shell("sudo docker rmi {}".format(regex_imageid.match(output[0]).group(3)))