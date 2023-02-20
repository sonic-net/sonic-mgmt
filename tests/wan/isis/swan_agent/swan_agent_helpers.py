import os
import re
import glob


DUT_SWAN_AGANT_PATH = '/tmp'
SWAN_AGENT_PATH = '/data/swan_agent'
SWAN_AGENT_NAME = 'SwanAgentSonic'

def get_swan_agent_file():
    regex_swan_agent = "swanagentsonic-*.x64.tar"
    file_iter = glob.glob(os.path.join(SWAN_AGENT_PATH, regex_swan_agent))
    for item in file_iter:
        return max(file_iter, key=os.path.getctime)


def load_swan_agent(duthost):
    agent_file = get_swan_agent_file()
    dest_file = os.path.join(DUT_SWAN_AGANT_PATH, os.path.basename(agent_file))

    duthost.file(path=dest_file, state='absent')
    duthost.copy(src=agent_file, dest=dest_file)
    duthost.shell("sudo docker load -i {}".format(dest_file))

    output = duthost.shell("sudo docker images | grep 'swanagent'")["stdout_lines"]
    regex_imageid = re.compile(r'(\S+)\s+(\S+)\s+(\S+).*')
    if regex_imageid.match(output[0]):
        duthost.shell("sudo docker run --name {} -itd --network host --cap-add=SYS_ADMIN {}".format(
            SWAN_AGENT_NAME, regex_imageid.match(output[0]).group(3)))
        time.sleep(5)
        regex_containerid = re.compile(r'^(\S+)\s+.*')
        output = duthost.shell("docker ps | grep '{}'".format(SWAN_AGENT_NAME))
        containerid = regex_containerid.match(output["stdout_lines"][0]).group(1)
        duthost.shell("sudo docker cp {}:/go/src/grpcStub /tmp".format(containerid))
        duthost.shell("nohup sudo python3 /tmp/grpcStub/server.py > /tmp/grpcStub.log 2>&1 &")
        time.sleep(10)


def remove_swan_agent(duthost):
    agent_file = get_swan_agent_file()
    dest_file = os.path.join(DUT_SWAN_AGANT_PATH, os.path.basename(agent_file))
    duthost.file(path=dest_file, state='absent')

    duthost.shell("sudo docker stop {}".format(SWAN_AGENT_NAME))
    time.sleep(3)
    duthost.shell("sudo docker rm {}".format(SWAN_AGENT_NAME))
    duthost.shell("sudo pkill -f /tmp/grpcStub/server.py", module_ignore_errors=True)

    output = duthost.shell("sudo docker images | grep 'swanagent'")["stdout_lines"]
    regex_imageid = re.compile(r'(\S+)\s+(\S+)\s+(\S+).*')
    if regex_imageid.match(output[0]):
        duthost.shell("sudo docker rmi {}".format(regex_imageid.match(output[0]).group(3)))