import os
import docker
import shutil
import socket
import random
import tempfile
from datetime import datetime

from spytest import st

import utilities.common as utils

log_info = st.log
log_error = st.error
log_exp = st.exception
report_env_fail = st.report_env_fail
show_files = False

def log_file_content(name, content):
    log_info("============ {} ================".format(name))
    log_info(content)
    log_info("========================================")

def verify_url(DOCKER_HOST):
    url_info = utils.parse_url(DOCKER_HOST)
    path = url_info["path"]
    if path:
        if not os.path.exists(path):
            log_error("Valid socket path is not provided for DOCKER")
            report_env_fail("ip_verification_fail")
        return ""
    elif not utils.is_valid_ipv4(url_info["ip"]):
        log_error("Valid IPv4 address is not provided for DOCKER")
        report_env_fail("ip_verification_fail")
    return url_info["ip"]

def next_free_port(min_port=40000, max_port=42000, used=[]):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        if len(used) >= (max_port-min_port):
            break
        port = random.randint(min_port, max_port)
        if port in used: continue
        used.append(port)
        try:
            addr = os.getenv("DOCKER_HOST_BIND", "")
            sock.bind((addr, port))
            sock.close()
            return port
        except OSError:
            pass
    raise IOError('no free ports')

def init_docker_services(log=None, sf=False):
    global log_info, log_error, log_exp, report_env_fail, show_files
    log_info = log.info
    log_error = log.error
    log_exp = log.exception
    report_env_fail = log.error
    show_files = sf

def save_docker_files(entrypoint, dockerfile):
    temp_dir = tempfile.mkdtemp()
    utils.write_file(os.path.join(temp_dir, "startup.sh"), entrypoint)
    # nosemgrep-next-line
    os.chmod(os.path.join(temp_dir, "startup.sh"), 0o777)
    utils.write_file(os.path.join(temp_dir, "Dockerfile"), dockerfile)
    log_info("Dockerfile: {}".format(dockerfile))
    return temp_dir

def start_container(client, tag, *port_list):
    log_info("Starting Container: {}".format(tag))
    for _ in range(3):
        ports = {}
        for p in port_list:
            ports[p] = next_free_port()
        try:
            cont = client.containers.run(tag, detach=True, ports=ports, tty=True)
            break
        except Exception as exp:
            log_exp(exp)
            cont = None
    return cont

def remove_docker_container(contid, DOCKER_HOST):

    log_info("Removing Docker Container: {}".format(contid))
    verify_url(DOCKER_HOST)
    client = docker.DockerClient(base_url=DOCKER_HOST)

    cont = client.containers.get(contid)
    if cont:
        cont.stop()
        cont.remove()

def cleanup_docker_containers(DOCKER_HOST, days=7):
    verify_url(DOCKER_HOST)
    client = docker.DockerClient(base_url=DOCKER_HOST)
    now = datetime.utcnow()
    seconds = days * 24 * 60 * 60
    for cont in client.containers.list(all=True):
        date_time_str = cont.attrs["State"]["StartedAt"].split(".")[0]
        try:
            old = datetime.strptime(date_time_str, '%Y-%m-%dT%H:%M:%S')
        except Exception:
            log_error("failed to parse {}".format(date_time_str))
            continue
        elapsed = int((now-old).total_seconds())
        if elapsed > seconds:
            log_info("Removing Docker Container {} Created {} Elapsed {}".format(cont, date_time_str, elapsed))
            cont.stop()
            cont.remove()


radius_entrypoint = """\
#!/bin/bash
service ssh start
service freeradius start
bash
"""
radius_username_password = ['admin','YourPaSsWoRd']

radius_dockerfile = r"""
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install openssh-server sudo -y
RUN mkdir -p /run/sshd
RUN ssh-keygen -A
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN useradd -rm -d /home/admin -s /bin/bash -g root -G sudo -u 1000 {0}
RUN echo '{0}:{1}' | chpasswd
RUN service ssh start
EXPOSE 22/tcp
RUN apt update && apt install freeradius -y
RUN sed -i 's/stripped_names = no/stripped_names = yes/g' /etc/freeradius/3.0/radiusd.conf
RUN sed -i 's/auth_accept = no/auth_accept = yes/g' /etc/freeradius/3.0/radiusd.conf
RUN sed -i 's/auth_badpass = no/auth_badpass = yes/g' /etc/freeradius/3.0/radiusd.conf
RUN sed -i 's/auth_goodpass = no/auth_goodpass = yes/g' /etc/freeradius/3.0/radiusd.conf
RUN sed -i 's/auth = no/auth = yes/g' /etc/freeradius/3.0/radiusd.conf
RUN sed -i 's/default_eap_type = md5/default_eap_type = peap/g' /etc/freeradius/3.0/mods-available/eap
RUN sed -i 's/use_tunneled_reply = no/use_tunneled_reply = yes/g' /etc/freeradius/3.0/mods-available/eap
EXPOSE 1812/udp 1813/udp
ADD ./startup.sh /startup.sh

ENTRYPOINT ["/startup.sh"]
""".format(radius_username_password[0],radius_username_password[1])

radius_docker_image_tag = "spytest-freeradius:1.4"

def create_radius_docker_image(client):
    temp_dir = save_docker_files(radius_entrypoint, radius_dockerfile)

    if show_files:
        log_file_content("startup.sh", radius_entrypoint)
        log_file_content("Dockerfile", radius_dockerfile)

    try:
        log_info("Building: {}".format(radius_docker_image_tag))
        client.images.build(path=temp_dir, tag=radius_docker_image_tag)
        retval = True
    except Exception as exp:
        log_exp(exp)
        retval = False
        report_env_fail("docker_image_installation", "failed")

    shutil.rmtree(temp_dir)
    return retval

def create_radius_docker_container(DOCKER_HOST):
    radius_docker_dict={}
    ip = verify_url(DOCKER_HOST)
    client = docker.DockerClient(base_url=DOCKER_HOST)

    # create the image if not already present
    try: client.images.get(radius_docker_image_tag)
    except Exception: create_radius_docker_image(client)

    # start the container
    cont = start_container(client, radius_docker_image_tag, '22/tcp', '1812/udp', '1813/udp')
    if cont is None:
        report_env_fail("docker_run", "failed")

    # find the ports
    apic = docker.APIClient(base_url=DOCKER_HOST)
    port_data = apic.inspect_container(cont.id)['NetworkSettings']['Ports']
    radius_docker_dict['radius_port'] = port_data['1812/udp'][0]["HostPort"]
    radius_docker_dict['host'] = ip
    radius_docker_dict['ssh_port'] = port_data['22/tcp'][0]["HostPort"]
    radius_docker_dict['cont_id'] = cont.id
    radius_docker_dict['username'] = radius_username_password[0]
    radius_docker_dict['password'] = radius_username_password[1]
    return radius_docker_dict

def remove_radius_docker_container(contid, DOCKER_HOST):
    remove_docker_container(contid, DOCKER_HOST)


snmptrapd_entrypoint = """\
#!/bin/bash
service ssh start
service snmptrapd start
bash
"""
snmptrapd_username_password = ['admin','YourPaSsWoRd']

snmptrapd_dockerfile = r"""
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install openssh-server sudo -y
RUN mkdir -p /run/sshd
RUN ssh-keygen -A
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN useradd -rm -d /home/admin -s /bin/bash -g root -G sudo -u 1000 {0}
RUN echo '{0}:{1}' | chpasswd
RUN service ssh start
EXPOSE 22/tcp
RUN apt update && apt install snmp snmptrapd -y
RUN sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmptrapd
RUN service snmptrapd start
EXPOSE 161/udp
ADD ./startup.sh /startup.sh

ENTRYPOINT ["/startup.sh"]
""".format(snmptrapd_username_password[0],snmptrapd_username_password[1])

snmptrapd_docker_image_tag = "spytest-snmptrapd:1.0"

def create_snmptrapd_docker_image(client):
    temp_dir = save_docker_files(snmptrapd_entrypoint, snmptrapd_dockerfile)

    try:
        log_info("Building: {}".format(snmptrapd_docker_image_tag))
        client.images.build(path=temp_dir, tag=snmptrapd_docker_image_tag)
        retval = True
    except Exception as exp:
        log_exp(exp)
        retval = False
        report_env_fail("docker_image_installation", "failed")

    shutil.rmtree(temp_dir)
    return retval

def create_snmptrapd_docker_container(DOCKER_HOST):
    snmptrapd_docker_dict={}
    verify_url(DOCKER_HOST)
    client = docker.DockerClient(base_url=DOCKER_HOST)

    # create the image if not already present
    try: client.images.get(snmptrapd_docker_image_tag)
    except Exception: create_snmptrapd_docker_image(client)

    # start the container
    cont = start_container(client, snmptrapd_docker_image_tag, '22/tcp', '161/udp')
    if cont is None:
        report_env_fail("docker_run", "failed")

    # find the ports
    apic = docker.APIClient(base_url=DOCKER_HOST)
    port_data = apic.inspect_container(cont.id)['NetworkSettings']['Ports']
    snmptrapd_docker_dict['snmptrapd_port'] = port_data['161/udp'][0]["HostPort"]
    snmptrapd_docker_dict['ssh_port'] = port_data['22/tcp'][0]["HostPort"]
    snmptrapd_docker_dict['cont_id'] = cont.id
    snmptrapd_docker_dict['username'] = snmptrapd_username_password[0]
    snmptrapd_docker_dict['password'] = snmptrapd_username_password[1]
    return snmptrapd_docker_dict

def remove_snmptrapd_docker_container(contid, DOCKER_HOST):
    remove_docker_container(contid, DOCKER_HOST)

tacacs_entrypoint = """\
#!/bin/bash
service ssh start
service tacacs_plus start
bash
"""
tacacs_username_password = ['admin','YourPaSsWoRd']

tacacs_dockerfile = r"""
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install openssh-server sudo -y
RUN mkdir -p /run/sshd
RUN ssh-keygen -A
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN useradd -rm -d /home/admin -s /bin/bash -g root -G sudo -u 1000 {0}
RUN echo '{0}:{1}' | chpasswd
RUN service ssh start
EXPOSE 22/tcp
RUN apt update && apt install tacacs+ -y
RUN service tacacs_plus start
EXPOSE 49/tcp
ADD ./startup.sh /startup.sh

ENTRYPOINT ["/startup.sh"]
""".format(tacacs_username_password[0],tacacs_username_password[1])

tacacs_docker_image_tag = "spytest-tacacs:1.0"

def create_tacacs_docker_image(client):
    temp_dir = save_docker_files(tacacs_entrypoint, tacacs_dockerfile)
    src = os.path.join(os.path.dirname(__file__), 'tac_plus.conf')
    utils.copy_file(src, temp_dir)

    try:
        log_info("Building: {}".format(tacacs_docker_image_tag))
        client.images.build(path=temp_dir, tag=tacacs_docker_image_tag)
        retval = True
    except Exception as exp:
        log_exp(exp)
        retval = False
        report_env_fail("docker_image_installation", "failed")

    shutil.rmtree(temp_dir)
    return retval

def create_tacacs_docker_container(DOCKER_HOST):
    tacacs_docker_dict={}
    verify_url(DOCKER_HOST)
    client = docker.DockerClient(base_url=DOCKER_HOST)

    # create the image if not already present
    try: client.images.get(tacacs_docker_image_tag)
    except Exception: create_tacacs_docker_image(client)

    # start the container
    cont = start_container(client, tacacs_docker_image_tag, '22/tcp', '49/tcp')
    if cont is None:
        report_env_fail("docker_run", "failed")

    # find the ports
    apic = docker.APIClient(base_url=DOCKER_HOST)
    port_data = apic.inspect_container(cont.id)['NetworkSettings']['Ports']
    tacacs_docker_dict['tacacs_port'] = port_data['49/tcp'][0]["HostPort"]
    tacacs_docker_dict['ssh_port'] = port_data['22/tcp'][0]["HostPort"]
    tacacs_docker_dict['cont_id'] = cont.id
    tacacs_docker_dict['username'] = tacacs_username_password[0]
    tacacs_docker_dict['password'] = tacacs_username_password[1]
    return tacacs_docker_dict

def remove_tacacs_docker_container(contid, DOCKER_HOST):
    remove_docker_container(contid, DOCKER_HOST)
