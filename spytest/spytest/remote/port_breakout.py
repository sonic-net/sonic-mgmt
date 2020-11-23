#! /usr/bin/python -u

import os
import sys
import re
import getopt
import copy
import json
import shutil
import os.path
import subprocess

SIM_HOST = False

SAI_PROFILE_DELIMITER = '='
INTERFACE_KEY="Ethernet"
NEW_FILE_EXT=""

sonic_platforms = {
    "x86_64-accton_as9716_32d-r0": {
        "breakout": {
            "0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,200,208,216,240,248": [ "1x400", "4x100", "4x50", "2x100", "2x200", "4x25", "4x10" ]
        }
    },
    "x86_64-accton_as7326_56x-r0": {
        "breakout": {
            "48,52,56,60,64,68,72": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-accton_as7712_32x-r0": {
        "breakout": {
            "0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100,104,108,112,116,120,124": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-accton_as7816_64x-r0": {
        "breakout": {
            "0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-accton_as7726_32x-r0": {
        "breakout": {
            "0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100,104,108,112,116,120": [ "4x25", "4x10", "1x100", "1x40" ]
        }
    },
    "x86_64-delta_ag9032v1-r0": {
        "breakout": {
            "0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,96,100,104,108,112,116,120,124": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-quanta_ix4_bwde-r0": {
        "breakout": {
            "128,132,136,140,144,148,152,156,192,196,200,204,208,212,216,220": [
                "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-quanta_ix8_rglbmc-r0": {
        "breakout": {
            "48,52,56,60,64,68,72": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    },
    "x86_64-quanta_ix9_bwde-r0": {
        "breakout": {
             "0,8,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136,144,152,160,168,176,184,192,200,208,216,240,248": [ "1x400", "4x100", "4x25", "4x10", "4x50", "2x200", "2x100" ]
        }
    },
    "x86_64-quanta_ix8a_bwde-r0": {
        "breakout": {
            "48,76": [ "4x10", "4x25", "1x100", "1x40" ]
        }
    }
}

#####################################################################################################
### Platform related code

if not SIM_HOST:
    def get_platform():
        cmd = "cat /host/machine.conf | grep onie_platform | cut -d '=' -f 2"
        pin = subprocess.Popen(cmd,
                               shell=True,
                               close_fds=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        id = pin.communicate()[0]
        id = id.strip()
        return id

    def get_platform_path():
        path = "/usr/share/sonic/platform"
        if os.path.exists(path):
            return path
        path = "/usr/share/sonic/device/" + get_platform()
        return path

    def get_hwsku():
        dir = get_platform_path()
        pin = subprocess.Popen("cat " + dir + "/default_sku | cut -d ' ' -f 1",
                               shell=True,
                               close_fds=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        id = pin.communicate()[0]
        id = id.strip()
        return id


    # run command
    def run_command(command, display_cmd=False, ignore_error=False, print_to_console=True):
        ###
        ### Run bash command and print output to stdout
        ###
        if display_cmd is True:
            print("Running command: " + command)

        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        (out, err) = proc.communicate()

        if len(out) > 0 and print_to_console:
            print(out)

        if proc.returncode != 0 and not ignore_error:
            sys.exit(proc.returncode)

        return out, err

    def get_bcm_file(platform, hwsku):
        sai_profile_kvs = {}

        sai_file = get_platform_path() + "/" + hwsku + "/" + "sai.profile"
        if os.path.exists(sai_file):
            command = "grep SAI_INIT_CONFIG_FILE "+ sai_file
        else:
            command = "sonic-cfggen -d -t " + sai_file + ".j2 | grep SAI_INIT_CONFIG_FILE"
        sai_profile_content, _ = run_command(command, print_to_console=False)

        for line in sai_profile_content.split('\n'):
            if not SAI_PROFILE_DELIMITER in line:
                continue
            key, value = line.split(SAI_PROFILE_DELIMITER)
            sai_profile_kvs[key] = value.strip()

        try:
            sai_xml_path = sai_profile_kvs['SAI_INIT_CONFIG_FILE']
        except KeyError:
            print("Failed to get SAI XML from sai profile")
            sys.exit(1)

        bcm_file = "config.bcm"
        if not SIM_HOST:
            bcm_file = get_platform_path() + "/" + hwsku + "/" + os.path.basename(sai_xml_path)

        return bcm_file

#####################################################################################################

def get_platform_file(platform, hwsku):
    if not SIM_HOST:
        platform_file = get_platform_path() + '/' + hwsku + '/' + "platform.json"
    else:
        platform_file = "platform.json"
    return platform_file

def get_ini_file(platform, hwsku):
    if not SIM_HOST:
        ini_file = get_platform_path() + '/' + hwsku + '/' + "port_config.ini"
    else:
        ini_file = "port_config.ini"
    return ini_file

def get_cfg_file(platform, hwsku):
    if not SIM_HOST:
        cfg_file = "/etc/sonic/config_db.json"
    else:
        cfg_file = "config_db.json"
    return cfg_file

def get_led_file(platform, hwsku):
    if not SIM_HOST:
        led_file = get_platform_path() + "/led_proc_init.soc"
    else:
        led_file = "led_proc_init.soc"
    return led_file

def display_files(platform, hwsku):
    print("BCM File:[%s]" % (get_bcm_file(platform, hwsku)))
    print("INI File:[%s]" % (get_ini_file(platform, hwsku)))
    print("CFG File:[%s]" % (get_cfg_file(platform, hwsku)))

bko_dict_4 = {
    "1x100": { "lanes":4, "speed":100, "step":4, "bko":0, "name": "hundredGigE" },
    "1x40":  { "lanes":4, "speed":40,  "step":4, "bko":0, "name": "fourtyGigE" },
    "4x10":  { "lanes":4, "speed":10,  "step":1, "bko":1, "name": "tenGigE" },
    "4x25":  { "lanes":4, "speed":25,  "step":1, "bko":1, "name": "twentyfiveGigE" },
    "2x10":  { "lanes":2, "speed":10,  "step":1, "bko":1, "name": "tenGigE" },
    "2x25":  { "lanes":2, "speed":25,  "step":1, "bko":1, "name": "twentyfiveGigE" },
}

bko_dict_8 = {
    "1x400": { "lanes":8, "speed":400, "step":8, "bko":0, "name": "fourhundredGigE" },
    "2x200": { "lanes":8, "speed":200, "step":4, "bko":1, "name": "twohundredGigE" },
    "2x100": { "lanes":8, "speed":100, "step":4, "bko":1, "name": "hundredGigE" },
    "4x100": { "lanes":8, "speed":100, "step":2, "bko":1, "name": "hundredGigE" },
    "4x50":  { "lanes":8, "speed":50,  "step":2, "bko":1, "name": "fiftyGigE" },
    "4x25":  { "lanes":4, "speed":25,  "step":1, "bko":1, "name": "twentyfiveGigE" },
    "4x10":  { "lanes":4, "speed":10,  "step":1, "bko":1, "name": "tenGigE" },
}

bko_dict = bko_dict_4

#
#   Get breakout step:
#
def bko_opt_valid(opt):
    if opt in bko_dict:
        return True
    else:
        return False

def get_bkout_step(opt):
    return bko_dict[opt]["step"]

def get_bkout_subport_name(opt):
    return bko_dict[opt]["name"]

def get_bkout_subport_speed(opt):
    return bko_dict[opt]["speed"]

def get_is_bkout(opt):
    return bko_dict[opt]["bko"]

def get_bkout_lanes(opt):
    return bko_dict[opt]["lanes"]

def get_bkout_ports(port, opt):
    lanes = 4
    step  = 1

    if not port.startswith(INTERFACE_KEY):
        return None

    idx   = port.split()[0].split(INTERFACE_KEY,1)[1]
    if not idx.isdigit():
        return None

    ports = []
    for i in range(0, lanes, step):
        portx = INTERFACE_KEY + str(int(idx) + (i/step))
        ports.append(portx)
    return ports


#
#   Breakout a port in INI file:
#   Ethernet48       81,82,83,84           hundredGigE13

#   Change to
#   Ethernet48       81           twentyfiveGigE13:1
#   Ethernet49       82           twentyfiveGigE13:2
#   Ethernet50       83           twentyfiveGigE13:3
#   Ethernet51       84           twentyfiveGigE13:4

#
#   Ethernet48      81,82,83,84           hundredGigE13
#   return:
#      "48"
#      ["81", "82", "83", "84"]
#      "hundredGigE"
#      "13"


def get_info_in_ini(line, title):
    idx = line.split()[0].split(INTERFACE_KEY,1)[1]
    lanes = line.split()[1].split(",")
    name = line.split()[2]
    temp = name.split(":")[0]
    porti = re.sub('.*?([0-9]*)$',r'\1', temp)

    if "index" in title:
        fp_idx = int(line.split()[title.index("index")])
    else:
        fp_idx = None
    return idx, lanes, name, porti, fp_idx

def break_in_ini(port, ini_file, opt):
    print("Breaking port %s to %s in ini ..." % (port, opt))

    bak_file = ini_file + ".bak"
    shutil.copy(ini_file, bak_file)

    new_file = ini_file + NEW_FILE_EXT
    step = get_bkout_step(opt)

    f_in = open(bak_file, 'r')
    f_out = open(new_file, 'w')

    first_port = True
    title = []

    done = False
    for line in f_in.readlines():
        line.strip()
        if len(line.rstrip()) == 0:
            continue

        if re.search("^#", line) is not None:
            # The current format is: # name lanes alias index speed
            # Where the ordering of the columns can vary
            if len(title) == 0:
                title = line.split()[1:]
                print(title)
            f_out.write(line)
            continue

        line = line.lstrip()
        line_port = line.split()[0]

        if line_port in get_bkout_ports(port, opt):
            if done:
                f_out.write(line)
                continue
            done = True
            oidx, olanes, _, oporti, fp_idx = get_info_in_ini(line, title)

            if get_is_bkout(opt) and len(olanes) < get_bkout_lanes(opt):
                print("Port %s Already breakout ..." % (port))
                print("Existing ...")
                f_in.close()
                f_out.close()
                shutil.copy(bak_file, new_file)

                sys.exit()

            #
            # Non-Breakout case
            #
            if not get_is_bkout(opt) and not first_port:
                print("--- {} removed".format(line_port))
                continue

            if not get_is_bkout(opt) and first_port:
                idx = oidx
                lanes = []
                for i in range(0, get_bkout_lanes(opt), 1):
                    lanes.append(str(int(olanes[0])+i))
                porti = oporti

            if get_is_bkout(opt):
                idx = oidx
                lanes = olanes
                porti = oporti

            #
            # original string:
            # Ethernet20      69,70,71,72           hundredGigE6
            #
            print("    %s" % line.rstrip())

            # Generate new interface line
            for i in range(0, min(len(lanes), get_bkout_lanes(opt)), step):
                #
                # Ethernet20
                #
                temp_str = "Ethernet%d" % (int(idx) + (i/step))
                new_intf = "%-15s " % temp_str

                temp_str = lanes[i+0]
                #
                # generate  69
                #
                for j in range(1, step):
                    temp_str += ",%s" % (lanes[i+j])
                new_intf += "%-21s " % temp_str

                #
                # Generate twentyfiveGigE6:i
                #
                if get_is_bkout(opt):
                    temp_str = "%s%s:%d" % (get_bkout_subport_name(opt), porti, (i/step + 1))
                else:
                    temp_str = "%s%s" % (get_bkout_subport_name(opt), porti)

                new_intf += "%-19s " % temp_str

                #
                # index
                #
                if fp_idx is not None:
                    temp_str = "%d" % (fp_idx)
                    new_intf += "%-6s " % temp_str


                #
                # speed
                #
                temp_str = "%d000" % get_bkout_subport_speed(opt)
                new_intf += "%-10s " % temp_str

                #
                # valid_speeds
                #
                if 'valid_speeds' in title:
                    temp_str = str(get_bkout_subport_speed(opt) * 1000)
                    if get_bkout_subport_speed(opt) == 100:
                        if get_bkout_step(opt) == 4:
                            # NRZ mode
                            temp_str = "100000,40000"
                        else:
                            # PAM4 mode
                            temp_str = "100000"
                    elif get_bkout_subport_speed(opt) == 40:
                        temp_str = "100000,40000"

                    new_intf += "%s" % temp_str


                if not get_is_bkout(opt) and first_port:
                    print("===>" + new_intf)
                    new_intf += "\n"
                    f_out.write(new_intf)
                    first_port = False
                if get_is_bkout(opt):
                    print("===>" + new_intf)
                    new_intf += "\n"
                    f_out.write(new_intf)

        else:
            f_out.write(line)

    print("--------------------------------------------------------")
    f_in.close()
    f_out.close()

    print(lanes)
    return lanes

#
# Parse logic port, phyical port, speed from bcm
#
def parse_port_bcm(bcm_str):
    lp = bcm_str.split("=")[0].split("_")[1]
    pp = bcm_str.split("=")[1].split(":")[0]
    sp = bcm_str.split("=")[1].split(":")[1]

    return lp, pp, sp

#
# portmap_84=81:100
#
# portmap_84=81:25
# portmap_85=82:25
# portmap_86=83:25
# portmap_87=84:25
#
#
def break_in_bcm(port, lanes, bcm_file, opt, platform):
    print("Breaking %s to %s in bcm ..." % (port, opt))

    bak_file = bcm_file + ".bak"
    shutil.copy(bcm_file, bak_file)

    new_file = bcm_file + NEW_FILE_EXT
    step = get_bkout_step(opt)

    f_in = open(bak_file, 'r')
    f_out = open(new_file, 'w')

    first_port = True
    print(lanes)
    for oline in f_in.readlines():
        line = oline.lstrip()

        if line.startswith('#'):
            f_out.write(oline)
            continue

        if not line.startswith("portmap"):
            f_out.write(oline)
            continue

        ### logic port, phyical port, speed
        lp, pp, _ =  parse_port_bcm(line)
        if pp not in lanes:
            f_out.write(oline)
            continue

        if not get_is_bkout(opt) and not first_port:
            print("--- portmap_{} removed".format(lp))
            continue

        #### generate new port map
        print("    %s" % line.rstrip())
        for i in range(0, min(len(lanes), get_bkout_lanes(opt)), step):
            if '.' in lp:
                nlp = lp.split('.')[0]
                unit = lp.split('.')[1]
                new_intf = "portmap_%d.%s=%d:%d:%d" % ((int(nlp) + (i / step)), unit, (int(pp)+i), get_bkout_subport_speed(opt), get_bkout_step(opt))
            else:
                new_intf = "portmap_%d=%d:%d:%d" % ((int(lp) + (i / step)), (int(pp)+i), get_bkout_subport_speed(opt), get_bkout_step(opt))

            if not get_is_bkout(opt) and first_port:
                f_out.write(new_intf)
                f_out.write("\n")
                print("===>" + new_intf)
                first_port = False
            if get_is_bkout(opt):
                f_out.write(new_intf)
                f_out.write("\n")
                print("===>" + new_intf)

    print("--------------------------------------------------------")
    f_in.close()
    f_out.close()

#
# breakout ports in json file
#
def break_in_cfg(port, cfg_file, lanes, opt, platform):
    if not os.access(os.path.dirname(cfg_file), os.W_OK):
        print("Skipping config_db.json updates for a write permission issue")
        return

    step = get_bkout_step(opt)
    print("Breaking %s to %s in cfg ... " % (port, opt))

    bak_file = cfg_file + ".bak"
    shutil.copy(cfg_file, bak_file)

    new_file = cfg_file + NEW_FILE_EXT

    with open(bak_file) as f:
        data = json.load(f)

    with open(cfg_file, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=True)

    ###
    ### Process in 'INTERFACE'
    ###
    if 'INTERFACE' in data:
        for key, _ in sorted(data['INTERFACE'].items()):
            pkey = key.split('|')[0]
            if port == pkey:
                data['INTERFACE'].pop(key)

    ###
    ### Process in 'PORT'


    ### remove port instance in data
    ###
    idx = 0
    ports = get_bkout_ports(port, opt)
    for x in ports:
        if idx >= get_bkout_lanes(opt):
            break
        idx += 1
        if data['PORT'].get(x) != None:
            port_instance = data['PORT'].get(x)
            data['PORT'].pop(x)
            print("    ", x, port_instance)

    idx = port.split()[0].split(INTERFACE_KEY,1)[1]
    porti = re.sub('.*?([0-9]*)$',r'\1', port_instance['alias'].split(":")[0])

    for i in range(0, min(len(lanes), get_bkout_lanes(opt)), step):

        if get_is_bkout(opt):
            temp_str = lanes[i]
            for j in range(1, step):
                temp_str += ",%s" % (lanes[i+j])
            port_instance['lanes'] = temp_str
            port_instance['alias'] = get_bkout_subport_name(opt) + porti + ':' + str(i/step + 1)
        else:
            port_instance['alias'] = get_bkout_subport_name(opt) + porti
            port_instance['lanes'] = ','.join(str(e) for e in lanes)

        port_instance['speed'] = str(get_bkout_subport_speed(opt)) + "000"
        port_instance['valid_speeds'] = str(get_bkout_subport_speed(opt)) + "000"

        if platform == "x86_64-accton_as9716_32d-r0" or platform == "x86_64-quanta_ix9_bwde-r0":
            # 200G PAM4: fec rs
            # 100G PAM4: fec rs
            # 100G  NRZ: fec none
            if get_bkout_subport_speed(opt) >= 200:
                port_instance['fec'] = 'rs'
            elif get_bkout_subport_speed(opt) == 100:
                if step == 2:
                    port_instance['fec'] = 'rs'
                else:
                    port_instance['fec'] = 'none'

        new_port = INTERFACE_KEY + str(int(idx) + (i/step))
        xxx = copy.deepcopy(port_instance)
        data['PORT'][new_port] = xxx
        ### print data['PORT'][new_port]

    for i in range(0, min(len(lanes), get_bkout_lanes(opt)), step):
        new_port = INTERFACE_KEY + str(int(idx) + (i/step))
        print("===>", new_port, data['PORT'][new_port])

    with open(new_file, 'w') as outfile:
        json.dump(data, outfile, indent=4, sort_keys=True)

    print("--------------------------------------------------------")

def break_a_port(port, opt, platform, hwsku):
    ini_file = get_ini_file(platform, hwsku)
    bcm_file = get_bcm_file(platform, hwsku)
    cfg_file = get_cfg_file(platform, hwsku)

    lanes = break_in_ini(port, ini_file, opt)
    break_in_bcm(port, lanes, bcm_file, opt, platform)
    break_in_cfg(port, cfg_file, lanes, opt, platform)

def usage():
    print("Usage: " + sys.argv[0] + " interface 4x100|4x25")
    print("Breakout None-breaokout a port")
    print("Options:")
    print("  -p port")
    print("  -o breakout option")
    for k in bko_dict:
        print("         %s" % k)
    print("   ")
    print("Example:")
    print("  Breakout port Ethernet4 to 4x10G")
    print("    %s -p Ethernet4 -o 4x10" % (sys.argv[0]))
    print("  None-Breakout port Ethernet4 to 40G")
    print("    %s -p Ethernet4 -o 1x40" % (sys.argv[0]))
    print("   ")
    print("Note:")
    print("  Make sure understand which ports are able to breakout before execute command.")
    print("  Make backup below config files")
    print("  - /usr/share/sonic/device/[platform]/[hwsku]/[config.bcm]")
    print("  - /usr/share/sonic/device/[platform]/[hwsku]/port_config.ini")
    print("  - /etc/sonic/config_db.json")

    sys.exit(1)

def platform_checking(platform, hwsku, port, opt):
    #
    # default allow breakout ports on any platforms and ports
    #
    rc = True

    platform_file = get_platform_file(platform, hwsku)
    if os.path.exists(platform_file):
        print("Dynamic Port Breakout is enable for this platform...")
        print("Can not use port_breakout.py ...")
        return False

    if not port.startswith(INTERFACE_KEY):
        print("Wrong port name %s ..." % (port))
        return False


    if platform in sonic_platforms and 'breakout' in sonic_platforms[platform]:
        idx   = port.split()[0].split(INTERFACE_KEY,1)[1]
        for keys in sonic_platforms[platform]['breakout']:
            if idx in keys.split(',') and opt in sonic_platforms[platform]['breakout'][keys]:
                print("Breakout port %s to %s in platform %s is allowed." % (port, opt, platform))
                return True
            else:
                print("Error: Breakout port %s to %s in platform %s is NOT allowed !!!" % (port, opt, platform))
                rc = False


    #
    # Platforms not in sonic_platforms, or not defined 'breakout'
    #
    if rc is True:
        print("Warnning:")
        print("Breakout port on platform %s is dangerous !!!" % (platform))
        print("Please double-check make sure port %s can be configured to %s" % (port, opt))

    return rc

#
# check breakout option valid
#       configure files existing
#
def check_vaildation(platform, hwsku, port, opt):

    ini_file = get_ini_file(platform, hwsku)

    ports =  get_bkout_ports(port, opt)
    if ports is None:
        print("Wrong interface name:%s" % (port))
        return False

    ### need re-visit
    idx   = port.split()[0].split(INTERFACE_KEY,1)[1]

    if  int(idx) % (get_bkout_lanes(opt) / get_bkout_step(opt)) != 0:
        print("Can not work on port:%s" % (port))
        return False

    f_in = open(ini_file, 'r')

    ini_ports = []
    ini_lanes = []
    port_found = 0
    title = []

    for line in f_in.readlines():
        line = line.lstrip()
        line = line.strip()
        if len(line) == 0:
            continue

        if re.search("^#", line) is not None:
            # The current format is: # name lanes alias index speed
            # Where the ordering of the columns can vary
            title = line.split()[1:]
            continue


        line_port = line.split()[0]

        ### Check breakout case
        if get_is_bkout(opt):
            if line_port == port:
                port_found += 1
                _, olanes, _, _, _ = get_info_in_ini(line, title)
                if len(olanes) < get_bkout_lanes(opt):
                    print("port %s can not breakout to %s." % (port, opt))
                    f_in.close()
                    return False
        else:
            if line_port in ports:
                port_found += 1
                _, olanes, _, _, _ = get_info_in_ini(line, title)
                ini_ports.append(line_port)
                ini_lanes += olanes

    f_in.close()

    if get_is_bkout(opt) and port_found != 1:
        if port_found == 0:
            print("port %s does not exist." % (port))
        if port_found > 1:
            print("Duplicate(%d) port %s found in INI file." % (port_found, port))
        return False

    if not get_is_bkout(opt):
        if len(ini_lanes) == 0:
            print("port %s does not exist." % (port))
            return False

    return True


def process_args(argv):
    verbose = 0
    cust = "./cust_platform.json"
    list = False
    port = None
    opt = None

    try:
        opts, _ = getopt.getopt(argv, "hlvc:p:o:", \
        ["help", "list", "verbose", "cust=", "port=", "opt="])

        for opt,arg in opts:
            if opt in ('-h','--help'):
                usage()
                return
            if opt in ('-l', '--list'):
                list = True
            if opt in ('-v', '--verbose'):
                verbose = 1
            if opt in ('-c', '--cust'):
                cust = arg
            if opt in ('-p', '--port'):
                port = arg
            if opt in ('-o', '--option'):
                opt = arg
    except getopt.GetoptError:
        print("Error: Invalid option")
        sys.exit(1)

    #print("# Custom Platform JSON: {}".format(cust))
    if os.path.isfile(cust):
        print("# Custom Platform JSON detected, merging the platform info...")
        try:
            with open(cust) as fp:
                sonic_platforms.update(json.load(fp))
        except Exception:
            pass
    else:
        print("# Custom Platform JSON not found")

    if list is True:
        print("Supported platform list:")
        for plat in sonic_platforms:
            print("* {}".format(plat))
        sys.exit(0)

    if port is None or opt is None:
        print("Error: must give -p [port] and -o [option]")

        usage()
        sys.exit(1)

    return verbose, port, opt

### Breakout interface
def main(argv):
    global bko_dict

    if len(argv) > 0 and argv[0] == "-h":
        usage()
        return

    _, port, opt = process_args(argv)
    """
    print verbose, port, opt
    """

    if not SIM_HOST:
        platform = get_platform()
        hwsku = get_hwsku()
    else:
        platform = 'xxx'
        hwsku = 'yyy'

    bcm_file = get_bcm_file(platform, hwsku)
    if "th3" in bcm_file:
        bko_dict = bko_dict_8
    else:
        bko_dict = bko_dict_4

    if not bko_opt_valid(opt):
        print("Invalid breakout option :%s" % (opt))
        print("Supported breakout option :%s" % (list(bko_dict.keys())))
        return

    """
    print("Platform=[%s]" % (platform))
    print("hwsku=[%s]" % (hwsku))
    display_files(platform, hwsku)
    """

    if platform_checking(platform, hwsku, port, opt) is False:
        return

    if check_vaildation(platform, hwsku, port, opt) is False:
        print("breakout options checking failed.")
        return

    break_a_port(port, opt, platform, hwsku)

    ### disable pre-emphasis workaround in 'led_proc_init.soc'
    #file = get_led_file(platform, hwsku)
    #if os.path.exists(file):
    #    run_command("sed -i 's/^rcload/#rcload/g' " + file)

if __name__ == "__main__":
    main(sys.argv[1:])

