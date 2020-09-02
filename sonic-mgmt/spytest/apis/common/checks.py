
from spytest import st, tgapi, tgapi
import utilities.common as utils
import apis.system.port as portapi

def log_info(fmt, *args):
    st.log(fmt % args)

def warn(fmt, *args):
    st.warn(fmt % args)

def trace(dut, local, partner, remote, status):
    #print(dut, local, partner, remote, status)
    pass

def wait():
  st.wait(5)

def check_status(s1, s2, s3, s4):
    #print(s1, s2, s3, s4)
    if not s1 or not s3:
        return False
    if s1.lower() != s2.lower():
        return False
    if s3.lower() != s4.lower():
        return False
    return True

def get_link_status(tg, ph):
    return tg.tg_interface_control(mode="check_link", desired_status='up',
                                   port_handle=ph)

def verify_topology(check_type, threads=True):
    if check_type in ["status", "status2", "status3", "status4"]:
        return links_status(threads, check_type)

    retval = True
    results = []
    header = ['DUT', 'Local', "Partner", "Remote", "Status"]
    check_oneway = True
    exclude = []
    for dut in st.get_dut_names():
        alias = st.get_device_alias(dut)
        for local, partner, remote in st.get_dut_links(dut):
            palias = st.get_device_alias(partner)

            # check if the port is verified from other direction
            skip = False
            for ex in exclude:
                #print("CMP", dut, local, ex[0], ex[1])
                if dut == ex[0] and local == ex[1]:
                    skip = True
                    break
            if skip:
                log_info("{}/{} is already verified".format(alias, local))
                continue

            result = [alias, local, palias, remote, "Fail"]

            # shutdown local link and get remote link stats in partner
            portapi.shutdown(dut, [local])
            wait()
            status1 = portapi.get_interface_status(partner, remote)
            trace(alias, local, palias, remote, status1)

            # noshutdown local link and get remote link stats in partner
            portapi.noshutdown(dut, [local])
            wait()
            status2 = portapi.get_interface_status(partner, remote)
            trace(alias, local, palias, remote, status2)

            # log the result on fail
            if not check_status(status1, "down", status2, "up"):
                warn("1. port %s/%s is not connected to %s/%s\n",
                     alias, local, palias, remote)
                results.append(result)
                exclude.append([partner, remote])
                retval = False
                continue

            if not check_oneway:
                # shutdown remote link and get local link status
                portapi.shutdown(partner, [remote])
                wait()
                status3 = portapi.get_interface_status(dut, local)
                trace(alias, local, palias, remote, status3)

                # noshutdown remote link and get local link status
                portapi.noshutdown(partner, [remote])
                wait()
                status4 = portapi.get_interface_status(dut, local)
                trace(alias, local, palias, remote, status4)

                # log the result on fail
                if not check_status(status3, "down", status4, "up"):
                    warn("2. port %s/%s is not connected to %s/%s\n",
                         alias, local, palias, remote)
                    results.append(result)
                    retval = False
                    continue

            # log the result on pass
            result[4] = "OK"
            results.append(result)
            exclude.append([partner, remote])

        for local, partner, remote in st.get_tg_links(dut):
            palias = st.get_device_alias(partner)
            (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=remote)

            result = [alias, local, palias, remote, "Fail"]

            tgen_link_status_supported = False
            if tgen_link_status_supported:
                # shutdown local link and get remote link stats in partner
                portapi.shutdown(dut, [local])
                wait()
                status1 = get_link_status(tg, ph)
                trace(alias, local, palias, remote, status1)

                # no shutdown local link and get remote link stats in partner
                portapi.noshutdown(dut, [local])
                wait()
                status2 = get_link_status(tg, ph)
                trace(alias, local, palias, remote, status2)

                # log the result on fail
                if tgen_link_status_supported and (status1 or not status2):
                    warn("3. port %s/%s is not connected to %s/%s\n",
                         alias, local, palias, remote)
                    results.append(result)
                    retval = False
                    continue

            # shutdown remote link and get local link status
            tg.tg_interface_control(mode="break_link", port_handle=ph)
            wait()
            status3 = portapi.get_interface_status(dut, local)
            trace(alias, local, palias, remote, status3)

            # noshutdown remote link and get local link status
            tg.tg_interface_control(mode="restore_link", port_handle=ph)
            wait()
            status4 = portapi.get_interface_status(dut, local)
            trace(alias, local, palias, remote, status4)

            # log the result on fail
            if not check_status(status3, "down", status4, "up"):
                warn("4. port %s/%s is not connected to %s/%s\n",
                     alias, local, palias, remote)
                results.append(result)
                retval = False
                continue

            # log the result on pass
            result[4] = "OK"
            results.append(result)

    return [retval, header, results]

def fill_alias():
    alias = dict()
    for dut in st.get_dut_names():
        alias[dut] = st.get_device_alias(dut)
    for tg in st.get_tg_names():
        alias[tg] = st.get_device_alias(tg)
    return alias

def links_status(threads, check_type):
    header = ['DUT', 'Local', "LStatus (A/O)", "Partner", "Remote", "RStatus (A/O)"]
    funcs = [
        [tg_links_status, check_type],
        [duts_links_status, threads]
    ]
    [[v1, v2], [e1, e2]] = utils.exec_all(threads, funcs, True)
    if v1 is None or v2 is None or e1 is not None or e2 is not None:
        print(v1, v2, e1, e2)
        return [True, header, []]

    v1_default = "?2?" if v1 else "NA"
    (results, exclude, alias) = ([], [], fill_alias())
    for dut in st.get_dut_names():
        for local, partner, remote in st.get_tg_links(dut):
            res = []
            res.append(alias.get(dut, "?"))
            res.append(local)
            res.append(v2.get("{}--{}".format(dut, local), "?1?"))
            res.append(alias.get(partner, "?"))
            res.append(remote)
            res.append(v1.get("{}--{}".format(partner, remote), v1_default))
            results.append(res)
        for local, partner, remote in st.get_dut_links(dut):
            name = "{}--{}".format(dut, local)
            if name in exclude:
                continue
            res = []
            res.append(alias.get(dut, "?"))
            res.append(local)
            res.append(v2.get("{}--{}".format(dut, local), "?3?"))
            res.append(alias.get(partner, "?"))
            res.append(remote)
            res.append(v2.get("{}--{}".format(partner, remote), "?4?"))
            exclude.append("{}--{}".format(partner, remote))
            results.append(res)
    return [True, header, results]

def tg_links_status_1():
    results = dict()
    for dut in st.get_dut_names():
        for local, partner, remote in st.get_tg_links(dut):
            (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=remote)
            name = "{}--{}".format(partner, remote)
            results[name] = get_link_status(tg, ph)
    return results

def tg_links_status_0():
    # build port list per tgen
    tg_port_dict = {}
    for dut in st.get_dut_names():
        for local, partner, remote in st.get_tg_links(dut):
            tg_port_dict.setdefault(partner, []).append(remote)

    results = dict()
    for partner, port_list in tg_port_dict.items():
        # get tgen handle using first port
        (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=port_list[0])
        # get all ports status
        rv = tg.get_port_status(port_list)
        # fill the results
        for port in port_list:
            name = "{}--{}".format(partner, port)
            results[name] = rv[port]

    return results

def tg_links_status(check_type):
    if check_type in ["status3"]:
        return dict()
    try:
        return tg_links_status_0()
    except:
        return tg_links_status_1()

def duts_links_status(threads):
    results = dict()
    [rvs, exs] = utils.exec_foreach(threads, st.get_dut_names(), dut_links_status)
    for rv in rvs:
        if rv:
            results.update(rv)
    return results

def dut_links_status(dut):
    local_list = []
    for local, partner, remote in st.get_dut_links(dut):
        local_list.append(local)
    for local, partner, remote in st.get_tg_links(dut):
        local_list.append(local)
    output = portapi.get_status(dut, ",".join(local_list))

    results = dict()
    for local, partner, remote in st.get_dut_links(dut):
        match = {"interface": local}
        entries = utils.filter_and_select(output, ["admin","oper"], match)
        name = "{}--{}".format(dut, local)
        if entries:
            results[name] = "{}/{}".format(entries[0]["admin"], entries[0]["oper"])
        else:
            results[name] = "----"
    for local, partner, remote in st.get_tg_links(dut):
        match = {"interface": local}
        entries = utils.filter_and_select(output, ["admin","oper"], match)
        name = "{}--{}".format(dut, local)
        if entries:
            results[name] = "{}/{}".format(entries[0]["admin"], entries[0]["oper"])
        else:
            results[name] = "----"
    return results

