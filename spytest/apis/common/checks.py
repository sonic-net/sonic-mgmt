from random import randint
from spytest import st, tgapi, putils
import utilities.common as utils

tgen_link_status_supported = False
check_oneway = True


def log_info(fmt, *args):
    st.log(fmt % args)


def warn(fmt, *args):
    st.warn(fmt % args)


def trace(dut, did, local, partner, pdid, remote, status):
    # print(dut, did, local, partner, pdid, remote, status)
    pass


def wait():
    st.wait(5)


def check_status(s1, s2, s3, s4):
    # print(s1, s2, s3, s4)
    if not s1 or not s3:
        return False
    if s1.lower() != s2.lower():
        return False
    if s3.lower() != s4.lower():
        return False
    return True

# show-alias,tg-port-status,simulate-fail,tg-ports,dut-ports


def check_option(optname):
    default = "dut-ports,tg-ports"
    csv = st.getenv("SPYTEST_TOPOLOGY_OPTIONS", default)
    return bool(optname in utils.csv2list(csv))


def get_tg_link_status(tg, ph):
    return tg.tg_interface_control(mode="check_link", desired_status='up',
                                   port_handle=ph)


def get_tg_links(dut):
    ifname_type = st.get_ifname_type(dut)
    use_native = None if ifname_type in ["std-ext"] else True
    return st.get_tg_links(dut, native=use_native)


def get_dut_links(dut):
    ifname_type = st.get_ifname_type(dut)
    use_native = None if ifname_type in ["std-ext"] else True
    return st.get_dut_links(dut, native=use_native)


def get_dut_links_local(dut):
    ifname_type = st.get_ifname_type(dut)
    use_native = None if ifname_type in ["std-ext"] else True
    return st.get_dut_links_local(dut, native=use_native)


def fill_dev_ids():
    dids, palias = {}, {}
    for dut in st.get_dut_names():
        dids[dut] = st.get_device_alias(dut, True, True)
        palias[dut] = {}
        links = get_dut_links_local(dut)
        onames = st.get_other_names(dut, links)
        for index, local in enumerate(links):
            palias[dut][local] = onames[index]
    for tg in st.get_tg_names():
        dids[tg] = st.get_device_alias(tg, True, True)
    return dids, palias


def verify_topology(hooks, check_type, threads=True, skip_tgen=False):
    if check_type in ["module", "function"]:
        return links_status(hooks, threads, check_type, skip_tgen)

    retval = True
    results, exclude = [], []
    header = ['DUT', 'DId', 'Local', "Partner", "PDId", "Remote", "Status"]
    dids, _ = fill_dev_ids()
    for dut in st.get_dut_names():
        did = dids[dut]
        for local, partner, remote in get_dut_links(dut):
            pdid = dids[partner]

            # check if the port is verified from other direction
            skip = False
            for ex in exclude:
                # print("CMP", dut, local, ex[0], ex[1])
                if dut == ex[0] and local == ex[1]:
                    skip = True
                    break
            if skip:
                log_info("{}({})/{} is already verified".format(dut, did, local))
                continue

            result = [dut, did, local, partner, pdid, remote, "Fail"]

            # shutdown local link and get remote link stats in partner
            hooks.shutdown(dut, [local])
            wait()
            status1 = read_oper_status(partner, hooks, remote)
            trace(dut, did, local, partner, pdid, remote, status1)

            # noshutdown local link and get remote link stats in partner
            hooks.noshutdown(dut, [local])
            wait()
            status2 = read_oper_status(partner, hooks, remote)
            trace(dut, did, local, partner, pdid, remote, status2)

            # log the result on fail
            if not check_status(status1, "down", status2, "up"):
                warn("1. port %s(%s)/%s is not connected to %s(%s)/%s\n",
                     dut, did, local, partner, pdid, remote)
                results.append(result)
                exclude.append([partner, remote])
                retval = False
                continue

            if not check_oneway:
                # shutdown remote link and get local link status
                hooks.shutdown(partner, [remote])
                wait()
                status3 = read_oper_status(dut, hooks, local)
                trace(dut, did, local, partner, pdid, remote, status3)

                # noshutdown remote link and get local link status
                hooks.noshutdown(partner, [remote])
                wait()
                status4 = read_oper_status(dut, hooks, local)
                trace(dut, did, local, partner, pdid, remote, status4)

                # log the result on fail
                if not check_status(status3, "down", status4, "up"):
                    warn("2. port %s(%s)/%s is not connected to %s(%s)/%s\n",
                         dut, did, local, partner, pdid, remote)
                    results.append(result)
                    retval = False
                    continue

            # log the result on pass
            result[6] = "OK"
            results.append(result)
            exclude.append([partner, remote])

        for local, partner, remote in get_tg_links(dut):
            if skip_tgen:
                continue
            pdid = dids[partner]
            (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=remote)

            result = [dut, did, local, partner, pdid, remote, "Fail"]

            if tg.tg_type in ["scapy"]:
                result[6] = "OK"
                results.append(result)
                continue

            if tgen_link_status_supported:
                # shutdown local link and get remote link stats in partner
                hooks.shutdown(dut, [local])
                wait()
                status1 = get_tg_link_status(tg, ph)
                trace(dut, did, local, partner, pdid, remote, status1)

                # no shutdown local link and get remote link stats in partner
                hooks.noshutdown(dut, [local])
                wait()
                status2 = get_tg_link_status(tg, ph)
                trace(dut, did, local, partner, pdid, remote, status2)

                # log the result on fail
                if tgen_link_status_supported and (status1 or not status2):
                    warn("3. port %s(%s)/%s is not connected to %s/%s(%s)\n",
                         dut, did, local, partner, pdid, remote)
                    results.append(result)
                    retval = False
                    continue

            # shutdown remote link and get local link status
            tg.tg_interface_control(mode="break_link", port_handle=ph)
            wait()
            status3 = read_oper_status(dut, hooks, local)
            trace(dut, did, local, partner, pdid, remote, status3)

            # noshutdown remote link and get local link status
            tg.tg_interface_control(mode="restore_link", port_handle=ph)
            wait()
            status4 = read_oper_status(dut, hooks, local)
            trace(dut, did, local, partner, pdid, remote, status4)

            # log the result on fail
            if not check_status(status3, "down", status4, "up"):
                warn("4. port %s(%s)/%s is not connected to %s/%s(%s)\n",
                     dut, did, local, partner, pdid, remote)
                results.append(result)
                retval = False
                continue

            # log the result on pass
            result[6] = "OK"
            results.append(result)

    return [retval, header, results, False, False]


def links_status(hooks, threads, check_type, skip_tgen):
    header = ['DUT', 'DId', 'Local', "LStatus (A/O)", "Partner", 'PDId', "Remote", "RStatus (A/O)"]
    funcs = [
        [tg_links_status, check_type],
        [duts_links_status, hooks, threads, skip_tgen]
    ]

    show_alias = check_option("show-alias")
    if show_alias:
        header.insert(3, "LAlias")
        header.insert(8, "RAlias")

    # st.fail during ctrl+c or prompt not found scenarios, is causing issues.
    # To avoid that below code block should be in try-except only.
    try:
        [v1, [v2, seen_exp]], [e1, e2] = putils.exec_all2(threads, "trace", funcs, True)[:2]
        if v1 is None or v2 is None or e1 is not None or e2 is not None or seen_exp:
            print("links_status", v1, v2, e1, e2, seen_exp)
            return [True, header, [], True, show_alias]
    except Exception:
        print("Observed exception during the thread call return handling")
        return [True, header, [], True, show_alias]

    v1_default = "?2?" if v1 else "NA"
    results, exclude, (dids, palias) = [], [], fill_dev_ids()
    for dut in st.get_dut_names():
        for local, partner, remote in get_tg_links(dut):
            if skip_tgen:
                continue
            res = []
            res.append(dut)
            res.append(dids.get(dut, "?"))
            res.append(local)
            if show_alias:
                res.append(palias.get(local, local))
            default = "?1?" if check_option("tg-ports") else "NA"
            res.append(v2.get("{}--{}".format(dut, local), default))
            res.append(partner)
            res.append(dids.get(partner, "?"))
            res.append(remote)
            if show_alias:
                res.append(palias.get(remote, remote))
            res.append(v1.get("{}--{}".format(partner, remote), v1_default))
            results.append(res)
        for local, partner, remote in get_dut_links(dut):
            name = "{}--{}".format(dut, local)
            if name in exclude:
                continue
            res = []
            res.append(dut)
            res.append(dids.get(dut, "?"))
            res.append(local)
            if show_alias:
                res.append(palias.get(local, local))
            default = "?3?" if check_option("dut-ports") else "NA"
            res.append(v2.get("{}--{}".format(dut, local), default))
            res.append(partner)
            res.append(dids.get(partner, "?"))
            res.append(remote)
            if show_alias:
                res.append(palias.get(remote, remote))
            default = "?4?" if check_option("dut-ports") else "NA"
            if "{}--{}".format(partner, remote) not in v2:
                st.debug("{}--{} not found".format(partner, remote))
                st.debug(v2)
            res.append(v2.get("{}--{}".format(partner, remote), default))
            exclude.append("{}--{}".format(partner, remote))
            results.append(res)
    return [True, header, results, False, show_alias]


def tg_links_status_using_hltapi():
    results = dict()
    for dut in st.get_dut_names():
        for _, partner, remote in get_tg_links(dut):
            (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=remote)
            name = "{}--{}".format(partner, remote)
            results[name] = get_tg_link_status(tg, ph)
    return results


def tg_links_status_using_native_calls():
    # build port list per tgen
    tg_port_dict = {}
    for dut in st.get_dut_names():
        for _, partner, remote in get_tg_links(dut):
            tg_port_dict.setdefault(partner, []).append(remote)

    results = dict()
    for partner, port_list in tg_port_dict.items():
        # get tgen handle using first port
        (tg, _) = tgapi.get_handle_byname(None, tg=partner, port=port_list[0])
        # get all ports status
        rv = tg.get_port_status(port_list)
        # fill the results
        for port in port_list:
            name = "{}--{}".format(partner, port)
            results[name] = rv[port]

    return results


def tg_links_status(check_type):
    if not check_option("tg-port-status"):
        # avoid checking TGEN status for faster execution
        if check_type in ["module", "function"]:
            return dict()
    try:
        return tg_links_status_using_native_calls()
    except Exception:
        return tg_links_status_using_hltapi()


def duts_links_status(hooks, threads, skip_tgen):
    results = dict()
    rvs, exps = putils.exec_foreach2(threads, "trace", st.get_dut_names(), dut_links_status, hooks, skip_tgen)[:2]
    for rv in rvs:
        if rv:
            results.update(rv)
    return results, any(exps)


def simulate_link_fail():
    if not check_option("simulate-fail"):
        return False
    return bool(randint(0, 100) > 90)


def build_dut_local_links(dut, skip_tgen):
    local_list = []
    for local, _, _ in get_dut_links(dut):
        if check_option("dut-ports"):
            local_list.append(local)
    for local, _, _ in get_tg_links(dut):
        if check_option("tg-ports") and not skip_tgen:
            local_list.append(local)
    return local_list


def _parse_link_status(output, port_list):
    full, retval = True, {}
    for local in port_list:
        entries = utils.filter_and_select(output, None, {"interface": local})
        if not entries:
            entries = utils.filter_and_select(output, None, {"altname": local})
        if not entries:
            entries = utils.filter_and_select(output, None, {"alias": local})
        if entries:
            retval[local] = entries[0]
            retval[entries[0].get("interface", local)] = entries[0]
            retval[entries[0].get("altname", local)] = entries[0]
            retval[entries[0].get("alias", local)] = entries[0]
        else:
            full = False
    return full, retval


def _read_links_status(dut, hooks, port_list):
    retval = {}
    if port_list:
        output = hooks.get_status(dut, ",".join(port_list))
        full, retval = _parse_link_status(output, port_list)
        if not full:
            output = hooks.get_status(dut, None)
            retval = _parse_link_status(output, port_list)[1]
    return retval


def dut_links_status(dut, hooks, skip_tgen):
    results, local_list = {}, build_dut_local_links(dut, skip_tgen)
    if not local_list:
        return results
    entries = _read_links_status(dut, hooks, local_list)
    for local in local_list:
        name = "{}--{}".format(dut, local)
        if simulate_link_fail():
            results[name] = "up/down"
        elif local in entries:
            entry = entries[local]
            results[name] = "{}/{}".format(entry["admin"], entry["oper"])
            name = "{}--{}".format(dut, entry.get("interface", local))
            results[name] = "{}/{}".format(entry["admin"], entry["oper"])
            name = "{}--{}".format(dut, entry.get("altname", local))
            results[name] = "{}/{}".format(entry["admin"], entry["oper"])
            name = "{}--{}".format(dut, entry.get("alias", local))
            results[name] = "{}/{}".format(entry["admin"], entry["oper"])
        else:
            results[name] = "----"
    return results


def read_oper_status(dut, hooks, port):
    entries = _read_links_status(dut, hooks, [port])
    if port in entries:
        return entries[port]["oper"]
    return None
