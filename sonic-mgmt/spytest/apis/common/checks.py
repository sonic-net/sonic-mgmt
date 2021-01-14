from spytest import st, tgapi, putils
import utilities.common as utils

# None - Configured, False - Alias, True - Native
use_native=True # use only native
tgen_link_status_supported = False
check_oneway = True

def log_info(fmt, *args):
    st.log(fmt % args)

def warn(fmt, *args):
    st.warn(fmt % args)

def trace(dut, did, local, partner, pdid, remote, status):
    #print(dut, did, local, partner, pdid, remote, status)
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

def get_tg_link_status(tg, ph):
    return tg.tg_interface_control(mode="check_link", desired_status='up',
                                   port_handle=ph)

def fill_dev_ids():
    dids, palias = {}, {}
    for dut in st.get_dut_names():
        dids[dut] = st.get_device_alias(dut, True, True)
        palias[dut] = {}
        links = st.get_dut_links_local(dut)
        onames = st.get_other_names(dut, links)
        for index, local in enumerate(links):
            palias[dut][local] = onames[index]
    for tg in st.get_tg_names():
        dids[tg] = st.get_device_alias(tg, True, True)
    return dids, palias

def verify_topology(hooks, check_type, threads=True):
    if check_type in ["module", "function"]:
        return links_status(hooks, threads, check_type)

    retval = True
    results, exclude = [], []
    header = ['DUT', 'DId', 'Local', "Partner", "PDId", "Remote", "Status"]
    dids, _ = fill_dev_ids()
    for dut in st.get_dut_names():
        did = dids[dut]
        for local, partner, remote in st.get_dut_links(dut, native=use_native):
            pdid = dids[dut]

            # check if the port is verified from other direction
            skip = False
            for ex in exclude:
                #print("CMP", dut, local, ex[0], ex[1])
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
            status1 = hooks.get_interface_status(partner, remote)
            trace(dut, did, local, partner, pdid, remote, status1)

            # noshutdown local link and get remote link stats in partner
            hooks.noshutdown(dut, [local])
            wait()
            status2 = hooks.get_interface_status(partner, remote)
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
                status3 = hooks.get_interface_status(dut, local)
                trace(dut, did, local, partner, pdid, remote, status3)

                # noshutdown remote link and get local link status
                hooks.noshutdown(partner, [remote])
                wait()
                status4 = hooks.get_interface_status(dut, local)
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

        for local, partner, remote in st.get_tg_links(dut, native=use_native):
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
            status3 = hooks.get_interface_status(dut, local)
            trace(dut, did, local, partner, pdid, remote, status3)

            # noshutdown remote link and get local link status
            tg.tg_interface_control(mode="restore_link", port_handle=ph)
            wait()
            status4 = hooks.get_interface_status(dut, local)
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

def links_status(hooks, threads, check_type):
    header = ['DUT', 'DId', 'Local', "LStatus (A/O)", "Partner", 'PDId', "Remote", "RStatus (A/O)"]
    funcs = [
        [tg_links_status, check_type],
        [duts_links_status, hooks, threads]
    ]

    show_alias = bool(st.getenv("SPYTEST_TOPOLOGY_SHOW_ALIAS", "0") != "0")
    if show_alias:
        header.insert(3, "LAlias")
        header.insert(8, "RAlias")

    # st.fail during ctrl+c or prompt not found scenarios, is causing issues.
    # To avoid that below code block should be in try-except only.
    try:
        [[v1, [v2, seen_exp]], [e1, e2]] = putils.exec_all2(threads, "trace", funcs, True)
        if v1 is None or v2 is None or e1 is not None or e2 is not None or seen_exp:
            print(v1, v2, e1, e2, seen_exp)
            return [True, header, [], True, show_alias]
    except Exception:
        print("Observed exception during the thread call return handling")
        return [True, header, [], True, show_alias]

    v1_default = "?2?" if v1 else "NA"
    (results, exclude, (dids, palias)) = ([], [], fill_dev_ids())
    for dut in st.get_dut_names():
        for local, partner, remote in st.get_tg_links(dut, native=use_native):
            res = []
            res.append(dut)
            res.append(dids.get(dut, "?"))
            res.append(local)
            if show_alias:
                res.append(palias.get(local, local))
            res.append(v2.get("{}--{}".format(dut, local), "?1?"))
            res.append(partner)
            res.append(dids.get(partner, "?"))
            res.append(remote)
            if show_alias:
                res.append(palias.get(remote, remote))
            res.append(v1.get("{}--{}".format(partner, remote), v1_default))
            results.append(res)
        for local, partner, remote in st.get_dut_links(dut, native=use_native):
            name = "{}--{}".format(dut, local)
            if name in exclude:
                continue
            res = []
            res.append(dut)
            res.append(dids.get(dut, "?"))
            res.append(local)
            if show_alias:
                res.append(palias.get(local, local))
            res.append(v2.get("{}--{}".format(dut, local), "?3?"))
            res.append(partner)
            res.append(dids.get(partner, "?"))
            res.append(remote)
            if show_alias:
                res.append(palias.get(remote, remote))
            res.append(v2.get("{}--{}".format(partner, remote), "?4?"))
            exclude.append("{}--{}".format(partner, remote))
            results.append(res)
    return [True, header, results, False, show_alias]

def tg_links_status_using_hltapi():
    results = dict()
    for dut in st.get_dut_names():
        for _, partner, remote in st.get_tg_links(dut, native=use_native):
            (tg, ph) = tgapi.get_handle_byname(None, tg=partner, port=remote)
            name = "{}--{}".format(partner, remote)
            results[name] = get_tg_link_status(tg, ph)
    return results

def tg_links_status_using_native_calls():
    # build port list per tgen
    tg_port_dict = {}
    for dut in st.get_dut_names():
        for _, partner, remote in st.get_tg_links(dut, native=use_native):
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
    if st.getenv("SPYTEST_TOPOLOGY_STATUS_FAST", "1") == "1":
        # avoid checking TGEN status for faster execution
        if check_type in ["module", "function"]:
            return dict()
    try:
        return tg_links_status_using_native_calls()
    except Exception:
        return tg_links_status_using_hltapi()

def duts_links_status(hooks, threads):
    results = dict()
    [rvs, exps] = putils.exec_foreach2(threads, "trace", st.get_dut_names(), dut_links_status, hooks)
    for rv in rvs:
        if rv:
            results.update(rv)
    return results, any(exps)

def simulate_link_fail():
    if st.getenv("SPYTEST_TOPOLOGY_SIMULATE_FAIL", "0") == "0":
        return False
    from random import randint
    return bool(randint(0, 100) > 90)

def dut_links_status(dut, hooks):
    results, local_list = {}, []
    for local, _, _ in st.get_dut_links(dut, native=use_native):
        local_list.append(local)
    for local, _, _ in st.get_tg_links(dut, native=use_native):
        local_list.append(local)

    output = hooks.get_status(dut, ",".join(local_list))

    for local in local_list:
        match = {"interface": local}
        entries = utils.filter_and_select(output, ["admin","oper"], match)
        name = "{}--{}".format(dut, local)
        if simulate_link_fail():
            results[name] = "up/down"
        elif entries:
            results[name] = "{}/{}".format(entries[0]["admin"], entries[0]["oper"])
        else:
            results[name] = "----"
    return results

