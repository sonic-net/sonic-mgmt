import os
import sys

tgen_path = os.getenv("SCID_TGEN_PATH", "/projects/scid/tgen")
def_tcl_path = "/projects/scid/tools/ActivTcl/current/bin"
tcl_custom_pkgdir = os.path.abspath(os.path.dirname(__file__))

def tg_stc_load(version, logger, logs_path=None):

    stc_version_map = {"4.67": "4.67", "4.91": "4.91"}

    # verify STC version provided
    version_string = str(version)
    if version_string not in stc_version_map:
        logger.error("STC: unsupported version {}".format(version_string))
        return None

    # map STC version if needed
    version_string = stc_version_map[version_string]

    # check if STC root folder is found
    stc_root = os.path.join(tgen_path, "stc")
    if not os.path.exists(stc_root):
        logger.error("STC: not installed.")
        return None

    # build STC version root folder
    stc_ver_root = os.path.join(stc_root, version_string)
    if not os.path.exists(stc_ver_root):
        stc_ver_root = os.path.join(stc_root, "Spirent_TestCenter_{}".format(version_string))

    # check if STC version root folder is found
    if not os.path.exists(stc_ver_root):
        logger.error("STC: not installed..")
        return None

    # build STC app root folder
    stc_app_root = os.path.join(stc_ver_root, "Spirent_TestCenter_Application_Linux")

    # check if STC app root folder is found
    if not os.path.exists(stc_app_root):
        logger.error("STC: not installed...")
        return None

    stc_hl_src = stc_app_root + '/HltAPI/SourceCode'
    stc_hl_api_path = stc_hl_src + '/hltapiForPython'

    # build tclsh PATH
    stc_tcl_path = os.path.join(stc_app_root, "Tcl", "bin")
    if not os.path.exists(stc_tcl_path):
        stc_tcl_path = def_tcl_path
    tcl_path = os.getenv("SCID_TCL85_BIN", "")
    if not tcl_path or not os.path.exists(tcl_path):
        tcl_path = stc_tcl_path
    if float(version) < 4.91:
        tcl_path = os.getenv("SCID_TCL84_BIN", stc_tcl_path)
    tcl_lib_path = os.path.join(tcl_path, "..", "lib")
    tclsh = os.path.join(tcl_path, "tclsh8.5")
    if not os.path.exists(tclsh):
        tclsh = os.path.join(tcl_path, "tclsh")

    old_ldpath = os.getenv("LD_LIBRARY_PATH")
    ldpath = [old_ldpath] if old_ldpath else []
    ldpath.append(stc_app_root)
    os.environ['LD_LIBRARY_PATH'] = ":".join(ldpath)

    os.environ['STC_VERSION'] = version_string
    os.environ['STC_INSTALL_DIR'] = stc_app_root
    os.environ['STC_PRIVATE_INSTALL_DIR'] = stc_app_root
    os.environ["STC_TCL"] = tclsh
    os.environ['TCLLIBPATH'] = "{} {} {} /usr/lib".format(stc_hl_src, tcl_custom_pkgdir, tcl_lib_path)
    os.environ['HLPYAPI_LOG'] = logs_path or os.getenv("SPYTEST_USER_ROOT")
    os.environ['HOME'] = logs_path or os.getenv("SPYTEST_USER_ROOT")

    sys.path.insert(0, tcl_path)
    sys.path.insert(0, stc_hl_api_path)

    return version_string


def tg_ixia_load(version, logger, logs_path=None):

    ixia_version_map = {"7.4": "7.40", "7.40": "7.40",
                        "8.4": "8.40", "8.42": "8.42",
                        "9.0": "9.00", "9.00": "9.00"}
    version_string = str(version)
    if version_string not in ixia_version_map:
        logger.error("IXIA: unsupported version {}".format(version_string))
        return None

    version_string = ixia_version_map[version_string]

    ixia_hltapi_map = {'7.40': 'HLTSET173',
                       '8.40': 'HLTSET219',
                       '8.42': 'HLTSET223',
                       '9.00': 'HLTSET231',
                       }

    ixnetwork = os.path.join(tgen_path, "ixia", version_string, "lib")

    if os.path.exists(ixnetwork):
        hl_api = os.path.join(tgen_path, "ixia", version_string,
                            "lib", "hltapi", "library")

        ngpf_api = hl_api + str("/common/ixiangpf/python")
        ixn_py_api = ixnetwork + "/PythonApi"

        os.environ["IXIA_VERSION"] = ixia_hltapi_map[version_string]
        os.environ["IXIA_HOME"] = ixnetwork
        os.environ["TCLLIBPATH"] = str(ixnetwork)

        sys.path.append(ngpf_api)
        sys.path.append(ixn_py_api)

        return version_string

    #  9.0 onwards
    tcl_path = os.getenv("SCID_TCL85_BIN", def_tcl_path)
    tcl_lib_path = os.path.join(tcl_path, "..", "lib")
    ixia_root = os.path.join(tgen_path, "ixia", "all", "ixia")
    hlt_api = os.path.join(ixia_root, "hlapi", version_string)
    ngpf_api = os.path.join(hlt_api, "library", "common", "ixiangpf", "python")
    ixn_py_api = os.path.join(ixia_root, "ixnetwork", version_string,
                              "lib", "PythonApi")
    ixn_tcl_api_1 = os.path.join(ixia_root, "ixnetwork", version_string,
                                 "lib", "IxTclNetwork")
    ixn_tcl_api_2 = os.path.join(ixia_root, "ixnetwork", version_string,
                                 "lib", "TclApi", "IxTclNetwork")
    os.environ["IXIA_VERSION"] = ixia_hltapi_map[version_string]
    os.environ["TCLLIBPATH"] = " ".join([hlt_api, ixn_tcl_api_1, ixn_tcl_api_2, tcl_lib_path])
    sys.path.append(ngpf_api)
    sys.path.append(ixn_py_api)

    return version_string

def tg_scapy_load(version, logger, logs_path=None):
    return version

