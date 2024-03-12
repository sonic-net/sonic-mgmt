def load_db_config():
    '''
    Load the correct database config file:
     - database_global.json for multi asic
     - database_config.json for single asic
    Loading database config file is not required for
    201911 images so ignore import error or function
    name error.
    '''
    try:
        from sonic_py_common import multi_asic
        from swsscommon import swsscommon
        if multi_asic.is_multi_asic():
            if not swsscommon.SonicDBConfig.isGlobalInit():
                swsscommon.SonicDBConfig.load_sonic_global_db_config()
        else:
            if not swsscommon.SonicDBConfig.isInit():
                swsscommon.SonicDBConfig.load_sonic_db_config()
    except ImportError:
        pass
    except NameError:
        pass
    except AttributeError:
        pass
