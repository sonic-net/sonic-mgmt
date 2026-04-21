# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint:
# disable=use-list-literal,use-dict-literal,line-too-long,wrong-import-position,broad-exception-caught,invalid-name

""" Infinidat utilities """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# try:
#     import ansible.module_utils.errors
# except (ImportError, ModuleNotFoundError):
#     import errors  # Used during "make dev-hack-module-[present, stat, absent]"

try:
    from infinisdk import InfiniBox, core
    from infinisdk.core.exceptions import ObjectNotFound, APITransportFailure
except ImportError as imp_exc:
    HAS_INFINISDK = False
    INFINISDK_IMPORT_ERROR = imp_exc
else:
    HAS_INFINISDK = True
    INFINISDK_IMPORT_ERROR = None

HAS_ARROW = True
try:
    import arrow
except ImportError:
    HAS_ARROW = False
except Exception:
    HAS_INFINISDK = False

import pickle
from functools import wraps
from os import environ
from os import remove, path
from datetime import datetime

HAS_URLLIB3 = True
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    HAS_URLLIB3 = False


INFINIBOX_SYSTEM = None


def unixMillisecondsToDate(unix_ms):  # pylint: disable=invalid-name
    """Convert unix time with ms to a datetime UTC time"""
    return (datetime.utcfromtimestamp(unix_ms / 1000.0), "UTC")


def api_wrapper(func):
    """Catch API Errors Decorator"""

    @wraps(func)
    def __wrapper(*args, **kwargs):
        module = args[0]
        try:
            return func(*args, **kwargs)
        except core.exceptions.SystemNotFoundException as err:
            module.fail_json(msg=str(err))
        except core.exceptions.APICommandException as err:
            module.fail_json(msg=str(err))
        except Exception as err:
            module.fail_json(msg=str(err))
        return None  # Should never get to this line but it quiets pylint inconsistent-return-statements

    return __wrapper


def append_key_to_api_path(path, thing_to_append):
    appended_path = path
    appended_path += "&" if "?" in appended_path else "?"
    appended_path += thing_to_append
    return appended_path


@api_wrapper
def infinibox_api_get(module, path, fail_msg=None, disable_fail=False):
    """
    Call system.api.get.
    If the stay_logged_in_minutes is less then the equivalent setting on the IBOX, a session file
    may be used that will then fail on the IBOX.  If the happens, the SDK will try to login, but
    will not have credentials and fail with a TypeError. Catch that error.
    """
    system = get_system(module)
    page = 1
    page_size = 1000
    gathered_results = []

    while True:
        path_paging = f"page_size={page_size}&page={page}"
        path_paged = append_key_to_api_path(path, path_paging)

        # Some GET rest calls do not support paging, e.g. /api/rest/metadata/{id}.
        # Try first with paging, then if there is an UNKNOWN_PARAMETER error,
        # try without paging.
        paths_to_try = [path_paged, path]
        result = None
        for path_to_try in paths_to_try:
            try:
                result = system.api.get(path=path_to_try)
            except TypeError:
                msg = "Infinibox GET communication failed. Check credentials or stay_logged_in_minutes setting."
                module.fail_json(msg=msg)
            except Exception as err:

                if err.status_code == 404:  # Bad request, e.g. METADATA_NOT_FOUND
                    if disable_fail:
                        return None

                if err.status_code == 400:  # GET does not support paging
                    continue

                if not fail_msg:
                    fail_msg = f"Infinibox GET communication with path '{path_to_try}' failed: {err}"

                module.fail_json(msg=fail_msg)

        if not result:
            if not fail_msg:
                fail_msg = f"Infinibox GET communication with path '{path_paged}' and with path '{path}' failed"
            module.fail_json(msg=fail_msg)

        if result.status_code not in [200, 201]:
            if not fail_msg:
                fail_msg = f"Infinibox GET communication with path '{path_paged}' failed: {err}"
            error_msg = f"{fail_msg}: code: {result.json()['error']['code']}"
            module.fail_json(msg=error_msg)

        gathered_results += result.get_json()['result']
        metadata = result.get_json()["metadata"]
        page += 1

        try:
            if page > metadata["pages_total"]:
                # Reached end of the pagination.
                return gathered_results
        except KeyError as err:
            # If no pages_total key in metadata, then it is not a list.
            # Return the single result.
            assert "pages_total" in str(err)
            return result


@api_wrapper
def infinibox_api_post(module, path, data, fail_msg=None):
    """
    Call system.api.post.
    If the stay_logged_in_minutes is less then the equivalent setting on the IBOX, a session file
    may be used that will then fail on the IBOX.  If the happens, the SDK will try to login, but
    will not have credentials and fail with a TypeError. Catch that error.
    """
    system = get_system(module)
    try:
        result = system.api.post(path=path, data=data)
        return result
    except TypeError:
        msg = "Infinibox POST communication failed. Check credentials or stay_logged_in_minutes setting."
        module.fail_json(msg=msg)
    except Exception as err:
        if not fail_msg:
            fail_msg = f"Infinibox POST communication with path '{path}' failed: {err}"
        module.fail_json(msg=fail_msg)


def infinibox_argument_spec():
    """Return standard base dictionary used for the argument_spec argument in AnsibleModule"""
    return dict(
        system=dict(required=True),
        user=dict(required=False, default=None),
        password=dict(required=False, default=None, no_log=True),
        stay_logged_in=dict(required=False, type=bool, default=False),
        stay_logged_in_minutes=dict(required=False, type=int, default=5),
    )


def infinibox_required_together():
    """Return the default list used for the required_together argument to AnsibleModule"""
    return [["user", "password"]]


def merge_two_dicts(dict1, dict2):
    """
    Merge two dicts into one and return.
    result = {**dict1, **dict2} only works in py3.5+.
    """
    result = dict1.copy()
    result.update(dict2)
    return result


def get_infinibox_pickle_name(module):
    """Get a name with path for the pickle file that is IBOX unique"""
    box = module.params["system"]
    pickle_name = f"/tmp/infinibox_pickle_{box}"
    return pickle_name


def delete_aged_creds_file(module):
    """Delete creds file if the file age is greater than a limit.
    Return False if not deleted, True if deleted.
    """
    file_path = get_infinibox_pickle_name(module)
    n_minutes = module.params["stay_logged_in_minutes"]
    try:
        file_mod_time = path.getmtime(file_path)
        file_mod_date = datetime.fromtimestamp(file_mod_time)
        current_time = datetime.now()
        time_diff = current_time - file_mod_date
        if time_diff.total_seconds() > n_minutes * 60:
            remove(file_path)
            return True
        else:
            return False
    except FileNotFoundError:
        return True
    except Exception as e:
        msg = f"An unexpected error occurred while deleting credentials file {file_path}: {e}"
        module.fail_json(msg=msg)


def load_creds_from_file(module):
    """Load credentials from pickle file"""
    global INFINIBOX_SYSTEM  # pylint: disable=global-statement
    loaded_creds = None
    is_creds_removed = delete_aged_creds_file(module)
    stay_logged_in = module.params.get("stay_logged_in", None)
    if not is_creds_removed and stay_logged_in and not INFINIBOX_SYSTEM:
        try:
            with open(get_infinibox_pickle_name(module), "rb") as file:
                loaded_creds = pickle.load(file)
        except FileNotFoundError:
            pass
        except Exception as err:
            pass
    return loaded_creds


def save_creds_to_file(module):
    """Save credentials to pickle file"""
    global INFINIBOX_SYSTEM  # pylint: disable=global-statement
    stay_logged_in = module.params.get("stay_logged_in", None)
    if stay_logged_in and INFINIBOX_SYSTEM:
        # Remove existing file to ensure the creation time is updated
        file_path = get_infinibox_pickle_name(module)
        try:
            remove(file_path)
        except FileNotFoundError:
            pass

        saved_creds = INFINIBOX_SYSTEM.api.save_credentials()
        with open(get_infinibox_pickle_name(module), "wb") as file:
            pickle.dump(saved_creds, file)


@api_wrapper
def get_system(module):
    """
    Return System Object if it does not exist or Fail.
    Use a global system Infinibox object so that there will only be one
    system session used for this module instance.
    Enables execute_state() to log out of the only session properly.
    """
    global INFINIBOX_SYSTEM  # pylint: disable=global-statement

    loaded_creds = load_creds_from_file(module)

    if not INFINIBOX_SYSTEM:
        # Create system
        box = module.params["system"]
        user = module.params.get("user", None)
        password = module.params.get("password", None)
        if loaded_creds:
            INFINIBOX_SYSTEM = InfiniBox(box, use_ssl=True)
            INFINIBOX_SYSTEM.api.load_credentials(loaded_creds)
        elif user and password:
            INFINIBOX_SYSTEM = InfiniBox(box, auth=(user, password), use_ssl=True)
        elif environ.get("INFINIBOX_USER") and environ.get("INFINIBOX_PASSWORD"):
            INFINIBOX_SYSTEM = InfiniBox(
                box,
                auth=(environ.get("INFINIBOX_USER"), environ.get("INFINIBOX_PASSWORD")),
                use_ssl=True,
            )
        elif path.isfile(path.expanduser("~") + "/.infinidat/infinisdk.ini"):
            INFINIBOX_SYSTEM = InfiniBox(box, use_ssl=True)
        else:
            module.fail_json(
                msg="You must set INFINIBOX_USER and INFINIBOX_PASSWORD environment variables or set username/password module arguments"
            )

        if not loaded_creds:
            try:
                INFINIBOX_SYSTEM.login()
            except APITransportFailure:
                module.fail_json(
                    msg="Infinibox authentication failed. Check connectivity."
                )
            except Exception:
                module.fail_json(
                    msg="Infinibox authentication failed. Check credentials."
                )

        save_creds_to_file(module)

    return INFINIBOX_SYSTEM


@api_wrapper
def get_pool(module, system):
    """
    Return Pool. Try key look up using 'pool', or if that fails, 'name'.
    If the pool is not found, return None.
    """
    try:
        try:
            name = module.params["pool"]
        except KeyError:
            try:
                name = module.params["name"]
            except KeyError:
                name = module.params["object_name"]  # For metadata
        return system.pools.get(name=name)
    except Exception:
        return None


@api_wrapper
def get_filesystem(module, system):
    """Return Filesystem or None"""
    try:
        try:
            filesystem = system.filesystems.get(name=module.params["filesystem"])
        except KeyError:
            try:
                filesystem = system.filesystems.get(name=module.params["name"])
            except KeyError:
                filesystem = system.filesystems.get(name=module.params["object_name"])
        return filesystem
    except Exception:
        return None


@api_wrapper
def get_export(module, system):
    """Return export if found or None if not found"""
    try:
        try:
            export_name = module.params["export"]
        except KeyError:
            export_name = module.params["name"]

        export = system.exports.get(export_path=export_name)
    except ObjectNotFound:
        return None

    return export


@api_wrapper
def get_volume(module, system):
    """Return Volume or None"""
    try:
        try:
            volume = system.volumes.get(name=module.params["name"])
        except KeyError:
            try:
                volume = system.volumes.get(name=module.params["volume"])
            except KeyError:
                volume = system.volumes.get(
                    name=module.params["object_name"]
                )  # Used by metadata module
        return volume
    except Exception:
        return None


@api_wrapper
def get_net_space(module, system):
    """Return network space or None"""
    try:
        net_space = system.network_spaces.get(name=module.params["name"])
    except (KeyError, ObjectNotFound):
        return None
    return net_space


@api_wrapper
def get_vol_by_sn(module, system):
    """Return volume that matches the serial or None"""
    try:
        volume = system.volumes.get(serial=module.params["serial"])
    except Exception:
        return None
    return volume


@api_wrapper
def get_fs_by_sn(module, system):
    """Return filesystem that matches the serial or None"""
    try:
        filesystem = system.filesystems.get(serial=module.params["serial"])
    except Exception:
        return None
    return filesystem


@api_wrapper
def get_host(module, system):
    """Find a host by the name specified in the module"""
    host = None

    for a_host in system.hosts.to_list():
        a_host_name = a_host.get_name()
        try:
            host_param = module.params["name"]
        except KeyError:
            try:
                host_param = module.params["host"]
            except KeyError:
                host_param = module.params["object_name"]  # For metadata

        if a_host_name == host_param:
            host = a_host
            break
    return host


@api_wrapper
def get_cluster(module, system):
    """Find a cluster by the name specified in the module"""
    cluster = None

    for a_cluster in system.host_clusters.to_list():
        a_cluster_name = a_cluster.get_name()
        try:
            cluster_param = module.params["name"]
        except KeyError:
            try:
                cluster_param = module.params["cluster"]
            except KeyError:
                cluster_param = module.params["object_name"]  # For metadata

        if a_cluster_name == cluster_param:
            cluster = a_cluster
            break
    return cluster


@api_wrapper
def get_user(module, system, user_name_to_find=None):
    """Find a user by the user_name specified in the module"""
    user = None
    if not user_name_to_find:
        user_name = module.params["user_name"]
    else:
        user_name = user_name_to_find
    try:
        user = system.users.get(name=user_name)
    except ObjectNotFound:
        pass
    return user


def check_snapshot_lock_options(module):
    """
    Check if specified options are feasible for a snapshot.

    Prevent very long lock times.
    max_delta_minutes limits locks to 30 days (43200 minutes).

    This functionality is broken out from manage_snapshot_locks() to allow
    it to be called by create_snapshot() before the snapshot is actually
    created.
    """
    snapshot_lock_expires_at = module.params["snapshot_lock_expires_at"]

    if snapshot_lock_expires_at:  # Then user has specified wish to lock snap
        lock_expires_at = arrow.get(snapshot_lock_expires_at)

        # Check for lock in the past
        now = arrow.utcnow()
        if lock_expires_at <= now:
            msg = "Cannot lock snapshot with a snapshot_lock_expires_at "
            msg += f"of '{snapshot_lock_expires_at}' from the past"
            module.fail_json(msg=msg)

        # Check for lock later than max lock, i.e. too far in future.
        max_delta_minutes = 43200  # 30 days in minutes
        max_lock_expires_at = now.shift(minutes=max_delta_minutes)
        if lock_expires_at >= max_lock_expires_at:
            msg = f"snapshot_lock_expires_at exceeds {max_delta_minutes // 24 // 60} days in the future"
            module.fail_json(msg=msg)


def manage_snapshot_locks(module, snapshot):
    """
    Manage the locking of a snapshot. Check for bad lock times.
    See check_snapshot_lock_options() which has additional checks.
    """
    snapshot_lock_expires_at = module.params["snapshot_lock_expires_at"]
    snap_is_locked = snapshot.get_lock_state() == "LOCKED"
    current_lock_expires_at = snapshot.get_lock_expires_at()
    changed = False

    check_snapshot_lock_options(module)

    if snapshot_lock_expires_at:  # Then user has specified wish to lock snap
        lock_expires_at = arrow.get(snapshot_lock_expires_at)
        if snap_is_locked and lock_expires_at < current_lock_expires_at:
            # Lock earlier than current lock
            msg = f"snapshot_lock_expires_at '{lock_expires_at}' preceeds the current lock time of '{current_lock_expires_at}'"
            module.fail_json(msg=msg)
        elif snap_is_locked and lock_expires_at == current_lock_expires_at:
            # Lock already set to correct time
            pass
        else:
            # Set lock
            if not module.check_mode:
                snapshot.update_lock_expires_at(lock_expires_at)
            changed = True
    return changed


def catch_failed_module_utils_imports(module):
    msg = ""
    if not HAS_ARROW:
        msg += "Failed to import arrow module. "
    if not HAS_INFINISDK:
        msg += "Failed to import infinisdk module. "
    if not HAS_URLLIB3:
        msg += "Failed to import urllib3 module. "
    module.fail_json(msg=msg)


def execute_state_cleanup(module):
    """Run common clean up tasks after running execute_state()"""
    stay_logged_in = module.params["stay_logged_in"]
    if not stay_logged_in:
        system = get_system(module)
        system.logout()
