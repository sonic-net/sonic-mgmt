def iter_response_text(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from iter_response_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_response_text(item)
    elif value is not None:
        yield str(value)


def _iter_updates(value):
    if isinstance(value, dict):
        updates = value.get("update")
        if isinstance(updates, list):
            yield from (update for update in updates if isinstance(update, dict))
        for item in value.values():
            yield from _iter_updates(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_updates(item)


def response_has_update(value, text):
    for update in _iter_updates(value):
        update_value = update.get("val")
        if update_value is None or update_value == "" or update_value == {} or update_value == []:
            continue
        path = str(update.get("path") or "")
        if text in path or any(text in item for item in iter_response_text(update_value)):
            return True
    return False


def countersdb_prefix(duthost):
    if duthost.is_multi_asic:
        namespace = duthost.get_port_asic_instance("Ethernet0").namespace
    else:
        namespace = "localhost"
    return "sonic-db:COUNTERS_DB/{}".format(namespace)


def countersdb_config_path(duthost, iface="Ethernet0"):
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(iface).asic_index
        return "/etc/sonic/config_db{}.json".format(asic_index)
    return "/etc/sonic/config_db.json"
