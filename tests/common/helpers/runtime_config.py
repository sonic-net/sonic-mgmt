RUNTIME_REFRESH_FIELD = "require_manual_refresh"


def get_runtime_managed_entries(config, table_name="LOGGER"):
    table = config.get(table_name, {})
    if not isinstance(table, dict):
        return {}

    return {
        key: value
        for key, value in table.items()
        if isinstance(value, dict)
        and str(value.get(RUNTIME_REFRESH_FIELD, "")).lower() == "true"
    }


def get_unrestored_runtime_managed_entries(expected_config, current_config, table_name="LOGGER"):
    expected_entries = get_runtime_managed_entries(expected_config, table_name)
    current_table = current_config.get(table_name, {})
    if not isinstance(current_table, dict):
        current_table = {}

    return {
        key: {
            "expected": value,
            "current": current_table.get(key),
        }
        for key, value in expected_entries.items()
        if current_table.get(key) != value
    }


def get_unrestored_runtime_managed_entries_by_context(expected_configs, current_configs, table_name="LOGGER"):
    unrestored = {}
    for context, expected_config in expected_configs.items():
        entries = get_unrestored_runtime_managed_entries(
            expected_config,
            current_configs.get(context, {}),
            table_name,
        )
        if entries:
            unrestored[context] = entries
    return unrestored
