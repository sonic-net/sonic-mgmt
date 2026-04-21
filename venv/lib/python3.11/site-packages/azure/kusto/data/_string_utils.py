def assert_string_is_not_empty(value: str):
    if not value or not value.strip():
        raise ValueError("Should not be empty")
