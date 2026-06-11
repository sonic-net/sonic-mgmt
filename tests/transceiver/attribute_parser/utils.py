"""Common utility functions for transceiver attribute infrastructure."""


def format_kv_block(header, data, max_depth=2):
    """Format a dictionary as a readable indented block for logging/output (default max_depth=2).

    Args:
        header: Header title for the block.
        data: Dictionary to format.
        max_depth: Maximum nesting depth to expand.

    Returns:
        Formatted string with header and sorted key-value pairs, with nested dicts pretty-printed.
    """

    def _format_nested_value(value, depth=0):
        if depth >= max_depth or not isinstance(value, dict):
            return str(value)
        # Nested dict: format inline if small, otherwise multi-line
        if len(value) <= 3:
            items = ', '.join(f"{k}: {str(val)}" for k, val in sorted(value.items()))
            return '{' + items + '}'
        # Multi-line nested dict
        indent = '  ' * (depth + 1)
        nested_lines = ['{']
        for k in sorted(value.keys()):
            nested_lines.append(f"{indent}  {k}: {_format_nested_value(value[k], depth + 1)}")
        nested_lines.append(indent + '}')
        return '\n'.join(nested_lines)

    lines = [header + ': {']
    for k in sorted(data.keys()):
        lines.append(f"  {k}: {_format_nested_value(data[k], depth=1)}")
    lines.append('}')
    return '\n'.join(lines)
