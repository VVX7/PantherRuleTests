"""
Mock Panther base helpers for local testing

In production, these are provided by the Panther platform.
This module allows local testing without requiring Panther.
"""


def deep_get(data, *keys, default=None):
    """
    Safely retrieve nested dictionary values

    Args:
        data: Dictionary to search
        *keys: Sequence of keys to traverse
        default: Default value if key path not found

    Returns:
        Value at key path or default

    Example:
        deep_get(event, 'user', 'username', default='unknown')
    """
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current
