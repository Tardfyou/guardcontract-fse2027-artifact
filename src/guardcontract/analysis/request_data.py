"""Bounded JSON data domain shared by storage, static input, and observer output."""
from copy import deepcopy
import math


class DataDomainError(ValueError):
    pass


def snapshot(value):
    nodes, text_size = 0, 0
    ancestors = set()

    def visit(item, depth):
        nonlocal nodes, text_size
        nodes += 1
        if nodes > 4096 or depth > 32:
            raise DataDomainError("request_data_structure_budget")
        kind = type(item)
        if kind is str:
            text_size += len(item)
            if len(item) > 65536 or text_size > 262144:
                raise DataDomainError("request_data_text_budget")
        elif kind is int:
            if item.bit_length() > 4096:
                raise DataDomainError("request_data_integer_budget")
        elif kind is float:
            if not math.isfinite(item):
                raise DataDomainError("request_data_nonfinite")
        elif kind in {bool, type(None)}:
            return
        elif kind in {dict, list}:
            identity = id(item)
            if identity in ancestors:
                raise DataDomainError("request_data_cycle")
            if len(item) > 1024:
                raise DataDomainError("request_data_container_budget")
            ancestors.add(identity)
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DataDomainError("request_data_non_string_key")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            ancestors.remove(identity)
        else:
            raise DataDomainError("request_data_non_plain_value")

    visit(value, 0)
    return deepcopy(value)
