"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, u8, u16, u32, u64, strings) and patching binary data.
"""

from typing import Annotated
import ida_bytes
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import normalize_list_input, parse_address, MemoryRead, MemoryPatch


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idaread
def read_memory_bytes(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read bytes from memory addresses"""
    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in regions:
        addr = item.get("addr", "")
        size = item.get("size", 0)

        try:
            ea = parse_address(addr)
            data = " ".join(f"{x:#02x}" for x in ida_bytes.get_bytes(ea, size))
            results.append({"addr": addr, "data": data})
        except Exception as e:
            results.append({"addr": addr, "data": None, "error": str(e)})

    return results


@tool
@idaread
def data_read_byte(
    addrs: Annotated[list[str] | str, "Addresses to read 8-bit unsigned integers from"],
) -> list[dict]:
    """Read 8-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_byte(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def data_read_word(
    addrs: Annotated[
        list[str] | str, "Addresses to read 16-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 16-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_word(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def data_read_dword(
    addrs: Annotated[
        list[str] | str, "Addresses to read 32-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 32-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_wide_dword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def data_read_qword(
    addrs: Annotated[
        list[str] | str, "Addresses to read 64-bit unsigned integers from"
    ],
) -> list[dict]:
    """Read 64-bit unsigned integers from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = ida_bytes.get_qword(ea)
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@tool
@idaread
def data_read_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
) -> list[dict]:
    """Read strings from memory addresses"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            value = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8")
            results.append({"addr": addr, "value": value})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


def get_global_variable_value_internal(ea: int) -> str:
    import ida_typeinf
    import ida_nalt
    import ida_bytes
    from .sync import IDAError

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")

        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(f"Failed to get type information for variable at {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        return_string = idaapi.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f'"{return_string}"'
    elif size == 1:
        return hex(ida_bytes.get_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        return " ".join(hex(x) for x in ida_bytes.get_bytes(ea, size))


@tool
@idaread
def get_global_variable_value_by_name(
    names: Annotated[list[str] | str, "Global variable names to read values from"],
) -> list[dict]:
    """Read global variable values by name"""
    names = normalize_list_input(names)
    results = []

    for name in names:
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, name)

            if ea == idaapi.BADADDR:
                results.append({"name": name, "value": None, "error": "Not found"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"name": name, "value": value, "error": None})
        except Exception as e:
            results.append({"name": name, "value": None, "error": str(e)})

    return results


@tool
@idaread
def get_global_variable_value_at_address(
    addrs: Annotated[list[str] | str, "Global variable addresses to read values from"],
) -> list[dict]:
    """Read global variable values by address"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            if ea == idaapi.BADADDR:
                results.append({"addr": addr, "value": None, "error": "Invalid address"})
                continue

            value = get_global_variable_value_internal(ea)
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idawrite
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    if isinstance(patches, dict):
        patches = [patches]

    results = []

    for patch in patches:
        try:
            ea = parse_address(patch["addr"])
            data = bytes.fromhex(patch["data"])

            ida_bytes.patch_bytes(ea, data)
            results.append(
                {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
            )

        except Exception as e:
            results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

    return results
