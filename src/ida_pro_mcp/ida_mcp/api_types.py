from typing import Annotated

import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import ida_ida
import idaapi

from .rpc import tool
from .sync import idaread, idawrite, ida_major
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    StructureMember,
    StructureDefinition,
    StructRead,
    TypeApplication,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idawrite
def declare_c_type(
    c_declaration: Annotated[str, "C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };"],
) -> dict:
    """Create or update a local type from a C declaration"""
    try:
        flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
        errors, messages = parse_decls_ctypes(c_declaration, flags)

        pretty_messages = "\n".join(messages)
        if errors > 0:
            return {"decl": c_declaration, "error": f"Failed to parse:\n{pretty_messages}"}
        else:
            return {"decl": c_declaration, "ok": True}
    except Exception as e:
        return {"decl": c_declaration, "error": str(e)}


@tool
@idawrite
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare types (deprecated: use declare_c_type for single declarations)"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idaread
def get_defined_structures(
    limit: Annotated[int, "Max structures to return (default: 200, max: 2000)"] = 200,
    offset: Annotated[int, "Skip first N structures (default: 0)"] = 0,
    filter_pattern: Annotated[str, "Optional pattern to filter structure names"] = "",
) -> dict:
    """Returns a list of all defined structures"""
    # Enforce max limit
    if limit <= 0 or limit > 2000:
        limit = 2000

    all_structs = []
    type_limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, type_limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if tif.is_udt():
            type_name = tif.get_type_name()

            # Apply filter if provided
            if filter_pattern and filter_pattern.lower() not in (type_name or "").lower():
                continue

            udt = ida_typeinf.udt_type_data_t()
            members = []
            if tif.get_udt_details(udt):
                members = [
                    StructureMember(
                        name=x.name,
                        offset=hex(x.offset // 8),
                        size=hex(x.size // 8),
                        type=str(x.type),
                    )
                    for _, x in enumerate(udt)
                ]

            all_structs.append(
                StructureDefinition(
                    name=type_name, size=hex(tif.get_size()), members=members
                )
            )

    # Apply pagination
    total_structs = len(all_structs)
    paginated_structs = all_structs[offset : offset + limit]
    has_more = offset + limit < total_structs

    return {
        "structs": paginated_structs,
        "count": len(paginated_structs),
        "total": total_structs,
        "cursor": {"next": offset + limit} if has_more else {"done": True},
    }


@tool
@idaread
def analyze_struct_detailed(
    name: Annotated[str, "Name of the structure to analyze"],
    max_members: Annotated[int, "Max members to return per struct (default: 500, max: 2000, 0=all)"] = 500,
) -> dict:
    """Detailed analysis of a structure with all fields"""
    # Enforce max limit (0 means no limit up to max)
    if max_members < 0 or max_members > 2000:
        max_members = 2000

    try:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return {"name": name, "error": f"Struct '{name}' not found"}

        result = {
            "name": name,
            "type": str(tif._print()),
            "size": tif.get_size(),
            "is_udt": tif.is_udt(),
        }

        if not tif.is_udt():
            result["error"] = "Not a user-defined type"
            return result

        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            result["error"] = "Failed to get struct details"
            return result

        total_members = udt_data.size()
        result["cardinality"] = total_members
        result["is_union"] = udt_data.is_union
        result["udt_type"] = "Union" if udt_data.is_union else "Struct"

        members = []
        member_limit = max_members if max_members > 0 else total_members
        for i, member in enumerate(udt_data):
            if i >= member_limit:
                break

            offset = member.begin() // 8
            size = member.size // 8 if member.size > 0 else member.type.get_size()
            member_type = member.type._print()
            member_name = member.name

            member_info = {
                "index": i,
                "offset": f"0x{offset:08X}",
                "size": size,
                "type": member_type,
                "name": member_name,
                "is_nested_udt": member.type.is_udt(),
            }

            if member.type.is_udt():
                member_info["nested_size"] = member.type.get_size()

            members.append(member_info)

        result["members"] = members
        result["members_returned"] = len(members)
        result["members_truncated"] = len(members) < total_members
        result["total_size"] = tif.get_size()

        return result
    except Exception as e:
        return {"name": name, "error": str(e)}


@tool
@idaread
def get_struct_info_simple(
    name: Annotated[str, "Name of the structure"],
) -> dict:
    """Simple function to get basic structure information"""
    try:
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return {"name": name, "error": f"Struct '{name}' not found"}

        result = {
            "name": name,
            "type": str(tif._print()),
            "size": tif.get_size(),
            "is_udt": tif.is_udt(),
        }

        if not tif.is_udt():
            result["error"] = "Not a user-defined type"
            return result

        udt_data = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt_data):
            result["cardinality"] = udt_data.size()
            result["is_union"] = udt_data.is_union
            result["udt_type"] = "Union" if udt_data.is_union else "Struct"

        return result
    except Exception as e:
        return {"name": name, "error": str(e)}


@tool
@idaread
def get_struct_at_address(
    address: Annotated[str, "Address to analyze structure at"],
    struct_name: Annotated[str, "Name of the structure"],
    max_members: Annotated[int, "Max members to read per struct (default: 200, max: 1000, 0=all)"] = 200,
) -> dict:
    """Get structure field values at a specific address"""
    # Enforce max limit (0 means no limit up to max)
    if max_members < 0 or max_members > 1000:
        max_members = 1000

    try:
        addr = parse_address(address)

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, struct_name):
            return {
                "address": address,
                "struct": struct_name,
                "members": None,
                "error": f"Struct '{struct_name}' not found",
            }

        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return {
                "address": address,
                "struct": struct_name,
                "members": None,
                "error": "Failed to get struct details",
            }

        total_members = udt_data.size()
        member_limit = max_members if max_members > 0 else total_members

        members = []
        for i, member in enumerate(udt_data):
            if i >= member_limit:
                break

            offset = member.begin() // 8
            member_addr = addr + offset
            member_type = member.type._print()
            member_name = member.name
            member_size = member.type.get_size()

            try:
                if member.type.is_ptr():
                    is_64bit = (
                        ida_ida.inf_is_64bit()
                        if ida_major >= 9
                        else idaapi.get_inf_structure().is_64bit()
                    )
                    if is_64bit:
                        value = idaapi.get_qword(member_addr)
                        value_str = f"0x{value:016X}"
                    else:
                        value = idaapi.get_dword(member_addr)
                        value_str = f"0x{value:08X}"
                elif member_size == 1:
                    value = idaapi.get_byte(member_addr)
                    value_str = f"0x{value:02X} ({value})"
                elif member_size == 2:
                    value = idaapi.get_word(member_addr)
                    value_str = f"0x{value:04X} ({value})"
                elif member_size == 4:
                    value = idaapi.get_dword(member_addr)
                    value_str = f"0x{value:08X} ({value})"
                elif member_size == 8:
                    value = idaapi.get_qword(member_addr)
                    value_str = f"0x{value:016X} ({value})"
                else:
                    bytes_data = []
                    for j in range(min(member_size, 16)):
                        try:
                            byte_val = idaapi.get_byte(member_addr + j)
                            bytes_data.append(f"{byte_val:02X}")
                        except Exception:
                            break
                    value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
            except Exception:
                value_str = "<failed to read>"

            member_info = {
                "offset": f"0x{offset:08X}",
                "type": member_type,
                "name": member_name,
                "value": value_str,
            }

            members.append(member_info)

        return {
            "address": address,
            "struct": struct_name,
            "members": members,
            "members_returned": len(members),
            "total_members": total_members,
            "truncated": len(members) < total_members,
        }
    except Exception as e:
        return {
            "address": address,
            "struct": struct_name,
            "members": None,
            "error": str(e),
        }


@tool
@idaread
def search_structures(
    filter: Annotated[
        str, "Filter pattern to search for structures (case-insensitive)"
    ],
    limit: Annotated[int, "Max results to return (default: 200, max: 2000)"] = 200,
    offset: Annotated[int, "Skip first N results (default: 0)"] = 0,
) -> dict:
    """Search for structures by name pattern"""
    # Enforce max limit
    if limit <= 0 or limit > 2000:
        limit = 2000

    all_results = []
    type_limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, type_limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    all_results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    # Apply pagination
    total_results = len(all_results)
    paginated_results = all_results[offset : offset + limit]
    has_more = offset + limit < total_results

    return {
        "structs": paginated_results,
        "count": len(paginated_results),
        "total": total_results,
        "cursor": {"next": offset + limit} if has_more else {"done": True},
    }


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idawrite
def apply_types(applications: list[TypeApplication] | TypeApplication) -> list[dict]:
    """Apply types (function/global/local/stack)"""

    def parse_addr_type(s: str) -> dict:
        # Support "addr:typename" format (auto-detects kind)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "ty": parts[1].strip()}
        # Just typename without address (invalid)
        return {"ty": s.strip()}

    applications = normalize_dict_list(applications, parse_addr_type)
    results = []

    for app in applications:
        try:
            # Auto-detect kind if not provided
            kind = app.get("kind")
            if not kind:
                if "signature" in app:
                    kind = "function"
                elif "variable" in app:
                    kind = "local"
                elif "addr" in app:
                    # Check if address points to a function
                    try:
                        addr = parse_address(app["addr"])
                        func = idaapi.get_func(addr)
                        if func and "name" in app and "ty" in app:
                            kind = "stack"
                        else:
                            kind = "global"
                    except Exception:
                        kind = "global"
                else:
                    kind = "global"

            if kind == "function":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(app["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": app, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, app.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(app["addr"])

                tif = get_type_by_name(app["ty"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(app["ty"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(app["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stack":
                func = idaapi.get_func(parse_address(app["addr"]))
                if not func:
                    results.append({"edit": app, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": app, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(app["name"])
                if not udm:
                    results.append({"edit": app, "error": f"{app['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(app["ty"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": app,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": app, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": app, "error": str(e)})

    return results


@tool
@idaread
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer types"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Specialized Type Setting Functions
# ============================================================================


@tool
@idawrite
def set_function_prototype(
    function_address: Annotated[str, "Address of the function"],
    prototype: Annotated[str, "New function prototype"],
) -> dict:
    """Set a function's prototype"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            return {
                "function_address": function_address,
                "prototype": prototype,
                "error": "Function not found",
            }

        tif = ida_typeinf.tinfo_t()
        if not tif.deserialize(None, prototype):
            # Try parsing as C declaration
            tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)

        if not tif.is_func():
            return {
                "function_address": function_address,
                "prototype": prototype,
                "error": "Not a function type",
            }

        success = ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.TINFO_DEFINITE)
        return {
            "function_address": function_address,
            "prototype": prototype,
            "ok": success,
            "error": None if success else "Failed to apply prototype",
        }
    except Exception as e:
        return {
            "function_address": function_address,
            "prototype": prototype,
            "error": str(e),
        }


@tool
@idawrite
def set_local_variable_type(
    function_address: Annotated[str, "Address of the decompiled function containing the variable"],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"],
) -> dict:
    """Set a local variable's type"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            return {
                "function_address": function_address,
                "variable_name": variable_name,
                "new_type": new_type,
                "error": "Function not found",
            }

        new_tif = ida_typeinf.tinfo_t()
        if not new_tif.deserialize(None, new_type):
            # Try parsing as C type
            new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)

        modifier = my_modifier_t(variable_name, new_tif)
        success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)

        return {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
            "ok": success,
            "error": None if success else "Failed to set type",
        }
    except Exception as e:
        return {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type,
            "error": str(e),
        }


@tool
@idawrite
def set_global_variable_type(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"],
) -> dict:
    """Set a global variable's type"""
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
        if ea == idaapi.BADADDR:
            return {
                "variable_name": variable_name,
                "new_type": new_type,
                "error": f"Global variable '{variable_name}' not found",
            }

        tif = ida_typeinf.tinfo_t()
        if not tif.deserialize(None, new_type):
            # Try parsing as C type or getting by name
            tif = get_type_by_name(new_type)

        success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)

        return {
            "variable_name": variable_name,
            "new_type": new_type,
            "ok": success,
            "error": None if success else "Failed to set type",
        }
    except Exception as e:
        return {
            "variable_name": variable_name,
            "new_type": new_type,
            "error": str(e),
        }
