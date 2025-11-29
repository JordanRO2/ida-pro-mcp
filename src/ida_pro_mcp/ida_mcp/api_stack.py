"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated
import ida_typeinf
import ida_frame
import idaapi

from .rpc import tool
from .sync import idaread, idawrite
from .utils import (
    parse_address,
    get_type_by_name,
    get_stack_frame_variables_internal,
)


# ============================================================================
# Stack Frame Operations
# ============================================================================


@tool
@idaread
def get_stack_frame_variables(
    function_address: Annotated[str, "Address of the disassembled function to retrieve the stack frame variables"]
) -> list[dict]:
    """Retrieve the stack frame variables for a given function"""
    try:
        ea = parse_address(function_address)
        vars = get_stack_frame_variables_internal(ea, True)
        return vars
    except Exception as e:
        raise Exception(f"Failed to get stack frame variables: {str(e)}")


@tool
@idawrite
def create_stack_frame_variable(
    function_address: Annotated[str, "Address of the disassembled function to set the stack frame variables"],
    offset: Annotated[str, "Offset of the stack frame variable"],
    variable_name: Annotated[str, "Name of the stack variable"],
    type_name: Annotated[str, "Type of the stack variable"],
):
    """For a given function, create a stack variable at an offset and with a specific type"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            raise Exception("No function found")

        ea = parse_address(offset)

        frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame_tif, func):
            raise Exception("No frame returned")

        tif = get_type_by_name(type_name)
        if not ida_frame.define_stkvar(func, variable_name, ea, tif):
            raise Exception("Failed to define stack variable")

        return {"ok": True, "function_address": function_address, "variable_name": variable_name}
    except Exception as e:
        raise Exception(f"Failed to create stack frame variable: {str(e)}")


@tool
@idawrite
def set_stack_frame_variable_type(
    function_address: Annotated[str, "Address of the disassembled function to set the stack frame variables"],
    variable_name: Annotated[str, "Name of the stack variable"],
    type_name: Annotated[str, "Type of the stack variable"],
):
    """For a given disassembled function, set the type of a stack variable"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            raise Exception("No function found")

        frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame_tif, func):
            raise Exception("No frame returned")

        idx, udm = frame_tif.get_udm(variable_name)
        if not udm:
            raise Exception(f"Variable '{variable_name}' not found")

        tid = frame_tif.get_udm_tid(idx)
        if ida_frame.is_special_frame_member(tid):
            raise Exception(f"'{variable_name}' is a special frame member")

        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset = udm.offset // 8

        if ida_frame.is_funcarg_off(func, offset):
            raise Exception(f"'{variable_name}' is an argument member")

        tif = get_type_by_name(type_name)
        sval = ida_frame.soff_to_fpoff(func, offset)
        if not ida_frame.define_stkvar(func, variable_name, sval, tif):
            raise Exception("Failed to set stack variable type")

        return {"ok": True, "function_address": function_address, "variable_name": variable_name, "type_name": type_name}
    except Exception as e:
        raise Exception(f"Failed to set stack frame variable type: {str(e)}")


@tool
@idawrite
def rename_stack_frame_variable(
    function_address: Annotated[str, "Address of the disassembled function to set the stack frame variables"],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"],
):
    """Change the name of a stack variable for an IDA function"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            raise Exception("No function found")

        frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame_tif, func):
            raise Exception("No frame returned")

        idx, udm = frame_tif.get_udm(old_name)
        if not udm:
            raise Exception(f"Variable '{old_name}' not found")

        tid = frame_tif.get_udm_tid(idx)
        if ida_frame.is_special_frame_member(tid):
            raise Exception(f"'{old_name}' is a special frame member")

        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset = udm.offset // 8

        if ida_frame.is_funcarg_off(func, offset):
            raise Exception(f"'{old_name}' is an argument member")

        sval = ida_frame.soff_to_fpoff(func, offset)
        if not ida_frame.define_stkvar(func, new_name, sval, udm.type):
            raise Exception("Failed to rename stack variable")

        return {"ok": True, "function_address": function_address, "old_name": old_name, "new_name": new_name}
    except Exception as e:
        raise Exception(f"Failed to rename stack frame variable: {str(e)}")


@tool
@idawrite
def delete_stack_frame_variable(
    function_address: Annotated[str, "Address of the function to set the stack frame variables"],
    variable_name: Annotated[str, "Name of the stack variable"],
):
    """Delete the named stack variable for a given function"""
    try:
        func = idaapi.get_func(parse_address(function_address))
        if not func:
            raise Exception("No function found")

        frame_tif = ida_typeinf.tinfo_t()
        if not ida_frame.get_func_frame(frame_tif, func):
            raise Exception("No frame returned")

        idx, udm = frame_tif.get_udm(variable_name)
        if not udm:
            raise Exception(f"Variable '{variable_name}' not found")

        tid = frame_tif.get_udm_tid(idx)
        if ida_frame.is_special_frame_member(tid):
            raise Exception(f"'{variable_name}' is a special frame member")

        udm = ida_typeinf.udm_t()
        frame_tif.get_udm_by_tid(udm, tid)
        offset = udm.offset // 8
        size = udm.size // 8

        if ida_frame.is_funcarg_off(func, offset):
            raise Exception(f"'{variable_name}' is an argument member")

        if not ida_frame.delete_frame_members(func, offset, offset + size):
            raise Exception("Failed to delete stack variable")

        return {"ok": True, "function_address": function_address, "variable_name": variable_name}
    except Exception as e:
        raise Exception(f"Failed to delete stack frame variable: {str(e)}")
