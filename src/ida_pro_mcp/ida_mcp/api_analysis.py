from typing import Annotated, Optional
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_funcs
import idaapi
import idautils
import idc
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_ida
import ida_entry
import ida_search
import ida_idaapi
import ida_xref
from .rpc import tool
from .sync import idaread, is_window_active
from .utils import (
    parse_address,
    normalize_list_input,
    get_function,
    get_prototype,
    get_stack_frame_variables_internal,
    decompile_checked,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callees,
    get_callers,
    get_xrefs_from_internal,
    extract_function_strings,
    extract_function_constants,
    Function,
    Argument,
    DisassemblyFunction,
    Xref,
    FunctionAnalysis,
    BasicBlock,
    PathQuery,
    StructFieldQuery,
    StringFilter,
    InsnPattern,
)

# ============================================================================
# String Cache
# ============================================================================

# Cache for idautils.Strings() to avoid rebuilding on every call
_strings_cache: Optional[list[dict]] = None
_strings_cache_md5: Optional[str] = None


def _get_cached_strings_dict() -> list[dict]:
    """Get cached strings as dicts, rebuilding if IDB changed"""
    global _strings_cache, _strings_cache_md5

    # Get current IDB modification hash
    current_md5 = ida_nalt.retrieve_input_file_md5()

    # Rebuild cache if needed
    if _strings_cache is None or _strings_cache_md5 != current_md5:
        _strings_cache = []
        for s in idautils.Strings():
            try:
                _strings_cache.append(
                    {
                        "addr": hex(s.ea),
                        "length": s.length,
                        "string": str(s),
                        "type": s.strtype,
                    }
                )
            except Exception:
                pass
        _strings_cache_md5 = current_md5

    return _strings_cache


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idaread
def decompile_function(
    addrs: Annotated[list[str] | str, "Function addresses to decompile"],
    max_lines: Annotated[int, "Max lines per function (default: 2000, max: 10000, 0 for all)"] = 2000,
    offset: Annotated[int, "Skip first N lines (default: 0)"] = 0,
) -> list[dict]:
    """Decompile functions to pseudocode with line-based pagination"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit (0 means no limit up to 10000)
    if max_lines < 0 or max_lines > 10000:
        max_lines = 10000

    results = []

    for addr in addrs:
        try:
            start = parse_address(addr)
            cfunc = decompile_checked(start)
            if is_window_active():
                ida_hexrays.open_pseudocode(start, ida_hexrays.OPF_REUSE)
            sv = cfunc.get_pseudocode()

            # Collect all lines first
            all_lines = []
            for i, sl in enumerate(sv):
                sl: ida_kernwin.simpleline_t
                item = ida_hexrays.ctree_item_t()
                ea = None if i > 0 else cfunc.entry_ea
                if cfunc.get_line_item(sl.line, 0, False, None, item, None):
                    dstr: str | None = item.dstr()
                    if dstr:
                        ds = dstr.split(": ")
                        if len(ds) == 2:
                            try:
                                ea = int(ds[0], 16)
                            except ValueError:
                                pass
                line = ida_lines.tag_remove(sl.line)
                if not ea:
                    all_lines.append(f"/* line: {i} */ {line}")
                else:
                    all_lines.append(f"/* line: {i}, address: {hex(ea)} */ {line}")

            total_lines = len(all_lines)

            # Apply pagination
            if max_lines == 0:
                paginated_lines = all_lines[offset:]
                has_more = False
            else:
                paginated_lines = all_lines[offset : offset + max_lines]
                has_more = offset + max_lines < total_lines

            code = "\n".join(paginated_lines)

            results.append({
                "addr": addr,
                "code": code,
                "line_count": len(paginated_lines),
                "total_lines": total_lines,
                "cursor": {"next": offset + max_lines} if has_more else {"done": True},
            })
        except Exception as e:
            results.append({
                "addr": addr,
                "code": None,
                "error": str(e),
                "cursor": {"done": True},
            })

    return results


@tool
@idaread
def disassemble_function(
    addrs: Annotated[list[str] | str, "Function addresses to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
) -> list[dict]:
    """Disassemble functions to assembly instructions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000

    results = []

    for start_addr in addrs:
        try:
            start = parse_address(start_addr)
            func = idaapi.get_func(start)

            if is_window_active():
                ida_kernwin.jumpto(start)

            # Get segment info
            seg = idaapi.getseg(start)
            if not seg:
                results.append(
                    {
                        "addr": start_addr,
                        "asm": None,
                        "error": "No segment found",
                        "cursor": {"done": True},
                    }
                )
                continue

            segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

            # Collect instructions
            all_instructions = []

            if func:
                # Function exists: disassemble function items starting from requested address
                func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                header_addr = start  # Use requested address, not function start

                for ea in idautils.FuncItems(func.start_ea):
                    if ea == idaapi.BADADDR:
                        continue
                    # Skip instructions before the requested start address
                    if ea < start:
                        continue

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))
            else:
                # No function: disassemble sequentially from start address
                func_name = f"<no function>"
                header_addr = start

                ea = start
                while ea < seg.end_ea and len(all_instructions) < max_instructions + offset:
                    if ea == idaapi.BADADDR:
                        break

                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, ea) == 0:
                        break

                    # Use generate_disasm_line to get full line with comments
                    line = idc.generate_disasm_line(ea, 0)
                    instruction = ida_lines.tag_remove(line) if line else ""
                    all_instructions.append((ea, instruction))

                    ea = idc.next_head(ea, seg.end_ea)

            # Apply pagination
            total_insns = len(all_instructions)
            paginated_insns = all_instructions[offset : offset + max_instructions]
            has_more = offset + max_instructions < total_insns

            # Build disassembly string from paginated instructions
            lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
            for ea, instruction in paginated_insns:
                lines_str += f"\n{ea:x}  {instruction}"

            rettype = None
            args: Optional[list[Argument]] = None
            stack_frame = None

            if func:
                tif = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
                    ftd = ida_typeinf.func_type_data_t()
                    if tif.get_func_details(ftd):
                        rettype = str(ftd.rettype)
                        args = [
                            Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                            for i, a in enumerate(ftd)
                        ]
                stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(header_addr),
                "lines": lines_str,
            }
            if stack_frame:
                out["stack_frame"] = stack_frame
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            results.append(
                {
                    "addr": start_addr,
                    "asm": out,
                    "instruction_count": len(paginated_insns),
                    "total_instructions": total_insns,
                    "cursor": (
                        {"next": offset + max_instructions}
                        if has_more
                        else {"done": True}
                    ),
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": start_addr,
                    "asm": None,
                    "error": str(e),
                    "cursor": {"done": True},
                }
            )

    return results


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idaread
def get_xrefs_to(
    addrs: Annotated[list[str] | str, "Addresses to find cross-references to"],
    limit: Annotated[int, "Max xrefs per address (default: 500, max: 5000)"] = 500,
    offset: Annotated[int, "Skip first N xrefs (default: 0)"] = 0,
) -> list[dict]:
    """Get cross-references to specified addresses with pagination"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if limit <= 0 or limit > 5000:
        limit = 5000

    results = []

    for addr in addrs:
        try:
            all_xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(parse_address(addr)):
                all_xrefs.append(
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                )

            # Apply pagination
            total_xrefs = len(all_xrefs)
            paginated_xrefs = all_xrefs[offset : offset + limit]
            has_more = offset + limit < total_xrefs

            results.append({
                "addr": addr,
                "xrefs": paginated_xrefs,
                "count": len(paginated_xrefs),
                "total": total_xrefs,
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            })
        except Exception as e:
            results.append({
                "addr": addr,
                "xrefs": None,
                "error": str(e),
                "cursor": {"done": True},
            })

    return results


@tool
@idaread
def get_xrefs_to_field(
    queries: list[StructFieldQuery] | StructFieldQuery,
    limit: Annotated[int, "Max xrefs per field (default: 500, max: 5000)"] = 500,
    offset: Annotated[int, "Skip first N xrefs (default: 0)"] = 0,
) -> list[dict]:
    """Get cross-references to structure fields with pagination"""
    if isinstance(queries, dict):
        queries = [queries]

    # Enforce max limit
    if limit <= 0 or limit > 5000:
        limit = 5000

    results = []
    til = ida_typeinf.get_idati()
    if not til:
        return [
            {
                "struct": q.get("struct"),
                "field": q.get("field"),
                "xrefs": [],
                "error": "Failed to retrieve type library",
                "cursor": {"done": True},
            }
            for q in queries
        ]

    for query in queries:
        struct_name = query.get("struct", "")
        field_name = query.get("field", "")

        try:
            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(
                til, struct_name, ida_typeinf.BTF_STRUCT, True, False
            ):
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Struct '{struct_name}' not found",
                        "cursor": {"done": True},
                    }
                )
                continue

            idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
            if idx == -1:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": f"Field '{field_name}' not found in '{struct_name}'",
                        "cursor": {"done": True},
                    }
                )
                continue

            tid = tif.get_udm_tid(idx)
            if tid == ida_idaapi.BADADDR:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": "Unable to get tid",
                        "cursor": {"done": True},
                    }
                )
                continue

            all_xrefs = []
            xref: ida_xref.xrefblk_t
            for xref in idautils.XrefsTo(tid):
                all_xrefs.append(
                    Xref(
                        addr=hex(xref.frm),
                        type="code" if xref.iscode else "data",
                        fn=get_function(xref.frm, raise_error=False),
                    )
                )

            # Apply pagination
            total_xrefs = len(all_xrefs)
            paginated_xrefs = all_xrefs[offset : offset + limit]
            has_more = offset + limit < total_xrefs

            results.append({
                "struct": struct_name,
                "field": field_name,
                "xrefs": paginated_xrefs,
                "count": len(paginated_xrefs),
                "total": total_xrefs,
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            })
        except Exception as e:
            results.append(
                {
                    "struct": struct_name,
                    "field": field_name,
                    "xrefs": [],
                    "error": str(e),
                    "cursor": {"done": True},
                }
            )

    return results


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idaread
def get_callees(
    addrs: Annotated[list[str] | str, "Function addresses to get callees for"],
    limit: Annotated[int, "Max callees per function (default: 200, max: 2000)"] = 200,
    offset: Annotated[int, "Skip first N callees (default: 0)"] = 0,
) -> list[dict]:
    """Get functions called by the specified functions with pagination"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if limit <= 0 or limit > 2000:
        limit = 2000

    results = []

    for fn_addr in addrs:
        try:
            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append({
                    "addr": fn_addr,
                    "callees": None,
                    "error": "No function found",
                    "cursor": {"done": True},
                })
                continue
            func_end = idc.find_func_end(func_start)
            all_callees: list[dict[str, str]] = []
            current_ea = func_start
            while current_ea < func_end:
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, current_ea)
                if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    target = idc.get_operand_value(current_ea, 0)
                    target_type = idc.get_operand_type(current_ea, 0)
                    if target_type in [idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                        func_type = (
                            "internal"
                            if idaapi.get_func(target) is not None
                            else "external"
                        )
                        func_name = idc.get_name(target)
                        if func_name is not None:
                            all_callees.append(
                                {
                                    "addr": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                            )
                current_ea = idc.next_head(current_ea, func_end)

            unique_callee_tuples = {tuple(callee.items()) for callee in all_callees}
            unique_callees = [dict(callee) for callee in unique_callee_tuples]

            # Apply pagination
            total_callees = len(unique_callees)
            paginated_callees = unique_callees[offset : offset + limit]
            has_more = offset + limit < total_callees

            results.append({
                "addr": fn_addr,
                "callees": paginated_callees,
                "count": len(paginated_callees),
                "total": total_callees,
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            })
        except Exception as e:
            results.append({
                "addr": fn_addr,
                "callees": None,
                "error": str(e),
                "cursor": {"done": True},
            })

    return results


@tool
@idaread
def get_callers(
    addrs: Annotated[list[str] | str, "Function addresses to get callers for"],
    limit: Annotated[int, "Max callers per function (default: 200, max: 2000)"] = 200,
    offset: Annotated[int, "Skip first N callers (default: 0)"] = 0,
) -> list[dict]:
    """Get functions that call the specified functions with pagination"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if limit <= 0 or limit > 2000:
        limit = 2000

    results = []

    for fn_addr in addrs:
        try:
            all_callers = {}
            for caller_addr in idautils.CodeRefsTo(parse_address(fn_addr), 0):
                func = get_function(caller_addr, raise_error=False)
                if not func:
                    continue
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, caller_addr)
                if insn.itype not in [
                    idaapi.NN_call,
                    idaapi.NN_callfi,
                    idaapi.NN_callni,
                ]:
                    continue
                all_callers[func["addr"]] = func

            caller_list = list(all_callers.values())

            # Apply pagination
            total_callers = len(caller_list)
            paginated_callers = caller_list[offset : offset + limit]
            has_more = offset + limit < total_callers

            results.append({
                "addr": fn_addr,
                "callers": paginated_callers,
                "count": len(paginated_callers),
                "total": total_callers,
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            })
        except Exception as e:
            results.append({
                "addr": fn_addr,
                "callers": None,
                "error": str(e),
                "cursor": {"done": True},
            })

    return results


@tool
@idaread
def get_entry_points(
    limit: Annotated[int, "Max entrypoints to return (default: 500, max: 5000)"] = 500,
    offset: Annotated[int, "Skip first N entrypoints (default: 0)"] = 0,
) -> dict:
    """Get entry points with pagination"""
    # Enforce max limit
    if limit <= 0 or limit > 5000:
        limit = 5000

    all_entries = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        addr = ida_entry.get_entry(ordinal)
        func = get_function(addr, raise_error=False)
        if func is not None:
            all_entries.append(func)

    # Apply pagination
    total_entries = len(all_entries)
    paginated_entries = all_entries[offset : offset + limit]
    has_more = offset + limit < total_entries

    return {
        "entrypoints": paginated_entries,
        "count": len(paginated_entries),
        "total": total_entries,
        "cursor": {"next": offset + limit} if has_more else {"done": True},
    }


# ============================================================================
# Comprehensive Function Analysis
# ============================================================================


@tool
@idaread
def analyze_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to comprehensively analyze"],
    include_code: Annotated[bool, "Include decompiled pseudocode (default: True)"] = True,
    include_asm: Annotated[bool, "Include assembly (default: True)"] = True,
    max_xrefs: Annotated[int, "Max xrefs per direction (default: 100)"] = 100,
    max_calls: Annotated[int, "Max callees/callers (default: 50)"] = 50,
    max_strings: Annotated[int, "Max strings (default: 100)"] = 100,
    max_constants: Annotated[int, "Max constants (default: 100)"] = 100,
    max_blocks: Annotated[int, "Max basic blocks (default: 200)"] = 200,
) -> list[FunctionAnalysis]:
    """Comprehensive function analysis with configurable limits to prevent token overflow"""
    addrs = normalize_list_input(addrs)
    results = []
    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)

            if not func:
                results.append(
                    FunctionAnalysis(
                        addr=addr,
                        name=None,
                        code=None,
                        asm=None,
                        xto=[],
                        xfrom=[],
                        callees=[],
                        callers=[],
                        strings=[],
                        constants=[],
                        blocks=[],
                        error="Function not found",
                    )
                )
                continue

            # Get basic blocks with limit
            flowchart = idaapi.FlowChart(func)
            blocks = []
            for i, block in enumerate(flowchart):
                if i >= max_blocks:
                    break
                blocks.append(
                    {
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "type": block.type,
                    }
                )

            # Collect xrefs with limit
            xto_list = []
            for i, x in enumerate(idautils.XrefsTo(ea, 0)):
                if i >= max_xrefs:
                    break
                xto_list.append(
                    Xref(
                        addr=hex(x.frm),
                        type="code" if x.iscode else "data",
                        fn=get_function(x.frm, raise_error=False),
                    )
                )

            xfrom_list = get_xrefs_from_internal(ea)[:max_xrefs]
            callees_list = get_callees(addr)[:max_calls]
            callers_list = get_callers(addr)[:max_calls]
            strings_list = extract_function_strings(ea)[:max_strings]
            constants_list = extract_function_constants(ea)[:max_constants]

            result = FunctionAnalysis(
                addr=addr,
                name=ida_funcs.get_func_name(func.start_ea),
                code=decompile_function_safe(ea) if include_code else None,
                asm=get_assembly_lines(ea) if include_asm else None,
                xto=xto_list,
                xfrom=xfrom_list,
                callees=callees_list,
                callers=callers_list,
                strings=strings_list,
                constants=constants_list,
                blocks=blocks,
                error=None,
            )
            results.append(result)
        except Exception as e:
            results.append(
                FunctionAnalysis(
                    addr=addr,
                    name=None,
                    code=None,
                    asm=None,
                    xto=[],
                    xfrom=[],
                    callees=[],
                    callers=[],
                    strings=[],
                    constants=[],
                    blocks=[],
                    error=str(e),
                )
            )
    return results


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idaread
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    patterns = normalize_list_input(patterns)

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = []
        try:
            # Parse the pattern
            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                    }
                )
                continue

            # Search for all matches
            ea = ida_ida.inf_get_min_ea()
            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, ida_ida.inf_get_max_ea(), compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    all_matches.append(hex(ea))
                    ea += 1
        except Exception:
            pass

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


@tool
@idaread
def find_insns(
    sequences: Annotated[
        list[list[str]] | list[str], "Instruction mnemonic sequences to search for"
    ],
    limit: Annotated[
        int, "Max matches per sequence (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for sequences of instruction mnemonics in the binary"""
    # Handle single sequence vs array of sequences
    if sequences and isinstance(sequences[0], str):
        sequences = [sequences]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    for sequence in sequences:
        if not sequence:
            results.append(
                {
                    "sequence": sequence,
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                }
            )
            continue

        all_matches = []
        # Scan all code segments
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                continue

            ea = seg.start_ea
            while ea < seg.end_ea:
                # Try to match sequence starting at ea
                match_ea = ea
                matched = True

                for expected_mnem in sequence:
                    insn = idaapi.insn_t()
                    if idaapi.decode_insn(insn, match_ea) == 0:
                        matched = False
                        break

                    actual_mnem = idc.print_insn_mnem(match_ea)
                    if actual_mnem != expected_mnem:
                        matched = False
                        break

                    match_ea = idc.next_head(match_ea, seg.end_ea)
                    if match_ea == idaapi.BADADDR:
                        matched = False
                        break

                if matched:
                    all_matches.append(hex(ea))

                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "sequence": sequence,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idaread
def basic_blocks(
    addrs: Annotated[list[str] | str, "Function addresses to get basic blocks for"],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Get control flow graph basic blocks for functions"""
    addrs = normalize_list_input(addrs)

    # Enforce max limit
    if max_blocks <= 0 or max_blocks > 10000:
        max_blocks = 10000

    results = []
    for fn_addr in addrs:
        try:
            ea = parse_address(fn_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": "Function not found",
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
                continue

            flowchart = idaapi.FlowChart(func)
            all_blocks = []

            for block in flowchart:
                all_blocks.append(
                    BasicBlock(
                        start=hex(block.start_ea),
                        end=hex(block.end_ea),
                        size=block.end_ea - block.start_ea,
                        type=block.type,
                        successors=[hex(succ.start_ea) for succ in block.succs()],
                        predecessors=[hex(pred.start_ea) for pred in block.preds()],
                    )
                )

            # Apply pagination
            total_blocks = len(all_blocks)
            blocks = all_blocks[offset : offset + max_blocks]
            has_more = offset + max_blocks < total_blocks

            results.append(
                {
                    "addr": fn_addr,
                    "blocks": blocks,
                    "count": len(blocks),
                    "total_blocks": total_blocks,
                    "cursor": (
                        {"next": offset + max_blocks} if has_more else {"done": True}
                    ),
                    "error": None,
                }
            )
        except Exception as e:
            results.append(
                {
                    "addr": fn_addr,
                    "error": str(e),
                    "blocks": [],
                    "cursor": {"done": True},
                }
            )
    return results


@tool
@idaread
def find_paths(
    queries: list[PathQuery] | PathQuery,
    max_paths: Annotated[int, "Maximum paths to find per query (default: 10, max: 50)"] = 10,
    max_depth: Annotated[int, "Maximum path depth in blocks (default: 20, max: 100)"] = 20,
) -> list[dict]:
    """Find execution paths between source and target addresses with configurable limits"""
    if isinstance(queries, dict):
        queries = [queries]

    # Enforce limits
    if max_paths <= 0 or max_paths > 50:
        max_paths = 50
    if max_depth <= 0 or max_depth > 100:
        max_depth = 100

    results = []

    for query in queries:
        source = parse_address(query["source"])
        target = parse_address(query["target"])

        # Get containing function
        func = idaapi.get_func(source)
        if not func:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Source not in a function",
                }
            )
            continue

        # Build flow graph
        flowchart = idaapi.FlowChart(func)

        # Find source and target blocks
        source_block = None
        target_block = None
        for block in flowchart:
            if block.start_ea <= source < block.end_ea:
                source_block = block
            if block.start_ea <= target < block.end_ea:
                target_block = block

        if not source_block or not target_block:
            results.append(
                {
                    "source": query["source"],
                    "target": query["target"],
                    "paths": [],
                    "reachable": False,
                    "error": "Could not find basic blocks",
                }
            )
            continue

        # Simple BFS to find paths
        paths = []
        queue = [([source_block], {source_block.id})]

        while queue and len(paths) < max_paths:
            path, visited = queue.pop(0)
            current = path[-1]

            if current.id == target_block.id:
                paths.append([hex(b.start_ea) for b in path])
                continue

            for succ in current.succs():
                if succ.id not in visited and len(path) < max_depth:
                    queue.append((path + [succ], visited | {succ.id}))

        results.append(
            {
                "source": query["source"],
                "target": query["target"],
                "paths": paths,
                "path_count": len(paths),
                "reachable": len(paths) > 0,
                "error": None,
            }
        )

    return results


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idaread
def search(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Search for patterns in the binary (strings, immediate values, or references)"""
    if not isinstance(targets, list):
        targets = [targets]

    # Enforce max limit to prevent token overflow
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []

    if type == "string":
        # Search for strings containing pattern
        all_strings = _get_cached_strings_dict()
        for pattern in targets:
            pattern_str = str(pattern)
            all_matches = [
                s["addr"]
                for s in all_strings
                if pattern_str.lower() in s["string"].lower()
            ]

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": pattern_str,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "immediate":
        # Search for immediate values
        for value in targets:
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError:
                    value = 0

            all_matches = []
            try:
                ea = ida_ida.inf_get_min_ea()
                while ea < ida_ida.inf_get_max_ea():
                    result = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, value)
                    if result[0] == idaapi.BADADDR:
                        break
                    all_matches.append(hex(result[0]))
                    ea = result[0] + 1
            except Exception:
                pass

            # Apply pagination
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)

            results.append(
                {
                    "query": value,
                    "matches": matches,
                    "count": len(matches),
                    "cursor": {"next": offset + limit} if has_more else {"done": True},
                    "error": None,
                }
            )

    elif type == "data_ref":
        # Find all data references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.DataRefsTo(target)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    elif type == "code_ref":
        # Find all code references to targets
        for target_str in targets:
            try:
                target = parse_address(str(target_str))
                all_matches = [hex(xref) for xref in idautils.CodeRefsTo(target, 0)]

                # Apply pagination
                if limit > 0:
                    matches = all_matches[offset : offset + limit]
                    has_more = offset + limit < len(all_matches)
                else:
                    matches = all_matches[offset:]
                    has_more = False

                results.append(
                    {
                        "query": str(target_str),
                        "matches": matches,
                        "count": len(matches),
                        "cursor": (
                            {"next": offset + limit} if has_more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": str(target_str),
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )

    else:
        results.append(
            {
                "query": None,
                "matches": [],
                "count": 0,
                "cursor": {"done": True},
                "error": f"Unknown search type: {type}",
            }
        )

    return results


@tool
@idaread
def find_insn_operands(
    patterns: list[InsnPattern] | InsnPattern,
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Find instructions with specific mnemonics and operand values"""
    if isinstance(patterns, dict):
        patterns = [patterns]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in patterns:
        all_matches = _find_insn_pattern(pattern)

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )
    return results


def _find_insn_pattern(pattern: dict) -> list[str]:
    """Internal helper to find instructions matching a pattern"""
    mnem = pattern.get("mnem", "").lower()
    op0_val = pattern.get("op0")
    op1_val = pattern.get("op1")
    op2_val = pattern.get("op2")
    any_val = pattern.get("op_any")

    matches = []

    # Scan all executable segments
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
            continue

        ea = seg.start_ea
        while ea < seg.end_ea:
            # Check mnemonic
            if mnem and idc.print_insn_mnem(ea).lower() != mnem:
                ea = idc.next_head(ea, seg.end_ea)
                if ea == idaapi.BADADDR:
                    break
                continue

            # Check specific operand positions
            match = True
            if op0_val is not None:
                if idc.get_operand_value(ea, 0) != op0_val:
                    match = False

            if op1_val is not None:
                if idc.get_operand_value(ea, 1) != op1_val:
                    match = False

            if op2_val is not None:
                if idc.get_operand_value(ea, 2) != op2_val:
                    match = False

            # Check any operand
            if any_val is not None and match:
                found_any = False
                for i in range(8):
                    if idc.get_operand_type(ea, i) == idaapi.o_void:
                        break
                    if idc.get_operand_value(ea, i) == any_val:
                        found_any = True
                        break
                if not found_any:
                    match = False

            if match:
                matches.append(hex(ea))

            ea = idc.next_head(ea, seg.end_ea)
            if ea == idaapi.BADADDR:
                break

    return matches


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idaread
def export_funcs(
    addrs: Annotated[list[str] | str, "Function addresses to export"],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
    include_code: Annotated[bool, "Include decompiled pseudocode in json format"] = True,
    include_asm: Annotated[bool, "Include assembly in json format"] = True,
    max_funcs: Annotated[int, "Max functions to export (default: 20, max: 100)"] = 20,
) -> dict:
    """Export function data in various formats with configurable limits"""
    addrs = normalize_list_input(addrs)

    # Enforce max functions limit
    if max_funcs <= 0 or max_funcs > 100:
        max_funcs = 100

    truncated = len(addrs) > max_funcs
    addrs = addrs[:max_funcs]

    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_data = {
                "addr": addr,
                "name": ida_funcs.get_func_name(func.start_ea),
                "prototype": get_prototype(func),
                "size": hex(func.end_ea - func.start_ea),
                "comments": get_all_comments(ea),
            }

            if format == "json":
                if include_asm:
                    func_data["asm"] = get_assembly_lines(ea)
                if include_code:
                    func_data["code"] = decompile_function_safe(ea)
                func_data["xrefs"] = get_all_xrefs(ea)

            results.append(func_data)

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    if format == "c_header":
        # Generate C header file
        lines = ["// Auto-generated by IDA Pro MCP", ""]
        for func in results:
            if "prototype" in func and func["prototype"]:
                lines.append(f"{func['prototype']};")
        return {"format": "c_header", "content": "\n".join(lines), "truncated": truncated}

    elif format == "prototypes":
        # Just prototypes
        prototypes = []
        for func in results:
            if "prototype" in func and func["prototype"]:
                prototypes.append(
                    {"name": func.get("name"), "prototype": func["prototype"]}
                )
        return {"format": "prototypes", "functions": prototypes, "truncated": truncated}

    return {"format": "json", "functions": results, "count": len(results), "truncated": truncated}


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idaread
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal (default: 5)"] = 5,
    max_nodes: Annotated[int, "Maximum nodes to return (default: 500, max: 5000)"] = 500,
    max_edges: Annotated[int, "Maximum edges to return (default: 2000, max: 10000)"] = 2000,
) -> list[dict]:
    """Build call graph starting from root functions with node and edge limits"""
    roots = normalize_list_input(roots)

    # Enforce max limits
    if max_depth <= 0 or max_depth > 20:
        max_depth = 20
    if max_nodes <= 0 or max_nodes > 5000:
        max_nodes = 5000
    if max_edges <= 0 or max_edges > 10000:
        max_edges = 10000

    results = []

    for root in roots:
        try:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "root": root,
                        "error": "Function not found",
                        "nodes": [],
                        "edges": [],
                        "truncated": False,
                    }
                )
                continue

            nodes = {}
            edges_set = set()  # Use set for deduplication
            visited = set()
            truncated = False

            def traverse(addr, depth):
                nonlocal truncated
                if depth > max_depth or addr in visited:
                    return
                if len(nodes) >= max_nodes or len(edges_set) >= max_edges:
                    truncated = True
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                func_name = ida_funcs.get_func_name(f.start_ea)
                nodes[hex(addr)] = {
                    "addr": hex(addr),
                    "name": func_name,
                    "depth": depth,
                }

                # Get callees
                for item_ea in idautils.FuncItems(f.start_ea):
                    if len(nodes) >= max_nodes or len(edges_set) >= max_edges:
                        truncated = True
                        return
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee_func = idaapi.get_func(xref)
                        if callee_func:
                            # Deduplicate edges using tuple key
                            edge_key = (hex(addr), hex(callee_func.start_ea))
                            if edge_key not in edges_set:
                                edges_set.add(edge_key)
                            traverse(callee_func.start_ea, depth + 1)

            traverse(ea, 0)

            # Convert edge set to list of dicts
            edges = [
                {"from": e[0], "to": e[1], "type": "call"}
                for e in edges_set
            ]

            results.append(
                {
                    "root": root,
                    "nodes": list(nodes.values()),
                    "edges": edges,
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                    "max_depth": max_depth,
                    "max_nodes": max_nodes,
                    "max_edges": max_edges,
                    "truncated": truncated,
                    "error": None,
                }
            )

        except Exception as e:
            results.append({
                "root": root,
                "error": str(e),
                "nodes": [],
                "edges": [],
                "truncated": False,
            })

    return results


# ============================================================================
# Cross-Reference Matrix
# ============================================================================


@tool
@idaread
def xref_matrix(
    entities: Annotated[
        list[str] | str, "Addresses to build cross-reference matrix for"
    ],
    max_entities: Annotated[int, "Max entities to process (default: 50, max: 200)"] = 50,
) -> dict:
    """Build matrix showing cross-references between entities (O(n^2) complexity)"""
    entities = normalize_list_input(entities)

    # Enforce max entities to prevent O(n^2) explosion
    if max_entities <= 0 or max_entities > 200:
        max_entities = 200

    truncated = len(entities) > max_entities
    entities = entities[:max_entities]

    matrix = {}

    for source in entities:
        try:
            source_ea = parse_address(source)
            matrix[source] = {}

            for target in entities:
                if source == target:
                    continue

                target_ea = parse_address(target)

                # Count references from source to target
                count = 0
                for xref in idautils.XrefsFrom(source_ea, 0):
                    if xref.to == target_ea:
                        count += 1

                if count > 0:
                    matrix[source][target] = count

        except Exception:
            matrix[source] = {"error": "Failed to process"}

    return {
        "matrix": matrix,
        "entities": entities,
        "entity_count": len(entities),
        "truncated": truncated,
    }


# ============================================================================
# String Analysis
# ============================================================================


@tool
@idaread
def analyze_strings(
    filters: list[StringFilter] | StringFilter,
    limit: Annotated[int, "Max matches per filter (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> list[dict]:
    """Analyze and filter strings in the binary"""
    if isinstance(filters, dict):
        filters = [filters]

    # Enforce max limit
    if limit <= 0 or limit > 10000:
        limit = 10000

    # Use cached strings to avoid rebuilding on every call
    all_strings = _get_cached_strings_dict()

    results = []

    for filt in filters:
        pattern = filt.get("pattern", "").lower()
        min_length = filt.get("min_length", 0)

        # Find all matching strings
        all_matches = []
        for s in all_strings:
            if len(s["string"]) < min_length:
                continue
            if pattern and pattern not in s["string"].lower():
                continue

            # Add xref info
            s_ea = parse_address(s["addr"])
            xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea, 0)]
            all_matches.append({**s, "xrefs": xrefs, "xref_count": len(xrefs)})

        # Apply pagination
        if limit > 0:
            matches = all_matches[offset : offset + limit]
            has_more = offset + limit < len(all_matches)
        else:
            matches = all_matches[offset:]
            has_more = False

        results.append(
            {
                "filter": filt,
                "matches": matches,
                "count": len(matches),
                "cursor": {"next": offset + limit} if has_more else {"done": True},
            }
        )

    return results
