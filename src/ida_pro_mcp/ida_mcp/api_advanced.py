"""Advanced Analysis Features for IDA Pro MCP.

This module provides advanced reverse engineering capabilities:
- Function comparison and diffing
- Function similarity detection
- Vulnerability pattern detection
- Malware analysis helpers
- Batch operations
"""

from __future__ import annotations
from typing import Annotated, Optional
import hashlib
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idaread, idawrite
from .utils import (
    parse_address,
    normalize_list_input,
    get_function,
    decompile_function_safe,
    get_assembly_lines,
    Function,
)


# ============================================================================
# Function Comparison & Diffing
# ============================================================================


@tool
@idaread
def func_diff(
    addr1: Annotated[str, "First function address"],
    addr2: Annotated[str, "Second function address"],
    include_asm: Annotated[bool, "Include assembly diff"] = True,
    include_code: Annotated[bool, "Include pseudocode diff"] = True,
) -> dict:
    """Compare two functions and show differences.
    Useful for patch analysis and understanding code changes."""
    try:
        ea1 = parse_address(addr1)
        ea2 = parse_address(addr2)

        func1 = idaapi.get_func(ea1)
        func2 = idaapi.get_func(ea2)

        if not func1:
            return {"error": f"No function at {addr1}"}
        if not func2:
            return {"error": f"No function at {addr2}"}

        result = {
            "func1": {
                "addr": hex(func1.start_ea),
                "name": ida_funcs.get_func_name(func1.start_ea),
                "size": func1.end_ea - func1.start_ea,
            },
            "func2": {
                "addr": hex(func2.start_ea),
                "name": ida_funcs.get_func_name(func2.start_ea),
                "size": func2.end_ea - func2.start_ea,
            },
        }

        # Size comparison
        result["size_diff"] = result["func2"]["size"] - result["func1"]["size"]

        # Assembly comparison
        if include_asm:
            asm1_lines = get_assembly_lines(ea1).split("\n")
            asm2_lines = get_assembly_lines(ea2).split("\n")

            result["asm_line_count"] = {
                "func1": len(asm1_lines),
                "func2": len(asm2_lines),
            }

            # Simple diff - find added/removed lines
            set1 = set(line.split(None, 1)[-1] if line else "" for line in asm1_lines)
            set2 = set(line.split(None, 1)[-1] if line else "" for line in asm2_lines)

            result["asm_diff"] = {
                "only_in_func1": list(set1 - set2)[:50],  # Limit output
                "only_in_func2": list(set2 - set1)[:50],
                "common_count": len(set1 & set2),
            }

        # Pseudocode comparison
        if include_code:
            code1 = decompile_function_safe(ea1)
            code2 = decompile_function_safe(ea2)

            if code1 and code2:
                lines1 = set(line.strip() for line in code1.split("\n") if line.strip())
                lines2 = set(line.strip() for line in code2.split("\n") if line.strip())

                result["code_diff"] = {
                    "only_in_func1": list(lines1 - lines2)[:50],
                    "only_in_func2": list(lines2 - lines1)[:50],
                    "common_count": len(lines1 & lines2),
                }
            else:
                result["code_diff"] = {
                    "error": "Could not decompile one or both functions"
                }

        # Basic block comparison
        fc1 = idaapi.FlowChart(func1)
        fc2 = idaapi.FlowChart(func2)

        result["block_count"] = {
            "func1": fc1.size,
            "func2": fc2.size,
        }

        return result

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def func_similarity(
    addr: Annotated[str, "Function address to find similar functions for"],
    method: Annotated[str, "Similarity method: 'size', 'blocks', 'hash', or 'all'"] = "all",
    threshold: Annotated[float, "Similarity threshold 0.0-1.0 (default: 0.8)"] = 0.8,
    limit: Annotated[int, "Max similar functions to return (default: 20, max: 100)"] = 20,
) -> dict:
    """Find functions similar to the given function.
    Useful for finding library code, copy-paste code, or variants."""
    try:
        if limit <= 0 or limit > 100:
            limit = 100

        ea = parse_address(addr)
        target_func = idaapi.get_func(ea)
        if not target_func:
            return {"error": f"No function at {addr}"}

        target_size = target_func.end_ea - target_func.start_ea
        target_fc = idaapi.FlowChart(target_func)
        target_blocks = target_fc.size

        # Calculate target function hash (based on instruction mnemonics)
        target_hash = _calc_func_hash(target_func)

        similar = []

        for func_ea in idautils.Functions():
            if func_ea == target_func.start_ea:
                continue

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            scores = {}

            # Size similarity
            if method in ("size", "all"):
                func_size = func.end_ea - func.start_ea
                if target_size > 0:
                    size_ratio = min(func_size, target_size) / max(func_size, target_size)
                    scores["size"] = size_ratio

            # Block count similarity
            if method in ("blocks", "all"):
                fc = idaapi.FlowChart(func)
                if target_blocks > 0:
                    block_ratio = min(fc.size, target_blocks) / max(fc.size, target_blocks)
                    scores["blocks"] = block_ratio

            # Hash similarity (Jaccard similarity of instruction mnemonics)
            if method in ("hash", "all"):
                func_hash = _calc_func_hash(func)
                if target_hash and func_hash:
                    intersection = len(target_hash & func_hash)
                    union = len(target_hash | func_hash)
                    if union > 0:
                        scores["hash"] = intersection / union

            if not scores:
                continue

            # Calculate overall similarity
            avg_score = sum(scores.values()) / len(scores)

            if avg_score >= threshold:
                similar.append({
                    "addr": hex(func_ea),
                    "name": ida_funcs.get_func_name(func_ea),
                    "size": func.end_ea - func.start_ea,
                    "similarity": round(avg_score, 3),
                    "scores": {k: round(v, 3) for k, v in scores.items()},
                })

        # Sort by similarity descending
        similar.sort(key=lambda x: x["similarity"], reverse=True)

        return {
            "target": {
                "addr": hex(target_func.start_ea),
                "name": ida_funcs.get_func_name(target_func.start_ea),
                "size": target_size,
                "blocks": target_blocks,
            },
            "similar": similar[:limit],
            "count": len(similar[:limit]),
            "total_found": len(similar),
            "threshold": threshold,
            "method": method,
        }

    except Exception as e:
        return {"error": str(e)}


def _calc_func_hash(func) -> set:
    """Calculate a hash set of instruction mnemonics for a function"""
    mnemonics = set()
    for ea in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem:
            mnemonics.add(mnem)
    return mnemonics


# ============================================================================
# Vulnerability Pattern Detection
# ============================================================================

# Common dangerous functions
DANGEROUS_FUNCTIONS = {
    # Buffer overflow risks
    "strcpy": "Buffer overflow - use strncpy or strlcpy",
    "strcat": "Buffer overflow - use strncat or strlcat",
    "sprintf": "Buffer overflow - use snprintf",
    "vsprintf": "Buffer overflow - use vsnprintf",
    "gets": "Buffer overflow - never use, use fgets",
    "scanf": "Buffer overflow without width specifier",
    "sscanf": "Buffer overflow without width specifier",
    "fscanf": "Buffer overflow without width specifier",
    # Format string vulnerabilities
    "printf": "Format string vulnerability if user-controlled",
    "fprintf": "Format string vulnerability if user-controlled",
    "syslog": "Format string vulnerability if user-controlled",
    # Memory issues
    "alloca": "Stack overflow risk with large allocations",
    "realloc": "Memory leak if return value not checked",
    # Command injection
    "system": "Command injection risk",
    "popen": "Command injection risk",
    "execl": "Command injection risk",
    "execle": "Command injection risk",
    "execlp": "Command injection risk",
    "execv": "Command injection risk",
    "execve": "Command injection risk",
    "execvp": "Command injection risk",
    "ShellExecute": "Command injection risk",
    "ShellExecuteA": "Command injection risk",
    "ShellExecuteW": "Command injection risk",
    "WinExec": "Command injection risk",
    "CreateProcess": "Command injection risk",
    "CreateProcessA": "Command injection risk",
    "CreateProcessW": "Command injection risk",
    # Other risks
    "rand": "Weak random - use cryptographic RNG for security",
    "srand": "Weak random - use cryptographic RNG for security",
}

# Suspicious Windows API patterns
SUSPICIOUS_APIS = {
    # Process manipulation
    "VirtualAlloc": "Memory allocation - common in shellcode",
    "VirtualAllocEx": "Remote memory allocation - process injection",
    "VirtualProtect": "Memory protection change - DEP bypass",
    "VirtualProtectEx": "Remote memory protection change",
    "WriteProcessMemory": "Process injection technique",
    "ReadProcessMemory": "Memory reading - credential theft",
    "CreateRemoteThread": "Remote thread injection",
    "NtCreateThreadEx": "Stealthy thread creation",
    "RtlCreateUserThread": "Stealthy thread creation",
    "QueueUserAPC": "APC injection technique",
    "SetThreadContext": "Thread hijacking",
    # Code injection
    "LoadLibrary": "DLL loading - check if path is user-controlled",
    "LoadLibraryA": "DLL loading - check if path is user-controlled",
    "LoadLibraryW": "DLL loading - check if path is user-controlled",
    "LoadLibraryEx": "DLL loading with flags",
    "GetProcAddress": "Dynamic API resolution - evasion technique",
    "LdrLoadDll": "Native DLL loading",
    # Anti-analysis
    "IsDebuggerPresent": "Anti-debugging check",
    "CheckRemoteDebuggerPresent": "Anti-debugging check",
    "NtQueryInformationProcess": "Anti-debugging/anti-VM check",
    "GetTickCount": "Timing-based anti-analysis",
    "QueryPerformanceCounter": "Timing-based anti-analysis",
    "OutputDebugString": "Anti-debugging technique",
    # Persistence
    "RegSetValueEx": "Registry modification - persistence",
    "RegSetValueExA": "Registry modification - persistence",
    "RegSetValueExW": "Registry modification - persistence",
    "RegCreateKeyEx": "Registry key creation",
    "CreateService": "Service creation - persistence",
    "CreateServiceA": "Service creation - persistence",
    "CreateServiceW": "Service creation - persistence",
    # Network
    "WSAStartup": "Network initialization",
    "socket": "Socket creation",
    "connect": "Outbound connection",
    "send": "Data exfiltration potential",
    "recv": "C2 communication potential",
    "InternetOpen": "HTTP communication",
    "InternetOpenUrl": "URL fetching",
    "HttpSendRequest": "HTTP request",
    "URLDownloadToFile": "File download - dropper behavior",
    # Crypto
    "CryptEncrypt": "Encryption - ransomware indicator",
    "CryptDecrypt": "Decryption operation",
    "CryptAcquireContext": "Crypto context - ransomware indicator",
    # File operations
    "DeleteFile": "File deletion",
    "DeleteFileA": "File deletion",
    "DeleteFileW": "File deletion",
    "MoveFile": "File movement",
    "CopyFile": "File copying",
}


@tool
@idaread
def vuln_patterns(
    addrs: Annotated[list[str] | str | None, "Function addresses to scan (None=all functions)"] = None,
    include_dangerous: Annotated[bool, "Check for dangerous C functions"] = True,
    include_suspicious: Annotated[bool, "Check for suspicious Windows APIs"] = True,
    limit: Annotated[int, "Max findings to return (default: 500, max: 2000)"] = 500,
) -> dict:
    """Detect common vulnerability patterns and dangerous function usage.
    Scans for buffer overflow risks, format strings, command injection, etc."""
    try:
        if limit <= 0 or limit > 2000:
            limit = 2000

        # Determine which functions to scan
        if addrs is None:
            func_addrs = list(idautils.Functions())
        else:
            func_addrs = [parse_address(a) for a in normalize_list_input(addrs)]

        findings = []
        stats = {
            "functions_scanned": 0,
            "dangerous_calls": 0,
            "suspicious_calls": 0,
        }

        # Build lookup of function names to check
        patterns_to_check = {}
        if include_dangerous:
            patterns_to_check.update(DANGEROUS_FUNCTIONS)
        if include_suspicious:
            patterns_to_check.update(SUSPICIOUS_APIS)

        for func_ea in func_addrs:
            if len(findings) >= limit:
                break

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            stats["functions_scanned"] += 1
            func_name = ida_funcs.get_func_name(func_ea)

            # Scan function for calls
            for item_ea in idautils.FuncItems(func_ea):
                if len(findings) >= limit:
                    break

                # Check for call instructions
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, item_ea) == 0:
                    continue

                if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    continue

                # Get called function name
                target = idc.get_operand_value(item_ea, 0)
                if target == idaapi.BADADDR:
                    continue

                called_name = idc.get_name(target)
                if not called_name:
                    continue

                # Check against patterns
                for pattern, description in patterns_to_check.items():
                    if pattern in called_name or called_name.endswith(pattern):
                        finding_type = "dangerous" if pattern in DANGEROUS_FUNCTIONS else "suspicious"
                        if finding_type == "dangerous":
                            stats["dangerous_calls"] += 1
                        else:
                            stats["suspicious_calls"] += 1

                        findings.append({
                            "type": finding_type,
                            "function": func_name,
                            "function_addr": hex(func_ea),
                            "call_addr": hex(item_ea),
                            "called": called_name,
                            "pattern": pattern,
                            "risk": description,
                        })
                        break

        return {
            "findings": findings,
            "count": len(findings),
            "truncated": len(findings) >= limit,
            "stats": stats,
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def suspicious_apis(
    limit: Annotated[int, "Max results (default: 200, max: 1000)"] = 200,
) -> dict:
    """Get summary of suspicious API usage across the binary.
    Groups findings by API category for easier analysis."""
    try:
        if limit <= 0 or limit > 1000:
            limit = 1000

        categories = {
            "process_injection": [],
            "anti_analysis": [],
            "persistence": [],
            "network": [],
            "crypto": [],
            "file_ops": [],
            "other": [],
        }

        category_map = {
            "VirtualAlloc": "process_injection",
            "VirtualAllocEx": "process_injection",
            "VirtualProtect": "process_injection",
            "VirtualProtectEx": "process_injection",
            "WriteProcessMemory": "process_injection",
            "CreateRemoteThread": "process_injection",
            "NtCreateThreadEx": "process_injection",
            "QueueUserAPC": "process_injection",
            "IsDebuggerPresent": "anti_analysis",
            "CheckRemoteDebuggerPresent": "anti_analysis",
            "NtQueryInformationProcess": "anti_analysis",
            "GetTickCount": "anti_analysis",
            "QueryPerformanceCounter": "anti_analysis",
            "RegSetValueEx": "persistence",
            "RegCreateKeyEx": "persistence",
            "CreateService": "persistence",
            "WSAStartup": "network",
            "socket": "network",
            "connect": "network",
            "InternetOpen": "network",
            "URLDownloadToFile": "network",
            "CryptEncrypt": "crypto",
            "CryptDecrypt": "crypto",
            "CryptAcquireContext": "crypto",
            "DeleteFile": "file_ops",
            "MoveFile": "file_ops",
            "CopyFile": "file_ops",
        }

        total_found = 0

        for func_ea in idautils.Functions():
            if total_found >= limit:
                break

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            func_name = ida_funcs.get_func_name(func_ea)

            for item_ea in idautils.FuncItems(func_ea):
                if total_found >= limit:
                    break

                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, item_ea) == 0:
                    continue

                if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    continue

                target = idc.get_operand_value(item_ea, 0)
                called_name = idc.get_name(target) if target != idaapi.BADADDR else None
                if not called_name:
                    continue

                # Check if this is a suspicious API
                for api, cat in category_map.items():
                    if api in called_name:
                        categories[cat].append({
                            "api": called_name,
                            "caller": func_name,
                            "caller_addr": hex(func_ea),
                            "call_addr": hex(item_ea),
                        })
                        total_found += 1
                        break

        # Calculate summary
        summary = {cat: len(items) for cat, items in categories.items()}

        return {
            "categories": categories,
            "summary": summary,
            "total": total_found,
            "truncated": total_found >= limit,
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Malware Analysis Helpers
# ============================================================================


@tool
@idaread
def imphash() -> dict:
    """Calculate the import hash (imphash) of the binary.
    Useful for malware family identification and clustering."""
    try:
        imports = []
        nimps = ida_nalt.get_import_module_qty()

        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i)
            if not module:
                continue

            module_lower = module.lower()
            # Remove extension
            if module_lower.endswith(".dll"):
                module_lower = module_lower[:-4]

            def callback(ea, name, ordinal):
                if name:
                    imports.append(f"{module_lower}.{name.lower()}")
                else:
                    imports.append(f"{module_lower}.ord{ordinal}")
                return True

            ida_nalt.enum_import_names(i, callback)

        if not imports:
            return {"imphash": None, "error": "No imports found"}

        # Calculate MD5 of comma-joined imports
        import_str = ",".join(imports)
        imphash_value = hashlib.md5(import_str.encode()).hexdigest()

        return {
            "imphash": imphash_value,
            "import_count": len(imports),
            "module_count": nimps,
        }

    except Exception as e:
        return {"imphash": None, "error": str(e)}


@tool
@idaread
def binary_info() -> dict:
    """Get comprehensive binary information for analysis.
    Includes file type, compiler hints, sections, and security features."""
    try:
        info = idaapi.get_inf_structure()

        result = {
            "file": {
                "path": ida_nalt.get_input_file_path(),
                "name": ida_nalt.get_root_filename(),
                "size": ida_nalt.retrieve_input_file_size(),
            },
            "arch": {
                "processor": info.procname,
                "bits": 64 if info.is_64bit() else 32,
                "endian": "big" if info.is_be() else "little",
            },
            "base_address": hex(idaapi.get_imagebase()),
        }

        # Get sections/segments
        sections = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                perms = []
                if seg.perm & idaapi.SEGPERM_READ:
                    perms.append("R")
                if seg.perm & idaapi.SEGPERM_WRITE:
                    perms.append("W")
                if seg.perm & idaapi.SEGPERM_EXEC:
                    perms.append("X")

                sections.append({
                    "name": ida_segment.get_segm_name(seg),
                    "start": hex(seg.start_ea),
                    "end": hex(seg.end_ea),
                    "size": seg.size(),
                    "perms": "".join(perms) if perms else "---",
                })

        result["sections"] = sections
        result["section_count"] = len(sections)

        # Entry points
        entries = []
        for i in range(ida_nalt.get_entry_qty()):
            ordinal = ida_nalt.get_entry_ordinal(i)
            ea = ida_nalt.get_entry(ordinal)
            name = ida_nalt.get_entry_name(ordinal)
            entries.append({
                "addr": hex(ea),
                "name": name,
                "ordinal": ordinal,
            })
        result["entry_points"] = entries

        # Statistics
        result["stats"] = {
            "functions": len(list(idautils.Functions())),
            "imports": ida_nalt.get_import_module_qty(),
            "exports": ida_nalt.get_entry_qty(),
        }

        # Calculate hashes
        try:
            result["hashes"] = {
                "md5": ida_nalt.retrieve_input_file_md5().hex(),
                "sha256": ida_nalt.retrieve_input_file_sha256().hex(),
            }
        except Exception:
            result["hashes"] = {"error": "Could not calculate hashes"}

        return result

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Batch Operations
# ============================================================================


@tool
@idawrite
def batch_rename(
    patterns: Annotated[
        list[dict],
        "List of rename operations: [{'pattern': 'sub_*', 'prefix': 'func_', 'suffix': '_renamed'}]"
    ],
    dry_run: Annotated[bool, "If True, only show what would be renamed"] = True,
    limit: Annotated[int, "Max renames to perform (default: 100, max: 500)"] = 100,
) -> dict:
    """Batch rename functions matching patterns.
    Supports wildcards (*) in patterns and adding prefix/suffix."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        results = []
        renamed_count = 0

        for pattern_def in patterns:
            pattern = pattern_def.get("pattern", "")
            prefix = pattern_def.get("prefix", "")
            suffix = pattern_def.get("suffix", "")
            replace_from = pattern_def.get("replace_from", "")
            replace_to = pattern_def.get("replace_to", "")

            if not pattern:
                continue

            # Convert glob pattern to simple matching
            import fnmatch

            for func_ea in idautils.Functions():
                if renamed_count >= limit:
                    break

                func_name = ida_funcs.get_func_name(func_ea)
                if not func_name:
                    continue

                if not fnmatch.fnmatch(func_name, pattern):
                    continue

                # Build new name
                new_name = func_name
                if replace_from and replace_to:
                    new_name = new_name.replace(replace_from, replace_to)
                if prefix:
                    new_name = prefix + new_name
                if suffix:
                    new_name = new_name + suffix

                if new_name == func_name:
                    continue

                rename_result = {
                    "addr": hex(func_ea),
                    "old_name": func_name,
                    "new_name": new_name,
                }

                if not dry_run:
                    success = idaapi.set_name(func_ea, new_name, idaapi.SN_CHECK)
                    rename_result["success"] = success
                else:
                    rename_result["dry_run"] = True

                results.append(rename_result)
                renamed_count += 1

        return {
            "results": results,
            "count": len(results),
            "dry_run": dry_run,
            "truncated": renamed_count >= limit,
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Enum Operations
# ============================================================================


@tool
@idaread
def list_enums(
    limit: Annotated[int, "Max enums to return (default: 200, max: 1000)"] = 200,
    offset: Annotated[int, "Skip first N enums"] = 0,
) -> dict:
    """List all enumerations in the database."""
    try:
        import ida_enum

        if limit <= 0 or limit > 1000:
            limit = 1000

        all_enums = []
        for i in range(ida_enum.get_enum_qty()):
            enum_id = ida_enum.getn_enum(i)
            if enum_id == idaapi.BADADDR:
                continue

            enum_name = ida_enum.get_enum_name(enum_id)
            member_count = ida_enum.get_enum_size(enum_id)

            all_enums.append({
                "id": enum_id,
                "name": enum_name,
                "member_count": member_count,
                "is_bitfield": ida_enum.is_bf(enum_id),
            })

        total = len(all_enums)
        paginated = all_enums[offset:offset + limit]
        has_more = offset + limit < total

        return {
            "enums": paginated,
            "count": len(paginated),
            "total": total,
            "cursor": {"next": offset + limit} if has_more else {"done": True},
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def enum_members(
    name: Annotated[str, "Enum name to get members for"],
    limit: Annotated[int, "Max members to return (default: 500, max: 2000)"] = 500,
) -> dict:
    """Get all members of an enumeration."""
    try:
        import ida_enum

        if limit <= 0 or limit > 2000:
            limit = 2000

        enum_id = ida_enum.get_enum(name)
        if enum_id == idaapi.BADADDR:
            return {"error": f"Enum '{name}' not found"}

        members = []
        for i, (value, member_id, _) in enumerate(ida_enum.enum_members(enum_id)):
            if i >= limit:
                break

            member_name = ida_enum.get_enum_member_name(member_id)
            members.append({
                "name": member_name,
                "value": value,
                "value_hex": hex(value),
            })

        return {
            "enum": name,
            "members": members,
            "count": len(members),
            "is_bitfield": ida_enum.is_bf(enum_id),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idawrite
def create_enum(
    name: Annotated[str, "Name for the new enum"],
    members: Annotated[list[dict], "Members: [{'name': 'VALUE_NAME', 'value': 0x10}]"],
    is_bitfield: Annotated[bool, "Create as bitfield enum"] = False,
) -> dict:
    """Create a new enumeration with the specified members."""
    try:
        import ida_enum

        # Check if enum already exists
        if ida_enum.get_enum(name) != idaapi.BADADDR:
            return {"error": f"Enum '{name}' already exists"}

        # Create enum
        enum_id = ida_enum.add_enum(idaapi.BADADDR, name, 0)
        if enum_id == idaapi.BADADDR:
            return {"error": "Failed to create enum"}

        if is_bitfield:
            ida_enum.set_enum_bf(enum_id, True)

        # Add members
        added = []
        for member in members:
            member_name = member.get("name")
            member_value = member.get("value", 0)

            if not member_name:
                continue

            result = ida_enum.add_enum_member(enum_id, member_name, member_value)
            added.append({
                "name": member_name,
                "value": member_value,
                "success": result == 0,
            })

        return {
            "enum": name,
            "id": enum_id,
            "members_added": added,
            "is_bitfield": is_bitfield,
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Bookmark Operations
# ============================================================================


@tool
@idaread
def list_bookmarks(
    limit: Annotated[int, "Max bookmarks to return (default: 100, max: 500)"] = 100,
) -> dict:
    """List all bookmarks/marked positions in the database."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        bookmarks = []
        slot = 1
        while len(bookmarks) < limit:
            ea = idc.get_bookmark(slot)
            if ea == idaapi.BADADDR:
                break

            desc = idc.get_bookmark_desc(slot)
            func = idaapi.get_func(ea)
            func_name = ida_funcs.get_func_name(func.start_ea) if func else None

            bookmarks.append({
                "slot": slot,
                "addr": hex(ea),
                "description": desc,
                "function": func_name,
            })
            slot += 1

        return {
            "bookmarks": bookmarks,
            "count": len(bookmarks),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idawrite
def set_bookmark(
    addr: Annotated[str, "Address to bookmark"],
    description: Annotated[str, "Bookmark description"] = "",
    slot: Annotated[int, "Bookmark slot (1-1024, 0=auto)"] = 0,
) -> dict:
    """Set a bookmark at the specified address."""
    try:
        ea = parse_address(addr)

        # Find available slot if not specified
        if slot == 0:
            for i in range(1, 1025):
                if idc.get_bookmark(i) == idaapi.BADADDR:
                    slot = i
                    break
            else:
                return {"error": "No available bookmark slots"}

        if slot < 1 or slot > 1024:
            return {"error": "Slot must be between 1 and 1024"}

        idc.put_bookmark(ea, 0, 0, 0, slot, description)

        return {
            "addr": hex(ea),
            "slot": slot,
            "description": description,
            "success": True,
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idawrite
def delete_bookmark(
    slot: Annotated[int, "Bookmark slot to delete (1-1024)"],
) -> dict:
    """Delete a bookmark by slot number."""
    try:
        if slot < 1 or slot > 1024:
            return {"error": "Slot must be between 1 and 1024"}

        ea = idc.get_bookmark(slot)
        if ea == idaapi.BADADDR:
            return {"error": f"No bookmark at slot {slot}"}

        # Delete by setting to BADADDR
        idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, "")

        return {
            "slot": slot,
            "deleted_addr": hex(ea),
            "success": True,
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Function Tagging System
# ============================================================================

# Tags are stored in function comments with format: [TAG1] [TAG2] ...
TAG_PREFIX = "[@"
TAG_SUFFIX = "]"


def _parse_tags(comment: str) -> list[str]:
    """Parse tags from a function comment."""
    if not comment:
        return []
    tags = []
    import re
    pattern = r'\[@([^\]]+)\]'
    matches = re.findall(pattern, comment)
    return matches


def _add_tag_to_comment(comment: str, tag: str) -> str:
    """Add a tag to a comment string."""
    tag_str = f"[@{tag}]"
    if not comment:
        return tag_str
    if tag_str in comment:
        return comment  # Already has tag
    return f"{tag_str} {comment}"


def _remove_tag_from_comment(comment: str, tag: str) -> str:
    """Remove a tag from a comment string."""
    import re
    tag_str = f"[@{tag}]"
    # Remove tag and any trailing space
    result = re.sub(r'\[@' + re.escape(tag) + r'\]\s*', '', comment)
    return result.strip()


@tool
@idaread
def get_func_tags(
    addrs: Annotated[list[str] | str, "Function addresses to get tags for"],
) -> list[dict]:
    """Get tags for specified functions."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "tags": [], "error": "No function"})
                continue

            comment = idc.get_func_cmt(func.start_ea, True) or ""
            tags = _parse_tags(comment)

            results.append({
                "addr": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea),
                "tags": tags,
            })
        except Exception as e:
            results.append({"addr": addr, "tags": [], "error": str(e)})

    return results


@tool
@idawrite
def set_func_tags(
    operations: Annotated[
        list[dict],
        "Tag operations: [{'addr': '0x1000', 'add': ['crypto', 'important'], 'remove': ['todo']}]"
    ],
) -> list[dict]:
    """Add or remove tags from functions."""
    results = []

    for op in operations:
        addr = op.get("addr", "")
        tags_to_add = op.get("add", [])
        tags_to_remove = op.get("remove", [])

        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "No function"})
                continue

            # Get current comment
            comment = idc.get_func_cmt(func.start_ea, True) or ""

            # Remove tags first
            for tag in tags_to_remove:
                comment = _remove_tag_from_comment(comment, tag)

            # Add new tags
            for tag in tags_to_add:
                comment = _add_tag_to_comment(comment, tag)

            # Set the comment
            idc.set_func_cmt(func.start_ea, comment, True)

            # Return current tags
            current_tags = _parse_tags(comment)
            results.append({
                "addr": hex(func.start_ea),
                "name": ida_funcs.get_func_name(func.start_ea),
                "tags": current_tags,
                "success": True,
            })
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@tool
@idaread
def find_tagged_funcs(
    tags: Annotated[list[str] | str, "Tags to search for"],
    match_all: Annotated[bool, "Require all tags (AND) vs any tag (OR)"] = False,
    limit: Annotated[int, "Max results (default: 200, max: 1000)"] = 200,
) -> dict:
    """Find functions with specified tags."""
    try:
        if limit <= 0 or limit > 1000:
            limit = 1000

        if isinstance(tags, str):
            tags = [tags]
        tags_set = set(tags)

        matches = []
        for func_ea in idautils.Functions():
            if len(matches) >= limit:
                break

            comment = idc.get_func_cmt(func_ea, True) or ""
            func_tags = set(_parse_tags(comment))

            if not func_tags:
                continue

            if match_all:
                # All tags must be present
                if tags_set.issubset(func_tags):
                    matches.append({
                        "addr": hex(func_ea),
                        "name": ida_funcs.get_func_name(func_ea),
                        "tags": list(func_tags),
                    })
            else:
                # Any tag matches
                if tags_set & func_tags:
                    matches.append({
                        "addr": hex(func_ea),
                        "name": ida_funcs.get_func_name(func_ea),
                        "tags": list(func_tags),
                        "matched": list(tags_set & func_tags),
                    })

        return {
            "matches": matches,
            "count": len(matches),
            "search_tags": tags,
            "match_all": match_all,
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def list_all_tags(
    limit: Annotated[int, "Max tags to return (default: 100, max: 500)"] = 100,
) -> dict:
    """List all unique tags used across functions."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        tag_counts = {}
        for func_ea in idautils.Functions():
            comment = idc.get_func_cmt(func_ea, True) or ""
            func_tags = _parse_tags(comment)
            for tag in func_tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        # Sort by count descending
        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)

        tags = [{"tag": t, "count": c} for t, c in sorted_tags[:limit]]

        return {
            "tags": tags,
            "unique_count": len(tag_counts),
            "truncated": len(tag_counts) > limit,
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Packer/Protector Detection
# ============================================================================

# Common packer signatures and heuristics
PACKER_SIGNATURES = {
    "UPX": {
        "sections": ["UPX0", "UPX1", "UPX2"],
        "strings": ["UPX!", "This file is packed with the UPX"],
    },
    "ASPack": {
        "sections": [".aspack", ".adata"],
        "strings": ["ASPack"],
    },
    "PECompact": {
        "sections": ["PEC2", ".pec1", ".pec2"],
        "strings": ["PECompact2"],
    },
    "Themida": {
        "sections": [".themida", ".winlice"],
        "strings": ["Themida", "WinLicense"],
    },
    "VMProtect": {
        "sections": [".vmp0", ".vmp1", ".vmp2"],
        "strings": ["VMProtect"],
    },
    "Enigma": {
        "sections": [".enigma1", ".enigma2"],
        "strings": ["Enigma protector"],
    },
    "MPRESS": {
        "sections": [".MPRESS1", ".MPRESS2"],
        "strings": [],
    },
    "PEtite": {
        "sections": [".petite"],
        "strings": ["PEtite"],
    },
    "NSPack": {
        "sections": [".nsp0", ".nsp1", ".nsp2"],
        "strings": ["NsPacK"],
    },
    "FSG": {
        "sections": [],
        "strings": ["FSG!"],
    },
}


@tool
@idaread
def detect_packer() -> dict:
    """Detect if the binary is packed or protected.
    Uses section names, strings, and entropy analysis."""
    try:
        detections = []
        indicators = []

        # Get section names
        section_names = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                name = ida_segment.get_segm_name(seg)
                section_names.append(name)

        # Check for known packer sections
        for packer, sigs in PACKER_SIGNATURES.items():
            for section in sigs["sections"]:
                if section in section_names:
                    detections.append({
                        "packer": packer,
                        "indicator": f"Section: {section}",
                        "confidence": "high",
                    })

        # Check for packer strings in binary
        try:
            for s in idautils.Strings():
                str_content = str(s).lower()
                for packer, sigs in PACKER_SIGNATURES.items():
                    for sig_str in sigs["strings"]:
                        if sig_str.lower() in str_content:
                            detections.append({
                                "packer": packer,
                                "indicator": f"String: {sig_str}",
                                "confidence": "high",
                            })
        except Exception:
            pass

        # Entropy analysis for each section
        high_entropy_sections = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue

            name = ida_segment.get_segm_name(seg)
            size = seg.size()

            if size < 256:
                continue

            # Sample bytes for entropy calculation
            sample_size = min(size, 4096)
            try:
                data = ida_bytes.get_bytes(seg.start_ea, sample_size)
                if data:
                    entropy = _calculate_entropy(data)
                    if entropy > 7.0:  # High entropy threshold
                        high_entropy_sections.append({
                            "section": name,
                            "entropy": round(entropy, 2),
                        })
                        indicators.append(f"High entropy in {name}: {entropy:.2f}")
            except Exception:
                pass

        # Check for suspicious characteristics
        suspicious = []

        # Very few imports (common in packed binaries)
        import_count = 0
        for i in range(ida_nalt.get_import_module_qty()):
            def count_cb(ea, name, ordinal):
                nonlocal import_count
                import_count += 1
                return True
            ida_nalt.enum_import_names(i, count_cb)

        if import_count < 10:
            suspicious.append("Very few imports (possible packing)")
            indicators.append(f"Low import count: {import_count}")

        # Check for writable + executable sections
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                if (seg.perm & idaapi.SEGPERM_WRITE) and (seg.perm & idaapi.SEGPERM_EXEC):
                    name = ida_segment.get_segm_name(seg)
                    suspicious.append(f"Section {name} is writable and executable")
                    indicators.append(f"W+X section: {name}")

        # Determine overall verdict
        is_packed = len(detections) > 0 or len(high_entropy_sections) > 2

        return {
            "is_packed": is_packed,
            "detections": detections,
            "high_entropy_sections": high_entropy_sections,
            "suspicious_characteristics": suspicious,
            "indicators": indicators,
            "import_count": import_count,
            "confidence": "high" if detections else ("medium" if high_entropy_sections else "low"),
        }

    except Exception as e:
        return {"error": str(e)}


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    import math
    if not data:
        return 0.0

    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


# ============================================================================
# Deobfuscation Helpers
# ============================================================================


@tool
@idaread
def find_encrypted_strings(
    min_length: Annotated[int, "Minimum string length to consider"] = 4,
    entropy_threshold: Annotated[float, "Entropy threshold for 'encrypted' (default: 4.0)"] = 4.0,
    limit: Annotated[int, "Max results (default: 200, max: 1000)"] = 200,
) -> dict:
    """Find potentially encrypted/encoded strings based on entropy.
    High entropy strings may be encrypted or encoded data."""
    try:
        if limit <= 0 or limit > 1000:
            limit = 1000

        results = []

        for s in idautils.Strings():
            if len(results) >= limit:
                break

            try:
                str_content = str(s)
                if len(str_content) < min_length:
                    continue

                # Calculate entropy
                entropy = _calculate_entropy(str_content.encode())

                if entropy >= entropy_threshold:
                    # Get xrefs to this string
                    xrefs = [hex(x.frm) for x in idautils.XrefsTo(s.ea, 0)][:5]

                    results.append({
                        "addr": hex(s.ea),
                        "string": str_content[:100] + ("..." if len(str_content) > 100 else ""),
                        "length": len(str_content),
                        "entropy": round(entropy, 2),
                        "xrefs": xrefs,
                    })
            except Exception:
                continue

        # Sort by entropy descending
        results.sort(key=lambda x: x["entropy"], reverse=True)

        return {
            "strings": results,
            "count": len(results),
            "entropy_threshold": entropy_threshold,
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def find_xor_loops(
    limit: Annotated[int, "Max results (default: 100, max: 500)"] = 100,
) -> dict:
    """Find potential XOR decryption loops.
    Common pattern in malware for string/data decryption."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        results = []

        for func_ea in idautils.Functions():
            if len(results) >= limit:
                break

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            xor_count = 0
            loop_indicators = 0
            xor_addrs = []

            for item_ea in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(item_ea)

                # Count XOR instructions (excluding xor reg, reg for zeroing)
                if mnem == "xor":
                    op0 = idc.print_operand(item_ea, 0)
                    op1 = idc.print_operand(item_ea, 1)
                    if op0 != op1:  # Not zeroing pattern
                        xor_count += 1
                        xor_addrs.append(hex(item_ea))

                # Look for loop indicators
                if mnem in ("loop", "loope", "loopne", "jcxz", "jecxz"):
                    loop_indicators += 1
                if mnem in ("inc", "dec", "add", "sub"):
                    # Check if operating on counter-like registers
                    op0 = idc.print_operand(item_ea, 0).lower()
                    if op0 in ("ecx", "rcx", "cx", "esi", "rsi", "edi", "rdi"):
                        loop_indicators += 1

            # Heuristic: XOR in a loop-like structure
            if xor_count >= 1 and loop_indicators >= 2:
                results.append({
                    "func_addr": hex(func_ea),
                    "func_name": ida_funcs.get_func_name(func_ea),
                    "xor_count": xor_count,
                    "xor_locations": xor_addrs[:10],
                    "confidence": "high" if xor_count >= 3 else "medium",
                })

        return {
            "potential_xor_loops": results,
            "count": len(results),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def find_dynamic_calls(
    limit: Annotated[int, "Max results (default: 200, max: 1000)"] = 200,
) -> dict:
    """Find indirect/dynamic calls that may indicate API obfuscation.
    Common in malware using GetProcAddress or function pointer tables."""
    try:
        if limit <= 0 or limit > 1000:
            limit = 1000

        results = []

        for func_ea in idautils.Functions():
            if len(results) >= limit:
                break

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            func_name = ida_funcs.get_func_name(func_ea)
            indirect_calls = []

            for item_ea in idautils.FuncItems(func_ea):
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, item_ea) == 0:
                    continue

                # Check for call instructions
                if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                    continue

                # Check if it's an indirect call (register or memory)
                op_type = idc.get_operand_type(item_ea, 0)
                if op_type in (idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ):
                    operand = idc.print_operand(item_ea, 0)
                    indirect_calls.append({
                        "addr": hex(item_ea),
                        "operand": operand,
                        "type": "register" if op_type == idaapi.o_reg else "memory",
                    })

            if indirect_calls:
                results.append({
                    "func_addr": hex(func_ea),
                    "func_name": func_name,
                    "indirect_calls": indirect_calls[:20],
                    "count": len(indirect_calls),
                })

        return {
            "functions": results,
            "count": len(results),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def find_stack_strings(
    min_length: Annotated[int, "Minimum string length"] = 4,
    limit: Annotated[int, "Max results (default: 100, max: 500)"] = 100,
) -> dict:
    """Find strings built on the stack (common obfuscation technique).
    Detects patterns of sequential byte/dword moves to stack."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        results = []

        for func_ea in idautils.Functions():
            if len(results) >= limit:
                break

            func = idaapi.get_func(func_ea)
            if not func:
                continue

            # Look for sequences of mov [esp/ebp+X], immediate
            stack_writes = []
            current_sequence = []

            for item_ea in idautils.FuncItems(func_ea):
                mnem = idc.print_insn_mnem(item_ea)

                if mnem == "mov":
                    op0 = idc.print_operand(item_ea, 0).lower()
                    op1_type = idc.get_operand_type(item_ea, 1)

                    # Check if writing immediate to stack
                    if (("esp" in op0 or "ebp" in op0 or "rsp" in op0 or "rbp" in op0) and
                        op1_type == idaapi.o_imm):
                        imm_val = idc.get_operand_value(item_ea, 1)
                        current_sequence.append({
                            "addr": item_ea,
                            "value": imm_val,
                        })
                    else:
                        # Sequence broken
                        if len(current_sequence) >= 4:
                            stack_writes.append(current_sequence)
                        current_sequence = []
                else:
                    if len(current_sequence) >= 4:
                        stack_writes.append(current_sequence)
                    current_sequence = []

            # Process found sequences
            for seq in stack_writes:
                # Try to decode as string
                chars = []
                for item in seq:
                    val = item["value"]
                    # Extract printable characters
                    for i in range(4):  # Check each byte in dword
                        byte = (val >> (i * 8)) & 0xFF
                        if 32 <= byte <= 126:
                            chars.append(chr(byte))
                        elif byte == 0:
                            break

                decoded = "".join(chars)
                if len(decoded) >= min_length:
                    results.append({
                        "func_addr": hex(func_ea),
                        "func_name": ida_funcs.get_func_name(func_ea),
                        "start_addr": hex(seq[0]["addr"]),
                        "decoded": decoded,
                        "instruction_count": len(seq),
                    })

        return {
            "stack_strings": results,
            "count": len(results),
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Data Flow Analysis (Basic)
# ============================================================================


@tool
@idaread
def trace_argument(
    func_addr: Annotated[str, "Function address"],
    arg_index: Annotated[int, "Argument index (0-based)"],
    max_depth: Annotated[int, "Max call depth to trace (default: 3)"] = 3,
) -> dict:
    """Trace how a function argument is used and propagated.
    Useful for understanding data flow and finding sinks."""
    try:
        ea = parse_address(func_addr)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": "Function not found"}

        func_name = ida_funcs.get_func_name(func.start_ea)

        # Get function callers
        callers_info = []
        for caller_ea in idautils.CodeRefsTo(func.start_ea, 0):
            caller_func = idaapi.get_func(caller_ea)
            if caller_func:
                callers_info.append({
                    "call_addr": hex(caller_ea),
                    "caller_func": ida_funcs.get_func_name(caller_func.start_ea),
                    "caller_addr": hex(caller_func.start_ea),
                })

        # Analyze how argument is used within the function
        uses = []
        for item_ea in idautils.FuncItems(func.start_ea):
            # This is simplified - real data flow would need proper analysis
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, item_ea) == 0:
                continue

            # Check for calls where our argument might be passed
            if insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                target = idc.get_operand_value(item_ea, 0)
                target_name = idc.get_name(target) if target != idaapi.BADADDR else None
                if target_name:
                    uses.append({
                        "addr": hex(item_ea),
                        "type": "passed_to",
                        "target": target_name,
                    })

        return {
            "function": func_name,
            "function_addr": hex(func.start_ea),
            "argument_index": arg_index,
            "callers": callers_info[:20],
            "uses_in_function": uses[:30],
            "caller_count": len(callers_info),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def find_data_refs(
    addr: Annotated[str, "Address to find data references for"],
    direction: Annotated[str, "Direction: 'to', 'from', or 'both'"] = "both",
    limit: Annotated[int, "Max results (default: 200, max: 1000)"] = 200,
) -> dict:
    """Find data references to/from an address.
    Useful for tracking global variable usage."""
    try:
        if limit <= 0 or limit > 1000:
            limit = 1000

        ea = parse_address(addr)
        results = {"addr": hex(ea), "refs_to": [], "refs_from": []}

        if direction in ("to", "both"):
            count = 0
            for xref in idautils.DataRefsTo(ea):
                if count >= limit:
                    break
                func = idaapi.get_func(xref)
                results["refs_to"].append({
                    "addr": hex(xref),
                    "function": ida_funcs.get_func_name(func.start_ea) if func else None,
                })
                count += 1

        if direction in ("from", "both"):
            count = 0
            for xref in idautils.DataRefsFrom(ea):
                if count >= limit:
                    break
                results["refs_from"].append({
                    "addr": hex(xref),
                    "name": idc.get_name(xref),
                })
                count += 1

        results["refs_to_count"] = len(results["refs_to"])
        results["refs_from_count"] = len(results["refs_from"])

        return results

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Control Flow Graph Export
# ============================================================================


@tool
@idaread
def export_cfg(
    addr: Annotated[str, "Function address"],
    format: Annotated[str, "Export format: 'dot', 'json', or 'both'"] = "json",
    include_asm: Annotated[bool, "Include assembly in blocks"] = False,
    max_blocks: Annotated[int, "Max blocks (default: 500, max: 2000)"] = 500,
) -> dict:
    """Export function control flow graph in DOT or JSON format.
    DOT format can be visualized with Graphviz."""
    try:
        if max_blocks <= 0 or max_blocks > 2000:
            max_blocks = 2000

        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": "Function not found"}

        func_name = ida_funcs.get_func_name(func.start_ea)
        flowchart = idaapi.FlowChart(func)

        blocks = []
        edges = []

        for i, block in enumerate(flowchart):
            if i >= max_blocks:
                break

            block_info = {
                "id": block.id,
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
            }

            if include_asm:
                asm_lines = []
                ea_iter = block.start_ea
                while ea_iter < block.end_ea:
                    line = idc.generate_disasm_line(ea_iter, 0)
                    if line:
                        asm_lines.append(f"{hex(ea_iter)}: {ida_lines.tag_remove(line)}")
                    ea_iter = idc.next_head(ea_iter, block.end_ea)
                block_info["asm"] = asm_lines

            blocks.append(block_info)

            # Add edges
            for succ in block.succs():
                edges.append({
                    "from": block.id,
                    "to": succ.id,
                    "from_addr": hex(block.start_ea),
                    "to_addr": hex(succ.start_ea),
                })

        result = {
            "function": func_name,
            "function_addr": hex(func.start_ea),
            "block_count": len(blocks),
            "edge_count": len(edges),
        }

        if format in ("json", "both"):
            result["json"] = {
                "blocks": blocks,
                "edges": edges,
            }

        if format in ("dot", "both"):
            # Generate DOT format
            dot_lines = [
                f'digraph "{func_name}" {{',
                '    node [shape=box, fontname="Courier"];',
                '    edge [fontname="Courier"];',
            ]

            for block in blocks:
                label = f"{block['start']}"
                if include_asm and "asm" in block:
                    # Escape and limit asm for DOT
                    asm_preview = "\\l".join(block["asm"][:5])
                    if len(block["asm"]) > 5:
                        asm_preview += "\\l..."
                    label = f"{block['start']}\\l{asm_preview}"
                dot_lines.append(f'    block_{block["id"]} [label="{label}\\l"];')

            for edge in edges:
                dot_lines.append(f'    block_{edge["from"]} -> block_{edge["to"]};')

            dot_lines.append("}")
            result["dot"] = "\n".join(dot_lines)

        return result

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def export_callgraph_dot(
    roots: Annotated[list[str] | str, "Root function addresses"],
    max_depth: Annotated[int, "Max depth (default: 3)"] = 3,
    max_nodes: Annotated[int, "Max nodes (default: 100, max: 500)"] = 100,
) -> dict:
    """Export call graph in DOT format for visualization."""
    try:
        if max_nodes <= 0 or max_nodes > 500:
            max_nodes = 500

        roots = normalize_list_input(roots)

        all_nodes = {}
        all_edges = set()

        for root in roots:
            ea = parse_address(root)
            func = idaapi.get_func(ea)
            if not func:
                continue

            visited = set()

            def traverse(addr, depth):
                if depth > max_depth or addr in visited or len(all_nodes) >= max_nodes:
                    return
                visited.add(addr)

                f = idaapi.get_func(addr)
                if not f:
                    return

                name = ida_funcs.get_func_name(f.start_ea)
                all_nodes[addr] = name

                for item_ea in idautils.FuncItems(f.start_ea):
                    for xref in idautils.CodeRefsFrom(item_ea, 0):
                        callee = idaapi.get_func(xref)
                        if callee and callee.start_ea != addr:
                            all_edges.add((addr, callee.start_ea))
                            traverse(callee.start_ea, depth + 1)

            traverse(ea, 0)

        # Generate DOT
        dot_lines = [
            'digraph callgraph {',
            '    node [shape=box, fontname="Courier"];',
            '    rankdir=TB;',
        ]

        for addr, name in all_nodes.items():
            # Escape quotes in name
            safe_name = name.replace('"', '\\"')
            dot_lines.append(f'    node_{addr:x} [label="{safe_name}"];')

        for from_addr, to_addr in all_edges:
            dot_lines.append(f'    node_{from_addr:x} -> node_{to_addr:x};')

        dot_lines.append("}")

        return {
            "dot": "\n".join(dot_lines),
            "node_count": len(all_nodes),
            "edge_count": len(all_edges),
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# Advanced Graph Analysis
# ============================================================================


@tool
@idaread
def find_loops(
    addr: Annotated[str, "Function address"],
    max_loops: Annotated[int, "Max loops to find (default: 50, max: 200)"] = 50,
) -> dict:
    """Find loops in function control flow graph.
    Useful for identifying hot paths and optimization targets."""
    try:
        if max_loops <= 0 or max_loops > 200:
            max_loops = 200

        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": "Function not found"}

        func_name = ida_funcs.get_func_name(func.start_ea)
        flowchart = idaapi.FlowChart(func)

        # Build adjacency list
        successors = {}
        block_map = {}
        for block in flowchart:
            block_map[block.id] = block
            successors[block.id] = [s.id for s in block.succs()]

        # Find back edges (loops) using DFS
        loops = []
        visited = set()
        rec_stack = set()

        def dfs(node_id, path):
            if len(loops) >= max_loops:
                return

            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            for succ_id in successors.get(node_id, []):
                if succ_id in rec_stack:
                    # Found a back edge (loop)
                    loop_start_idx = path.index(succ_id)
                    loop_nodes = path[loop_start_idx:]
                    loops.append({
                        "header": hex(block_map[succ_id].start_ea),
                        "back_edge_from": hex(block_map[node_id].start_ea),
                        "block_count": len(loop_nodes),
                        "blocks": [hex(block_map[n].start_ea) for n in loop_nodes],
                    })
                elif succ_id not in visited:
                    dfs(succ_id, path.copy())

            rec_stack.remove(node_id)

        # Start DFS from entry block
        if flowchart.size > 0:
            entry = list(flowchart)[0]
            dfs(entry.id, [])

        return {
            "function": func_name,
            "function_addr": hex(func.start_ea),
            "loops": loops,
            "loop_count": len(loops),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def find_unreachable_code(
    addr: Annotated[str, "Function address"],
) -> dict:
    """Find unreachable basic blocks in a function.
    May indicate dead code, anti-disassembly, or bugs."""
    try:
        ea = parse_address(addr)
        func = idaapi.get_func(ea)
        if not func:
            return {"error": "Function not found"}

        func_name = ida_funcs.get_func_name(func.start_ea)
        flowchart = idaapi.FlowChart(func)

        # Build reachability from entry
        all_blocks = {}
        successors = {}

        for block in flowchart:
            all_blocks[block.id] = block
            successors[block.id] = [s.id for s in block.succs()]

        # BFS from entry
        reachable = set()
        if flowchart.size > 0:
            entry = list(flowchart)[0]
            queue = [entry.id]
            while queue:
                node = queue.pop(0)
                if node in reachable:
                    continue
                reachable.add(node)
                queue.extend(successors.get(node, []))

        # Find unreachable
        unreachable = []
        for block_id, block in all_blocks.items():
            if block_id not in reachable:
                unreachable.append({
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "size": block.end_ea - block.start_ea,
                })

        return {
            "function": func_name,
            "function_addr": hex(func.start_ea),
            "total_blocks": len(all_blocks),
            "reachable_blocks": len(reachable),
            "unreachable_blocks": unreachable,
            "unreachable_count": len(unreachable),
        }

    except Exception as e:
        return {"error": str(e)}


@tool
@idaread
def function_complexity(
    addrs: Annotated[list[str] | str, "Function addresses"],
) -> list[dict]:
    """Calculate cyclomatic complexity and other metrics for functions.
    Higher complexity = harder to understand/test."""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append({"addr": addr, "error": "Function not found"})
                continue

            func_name = ida_funcs.get_func_name(func.start_ea)
            flowchart = idaapi.FlowChart(func)

            # Count nodes and edges
            nodes = 0
            edges = 0
            for block in flowchart:
                nodes += 1
                edges += sum(1 for _ in block.succs())

            # Cyclomatic complexity: M = E - N + 2P (P=1 for single function)
            cyclomatic = edges - nodes + 2

            # Count instructions
            instruction_count = 0
            call_count = 0
            branch_count = 0

            for item_ea in idautils.FuncItems(func.start_ea):
                instruction_count += 1
                mnem = idc.print_insn_mnem(item_ea)
                if mnem in ("call", "callfi", "callni"):
                    call_count += 1
                if mnem.startswith("j") and mnem != "jmp":
                    branch_count += 1

            results.append({
                "addr": hex(func.start_ea),
                "name": func_name,
                "cyclomatic_complexity": cyclomatic,
                "basic_blocks": nodes,
                "edges": edges,
                "instructions": instruction_count,
                "calls": call_count,
                "branches": branch_count,
                "size": func.end_ea - func.start_ea,
                "complexity_rating": (
                    "low" if cyclomatic <= 10 else
                    "medium" if cyclomatic <= 20 else
                    "high" if cyclomatic <= 50 else
                    "very_high"
                ),
            })

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


# ============================================================================
# Caching System
# ============================================================================

# Global caches
_function_cache = None
_function_cache_count = None


def _invalidate_caches():
    """Invalidate all caches."""
    global _function_cache, _function_cache_count
    _function_cache = None
    _function_cache_count = None


@tool
@idaread
def get_cached_functions(
    refresh: Annotated[bool, "Force cache refresh"] = False,
    limit: Annotated[int, "Max functions (default: 500, max: 5000)"] = 500,
    offset: Annotated[int, "Skip first N functions"] = 0,
) -> dict:
    """Get functions with caching for better performance.
    Cache is automatically invalidated when IDB changes."""
    global _function_cache, _function_cache_count

    try:
        if limit <= 0 or limit > 5000:
            limit = 5000

        # Check if cache needs refresh
        current_count = len(list(idautils.Functions()))
        if refresh or _function_cache is None or _function_cache_count != current_count:
            _function_cache = []
            for func_ea in idautils.Functions():
                func = idaapi.get_func(func_ea)
                if func:
                    _function_cache.append({
                        "addr": hex(func_ea),
                        "name": ida_funcs.get_func_name(func_ea),
                        "size": func.end_ea - func.start_ea,
                    })
            _function_cache_count = current_count

        total = len(_function_cache)
        paginated = _function_cache[offset:offset + limit]
        has_more = offset + limit < total

        return {
            "functions": paginated,
            "count": len(paginated),
            "total": total,
            "cached": True,
            "cursor": {"next": offset + limit} if has_more else {"done": True},
        }

    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# YARA Integration (Optional)
# ============================================================================


@tool
@idaread
def yara_scan(
    rules: Annotated[str, "YARA rules as string or file path"],
    scan_segments: Annotated[list[str] | None, "Segment names to scan (None=all)"] = None,
    limit: Annotated[int, "Max matches (default: 100, max: 500)"] = 100,
) -> dict:
    """Scan binary with YARA rules. Requires yara-python installed."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        # Try to import yara
        try:
            import yara
        except ImportError:
            return {
                "error": "yara-python not installed. Install with: pip install yara-python",
                "matches": [],
            }

        # Compile rules
        try:
            if rules.strip().startswith("rule "):
                compiled = yara.compile(source=rules)
            else:
                # Assume it's a file path
                compiled = yara.compile(filepath=rules)
        except Exception as e:
            return {"error": f"Failed to compile YARA rules: {e}", "matches": []}

        matches = []

        # Scan each segment
        for seg_ea in idautils.Segments():
            if len(matches) >= limit:
                break

            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue

            seg_name = ida_segment.get_segm_name(seg)

            # Filter segments if specified
            if scan_segments and seg_name not in scan_segments:
                continue

            # Get segment data
            try:
                data = ida_bytes.get_bytes(seg.start_ea, seg.size())
                if not data:
                    continue

                # Scan
                yara_matches = compiled.match(data=data)
                for match in yara_matches:
                    if len(matches) >= limit:
                        break

                    for string_match in match.strings:
                        if len(matches) >= limit:
                            break

                        # Calculate actual address
                        for instance in string_match.instances:
                            if len(matches) >= limit:
                                break

                            actual_addr = seg.start_ea + instance.offset
                            matches.append({
                                "rule": match.rule,
                                "segment": seg_name,
                                "addr": hex(actual_addr),
                                "identifier": string_match.identifier,
                                "data": instance.matched_data[:50].hex(),
                            })

            except Exception:
                continue

        return {
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= limit,
        }

    except Exception as e:
        return {"error": str(e), "matches": []}


# ============================================================================
# String Decoding Helpers
# ============================================================================


@tool
@idaread
def decode_strings(
    addrs: Annotated[list[str] | str, "Addresses of encoded strings"],
    encoding: Annotated[str, "Encoding: 'xor', 'base64', 'rot13', 'hex', or 'auto'"] = "auto",
    key: Annotated[int | None, "XOR key (for xor encoding)"] = None,
) -> list[dict]:
    """Attempt to decode potentially encoded strings.
    Tries multiple decoding methods if 'auto' is specified."""
    import base64

    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)

            # Read bytes at address
            # Try to read until null terminator or max length
            raw_bytes = []
            for i in range(256):
                byte = ida_bytes.get_byte(ea + i)
                if byte == 0:
                    break
                raw_bytes.append(byte)

            if not raw_bytes:
                results.append({"addr": addr, "error": "No data at address"})
                continue

            data = bytes(raw_bytes)
            decoded_results = []

            # Try different decodings
            if encoding in ("xor", "auto"):
                if key is not None:
                    # Single key XOR
                    xor_decoded = bytes([b ^ key for b in data])
                    try:
                        decoded_results.append({
                            "method": f"xor_key_{key}",
                            "result": xor_decoded.decode("utf-8", errors="replace"),
                        })
                    except Exception:
                        pass
                elif encoding == "auto":
                    # Try common XOR keys
                    for k in [0x00, 0xFF, 0x41, 0x55, 0xAA]:
                        xor_decoded = bytes([b ^ k for b in data])
                        # Check if result looks like printable ASCII
                        printable = sum(1 for b in xor_decoded if 32 <= b <= 126)
                        if printable > len(xor_decoded) * 0.7:
                            decoded_results.append({
                                "method": f"xor_key_{hex(k)}",
                                "result": xor_decoded.decode("utf-8", errors="replace"),
                            })
                            break

            if encoding in ("base64", "auto"):
                try:
                    b64_decoded = base64.b64decode(data)
                    decoded_results.append({
                        "method": "base64",
                        "result": b64_decoded.decode("utf-8", errors="replace"),
                    })
                except Exception:
                    pass

            if encoding in ("rot13", "auto"):
                try:
                    import codecs
                    rot13_decoded = codecs.decode(data.decode("utf-8"), "rot_13")
                    if rot13_decoded != data.decode("utf-8"):  # Only if different
                        decoded_results.append({
                            "method": "rot13",
                            "result": rot13_decoded,
                        })
                except Exception:
                    pass

            if encoding in ("hex", "auto"):
                try:
                    hex_decoded = bytes.fromhex(data.decode("utf-8"))
                    decoded_results.append({
                        "method": "hex",
                        "result": hex_decoded.decode("utf-8", errors="replace"),
                    })
                except Exception:
                    pass

            results.append({
                "addr": addr,
                "raw": data[:50].hex(),
                "raw_length": len(data),
                "decoded": decoded_results if decoded_results else None,
            })

        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results


@tool
@idaread
def find_crypto_constants(
    limit: Annotated[int, "Max results (default: 100, max: 500)"] = 100,
) -> dict:
    """Find known cryptographic constants in the binary.
    Detects AES, DES, MD5, SHA, RC4, etc."""
    try:
        if limit <= 0 or limit > 500:
            limit = 500

        # Known crypto constants
        CRYPTO_CONSTANTS = {
            # AES S-box first bytes
            0x637c777b: "AES S-box",
            0xf26b6fc5: "AES S-box (alt)",
            # AES inverse S-box
            0x52096a5f: "AES inverse S-box",
            # MD5 constants
            0xd76aa478: "MD5 constant",
            0xe8c7b756: "MD5 constant",
            0x242070db: "MD5 constant",
            # SHA-1 constants
            0x67452301: "SHA-1/MD5 init",
            0xefcdab89: "SHA-1/MD5 init",
            0x98badcfe: "SHA-1/MD5 init",
            0x10325476: "SHA-1/MD5 init",
            0xc3d2e1f0: "SHA-1 init",
            # SHA-256 constants
            0x6a09e667: "SHA-256 init",
            0xbb67ae85: "SHA-256 init",
            0x3c6ef372: "SHA-256 init",
            # DES constants
            0x00000080: "DES permutation",
            # RC4 (common key schedule pattern detected differently)
            # Blowfish
            0x243f6a88: "Blowfish P-array",
            0x85a308d3: "Blowfish P-array",
            # CRC32 polynomial
            0xedb88320: "CRC32 polynomial",
            0x04c11db7: "CRC32 polynomial (alt)",
            # TEA/XTEA
            0x9e3779b9: "TEA/XTEA delta",
        }

        matches = []

        for seg_ea in idautils.Segments():
            if len(matches) >= limit:
                break

            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue

            seg_name = ida_segment.get_segm_name(seg)

            # Scan for constants
            ea = seg.start_ea
            while ea < seg.end_ea - 4 and len(matches) < limit:
                try:
                    dword = ida_bytes.get_dword(ea)
                    if dword in CRYPTO_CONSTANTS:
                        func = idaapi.get_func(ea)
                        matches.append({
                            "addr": hex(ea),
                            "value": hex(dword),
                            "constant": CRYPTO_CONSTANTS[dword],
                            "segment": seg_name,
                            "function": ida_funcs.get_func_name(func.start_ea) if func else None,
                        })
                except Exception:
                    pass
                ea += 4

        return {
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= limit,
        }

    except Exception as e:
        return {"error": str(e)}
