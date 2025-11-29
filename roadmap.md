# IDA Pro MCP - Development Roadmap

## Completed

### Pagination Improvements (v1.3.0)

Added comprehensive pagination support to prevent token overflow with large binaries:

#### Critical Functions (High Impact)
- [x] `decompile()` - Line-based pagination (default: 2000 lines, max: 10000)
- [x] `xrefs_to()` - Pagination with cursor (default: 500, max: 5000)
- [x] `get_xrefs_to_field()` - Pagination with cursor (default: 500, max: 5000)
- [x] `callees()` - Pagination with cursor (default: 200, max: 2000)
- [x] `callers()` - Pagination with cursor (default: 200, max: 2000)
- [x] `callgraph()` - Node limit with truncation flag (default: 500 nodes, max: 5000)
- [x] `entrypoints()` - Pagination with cursor (default: 500, max: 5000)

#### Type/Structure Functions
- [x] `local_types()` - Pagination with filter support (default: 500, max: 5000)
- [x] `structs()` - Pagination with filter support (default: 200, max: 2000)
- [x] `search_structs()` - Pagination with cursor (default: 200, max: 2000)

#### Response Format
All paginated functions now return consistent cursor objects:
```json
{
  "data": [...],
  "count": 100,
  "total": 5000,
  "cursor": {"next": 100} or {"done": true}
}
```

## Completed in v1.5.0

### Resource Endpoints Pagination
- [x] `functions_resource()` - Already had pagination
- [x] `globals_resource()` - Already had pagination
- [x] `strings_resource()` - Already had pagination
- [x] `imports_resource()` - Already had pagination
- [x] `types_resource()` - Added pagination (default: 100)
- [x] `structs_resource()` - Added pagination (default: 100)
- [x] `xrefs_to_addr_resource()` - Added pagination (default: 200)
- [x] `xrefs_from_resource()` - Added pagination (default: 200)

### analyze_funcs() Improvements
- [x] Add limits to nested xrefs data (max_xrefs: 100)
- [x] Add limits to strings extraction (max_strings: 100)
- [x] Add limits to constants extraction (max_constants: 100)
- [x] Add option to exclude heavy data (include_code, include_asm flags)
- [x] Add limits to callees/callers (max_calls: 50)
- [x] Add limits to basic blocks (max_blocks: 200)

### Graph Operations Improvements
- [x] `callgraph()` - Added max_edges limit (default: 2000, max: 10000)
- [x] `callgraph()` - Fixed duplicate edges using set-based deduplication
- [x] `xref_matrix()` - Added max_entities limit (default: 50, max: 200) to prevent O(n^2) explosion

### Export and Path Operations
- [x] `export_funcs()` - Added max_funcs limit (default: 20, max: 100)
- [x] `export_funcs()` - Added include_code and include_asm flags to exclude heavy data
- [x] `export_funcs()` - Added truncated flag to response
- [x] `find_paths()` - Made max_paths configurable (default: 10, max: 50)
- [x] `find_paths()` - Made max_depth configurable (default: 20, max: 100)
- [x] `find_paths()` - Added path_count to response

### Query and Structure Operations
- [x] `lookup_funcs()` - Added pagination when using '*' (default: 100, max: 1000)
- [x] `struct_info()` - Added max_members limit (default: 500, max: 2000)
- [x] `struct_info()` - Added members_returned and members_truncated to response
- [x] `read_struct()` - Added max_members limit (default: 200, max: 1000)
- [x] `read_struct()` - Added truncated flag and member counts to response

### Advanced Analysis Features (api_advanced.py)

#### Function Comparison & Similarity
- [x] `func_diff()` - Compare two functions (asm, pseudocode, blocks)
- [x] `func_similarity()` - Find similar functions by size/blocks/hash

#### Vulnerability & Security Analysis
- [x] `vuln_patterns()` - Detect dangerous functions (buffer overflow, format string, command injection)
- [x] `suspicious_apis()` - Categorized suspicious API detection (injection, anti-analysis, persistence, network)

#### Malware Analysis Helpers
- [x] `imphash()` - Calculate PE import hash for malware fingerprinting
- [x] `binary_info()` - Comprehensive binary metadata (arch, sections, entries, hashes)

#### Batch & Convenience Operations
- [x] `batch_rename()` - Pattern-based bulk function renaming with wildcards
- [x] `list_enums()` - List all enumerations with pagination
- [x] `enum_members()` - Get enum members
- [x] `create_enum()` - Create new enumerations
- [x] `list_bookmarks()` - List IDA bookmarks
- [x] `set_bookmark()` - Create bookmarks
- [x] `delete_bookmark()` - Remove bookmarks

#### Function Tagging System
- [x] `get_func_tags()` - Get tags for functions
- [x] `set_func_tags()` - Add/remove tags from functions
- [x] `find_tagged_funcs()` - Search functions by tags (AND/OR)
- [x] `list_all_tags()` - List all unique tags with counts

#### Packer/Protector Detection
- [x] `detect_packer()` - Detect packers via signatures, entropy analysis, section names
- [x] Supports: UPX, ASPack, PECompact, Themida, VMProtect, Enigma, MPRESS, PEtite, NSPack, FSG

#### Deobfuscation Helpers
- [x] `find_encrypted_strings()` - Find high-entropy strings (potential encryption)
- [x] `find_xor_loops()` - Detect XOR decryption loops
- [x] `find_dynamic_calls()` - Find indirect/dynamic API calls
- [x] `find_stack_strings()` - Detect stack-built strings (obfuscation)

#### Data Flow Analysis
- [x] `trace_argument()` - Trace function argument usage and propagation
- [x] `find_data_refs()` - Find data references to/from addresses

#### Control Flow Graph Export
- [x] `export_cfg()` - Export CFG in DOT or JSON format with optional assembly
- [x] `export_callgraph_dot()` - Export call graph in DOT format for Graphviz

#### Advanced Graph Analysis
- [x] `find_loops()` - Detect loops in function CFG (back edge detection)
- [x] `find_unreachable_code()` - Find dead/unreachable basic blocks
- [x] `function_complexity()` - Calculate cyclomatic complexity and metrics

#### Caching System
- [x] `get_cached_functions()` - Cached function listing with auto-invalidation

#### YARA Integration
- [x] `yara_scan()` - Scan binary with YARA rules (requires yara-python)

#### Crypto Detection
- [x] `find_crypto_constants()` - Detect AES, MD5, SHA, Blowfish, TEA constants
- [x] `decode_strings()` - Attempt string decoding (XOR, base64, rot13, hex)

## Planned

### Performance Optimizations
- [ ] Lazy loading for structure members
- [ ] Streaming responses for very large results

### New Features
- [ ] Symbolic execution helpers
- [ ] Taint analysis

### Documentation
- [ ] API reference with pagination examples
- [ ] Best practices for large binary analysis
- [ ] Token usage optimization guide

## Breaking Changes Log

### v1.3.0
- `entrypoints()` now returns `dict` instead of `list[Function]`
- `local_types()` now returns `dict` instead of `list`
- `structs()` now returns `dict` instead of `list[StructureDefinition]`
- `search_structs()` now returns `dict` instead of `list[dict]`
- All above functions now include `cursor` object for pagination

Clients should update to handle new response format with cursor-based pagination.
