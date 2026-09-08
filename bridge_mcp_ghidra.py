# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

# Seconds to wait for the Ghidra plugin to answer. The original hardcoded 5 seconds was far too
# low: list_data_items timed out on any real program, and every bulk endpoint below would too.
DEFAULT_REQUEST_TIMEOUT = 60

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

# Overridable with --timeout; see main().
request_timeout = DEFAULT_REQUEST_TIMEOUT

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=request_timeout)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=request_timeout)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def _decode_json(response) -> dict:
    """
    Turn an HTTP response from a JSON endpoint into a dict.

    The JSON endpoints always answer with a document, including on failure, where it is
    ``{"error": "..."}``. Anything that is not parseable JSON -- a proxy error page, say -- is
    wrapped in the same shape so callers only ever have one failure mode to check.
    """
    response.encoding = 'utf-8'
    try:
        payload = response.json()
    except ValueError:
        return {"error": f"Non-JSON response (HTTP {response.status_code}): "
                         f"{response.text.strip()[:500]}"}
    if isinstance(payload, dict) and not response.ok and "error" not in payload:
        payload["error"] = f"HTTP {response.status_code}"
    return payload

def safe_get_json(endpoint: str, params: dict = None) -> dict:
    """
    GET a structured endpoint and return the parsed JSON document.

    Companion to safe_get for endpoints whose answer is a structure rather than a list of lines.
    """
    url = urljoin(ghidra_server_url, endpoint)
    try:
        return _decode_json(requests.get(url, params=params or {}, timeout=request_timeout))
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}

def safe_post_json(endpoint: str, data: dict, timeout: int = None) -> dict:
    """POST form-encoded parameters to an endpoint that answers with JSON."""
    url = urljoin(ghidra_server_url, endpoint)
    try:
        return _decode_json(
            requests.post(url, data=data, timeout=timeout or request_timeout))
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}

def safe_post_json_body(endpoint: str, payload) -> dict:
    """POST a JSON document to an endpoint that answers with JSON."""
    url = urljoin(ghidra_server_url, endpoint)
    try:
        return _decode_json(requests.post(url, json=payload, timeout=request_timeout))
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}

# ----------------------------------------------------------------------------------------------
# Project and program selection
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def list_project_items(recursive: bool = True) -> dict:
    """
    List files and folders in the currently open Ghidra project.

    Program files are marked with ``program: true`` and include their project path.  The path is
    the value to pass to open_project_program.  The response also says whether each item is open
    and whether it is the active program.  This lets an agent discover an imported/analyzed
    executable without requiring the user to open it manually.

    Args:
        recursive: Include items below subfolders (default: true).
    """
    return safe_get_json("project_items", {"recursive": str(recursive).lower()})

@mcp.tool()
def list_open_programs() -> dict:
    """
    List all programs currently open in Ghidra.

    Ghidra can keep multiple programs open, but only one is active at a time.  Existing analysis
    tools operate on the active program; use select_program to switch between entries.
    """
    return safe_get_json("open_programs")

@mcp.tool()
def open_project_program(path: str) -> dict:
    """
    Open an analyzed program from the current Ghidra project and make it active.

    ``path`` should normally be copied from the ``path`` field returned by list_project_items, for
    example ``/MassEffect1.exe`` or ``/games/MassEffect2.exe``.  A unique project-file name is also
    accepted.  If the program is already open, this only selects it and does not open a duplicate.
    After this call, all existing listing, decompilation, search and mutation tools target this
    program until another program is opened or selected.
    """
    if not path or not path.strip():
        return {"error": "path is required; call list_project_items first"}
    return safe_post_json("open_program", {"path": path})

@mcp.tool()
def select_program(path: str) -> dict:
    """
    Make an already-open Ghidra program the active program.

    Use the project ``path`` from list_open_programs or list_project_items.  This does not reopen
    or duplicate a program; if it is not open, call open_project_program instead.  All existing
    analysis tools operate on the selected program.
    """
    if not path or not path.strip():
        return {"error": "path is required; call list_open_programs first"}
    return safe_post_json("select_program", {"path": path})

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100,
                    start_address: str = None, end_address: str = None) -> list:
    """
    List defined data labels and their values with pagination.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of items to return (default: 100)
        start_address: Optional inclusive lower bound, 0x-prefixed hex (e.g. "0x7ff74b920000").
            Ask about one region instead of paging through the whole image.
        end_address: Optional inclusive upper bound, 0x-prefixed hex.

    Returns:
        Lines of the form "<address>: <label> = <value>". Items with no label read "(unnamed)".
    """
    params = {"offset": offset, "limit": limit}
    if start_address:
        params["start_address"] = start_address
    if end_address:
        params["end_address"] = end_address
    return safe_get("data", params)

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

# ----------------------------------------------------------------------------------------------
# Bulk reads
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, length: int, format: str = "hex") -> dict:
    """
    Read raw bytes out of the program's memory in one call.

    Reads the image as Ghidra has it loaded -- a memory dump, plus any patches applied in the
    project -- not the file on disk. This is the bulk-transfer primitive: use it instead of one
    get_xrefs_from per address when you need to sweep a table or a whole section.

    Args:
        address: Start address, 0x-prefixed hex (e.g. "0x7ff74b920898"). A bare hex string works too.
        length: Number of bytes to read, decimal. Must be 1..8388608 (8 MiB) per call.
        format: "hex" (default) for a lowercase hex string, or "base64".

    Returns:
        {"address": "0x...", "end_address": "0x...", "length": N, "format": "hex",
         "data": "<hex or base64 string>"}
        On failure: {"error": "..."}. An unmapped or uninitialized byte anywhere in the range
        fails the whole call and names the first bad address -- no zero-filling, so you can never
        mistake padding for data. Split the read around the gap, or use list_segments to see
        which ranges exist.

    Decode with: bytes.fromhex(result["data"]) or base64.b64decode(result["data"]).
    """
    return safe_get_json("read_memory",
                         {"address": address, "length": length, "format": format})

@mcp.tool()
def read_pointers(address: str, count: int) -> dict:
    """
    Read consecutive pointer-sized slots and resolve each one to a symbol.

    The convenience layer over read_memory for vtables, jump tables and relocation arrays. Slot
    width is the program's own pointer size, not a hardcoded 8.

    Args:
        address: Address of the first slot, 0x-prefixed hex (e.g. "0x7ff74b920898").
        count: Number of consecutive slots to read. Must be 1..262144, and
            count * pointer_size must not exceed 8 MiB.

    Returns:
        {"address": "0x...", "count": N, "pointer_size": 8, "pointers": [
            {"index": 83, "address": "0x7ff74b920b30", "value": "0x7ff74a903820",
             "symbol": "AK::WriteBytesCount::SetMemPool_NOTHINGFUNC",
             "is_function": true, "mapped": true}, ...]}

        "address" is the slot's own address; "value" is what the slot holds. "symbol" is the
        function at the target, else the primary symbol there, else the enclosing function with a
        byte offset, else null. "is_function" is true only when a function is defined at exactly
        the target address -- a false here on a vtable slot usually means Ghidra never analysed
        that address, which create_function can fix. "mapped" is false when the value is not an
        address in this program's memory.
        On failure: {"error": "..."} naming the first unreadable address.
    """
    return safe_get_json("read_pointers", {"address": address, "count": count})

# ----------------------------------------------------------------------------------------------
# Symbol search
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def search_symbols_by_name(query: str, type: str = "all",
                           offset: int = 0, limit: int = 100) -> dict:
    """
    Search every defined symbol by name substring -- data and labels, not just functions.

    search_functions_by_name only sees functions, which leaves labelled data (vtables, tables,
    globals) findable only by stumbling across a decompilation that references it.

    Args:
        query: Case-insensitive substring to match against symbol names (e.g. "vtbl_").
        type: "all" (default), "function", "data", or "label".
            "data" is the subset of labels that sit on a defined data item; "label" is every
            label, typed or not. If a name you expect is missing under "data", try "label" --
            the bytes under it may never have been given a type.
        offset: Pagination offset (default: 0)
        limit: Maximum number of symbols to return (default: 100)

    Returns:
        {"query": ..., "type": ..., "total_matches": N, "truncated": false,
         "offset": 0, "limit": 100, "symbols": [
            {"name": "vtbl_UObject", "address": "0x7ff74b920898", "type": "data",
             "namespace": "Global", "symbol_type": "Label",
             "data_type": "UObject_VTable"}, ...]}

        Matches are sorted by name, then address. "truncated" is true when more than 20000
        symbols matched and the result set was cut short -- narrow the query.
        On failure: {"error": "..."}.
    """
    return safe_get_json("search_symbols",
                         {"query": query, "type": type, "offset": offset, "limit": limit})

# ----------------------------------------------------------------------------------------------
# Data types
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def get_data_type(name: str) -> dict:
    """
    Dump a struct, union, enum or typedef definition with field offsets, sizes and names.

    Args:
        name: Type name (e.g. "UObject_VTable") or full path (e.g. "/UObject_VTable").
            Bare names are matched first through the data type manager's index, then
            case-insensitively.

    Returns:
        For a struct or union:
        {"name": ..., "path": ..., "size": 688, "kind": "structure", "is_packed": false,
         "alignment": 8, "num_components": 86, "num_defined_components": 86, "fields": [
            {"ordinal": 70, "offset": 560, "offset_hex": "0x230", "size": 8,
             "name": null, "default_name": "field70_0x230", "type": "pointer",
             "type_path": "/pointer", "comment": null, "is_bitfield": false}, ...]}

        "name" is the stored field name and is null when the field has never been named;
        "default_name" is what the decompiler prints in that case. Use "offset" (or "offset_hex")
        with set_struct_field to name it.

        For an enum: {"kind": "enum", "count": N, "values": [{"name", "value", "value_hex",
        "comment"}, ...]}. For a typedef: {"kind": "typedef", "base_type", "base_type_path"}.
        On failure: {"error": "..."}.
    """
    return safe_get_json("get_data_type", {"name": name})

@mcp.tool()
def set_struct_field(struct_name: str, offset: int, name: str = None,
                     type: str = None, comment: str = None) -> dict:
    """
    Name, retype or comment a single struct field, addressed by its byte offset.

    Naming vtable struct fields is worth far more than the equivalent comments: it changes every
    decompilation that goes through the struct at once, turning
    "(*(code *)param_1->VfTableObject->field70_0x230)(...)" into "this->vtbl->ProcessEvent(...)".

    Args:
        struct_name: Name or full path of the structure (e.g. "UObject_VTable").
        offset: Byte offset of the field's own start. Decimal (560) or hex (0x230) both work.
            An offset that lands inside a field rather than on its start is an error naming the
            field's real offset.
        name: New field name. Pass "" to clear the name and get the auto-generated one back.
            Omit to leave the name alone.
        type: New field type (e.g. "void *", "uint", "UObject_VTable *", "char[16]").
            Trailing "*" makes a pointer; a trailing "[N]" makes an array. An unknown type name
            is an error -- nothing is silently substituted. Omit to leave the type alone.
        comment: Field comment. Pass "" to clear it. Omit to leave it alone.

    Returns:
        {"struct": ..., "path": ..., "size": ..., "field": {<the updated field, same shape as
        get_data_type's entries>}}
        On failure: {"error": "..."}.

    Runs inside a Ghidra transaction, so a failure leaves the struct untouched.
    """
    params = {"struct_name": struct_name, "offset": offset}
    if name is not None:
        params["name"] = name
    if type is not None:
        params["type"] = type
    if comment is not None:
        params["comment"] = comment
    return safe_post_json("set_struct_field", params)

@mcp.tool()
def create_data_type(c_declaration: str, replace: bool = False) -> dict:
    """
    Parse a C declaration into the program's data type manager.

    Turns "define 86 fields" into one call. Accepts struct, union, enum and typedef declarations,
    and several of them in one string.

    Args:
        c_declaration: C source, e.g.
            "struct UObject_VTable { void *Destructor; void *ProcessEvent; };"
            Types referenced by the declaration must already exist in the program.
        replace: If a type of that name already exists, False (the default) refuses and names the
            clash rather than overwriting something the program already references. Pass True to
            overwrite deliberately. To change one field of an existing struct, use
            set_struct_field instead -- it does not disturb the other fields.

    Returns:
        {"last_type": ..., "last_type_path": "/UObject_VTable",
         "created": ["/UObject_VTable", ...], "replaced": false,
         "messages": "<parser warnings, or null>"}
        "created" holds the full paths of the types actually added to the program.
        On failure: {"error": "..."} -- either a parse error or an "already defined: ..." clash.

    Runs inside a Ghidra transaction, so a parse failure adds nothing.
    """
    params = {"c_declaration": c_declaration}
    if replace:
        params["replace"] = "true"
    return safe_post_json("create_data_type", params)

# ----------------------------------------------------------------------------------------------
# Defining code
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def create_function(address: str, name: str = None) -> dict:
    """
    Define a function at an address, disassembling first if nothing is defined there yet.

    Ghidra will leave an address undefined even when a hundred vtables point at it, and short
    thunks are a common casualty. Use this when read_pointers reports "is_function": false for a
    slot that plainly holds code.

    Args:
        address: Function entry point, 0x-prefixed hex (e.g. "0x7ff74a9ed540").
        name: Optional name for the new function. Omit to let Ghidra name it (FUN_...).
            Ignored if a function already exists there -- use rename_function_by_address for that.

    Returns:
        {"name": ..., "entry_point": "0x...", "body_min": "0x...", "body_max": "0x...",
         "body_size": N, "signature": "...", "already_existed": false, "disassembled": true}

        "already_existed" true means the address already had a function and nothing was changed.
        "disassembled" true means bytes had to be turned into code first.
        On failure: {"error": "..."} explaining whether disassembly or function creation failed.

    Runs inside a Ghidra transaction.
    """
    params = {"address": address}
    if name:
        params["name"] = name
    return safe_post_json("create_function", params)

@mcp.tool()
def disassemble_at(address: str, length: int = None) -> dict:
    """
    Turn bytes into code units at an address, without defining a function.

    Args:
        address: Where to start disassembling, 0x-prefixed hex.
        length: Optional byte budget. Omit to let the disassembler follow control flow as far as
            it goes; give a length to confine it to exactly that many bytes.

    Returns:
        {"address": "0x...", "bytes_disassembled": N, "range_start": "0x...",
         "range_end": "0x...", "instructions": ["7ff74a9ed540: MOV EAX,0x1", ...]}

        Calling this on an address that is already code is a no-op, not an error: the response
        carries "already_defined": true and lists the instructions that are there, so it is safe
        to call without checking first. The instruction list is capped at 1000 entries; use
        disassemble_function for more.
        On failure: {"error": "..."} -- most often because the bytes there are defined as data,
        which has to be cleared in the Ghidra UI first; the error names the data type.

    Runs inside a Ghidra transaction.
    """
    params = {"address": address}
    if length is not None:
        params["length"] = length
    return safe_post_json("disassemble_at", params)

# ----------------------------------------------------------------------------------------------
# Batch mutation
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def set_disassembly_comments(comments: list) -> dict:
    """
    Set many EOL disassembly comments in one call and one Ghidra transaction.

    Args:
        comments: List of {"address": "0x...", "comment": "..."} dicts. An empty comment string
            clears the comment at that address.

    Returns:
        {"total": N, "succeeded": X, "failed": Y, "results": [
            {"index": 0, "address": "0x...", "success": true, "error": null}, ...]}
        A bad address fails only its own entry; the rest still apply.
    """
    return safe_post_json_body("set_disassembly_comments", comments)

@mcp.tool()
def set_decompiler_comments(comments: list) -> dict:
    """
    Set many decompiler (PRE) comments in one call and one Ghidra transaction.

    Args:
        comments: List of {"address": "0x...", "comment": "..."} dicts. An empty comment string
            clears the comment at that address.

    Returns:
        {"total": N, "succeeded": X, "failed": Y, "results": [
            {"index": 0, "address": "0x...", "success": true, "error": null}, ...]}
        A bad address fails only its own entry; the rest still apply.
    """
    return safe_post_json_body("set_decompiler_comments", comments)

@mcp.tool()
def rename_functions(renames: list) -> dict:
    """
    Rename many functions in one call and one Ghidra transaction.

    Args:
        renames: List of {"address": "0x...", "new_name": "..."} dicts. The address may be the
            entry point or any address inside the function's body.

    Returns:
        {"total": N, "succeeded": X, "failed": Y, "results": [
            {"index": 0, "address": "0x...", "success": true, "error": null}, ...]}
        An address with no function, or a name that collides, fails only its own entry.
    """
    return safe_post_json_body("rename_functions", renames)

# ----------------------------------------------------------------------------------------------
# Scripting escape hatch
# ----------------------------------------------------------------------------------------------

@mcp.tool()
def run_script(source: str, lang: str = "python", timeout: int = 60) -> dict:
    """
    Run a Ghidra script against the open program and return its output.

    The general escape hatch: express a whole-image scan as ~20 lines instead of thousands of API
    calls. The script runs with the same globals a Script Manager script gets -- currentProgram,
    currentAddress, monitor, state -- and prints with println() or print().

    DIALECT: with lang="python" the script runs under whichever provider Ghidra has enabled for
    .py files. Ghidra 11.x ships PyGhidra (CPython 3, real Python 3 syntax); the older Jython 2.7
    extension is Python 2 syntax. The returned "provider" field says which one actually ran it --
    check it before assuming f-strings work, and prefer syntax valid in both ("%" formatting,
    print(...) with a single argument) when you do not want to care. lang="java" is also accepted;
    the source must declare a public class extending GhidraScript.

    OUTPUT: both print(...) and println(...) are captured and come back in "stdout". Ghidra's own
    Python providers send script output to the GUI Console rather than to the caller, so the
    plugin redirects sys.stdout and sys.stderr inside the interpreter to capture it. A traceback
    from an uncaught exception is captured the same way and appears in "stdout" too.

    Args:
        source: Complete script source.
        lang: "python" (default) or "java".
        timeout: Wall-clock budget in seconds, 1..3600 (default: 60).

    Returns:
        {"provider": "PyGhidraScriptProvider", "lang": "python", "stdout": "...", "stderr": "...",
         "error": null, "timed_out": false, "duration_ms": 1234}

        "error" holds a Java-level failure (the script could not be launched at all); a Python
        exception inside the script shows up as a traceback at the end of "stdout" instead.
        "timed_out" true means the task monitor was cancelled and "stdout" holds whatever had been
        printed by then -- a script that never checks monitor.isCancelled() keeps running in
        Ghidra after that. stdout is capped at 8 MiB.

    The script runs inside a Ghidra transaction, so mutations are undoable as one step. Mutations
    made before an exception are kept, not rolled back.

    Disabled if 'Enable run_script' is turned off under 'GhidraMCP HTTP Server' in Ghidra's tool
    options; the call then returns an error saying so.
    """
    # The HTTP request has to outlive the script's own budget, or the bridge gives up first and
    # the caller loses the partial output the plugin would have returned.
    http_timeout = max(request_timeout, (timeout or 60) + 30)
    return safe_post_json("run_script",
                          {"source": source, "lang": lang, "timeout": timeout},
                          timeout=http_timeout)

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                        help="Seconds to wait for the Ghidra plugin to answer, "
                             f"default: {DEFAULT_REQUEST_TIMEOUT}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variables to ensure they're properly updated
    global ghidra_server_url, request_timeout
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    if args.timeout:
        request_timeout = args.timeout

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

