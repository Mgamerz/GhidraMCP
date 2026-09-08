package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.util.cparser.C.CParser;
import ghidra.framework.options.Options;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectData;
import generic.jar.ResourceFile;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String RUN_SCRIPT_OPTION_NAME = "Enable run_script";
    private static final int DEFAULT_PORT = 8080;

    /**
     * Upper bound on a single /read_memory or /read_pointers transfer. Bulk reads are the whole
     * point of these endpoints, so this is deliberately generous; it exists only to stop a typo in
     * a length parameter from trying to allocate the entire address space.
     */
    private static final int MAX_MEMORY_READ_BYTES = 8 * 1024 * 1024;

    /** Upper bound on /read_pointers count, independent of the byte cap. */
    private static final int MAX_POINTER_COUNT = 262144;

    /** How many /search_symbols matches are collected before the result set is truncated. */
    private static final int MAX_SEARCH_MATCHES = 20000;

    /** Default and maximum wall-clock budget for /run_script. */
    private static final int DEFAULT_SCRIPT_TIMEOUT_SECONDS = 60;
    private static final int MAX_SCRIPT_TIMEOUT_SECONDS = 3600;

    /** Cap on captured script output, so a runaway print loop cannot exhaust the heap. */
    private static final int MAX_SCRIPT_OUTPUT_CHARS = 8 * 1024 * 1024;

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /** Matches the class declaration of a Java script, used to name its temporary source file. */
    private static final Pattern JAVA_CLASS_DECLARATION =
        Pattern.compile("(?m)^\\s*public\\s+class\\s+(\\w+)");

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        options.registerOption(RUN_SCRIPT_OPTION_NAME, true,
            null,
            "Whether the /run_script endpoint will execute scripts. The server is bound to " +
            "loopback, so this is a local-only capability, but turn it off if you would rather " +
            "the HTTP API could not run arbitrary code against the open program.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        // Bind to loopback only. Everything this server exposes -- and /run_script in particular --
        // is meant for a coding agent running on this machine, never for the network.
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);

        // Project/program management endpoints.  Ghidra supports multiple programs in one tool,
        // but only one active program at a time.  The existing analysis endpoints intentionally
        // continue to use the active program; these endpoints let an MCP client discover, open and
        // select that program without requiring manual interaction with the Project window.
        server.createContext("/project_items", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            boolean recursive = parseBooleanOrDefault(qparams.get("recursive"), true);
            sendJsonResponse(exchange, listProjectItems(recursive));
        });

        server.createContext("/open_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, openProjectProgram(params.get("path")));
        });

        server.createContext("/select_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, selectOpenProgram(params.get("path")));
        });

        server.createContext("/open_programs", exchange -> {
            sendJsonResponse(exchange, listOpenPrograms());
        });

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit,
                qparams.get("start_address"), qparams.get("end_address")));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // ------------------------------------------------------------------------------------
        // Bulk / structured endpoints. These answer with JSON rather than the line-oriented
        // plain text the endpoints above use; see sendJsonResponse and the JsonResult type.
        // ------------------------------------------------------------------------------------

        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, readMemory(
                qparams.get("address"), qparams.get("length"), qparams.get("format")));
        });

        server.createContext("/read_pointers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, readPointers(qparams.get("address"), qparams.get("count")));
        });

        server.createContext("/search_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendJsonResponse(exchange, searchSymbolsByName(
                qparams.get("query"), qparams.get("type"), offset, limit));
        });

        server.createContext("/get_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendJsonResponse(exchange, getDataTypeDefinition(qparams.get("name")));
        });

        server.createContext("/set_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, setStructField(
                params.get("struct_name"), params.get("offset"),
                params.get("name"), params.get("type"), params.get("comment")));
        });

        server.createContext("/create_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, createDataType(
                params.get("c_declaration"), params.get("replace")));
        });

        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, createFunctionAt(params.get("address"), params.get("name")));
        });

        server.createContext("/disassemble_at", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, disassembleAt(params.get("address"), params.get("length")));
        });

        server.createContext("/run_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendJsonResponse(exchange, runScript(
                params.get("source"), params.get("lang"), params.get("timeout")));
        });

        server.createContext("/set_disassembly_comments", exchange -> {
            sendJsonResponse(exchange, batchSetComments(readRequestBody(exchange),
                CodeUnit.EOL_COMMENT, "Set disassembly comments (batch)"));
        });

        server.createContext("/set_decompiler_comments", exchange -> {
            sendJsonResponse(exchange, batchSetComments(readRequestBody(exchange),
                CodeUnit.PRE_COMMENT, "Set decompiler comments (batch)"));
        });

        server.createContext("/rename_functions", exchange -> {
            sendJsonResponse(exchange, batchRenameFunctions(readRequestBody(exchange)));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    /** Return all files and folders in the active Ghidra project as a JSON document. */
    private JsonResult listProjectItems(boolean recursive) {
        if (tool.getProject() == null) {
            return JsonResult.badRequest("No Ghidra project is open");
        }

        ProjectData projectData = tool.getProject().getProjectData();
        if (projectData == null || projectData.getRootFolder() == null) {
            return JsonResult.badRequest("The active Ghidra project has no project data");
        }

        List<String> rendered = new ArrayList<>();
        collectProjectItems(projectData.getRootFolder(), recursive, rendered,
            new HashSet<String>());
        Collections.sort(rendered);
        return JsonResult.ok(new Json.Obj()
            .raw("items", Json.array(rendered))
            .num("count", rendered.size())
            .done());
    }

    private void collectProjectItems(DomainFolder folder, boolean recursive,
                                     List<String> rendered, Set<String> visitedFolders) {
        String folderPath = folder.getPathname();
        if (!visitedFolders.add(folderPath)) return;

        for (DomainFile file : folder.getFiles()) {
            rendered.add(renderProjectFile(file));
        }
        if (!recursive) return;

        for (DomainFolder child : folder.getFolders()) {
            rendered.add(renderProjectFolder(child));
            collectProjectItems(child, true, rendered, visitedFolders);
        }
    }

    private String renderProjectFolder(DomainFolder folder) {
        return new Json.Obj()
            .str("kind", "folder")
            .str("name", folder.getName())
            .str("path", folder.getPathname())
            .done();
    }

    private String renderProjectFile(DomainFile file) {
        Class<?> domainClass = file.getDomainObjectClass();
        boolean isProgram = domainClass != null && Program.class.isAssignableFrom(domainClass);
        Program current = getCurrentProgram();
        boolean currentProgram = current != null && sameProgramPath(current, file.getPathname());

        return new Json.Obj()
            .str("kind", "file")
            .str("name", file.getName())
            .str("path", file.getPathname())
            .str("content_type", file.getContentType())
            .str("domain_class", domainClass != null ? domainClass.getName() : null)
            .bool("program", isProgram)
            .bool("open", file.isOpen())
            .bool("current", currentProgram)
            .done();
    }

    /** Open a program by its project path and make it the active program. */
    private JsonResult openProjectProgram(String requestedPath) {
        if (requestedPath == null || requestedPath.trim().isEmpty()) {
            return JsonResult.badRequest("path is required; call list_project_items first");
        }
        if (tool.getProject() == null) {
            return JsonResult.badRequest("No Ghidra project is open");
        }

        DomainFile file = findProjectFile(requestedPath);
        if (file == null) {
            return JsonResult.badRequest("No project item matched '" + requestedPath + "'");
        }
        Class<?> domainClass = file.getDomainObjectClass();
        if (domainClass == null || !Program.class.isAssignableFrom(domainClass)) {
            return JsonResult.badRequest("Project item '" + file.getPathname()
                + "' is not a program (content type: " + file.getContentType() + ")");
        }

        AtomicReference<JsonResult> result = new AtomicReference<>();
        try {
            Runnable open = () -> {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm == null) {
                    result.set(JsonResult.serverError("Ghidra's ProgramManager service is unavailable"));
                    return;
                }

                Program program = findOpenProgram(pm, file.getPathname());
                if (program == null) {
                    program = pm.openProgram(file);
                }
                if (program == null) {
                    result.set(JsonResult.serverError("Ghidra could not open '"
                        + file.getPathname() + "'"));
                    return;
                }

                pm.setCurrentProgram(program);
                result.set(JsonResult.ok(programSummary(program, pm, "opened")));
            };
            if (SwingUtilities.isEventDispatchThread()) {
                open.run();
            }
            else {
                SwingUtilities.invokeAndWait(open);
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return JsonResult.serverError("Interrupted while opening '" + file.getPathname() + "'");
        }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            Msg.error(this, "Failed to open project program", cause);
            return JsonResult.serverError("Failed to open '" + file.getPathname()
                + "': " + cause.getMessage());
        }
        return result.get() != null
            ? result.get()
            : JsonResult.serverError("Ghidra did not return an open-program result");
    }

    /** Make an already-open program active without opening a second copy. */
    private JsonResult selectOpenProgram(String requestedPath) {
        if (requestedPath == null || requestedPath.trim().isEmpty()) {
            return JsonResult.badRequest("path is required; call list_open_programs first");
        }

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return JsonResult.serverError("Ghidra's ProgramManager service is unavailable");

        AtomicReference<JsonResult> result = new AtomicReference<>();
        Runnable select = () -> {
            Program program = findOpenProgram(pm, requestedPath);
            if (program == null) {
                result.set(JsonResult.badRequest("No open program matched '" + requestedPath
                    + "'; call open_project_program first"));
                return;
            }
            pm.setCurrentProgram(program);
            result.set(JsonResult.ok(programSummary(program, pm, "selected")));
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                select.run();
            }
            else {
                SwingUtilities.invokeAndWait(select);
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return JsonResult.serverError("Interrupted while selecting '" + requestedPath + "'");
        }
        catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            Msg.error(this, "Failed to select open program", cause);
            return JsonResult.serverError("Failed to select '" + requestedPath
                + "': " + cause.getMessage());
        }
        return result.get() != null
            ? result.get()
            : JsonResult.serverError("Ghidra did not return a selected-program result");
    }

    /** List every program open in this Ghidra tool, including which one is active. */
    private JsonResult listOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) return JsonResult.serverError("Ghidra's ProgramManager service is unavailable");

        List<String> programs = new ArrayList<>();
        for (Program program : pm.getAllOpenPrograms()) {
            programs.add(programSummary(program, pm, null));
        }
        programs.sort(Comparator.comparing(value -> value.toLowerCase(Locale.ROOT)));
        return JsonResult.ok(new Json.Obj()
            .raw("programs", Json.array(programs))
            .num("count", programs.size())
            .done());
    }

    private String programSummary(Program program, ProgramManager pm, String action) {
        DomainFile file = program.getDomainFile();
        String path = file != null ? file.getPathname() : null;
        Json.Obj object = new Json.Obj()
            .str("name", program.getName())
            .str("path", path)
            .str("executable_path", program.getExecutablePath())
            .bool("current", pm.getCurrentProgram() == program)
            .bool("visible", pm.isVisible(program));
        if (action != null) object.str("action", action);
        return object.done();
    }

    private DomainFile findProjectFile(String requestedPath) {
        ProjectData projectData = tool.getProject().getProjectData();
        String requested = normalizeProjectPath(requestedPath);
        DomainFile exact = projectData.getFile(requested);
        if (exact != null) return exact;

        List<DomainFile> matches = new ArrayList<>();
        collectProjectFiles(projectData.getRootFolder(), matches, new HashSet<String>());
        String requestedName = projectItemName(requestedPath);
        for (DomainFile file : matches) {
            if (file.getPathname().equalsIgnoreCase(requested)
                || file.getName().equalsIgnoreCase(requestedName)) {
                return file;
            }
        }
        return null;
    }

    private void collectProjectFiles(DomainFolder folder, List<DomainFile> files,
                                     Set<String> visitedFolders) {
        if (!visitedFolders.add(folder.getPathname())) return;
        Collections.addAll(files, folder.getFiles());
        for (DomainFolder child : folder.getFolders()) {
            collectProjectFiles(child, files, visitedFolders);
        }
    }

    private Program findOpenProgram(ProgramManager pm, String requestedPath) {
        String requested = normalizeProjectPath(requestedPath);
        String requestedName = projectItemName(requestedPath);
        for (Program program : pm.getAllOpenPrograms()) {
            DomainFile file = program.getDomainFile();
            String executablePath = program.getExecutablePath();
            if ((file != null && (file.getPathname().equalsIgnoreCase(requested)
                || file.getName().equalsIgnoreCase(requestedName)))
                || (executablePath != null && executablePath.equalsIgnoreCase(requestedPath.trim()))) {
                return program;
            }
        }
        return null;
    }

    private String projectItemName(String path) {
        String normalized = path.trim().replace('\\', '/');
        int separator = normalized.lastIndexOf('/');
        return separator >= 0 ? normalized.substring(separator + 1) : normalized;
    }

    private boolean sameProgramPath(Program program, String path) {
        DomainFile file = program.getDomainFile();
        return file != null && file.getPathname().equalsIgnoreCase(path);
    }

    private String normalizeProjectPath(String path) {
        String normalized = path.trim().replace('\\', '/');
        if (!normalized.startsWith("/")) normalized = "/" + normalized;
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Page page = new Page(offset, limit);
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (page.add(f::getName)) break;
        }
        return page.render();
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Page page = new Page(offset, limit);
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            if (page.add(() -> symbol.getName() + " -> " + symbol.getAddress())) break;
        }
        return page.render();
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        Page page = new Page(offset, limit);
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                if (page.add(() -> s.getName() + " -> " + s.getAddress())) break;
            }
        }
        return page.render();
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    /**
     * List defined data items, newest-style with optional address bounds.
     *
     * <p>The original implementation formatted <em>every</em> defined data item in the program --
     * including a {@link Data#getDefaultValueRepresentation()} call each, which is not cheap --
     * before handing the finished list to {@code paginateList} to be sliced, so {@code limit=15}
     * did the same work as {@code limit=1000000}. It was also accidentally quadratic: the outer
     * loop walked memory blocks while the inner iterator ran to the end of the program on every
     * pass, discarding out-of-block hits.
     *
     * <p>This version stops the inner iterator at the block boundary, formats only the items it is
     * actually going to return, and gives up as soon as {@code limit} of them have been collected.
     *
     * @param startAddress optional inclusive lower bound; when given, {@code endAddress} bounds the
     *                     scan to one region instead of paging through the whole image
     * @param endAddress   optional inclusive upper bound
     */
    private String listDefinedData(int offset, int limit, String startAddress, String endAddress) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Address from = null;
        Address to = null;
        if (startAddress != null && !startAddress.isEmpty()) {
            from = parseAddress(program, startAddress);
            if (from == null) return "Invalid start_address: " + startAddress;
        }
        if (endAddress != null && !endAddress.isEmpty()) {
            to = parseAddress(program, endAddress);
            if (to == null) return "Invalid end_address: " + endAddress;
        }
        if (from != null && to != null && from.compareTo(to) > 0) {
            return "start_address must not be greater than end_address";
        }

        Page page = new Page(offset, limit);
        Listing listing = program.getListing();

        if (from != null || to != null) {
            Address scanStart = (from != null) ? from : program.getMinAddress();
            if (scanStart == null) return "";
            DataIterator it = listing.getDefinedData(scanStart, true);
            while (it.hasNext()) {
                Data data = it.next();
                if (to != null && data.getAddress().compareTo(to) > 0) break;
                if (page.add(() -> formatDataItem(data))) break;
            }
            return page.render();
        }

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = listing.getDefinedData(block.getStart(), true);
            boolean full = false;
            while (it.hasNext()) {
                Data data = it.next();
                // getDefinedData() runs to the end of the program; stop at the block boundary
                // rather than iterating the whole image once per block.
                if (!block.contains(data.getAddress())) break;
                if (page.add(() -> formatDataItem(data))) {
                    full = true;
                    break;
                }
            }
            if (full) break;
        }
        return page.render();
    }

    private String formatDataItem(Data data) {
        String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
        String valRepr = data.getDefaultValueRepresentation();
        return String.format("%s: %s = %s",
            data.getAddress(),
            escapeNonAscii(label),
            escapeNonAscii(valRepr)
        );
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            Page page = new Page(offset, limit);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                if (page.add(() -> String.format("From %s%s [%s]",
                        fromAddr, describeContainer(program, fromAddr), refType.getName()))) {
                    break;
                }
            }

            return page.render();
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Describe what an address sits inside, as the {@code " in ..."} clause of an xref line.
     *
     * <p>Code references get the containing function, as they always have. Data references used to
     * get nothing at all -- just a bare address -- which left the caller to work out by hand which
     * object and which slot the reference belonged to, and it is easy to be off by one slot. So a
     * data address now reports the object it belongs to and its byte offset within it:
     *
     * <pre>From 7ff74b92aa10 in vtbl_AUActor+0x298 [DATA]</pre>
     *
     * @return a string starting with {@code " in "}, or an empty string when nothing is known
     */
    private String describeContainer(Program program, Address addr) {
        Function fromFunc = program.getFunctionManager().getFunctionContaining(addr);
        if (fromFunc != null) {
            return " in " + fromFunc.getName();
        }

        // A typed object (a vtable struct, an array) reports the whole object, so the offset is
        // relative to the object's own start.
        Data container = program.getListing().getDataContaining(addr);
        if (container != null) {
            Symbol sym = program.getSymbolTable().getPrimarySymbol(container.getMinAddress());
            if (sym != null) {
                return " in " + sym.getName() + offsetSuffix(addr, container.getMinAddress());
            }
        }

        // Untyped runs -- a vtable laid out as a series of individual pointers, say -- have no
        // enclosing object, so fall back to the nearest label at or before the address. The label
        // has to be in the same memory block for the offset to mean anything.
        Symbol preceding = findPrecedingLabel(program, addr);
        if (preceding != null) {
            return " in " + preceding.getName() + offsetSuffix(addr, preceding.getAddress());
        }

        return "";
    }

    private String offsetSuffix(Address addr, Address base) {
        long delta = addr.subtract(base);
        return (delta == 0) ? "" : String.format("+0x%x", delta);
    }

    /**
     * Find the closest symbol at or before {@code addr} within the same memory block, so an
     * unlabelled address can still be reported as {@code label+0xNN}.
     */
    private Symbol findPrecedingLabel(Program program, Address addr) {
        MemoryBlock block = program.getMemory().getBlock(addr);
        if (block == null) return null;

        SymbolIterator it = program.getSymbolTable().getSymbolIterator(addr, false);
        while (it.hasNext()) {
            Symbol sym = it.next();
            Address symAddr = sym.getAddress();
            if (symAddr == null || symAddr.compareTo(block.getStart()) < 0) return null;
            if (symAddr.compareTo(addr) > 0) continue;
            SymbolType type = sym.getSymbolType();
            if (type == SymbolType.LABEL || type == SymbolType.FUNCTION) {
                return sym;
            }
        }
        return null;
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);

            Page page = new Page(offset, limit);
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    } else {
                        // Mid-object target: name the object and the offset into it, the same way
                        // getXrefsTo does, rather than emitting a bare address.
                        Function containing = program.getFunctionManager().getFunctionContaining(toAddr);
                        if (containing != null) {
                            targetInfo = " to function " + containing.getName()
                                + offsetSuffix(toAddr, containing.getEntryPoint());
                        }
                        else {
                            String container = describeContainer(program, toAddr);
                            if (!container.isEmpty()) {
                                targetInfo = " to data " + container.substring(" in ".length());
                            }
                        }
                    }
                }

                final String info = targetInfo;
                if (page.add(() -> String.format("To %s%s [%s]", toAddr, info, refType.getName()))) {
                    break;
                }
            }

            return page.render();
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Page page = new Page(offset, limit);
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    if (page.add(() ->
                            String.format("%s: \"%s\"", data.getAddress(), escapeString(value)))) {
                        break;
                    }
                }
            }
        }

        return page.render();
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Bulk reads: raw memory and pointer tables
    // ----------------------------------------------------------------------------------

    /**
     * A JSON response together with the HTTP status it should be sent with.
     *
     * <p>The plain-text endpoints answer 200 with a human-readable error string in the body. The
     * JSON endpoints use real status codes, and always answer with a document -- an error body is
     * {@code {"error": "..."}} -- so the bridge can report the failure either way.
     */
    private static final class JsonResult {
        final int status;
        final String body;

        private JsonResult(int status, String body) {
            this.status = status;
            this.body = body;
        }

        static JsonResult ok(String body) {
            return new JsonResult(200, body);
        }

        /** The caller asked for something impossible: bad address, bad length, missing program. */
        static JsonResult badRequest(String message) {
            return new JsonResult(400, Json.error(message));
        }

        /** Something went wrong on this side that the caller could not have predicted. */
        static JsonResult serverError(String message) {
            return new JsonResult(500, Json.error(message));
        }
    }

    /**
     * Read raw bytes out of the program's memory.
     *
     * <p>This reads {@code currentProgram.getMemory()}, i.e. the image as Ghidra has it loaded --
     * a memory dump, any applied patches -- not the file on disk.
     *
     * <p>An unmapped or uninitialized byte anywhere in the requested range fails the whole call and
     * names the first bad address. Zero-filling the gap would be worse than useless: a caller
     * scanning for structure has no way to tell padding it asked for from padding it invented.
     */
    private JsonResult readMemory(String addressStr, String lengthStr, String format) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) {
            return JsonResult.badRequest("address is required");
        }

        String fmt = (format == null || format.isEmpty())
            ? "hex" : format.toLowerCase(Locale.ROOT);
        if (!fmt.equals("hex") && !fmt.equals("base64")) {
            return JsonResult.badRequest("format must be 'hex' or 'base64', got '" + format + "'");
        }

        long length;
        try {
            length = parseNumber(lengthStr);
        }
        catch (NumberFormatException e) {
            return JsonResult.badRequest("length is required, as a decimal or 0x-prefixed number");
        }
        if (length <= 0) {
            return JsonResult.badRequest("length must be positive, got " + length);
        }
        if (length > MAX_MEMORY_READ_BYTES) {
            return JsonResult.badRequest("length " + length + " exceeds the per-call cap of "
                + MAX_MEMORY_READ_BYTES + " bytes; split the read");
        }

        Address start = parseAddress(program, addressStr);
        if (start == null) {
            return JsonResult.badRequest("Invalid address: " + addressStr);
        }

        Address end;
        try {
            end = start.addNoWrap(length - 1);
        }
        catch (AddressOverflowException e) {
            return JsonResult.badRequest("range " + start + " + " + length
                + " bytes runs past the end of the address space");
        }

        Address firstBad = firstUnreadableAddress(program, start, end);
        if (firstBad != null) {
            return JsonResult.badRequest("memory at " + firstBad
                + " is unmapped or uninitialized (requested " + start + " - " + end
                + "); no bytes returned");
        }

        byte[] buffer = new byte[(int) length];
        try {
            int got = program.getMemory().getBytes(start, buffer, 0, (int) length);
            if (got != length) {
                return JsonResult.serverError("short read at " + start + ": asked for " + length
                    + " bytes, got " + got);
            }
        }
        catch (MemoryAccessException e) {
            return JsonResult.badRequest("memory read failed at " + start + ": " + e.getMessage());
        }

        String data = fmt.equals("hex")
            ? toHex(buffer)
            : Base64.getEncoder().encodeToString(buffer);

        return JsonResult.ok(new Json.Obj()
            .str("address", hexAddress(start))
            .str("end_address", hexAddress(end))
            .num("length", length)
            .str("format", fmt)
            .str("data", data)
            .done());
    }

    /**
     * Read {@code count} consecutive pointer-sized slots and resolve each to a symbol.
     *
     * <p>A convenience layer over {@link #readMemory} for the pattern that dominates this kind of
     * work -- vtables, jump tables, relocation arrays. The slot width is the program's own pointer
     * size, not a hardcoded 8.
     */
    private JsonResult readPointers(String addressStr, String countStr) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) {
            return JsonResult.badRequest("address is required");
        }

        long count;
        try {
            count = parseNumber(countStr);
        }
        catch (NumberFormatException e) {
            return JsonResult.badRequest("count is required, as a decimal or 0x-prefixed number");
        }
        if (count <= 0) {
            return JsonResult.badRequest("count must be positive, got " + count);
        }
        if (count > MAX_POINTER_COUNT) {
            return JsonResult.badRequest("count " + count + " exceeds the per-call cap of "
                + MAX_POINTER_COUNT);
        }

        int pointerSize = program.getDefaultPointerSize();
        long totalBytes = count * pointerSize;
        if (totalBytes > MAX_MEMORY_READ_BYTES) {
            return JsonResult.badRequest("count " + count + " x " + pointerSize
                + " bytes exceeds the per-call cap of " + MAX_MEMORY_READ_BYTES + " bytes");
        }

        Address start = parseAddress(program, addressStr);
        if (start == null) {
            return JsonResult.badRequest("Invalid address: " + addressStr);
        }

        Address end;
        try {
            end = start.addNoWrap(totalBytes - 1);
        }
        catch (AddressOverflowException e) {
            return JsonResult.badRequest("range " + start + " + " + totalBytes
                + " bytes runs past the end of the address space");
        }

        Address firstBad = firstUnreadableAddress(program, start, end);
        if (firstBad != null) {
            return JsonResult.badRequest("memory at " + firstBad
                + " is unmapped or uninitialized (requested " + start + " - " + end
                + "); no pointers returned");
        }

        byte[] buffer = new byte[(int) totalBytes];
        try {
            program.getMemory().getBytes(start, buffer, 0, buffer.length);
        }
        catch (MemoryAccessException e) {
            return JsonResult.badRequest("memory read failed at " + start + ": " + e.getMessage());
        }

        Memory memory = program.getMemory();
        boolean bigEndian = memory.isBigEndian();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        FunctionManager functions = program.getFunctionManager();

        List<String> entries = new ArrayList<>((int) count);
        for (int i = 0; i < count; i++) {
            long value = readUnsigned(buffer, i * pointerSize, pointerSize, bigEndian);
            Address slot = start.add((long) i * pointerSize);

            Json.Obj entry = new Json.Obj()
                .num("index", i)
                .str("address", hexAddress(slot))
                .str("value", "0x" + Long.toHexString(value));

            Address target = null;
            try {
                target = space.getAddress(value);
            }
            catch (Exception e) {
                // A slot that does not hold a valid address in this space: report it as unmapped
                // rather than failing the whole table.
            }

            boolean mapped = target != null && memory.contains(target);
            String symbol = mapped ? symbolNameFor(program, target) : null;
            boolean isFunction = mapped && functions.getFunctionAt(target) != null;

            entry.str("symbol", symbol).bool("is_function", isFunction).bool("mapped", mapped);
            entries.add(entry.done());
        }

        return JsonResult.ok(new Json.Obj()
            .str("address", hexAddress(start))
            .num("count", count)
            .num("pointer_size", pointerSize)
            .raw("pointers", Json.array(entries))
            .done());
    }

    /**
     * The first address in {@code [start, end]} that memory cannot supply, or null if all of it can.
     *
     * <p>Walks the initialized address set range by range rather than probing byte by byte, so the
     * cost is proportional to the number of memory blocks crossed, not to the length of the read.
     */
    private Address firstUnreadableAddress(Program program, Address start, Address end) {
        AddressSetView initialized = program.getMemory().getAllInitializedAddressSet();
        Address cursor = start;
        while (cursor.compareTo(end) <= 0) {
            AddressRange range = initialized.getRangeContaining(cursor);
            if (range == null) return cursor;
            Address rangeEnd = range.getMaxAddress();
            if (rangeEnd.compareTo(end) >= 0) return null;
            try {
                cursor = rangeEnd.addNoWrap(1);
            }
            catch (AddressOverflowException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Best-effort name for whatever lives at an address: the function there, else the primary
     * symbol, else the enclosing function with a byte offset.
     */
    private String symbolNameFor(Program program, Address target) {
        Function func = program.getFunctionManager().getFunctionAt(target);
        if (func != null) return func.getName(true);

        Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
        if (symbol != null) return symbol.getName(true);

        Function containing = program.getFunctionManager().getFunctionContaining(target);
        if (containing != null) {
            return containing.getName(true) + offsetSuffix(target, containing.getEntryPoint());
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Symbol search
    // ----------------------------------------------------------------------------------

    /**
     * Substring search over every defined symbol, not just functions.
     *
     * <p>{@code searchFunctionsByName} has always existed; there was no equivalent for data, which
     * made a labelled vtable findable only by stumbling across a decompilation that referenced it.
     */
    private JsonResult searchSymbolsByName(String query, String typeFilter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (query == null || query.isEmpty()) {
            return JsonResult.badRequest("query is required");
        }

        String wanted = (typeFilter == null || typeFilter.isEmpty())
            ? "all" : typeFilter.toLowerCase(Locale.ROOT);
        if (!wanted.equals("all") && !wanted.equals("function")
                && !wanted.equals("data") && !wanted.equals("label")) {
            return JsonResult.badRequest(
                "type must be one of 'function', 'data', 'label', 'all'; got '" + typeFilter + "'");
        }

        String needle = query.toLowerCase(Locale.ROOT);
        Listing listing = program.getListing();

        List<Symbol> matches = new ArrayList<>();
        boolean truncated = false;
        SymbolIterator it = program.getSymbolTable().getDefinedSymbols();
        while (it.hasNext()) {
            Symbol symbol = it.next();
            if (!symbol.getName().toLowerCase(Locale.ROOT).contains(needle)) continue;
            if (!matchesSymbolFilter(listing, symbol, wanted)) continue;
            if (matches.size() >= MAX_SEARCH_MATCHES) {
                truncated = true;
                break;
            }
            matches.add(symbol);
        }

        matches.sort(Comparator.comparing((Symbol s) -> s.getName())
            .thenComparing(s -> s.getAddress()));

        int start = Math.max(0, offset);
        int end = (limit <= 0) ? start : Math.min(matches.size(), start + limit);
        List<String> rendered = new ArrayList<>();
        for (int i = start; i < end && i < matches.size(); i++) {
            Symbol symbol = matches.get(i);
            Data data = listing.getDefinedDataAt(symbol.getAddress());
            Namespace ns = symbol.getParentNamespace();
            rendered.add(new Json.Obj()
                .str("name", symbol.getName())
                .str("address", hexAddress(symbol.getAddress()))
                .str("type", classifySymbol(listing, symbol))
                .str("namespace", ns != null ? ns.getName(true) : null)
                .str("symbol_type", symbol.getSymbolType().toString())
                .str("data_type", data != null ? data.getDataType().getName() : null)
                .done());
        }

        return JsonResult.ok(new Json.Obj()
            .str("query", query)
            .str("type", wanted)
            .num("total_matches", matches.size())
            .bool("truncated", truncated)
            .num("offset", start)
            .num("limit", limit)
            .raw("symbols", Json.array(rendered))
            .done());
    }

    /**
     * Bucket a symbol for the {@code type} filter.
     *
     * <p>{@code data} is the subset of labels that sit on a defined data item, so it is contained
     * in {@code label} rather than disjoint from it -- a caller who does not know whether the
     * bytes under a name have been typed yet still finds it under {@code label}.
     */
    private String classifySymbol(Listing listing, Symbol symbol) {
        SymbolType type = symbol.getSymbolType();
        if (type == SymbolType.FUNCTION) return "function";
        if (type == SymbolType.LABEL) {
            return listing.getDefinedDataAt(symbol.getAddress()) != null ? "data" : "label";
        }
        return type.toString().toLowerCase(Locale.ROOT);
    }

    private boolean matchesSymbolFilter(Listing listing, Symbol symbol, String wanted) {
        if (wanted.equals("all")) return true;
        SymbolType type = symbol.getSymbolType();
        switch (wanted) {
            case "function":
                return type == SymbolType.FUNCTION;
            case "label":
                return type == SymbolType.LABEL;
            case "data":
                return type == SymbolType.LABEL
                    && listing.getDefinedDataAt(symbol.getAddress()) != null;
            default:
                return false;
        }
    }

    // ----------------------------------------------------------------------------------
    // Data type inspection and editing
    // ----------------------------------------------------------------------------------

    /** Dump a struct, union, enum or typedef definition with offsets, sizes and names. */
    private JsonResult getDataTypeDefinition(String name) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (name == null || name.isEmpty()) return JsonResult.badRequest("name is required");

        DataType dt = lookupDataType(program.getDataTypeManager(), name);
        if (dt == null) {
            return JsonResult.badRequest("No data type named '" + name + "'");
        }

        Json.Obj out = new Json.Obj()
            .str("name", dt.getName())
            .str("path", dt.getPathName())
            .num("size", dt.getLength());

        if (dt instanceof Structure || dt instanceof ghidra.program.model.data.Union) {
            ghidra.program.model.data.Composite composite =
                (ghidra.program.model.data.Composite) dt;
            List<String> fields = new ArrayList<>();
            for (DataTypeComponent dtc : composite.getDefinedComponents()) {
                fields.add(renderStructField(dtc));
            }
            out.str("kind", dt instanceof Structure ? "structure" : "union")
               .bool("is_packed", composite.isPackingEnabled())
               .num("alignment", composite.getAlignment())
               .num("num_components", composite.getNumComponents())
               .num("num_defined_components", fields.size())
               .raw("fields", Json.array(fields));
        }
        else if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumDt = (ghidra.program.model.data.Enum) dt;
            List<String> values = new ArrayList<>();
            for (String valueName : enumDt.getNames()) {
                long value = enumDt.getValue(valueName);
                values.add(new Json.Obj()
                    .str("name", valueName)
                    .num("value", value)
                    .str("value_hex", "0x" + Long.toHexString(value))
                    .str("comment", enumDt.getComment(valueName))
                    .done());
            }
            out.str("kind", "enum")
               .num("count", enumDt.getCount())
               .raw("values", Json.array(values));
        }
        else if (dt instanceof TypeDef) {
            TypeDef typedef = (TypeDef) dt;
            out.str("kind", "typedef")
               .str("base_type", typedef.getBaseDataType().getName())
               .str("base_type_path", typedef.getBaseDataType().getPathName());
        }
        else {
            out.str("kind", "other")
               .str("description", dt.getDescription())
               .str("class", dt.getClass().getSimpleName());
        }

        return JsonResult.ok(out.done());
    }

    private String renderStructField(DataTypeComponent dtc) {
        return new Json.Obj()
            .num("ordinal", dtc.getOrdinal())
            .num("offset", dtc.getOffset())
            .str("offset_hex", "0x" + Integer.toHexString(dtc.getOffset()))
            .num("size", dtc.getLength())
            .str("name", dtc.getFieldName())
            .str("default_name", dtc.getDefaultFieldName())
            .str("type", dtc.getDataType().getName())
            .str("type_path", dtc.getDataType().getPathName())
            .str("comment", dtc.getComment())
            .bool("is_bitfield", dtc.isBitFieldComponent())
            .done();
    }

    /**
     * Name, retype or comment a single struct field, addressed by its byte offset.
     *
     * <p>Naming the fields of a vtable struct is worth far more than the equivalent number of
     * comments: it changes every decompilation that goes through the struct at once.
     */
    private JsonResult setStructField(String structName, String offsetStr,
                                      String fieldName, String typeName, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (structName == null || structName.isEmpty()) {
            return JsonResult.badRequest("struct_name is required");
        }
        if (fieldName == null && typeName == null && comment == null) {
            return JsonResult.badRequest("give at least one of name, type or comment");
        }

        int offset;
        try {
            offset = (int) parseNumber(offsetStr);
        }
        catch (NumberFormatException e) {
            return JsonResult.badRequest("offset is required, as a decimal or 0x-prefixed number");
        }
        if (offset < 0) return JsonResult.badRequest("offset must not be negative");

        AtomicReference<JsonResult> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dt = lookupDataType(dtm, structName);
                if (dt == null) {
                    result.set(JsonResult.badRequest("No data type named '" + structName + "'"));
                    return;
                }
                if (!(dt instanceof Structure)) {
                    result.set(JsonResult.badRequest("'" + structName + "' is a "
                        + dt.getClass().getSimpleName() + ", not a structure"));
                    return;
                }
                Structure struct = (Structure) dt;

                DataType newType = null;
                if (typeName != null && !typeName.isEmpty()) {
                    newType = resolveDataTypeStrict(dtm, typeName);
                    if (newType == null) {
                        result.set(JsonResult.badRequest("Unknown data type '" + typeName
                            + "'; create it first with create_data_type"));
                        return;
                    }
                }

                int tx = program.startTransaction("Set struct field");
                boolean commit = false;
                try {
                    DataTypeComponent dtc = struct.getComponentContaining(offset);
                    if (dtc == null) {
                        result.set(JsonResult.badRequest("offset 0x" + Integer.toHexString(offset)
                            + " is past the end of " + struct.getName()
                            + " (size " + struct.getLength() + ")"));
                        return;
                    }
                    if (dtc.getOffset() != offset) {
                        result.set(JsonResult.badRequest("offset 0x" + Integer.toHexString(offset)
                            + " falls inside the field at offset 0x"
                            + Integer.toHexString(dtc.getOffset())
                            + "; address a field by its own start offset"));
                        return;
                    }

                    // An empty name is how a caller asks for the auto-generated name back.
                    String resolvedName = (fieldName == null) ? dtc.getFieldName()
                        : (fieldName.isEmpty() ? null : fieldName);
                    String resolvedComment = (comment == null) ? dtc.getComment()
                        : (comment.isEmpty() ? null : comment);

                    if (newType != null) {
                        struct.replaceAtOffset(offset, newType, newType.getLength(),
                            resolvedName, resolvedComment);
                    }
                    else {
                        if (fieldName != null) dtc.setFieldName(resolvedName);
                        if (comment != null) dtc.setComment(resolvedComment);
                    }

                    DataTypeComponent updated = struct.getComponentContaining(offset);
                    result.set(JsonResult.ok(new Json.Obj()
                        .str("struct", struct.getName())
                        .str("path", struct.getPathName())
                        .num("size", struct.getLength())
                        .raw("field", updated != null ? renderStructField(updated) : "null")
                        .done()));
                    commit = true;
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting struct field", e);
                    result.set(JsonResult.badRequest("Failed to set field at offset 0x"
                        + Integer.toHexString(offset) + " of " + structName + ": " + e));
                }
                finally {
                    program.endTransaction(tx, commit);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to set struct field on Swing thread", e);
            return JsonResult.serverError("Failed to set struct field: " + e.getMessage());
        }

        JsonResult r = result.get();
        return r != null ? r : JsonResult.serverError("set_struct_field produced no result");
    }

    /** Parse a C struct/enum/typedef declaration into the program's data type manager. */
    private JsonResult createDataType(String declaration, String replaceStr) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (declaration == null || declaration.trim().isEmpty()) {
            return JsonResult.badRequest("c_declaration is required");
        }
        final boolean replace = "true".equalsIgnoreCase(replaceStr) || "1".equals(replaceStr);

        AtomicReference<JsonResult> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                DataTypeManager dtm = program.getDataTypeManager();
                int tx = program.startTransaction("Create data type");
                boolean commit = false;
                try {
                    CParser parser = new CParser(dtm);
                    DataType last = parser.parse(declaration);

                    // CParser builds the types but does not put them in the manager, so a parse
                    // that "succeeds" leaves nothing behind unless they are resolved in explicitly.
                    Map<String, DataType> parsed = new LinkedHashMap<>();
                    parsed.putAll(parser.getComposites());
                    parsed.putAll(parser.getDeclarations());
                    if (parsed.isEmpty() && last != null) {
                        parsed.put(last.getName(), last);
                    }
                    if (parsed.isEmpty()) {
                        result.set(JsonResult.badRequest(
                            "The declaration parsed but defined no named type"));
                        return;
                    }

                    // Overwriting a type that the rest of the program already references is not
                    // something to do by accident, so it has to be asked for.
                    if (!replace) {
                        List<String> clashes = new ArrayList<>();
                        for (DataType dt : parsed.values()) {
                            if (dtm.getDataType(dt.getPathName()) != null) {
                                clashes.add(dt.getPathName());
                            }
                        }
                        if (!clashes.isEmpty()) {
                            result.set(JsonResult.badRequest("already defined: "
                                + String.join(", ", clashes)
                                + ". Pass replace=true to overwrite, or edit fields individually "
                                + "with set_struct_field."));
                            return;
                        }
                    }

                    DataTypeConflictHandler handler = replace
                        ? DataTypeConflictHandler.REPLACE_HANDLER
                        : DataTypeConflictHandler.DEFAULT_HANDLER;

                    List<String> names = new ArrayList<>();
                    DataType resolvedLast = null;
                    for (DataType dt : parsed.values()) {
                        DataType resolved = dtm.resolve(dt, handler);
                        names.add(Json.quote(resolved.getPathName()));
                        if (last != null && dt.getName().equals(last.getName())) {
                            resolvedLast = resolved;
                        }
                    }
                    if (resolvedLast == null && last != null) {
                        resolvedLast = dtm.resolve(last, handler);
                    }

                    result.set(JsonResult.ok(new Json.Obj()
                        .str("last_type", resolvedLast != null ? resolvedLast.getName() : null)
                        .str("last_type_path", resolvedLast != null ? resolvedLast.getPathName() : null)
                        .raw("created", Json.array(names))
                        .bool("replaced", replace)
                        .str("messages", emptyToNull(parser.getParseMessages()))
                        .done()));
                    commit = true;
                }
                catch (Exception e) {
                    Msg.error(this, "Error parsing C declaration", e);
                    result.set(JsonResult.badRequest("Failed to parse declaration: " + e));
                }
                finally {
                    program.endTransaction(tx, commit);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create data type on Swing thread", e);
            return JsonResult.serverError("Failed to create data type: " + e.getMessage());
        }

        JsonResult r = result.get();
        return r != null ? r : JsonResult.serverError("create_data_type produced no result");
    }

    /**
     * Look up a data type by bare name or by full {@code /Category/Name} path.
     *
     * <p>Prefers the data type manager's own index over the linear scan in
     * {@link #findDataTypeByNameInAllCategories}, which walks every type in the program.
     */
    private DataType lookupDataType(DataTypeManager dtm, String name) {
        String trimmed = name.trim();
        if (trimmed.startsWith("/")) {
            DataType byPath = dtm.getDataType(trimmed);
            if (byPath != null) return byPath;
        }
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(trimmed, found);
        if (!found.isEmpty()) return found.get(0);

        return findDataTypeByNameInAllCategories(dtm, trimmed);
    }

    /**
     * Resolve a type name, returning null when it is unknown.
     *
     * <p>Deliberately unlike {@link #resolveDataType}, which falls back to {@code int} for anything
     * it does not recognise. Silently substituting a type is fine for a best-effort variable retype
     * and actively harmful when writing a struct layout, so this one reports failure instead.
     *
     * <p>Understands trailing {@code *} for pointers and a trailing {@code [N]} for arrays.
     */
    private DataType resolveDataTypeStrict(DataTypeManager dtm, String typeName) {
        String name = typeName.trim();

        int bracket = name.lastIndexOf('[');
        if (bracket > 0 && name.endsWith("]")) {
            String countStr = name.substring(bracket + 1, name.length() - 1).trim();
            DataType element = resolveDataTypeStrict(dtm, name.substring(0, bracket));
            if (element == null) return null;
            try {
                int count = (int) parseNumber(countStr);
                if (count <= 0) return null;
                return new ArrayDataType(element, count, element.getLength(), dtm);
            }
            catch (NumberFormatException e) {
                return null;
            }
        }

        if (name.endsWith("*")) {
            DataType base = resolveDataTypeStrict(dtm, name.substring(0, name.length() - 1));
            if (base == null) return null;
            return new PointerDataType(base, dtm);
        }

        DataType direct = lookupDataType(dtm, name);
        if (direct != null) return direct;

        // Built-ins live in the built-in manager, which the program's manager consults by path.
        return dtm.getDataType("/" + name);
    }

    // ----------------------------------------------------------------------------------
    // Defining code: disassembly and function creation
    // ----------------------------------------------------------------------------------

    /** Create code units at an address, optionally bounded to a byte range. */
    private JsonResult disassembleAt(String addressStr, String lengthStr) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) {
            return JsonResult.badRequest("address is required");
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return JsonResult.badRequest("Invalid address: " + addressStr);

        AddressSetView restricted = null;
        if (lengthStr != null && !lengthStr.isEmpty()) {
            long length;
            try {
                length = parseNumber(lengthStr);
            }
            catch (NumberFormatException e) {
                return JsonResult.badRequest("length must be a decimal or 0x-prefixed number");
            }
            if (length <= 0) return JsonResult.badRequest("length must be positive");
            try {
                restricted = new AddressSet(addr, addr.addNoWrap(length - 1));
            }
            catch (AddressOverflowException e) {
                return JsonResult.badRequest("range " + addr + " + " + length
                    + " bytes runs past the end of the address space");
            }
        }

        final AddressSetView restrictedSet = restricted;
        AtomicReference<JsonResult> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble at address");
                boolean commit = false;
                try {
                    // Ghidra's disassembler refuses to start on anything that is already a defined
                    // code unit. Asking to disassemble code that is already code is not an error,
                    // though -- it is an idempotent no-op -- so report what is there instead.
                    Instruction existing = program.getListing().getInstructionAt(addr);
                    if (existing != null) {
                        AddressSetView known = (restrictedSet != null)
                            ? restrictedSet : existingCodeRange(program, addr, existing);
                        result.set(JsonResult.ok(new Json.Obj()
                            .str("address", hexAddress(addr))
                            .num("bytes_disassembled", known.getNumAddresses())
                            .str("range_start", hexAddress(known.getMinAddress()))
                            .str("range_end", hexAddress(known.getMaxAddress()))
                            .bool("already_defined", true)
                            .raw("instructions", renderInstructions(program, known))
                            .done()));
                        commit = true;
                        return;
                    }

                    // Defined data is the case a caller genuinely has to act on, so say so plainly
                    // rather than letting the disassembler's own wording explain it.
                    Data definedData = program.getListing().getDefinedDataAt(addr);
                    if (definedData != null) {
                        result.set(JsonResult.badRequest("Address " + addr + " is defined as data ("
                            + definedData.getDataType().getName()
                            + "); clear it in Ghidra before disassembling"));
                        return;
                    }

                    DisassembleCommand cmd = new DisassembleCommand(addr, restrictedSet, true);
                    boolean applied = cmd.applyTo(program, new ConsoleTaskMonitor());
                    AddressSetView created = cmd.getDisassembledAddressSet();

                    if (!applied || created == null || created.isEmpty()) {
                        String status = cmd.getStatusMsg();
                        result.set(JsonResult.badRequest("Disassembly at " + addr + " produced no code"
                            + (status != null && !status.isEmpty() ? ": " + status : "")));
                        return;
                    }

                    result.set(JsonResult.ok(new Json.Obj()
                        .str("address", hexAddress(addr))
                        .num("bytes_disassembled", created.getNumAddresses())
                        .str("range_start", hexAddress(created.getMinAddress()))
                        .str("range_end", hexAddress(created.getMaxAddress()))
                        .raw("instructions", renderInstructions(program, created))
                        .done()));
                    commit = true;
                }
                catch (Exception e) {
                    Msg.error(this, "Error disassembling at address", e);
                    result.set(JsonResult.badRequest("Disassembly failed at " + addr + ": " + e));
                }
                finally {
                    program.endTransaction(tx, commit);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to disassemble on Swing thread", e);
            return JsonResult.serverError("Failed to disassemble: " + e.getMessage());
        }

        JsonResult r = result.get();
        return r != null ? r : JsonResult.serverError("disassemble_at produced no result");
    }

    /**
     * The range to report when an address is already code: the containing function's body if there
     * is one, otherwise just the instruction that is already there.
     */
    private AddressSetView existingCodeRange(Program program, Address addr, Instruction instruction) {
        Function func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) return func.getBody();
        return new AddressSet(instruction.getMinAddress(), instruction.getMaxAddress());
    }

    /** Render the instructions in an address set, capped so a large range cannot blow up. */
    private String renderInstructions(Program program, AddressSetView set) {
        final int maxInstructions = 1000;
        List<String> lines = new ArrayList<>();
        InstructionIterator it = program.getListing().getInstructions(set, true);
        while (it.hasNext() && lines.size() < maxInstructions) {
            Instruction instr = it.next();
            lines.add(Json.quote(instr.getAddress() + ": " + instr.toString()));
        }
        return Json.array(lines);
    }

    /**
     * Define a function at an address, disassembling first if nothing is there yet.
     *
     * <p>Ghidra will happily leave an address undefined even when a hundred vtables point at it,
     * and until now the only way to fix that was for a human to press D and then F.
     */
    private JsonResult createFunctionAt(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) {
            return JsonResult.badRequest("address is required");
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return JsonResult.badRequest("Invalid address: " + addressStr);

        AtomicReference<JsonResult> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function");
                boolean commit = false;
                try {
                    Function existing = program.getFunctionManager().getFunctionAt(addr);
                    if (existing != null) {
                        result.set(JsonResult.ok(renderFunction(existing, true, false)));
                        commit = true;
                        return;
                    }

                    TaskMonitor monitor = new ConsoleTaskMonitor();

                    boolean disassembled = false;
                    if (program.getListing().getInstructionAt(addr) == null) {
                        DisassembleCommand disasm = new DisassembleCommand(addr, null, true);
                        if (!disasm.applyTo(program, monitor)) {
                            String status = disasm.getStatusMsg();
                            result.set(JsonResult.badRequest("Cannot create a function at " + addr
                                + ": disassembly failed"
                                + (status != null && !status.isEmpty() ? " (" + status + ")" : "")));
                            return;
                        }
                        disassembled = true;
                        if (program.getListing().getInstructionAt(addr) == null) {
                            result.set(JsonResult.badRequest("Cannot create a function at " + addr
                                + ": disassembly produced no instruction there"));
                            return;
                        }
                    }

                    String requestedName = (name != null && !name.isEmpty()) ? name : null;
                    CreateFunctionCmd cmd =
                        new CreateFunctionCmd(requestedName, addr, null, SourceType.USER_DEFINED);
                    if (!cmd.applyTo(program, monitor)) {
                        String status = cmd.getStatusMsg();
                        result.set(JsonResult.badRequest("Failed to create a function at " + addr
                            + (status != null && !status.isEmpty() ? ": " + status : "")));
                        return;
                    }

                    Function created = cmd.getFunction();
                    if (created == null) {
                        created = program.getFunctionManager().getFunctionAt(addr);
                    }
                    if (created == null) {
                        result.set(JsonResult.badRequest(
                            "Function creation at " + addr + " reported success but defined nothing"));
                        return;
                    }

                    result.set(JsonResult.ok(renderFunction(created, false, disassembled)));
                    commit = true;
                }
                catch (Exception e) {
                    Msg.error(this, "Error creating function", e);
                    result.set(JsonResult.badRequest("Failed to create a function at " + addr + ": " + e));
                }
                finally {
                    program.endTransaction(tx, commit);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create function on Swing thread", e);
            return JsonResult.serverError("Failed to create function: " + e.getMessage());
        }

        JsonResult r = result.get();
        return r != null ? r : JsonResult.serverError("create_function produced no result");
    }

    private String renderFunction(Function func, boolean alreadyExisted, boolean disassembled) {
        AddressSetView body = func.getBody();
        return new Json.Obj()
            .str("name", func.getName(true))
            .str("entry_point", hexAddress(func.getEntryPoint()))
            .str("body_min", hexAddress(body.getMinAddress()))
            .str("body_max", hexAddress(body.getMaxAddress()))
            .num("body_size", body.getNumAddresses())
            .str("signature", func.getSignature().getPrototypeString())
            .bool("already_existed", alreadyExisted)
            .bool("disassembled", disassembled)
            .done();
    }

    // ----------------------------------------------------------------------------------
    // Batch mutation
    // ----------------------------------------------------------------------------------

    /**
     * Set many comments in one call and one transaction.
     *
     * <p>Annotating a vtable used to cost one round trip per slot. The whole batch commits or rolls
     * back together, but a single bad address only fails its own entry -- the per-item result says
     * which ones landed.
     */
    private JsonResult batchSetComments(String body, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");

        List<Map<String, Object>> items;
        try {
            items = Json.parseObjectArray(body);
        }
        catch (Json.JsonException e) {
            return JsonResult.badRequest("Request body must be a JSON array of "
                + "{\"address\": ..., \"comment\": ...} objects: " + e.getMessage());
        }

        return runBatch(program, transactionName, items, (item, index) -> {
            String addressStr = Json.optString(item, "address");
            String comment = Json.optString(item, "comment");
            if (addressStr == null || addressStr.isEmpty()) {
                return "address is required";
            }
            if (comment == null) {
                return "comment is required (use an empty string to clear one)";
            }
            Address addr = parseAddress(program, addressStr);
            if (addr == null) {
                return "Invalid address: " + addressStr;
            }
            program.getListing().setComment(addr, commentType, comment.isEmpty() ? null : comment);
            return null;
        });
    }

    /** Rename many functions in one call and one transaction. */
    private JsonResult batchRenameFunctions(String body) {
        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");

        List<Map<String, Object>> items;
        try {
            items = Json.parseObjectArray(body);
        }
        catch (Json.JsonException e) {
            return JsonResult.badRequest("Request body must be a JSON array of "
                + "{\"address\": ..., \"new_name\": ...} objects: " + e.getMessage());
        }

        return runBatch(program, "Rename functions (batch)", items, (item, index) -> {
            String addressStr = Json.optString(item, "address");
            String newName = Json.optString(item, "new_name");
            if (addressStr == null || addressStr.isEmpty()) {
                return "address is required";
            }
            if (newName == null || newName.isEmpty()) {
                return "new_name is required";
            }
            Address addr = parseAddress(program, addressStr);
            if (addr == null) {
                return "Invalid address: " + addressStr;
            }
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                return "No function at or containing " + addressStr;
            }
            func.setName(newName, SourceType.USER_DEFINED);
            return null;
        });
    }

    /** One batch item; returns null on success or a human-readable reason on failure. */
    private interface BatchItemAction {
        String apply(Map<String, Object> item, int index) throws Exception;
    }

    /**
     * Apply {@code action} to every item on the Swing thread inside a single transaction, and
     * report per-item outcomes so one bad address does not sink the whole call.
     */
    private JsonResult runBatch(Program program, String transactionName,
                                List<Map<String, Object>> items, BatchItemAction action) {
        List<String> results = new ArrayList<>(items.size());
        AtomicBoolean anySucceeded = new AtomicBoolean(false);
        int[] counts = new int[2]; // succeeded, failed

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    for (int i = 0; i < items.size(); i++) {
                        Map<String, Object> item = items.get(i);
                        String error;
                        try {
                            error = action.apply(item, i);
                        }
                        catch (Exception e) {
                            error = e.getClass().getSimpleName()
                                + (e.getMessage() != null ? ": " + e.getMessage() : "");
                        }

                        if (error == null) {
                            counts[0]++;
                            anySucceeded.set(true);
                        }
                        else {
                            counts[1]++;
                        }

                        results.add(new Json.Obj()
                            .num("index", i)
                            .str("address", Json.optString(item, "address"))
                            .bool("success", error == null)
                            .str("error", error)
                            .done());
                    }
                }
                finally {
                    program.endTransaction(tx, anySucceeded.get());
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to run batch on Swing thread", e);
            return JsonResult.serverError("Batch failed: " + e.getMessage());
        }

        return JsonResult.ok(new Json.Obj()
            .num("total", items.size())
            .num("succeeded", counts[0])
            .num("failed", counts[1])
            .raw("results", Json.array(results))
            .done());
    }

    // ----------------------------------------------------------------------------------
    // run_script: the general escape hatch
    // ----------------------------------------------------------------------------------

    /**
     * Execute a Ghidra script against the open program and return its output.
     *
     * <p>The script runs on a background thread, the way Ghidra's own Script Manager runs scripts,
     * inside a transaction so that a mutating script cannot leave the database inconsistent. It is
     * given a {@link GhidraState} pointing at the current program and location, so {@code
     * currentProgram} and {@code currentAddress} behave as they do in the Script Manager.
     *
     * <p>On timeout the task monitor is cancelled and whatever the script printed so far is
     * returned. A script that ignores cancellation will keep running -- and keep holding its
     * transaction open -- until it finishes; that is the unavoidable cost of arbitrary execution.
     */
    private JsonResult runScript(String source, String lang, String timeoutStr) {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        if (!options.getBoolean(RUN_SCRIPT_OPTION_NAME, true)) {
            return JsonResult.badRequest("run_script is disabled; enable '"
                + RUN_SCRIPT_OPTION_NAME + "' under '" + OPTION_CATEGORY_NAME
                + "' in Ghidra's tool options");
        }

        Program program = getCurrentProgram();
        if (program == null) return JsonResult.badRequest("No program loaded");
        if (source == null || source.trim().isEmpty()) {
            return JsonResult.badRequest("source is required");
        }

        String language = (lang == null || lang.isEmpty())
            ? "python" : lang.toLowerCase(Locale.ROOT);
        String extension;
        if (language.equals("python") || language.equals("py")) {
            extension = ".py";
            language = "python";
        }
        else if (language.equals("java")) {
            extension = ".java";
        }
        else {
            return JsonResult.badRequest("lang must be 'python' or 'java', got '" + lang + "'");
        }

        int timeoutSeconds = DEFAULT_SCRIPT_TIMEOUT_SECONDS;
        if (timeoutStr != null && !timeoutStr.isEmpty()) {
            try {
                timeoutSeconds = (int) parseNumber(timeoutStr);
            }
            catch (NumberFormatException e) {
                return JsonResult.badRequest("timeout must be a number of seconds");
            }
            if (timeoutSeconds <= 0 || timeoutSeconds > MAX_SCRIPT_TIMEOUT_SECONDS) {
                return JsonResult.badRequest("timeout must be between 1 and "
                    + MAX_SCRIPT_TIMEOUT_SECONDS + " seconds");
            }
        }

        List<File> temporaryFiles = new ArrayList<>();
        File captureFile = null;
        GhidraScriptUtil.acquireBundleHostReference();
        try {
            File scriptFile;
            if (extension.equals(".py")) {
                // Ghidra's Python script providers ignore the PrintWriter handed to execute() and
                // send output to the ConsoleService instead, so nothing a script prints would come
                // back over HTTP. Capture it inside the interpreter instead: the user's source is
                // executed by a small wrapper that redirects sys.stdout/sys.stderr to a file.
                File userFile = writeTemporaryScript(source, "_user.py", false);
                captureFile = new File(userFile.getParentFile(),
                    userFile.getName().replace("_user.py", "_out.txt"));
                scriptFile = writeTemporaryScript(
                    pythonCaptureWrapper(userFile, captureFile), ".py", true);
                temporaryFiles.add(userFile);
                temporaryFiles.add(captureFile);
            }
            else {
                // Java scripts use println(), which does honour the writer.
                scriptFile = writeTemporaryScript(source, extension, true);
            }
            temporaryFiles.add(scriptFile);
            ResourceFile resourceFile = new ResourceFile(scriptFile);

            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(resourceFile);
            if (provider == null) {
                return JsonResult.badRequest("No script provider is available for '" + extension
                    + "' scripts. Ghidra 11.x runs Python through PyGhidra (Python 3) or the older "
                    + "Jython 2.7 extension; enable one under File > Configure.");
            }

            CapturingWriter stdout = new CapturingWriter();
            CapturingWriter stderr = new CapturingWriter();
            PrintWriter outWriter = new PrintWriter(stdout, true);
            PrintWriter errWriter = new PrintWriter(stderr, true);

            GhidraScript script = provider.getScriptInstance(resourceFile, errWriter);
            if (script == null) {
                return JsonResult.badRequest("Script provider " + provider.getClass().getSimpleName()
                    + " could not load the script: " + stderr.snapshot());
            }

            ProgramLocation location = null;
            CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
            if (codeViewer != null) {
                location = codeViewer.getCurrentLocation();
            }
            GhidraState state = new GhidraState(
                tool, tool.getProject(), program, location, null, null);

            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
            AtomicReference<String> failure = new AtomicReference<>();

            long startedAt = System.currentTimeMillis();
            ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "GhidraMCP-run_script");
                t.setDaemon(true);
                return t;
            });

            boolean timedOut = false;
            try {
                Future<?> future = executor.submit(() -> {
                    // The transaction is opened and closed on this thread, so a script that
                    // outlives the HTTP request still closes its own transaction when it ends.
                    int tx = program.startTransaction("GhidraMCP run_script");
                    try {
                        script.execute(state, monitor, outWriter);
                    }
                    catch (Throwable t) {
                        failure.set(describeThrowable(t));
                    }
                    finally {
                        outWriter.flush();
                        errWriter.flush();
                        // Commit even when the script threw: a script that renamed 900 things and
                        // died on the 901st is more useful kept than discarded, and Ghidra's undo
                        // stack can still revert it.
                        program.endTransaction(tx, true);
                    }
                });

                try {
                    future.get(timeoutSeconds, TimeUnit.SECONDS);
                }
                catch (TimeoutException e) {
                    timedOut = true;
                    monitor.cancel();
                    try {
                        // Give a cooperative script a moment to notice the cancellation.
                        future.get(5, TimeUnit.SECONDS);
                    }
                    catch (Exception ignored) {
                        // Still running; report what we have.
                    }
                }
                catch (Exception e) {
                    failure.set(describeThrowable(e));
                }
            }
            finally {
                executor.shutdownNow();
            }

            // Merge the two channels a script can print on: the interpreter's own stdout, which
            // the wrapper redirected to a file, and println(), which goes to the writer.
            String captured = readCaptureFile(captureFile);
            String printed = stdout.snapshot();
            String combined = (captured.isEmpty() || printed.isEmpty())
                ? captured + printed
                : captured + (captured.endsWith("\n") ? "" : "\n") + printed;

            return JsonResult.ok(new Json.Obj()
                .str("provider", provider.getClass().getSimpleName())
                .str("lang", language)
                .str("stdout", truncateOutput(combined))
                .str("stderr", truncateOutput(stderr.snapshot()))
                .str("error", failure.get())
                .bool("timed_out", timedOut)
                .num("duration_ms", System.currentTimeMillis() - startedAt)
                .done());
        }
        catch (Exception e) {
            Msg.error(this, "run_script failed", e);
            return JsonResult.serverError("run_script failed: " + describeThrowable(e));
        }
        finally {
            GhidraScriptUtil.releaseBundleHostReference();
            for (File file : temporaryFiles) {
                if (file.exists() && !file.delete()) {
                    file.deleteOnExit();
                }
            }
        }
    }

    /**
     * Build the wrapper script that runs the user's source with its output redirected to a file.
     *
     * <p>Written to work unchanged under both interpreters Ghidra might pick: Jython 2.7 accepts
     * {@code exec(source, globals)} through its tuple form, and CPython 3 takes it as an ordinary
     * call. Executing in {@code globals()} means the user's code still sees {@code currentProgram},
     * {@code monitor} and the rest of the script namespace. The capture file is line buffered so
     * that a script cancelled on timeout still leaves behind what it had printed by then.
     */
    private String pythonCaptureWrapper(File userFile, File captureFile) {
        String userPath = pythonPathLiteral(userFile);
        String capturePath = pythonPathLiteral(captureFile);
        return String.join("\n",
            "import sys, traceback",
            "_mcp_capture = open(" + capturePath + ", 'w', 1)",
            "_mcp_stdout, _mcp_stderr = sys.stdout, sys.stderr",
            "sys.stdout = _mcp_capture",
            "sys.stderr = _mcp_capture",
            "try:",
            "    _mcp_source = open(" + userPath + ").read()",
            "    exec(compile(_mcp_source, " + userPath + ", 'exec'), globals())",
            "except:",
            "    traceback.print_exc(file=_mcp_capture)",
            "finally:",
            "    sys.stdout, sys.stderr = _mcp_stdout, _mcp_stderr",
            "    _mcp_capture.close()",
            "");
    }

    /** Render a file path as a Python string literal, forward-slashed so Windows paths are safe. */
    private String pythonPathLiteral(File file) {
        String path = file.getAbsolutePath().replace('\\', '/').replace("'", "\\'");
        return "'" + path + "'";
    }

    private String readCaptureFile(File captureFile) {
        if (captureFile == null || !captureFile.exists()) return "";
        try {
            return new String(Files.readAllBytes(captureFile.toPath()), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            Msg.warn(this, "Could not read run_script output capture", e);
            return "";
        }
    }

    /**
     * Write the script source somewhere a {@link GhidraScriptProvider} will accept it.
     *
     * <p>Prefers the user's script directory, which every provider already treats as a source root;
     * falls back to the system temp directory. A Java script's file name has to match its declared
     * class, so that name is taken from the source when it declares one.
     */
    private File writeTemporaryScript(String source, String suffix, boolean nameFromJavaClass)
            throws IOException {
        String baseName = "GhidraMCPScript_" + System.nanoTime();
        if (nameFromJavaClass && suffix.equals(".java")) {
            Matcher m = JAVA_CLASS_DECLARATION.matcher(source);
            if (m.find()) {
                baseName = m.group(1);
            }
        }

        File directory = null;
        ResourceFile userScripts = GhidraScriptUtil.getUserScriptDirectory();
        if (userScripts != null) {
            File candidate = userScripts.getFile(false);
            if (candidate != null && (candidate.isDirectory() || candidate.mkdirs())) {
                directory = candidate;
            }
        }
        if (directory == null) {
            directory = new File(System.getProperty("java.io.tmpdir"));
        }

        File scriptFile = new File(directory, baseName + suffix);
        Files.write(scriptFile.toPath(), source.getBytes(StandardCharsets.UTF_8));
        return scriptFile;
    }

    /**
     * A {@link Writer} that a script thread can fill while the HTTP thread reads a snapshot of it,
     * which is what makes returning partial output after a timeout possible.
     */
    private static final class CapturingWriter extends Writer {
        private final StringBuilder buffer = new StringBuilder();

        @Override
        public void write(char[] chars, int offset, int length) {
            synchronized (buffer) {
                buffer.append(chars, offset, length);
            }
        }

        @Override
        public void flush() {
            // Nothing to flush: writes land in the buffer immediately.
        }

        @Override
        public void close() {
            // Nothing to close.
        }

        String snapshot() {
            synchronized (buffer) {
                return buffer.toString();
            }
        }
    }

    private String truncateOutput(String text) {
        if (text == null || text.length() <= MAX_SCRIPT_OUTPUT_CHARS) return text;
        return text.substring(0, MAX_SCRIPT_OUTPUT_CHARS)
            + "\n... [truncated at " + MAX_SCRIPT_OUTPUT_CHARS + " characters]";
    }

    /** Render a throwable and its stack trace the way a script author would want to read it. */
    private String describeThrowable(Throwable t) {
        Throwable cause = (t instanceof InvocationTargetException && t.getCause() != null)
            ? t.getCause() : t;
        StringWriter sw = new StringWriter();
        cause.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                // Split on the first '=' only, so a value that decodes to one keeps it.
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            // Split on the first '=' only; script source and comments routinely contain more.
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Streaming counterpart to {@link #paginateList}: skips {@code offset} items and keeps at most
     * {@code limit}, so an iteration can stop as soon as the page is full instead of formatting
     * the whole program and throwing most of it away.
     *
     * <p>Only usable where the source iteration order is already the desired output order -- any
     * listing that sorts or de-duplicates still has to collect everything first.
     */
    private static final class Page {
        private final int offset;
        private final int limit;
        private final List<String> items = new ArrayList<>();
        private int seen;

        Page(int offset, int limit) {
            this.offset = Math.max(0, offset);
            this.limit = Math.max(0, limit);
        }

        /**
         * Offer one item. The supplier is only invoked for items that fall inside the page, which
         * is what keeps expensive per-item formatting off the skipped majority.
         *
         * @return true once the page is full and the caller should stop iterating
         */
        boolean add(java.util.function.Supplier<String> item) {
            if (limit == 0) return true;
            if (seen++ >= offset) {
                items.add(item.get());
            }
            return items.size() >= limit;
        }

        String render() {
            return String.join("\n", items);
        }
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /** Parse a boolean query parameter, or return the supplied default for omitted/invalid input. */
    private boolean parseBooleanOrDefault(String val, boolean defaultValue) {
        if (val == null) return defaultValue;
        if ("true".equalsIgnoreCase(val) || "1".equals(val)) return true;
        if ("false".equalsIgnoreCase(val) || "0".equals(val)) return false;
        return defaultValue;
    }

    /**
     * Parse an address written either bare ({@code 7ff74b920898}) or 0x-prefixed
     * ({@code 0x7ff74b920898}). Returns null if it is not a valid address for this program.
     */
    private Address parseAddress(Program program, String addressStr) {
        if (addressStr == null) return null;
        String trimmed = addressStr.trim();
        if (trimmed.isEmpty()) return null;
        try {
            Address addr = program.getAddressFactory().getAddress(trimmed);
            if (addr == null && trimmed.regionMatches(true, 0, "0x", 0, 2)) {
                addr = program.getAddressFactory().getAddress(trimmed.substring(2));
            }
            return addr;
        }
        catch (Exception e) {
            return null;
        }
    }

    /** Address rendered the way the JSON endpoints promise: lowercase hex with a 0x prefix. */
    private String hexAddress(Address addr) {
        return addr != null ? "0x" + addr.toString() : null;
    }

    /**
     * Parse a decimal or 0x-prefixed number. Lengths, counts and offsets all accept both, because
     * an address-space number is far more readable in hex and a count is not.
     */
    private static long parseNumber(String value) {
        if (value == null) throw new NumberFormatException("value is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) throw new NumberFormatException("value is required");

        boolean negative = trimmed.startsWith("-");
        if (negative || trimmed.startsWith("+")) {
            trimmed = trimmed.substring(1);
        }
        long magnitude = trimmed.regionMatches(true, 0, "0x", 0, 2)
            ? Long.parseLong(trimmed.substring(2), 16)
            : Long.parseLong(trimmed);
        return negative ? -magnitude : magnitude;
    }

    private static String toHex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            chars[i * 2] = HEX_DIGITS[value >>> 4];
            chars[i * 2 + 1] = HEX_DIGITS[value & 0x0f];
        }
        return new String(chars);
    }

    /** Assemble {@code size} bytes into an unsigned value, honouring the program's byte order. */
    private static long readUnsigned(byte[] buffer, int offset, int size, boolean bigEndian) {
        long value = 0;
        if (bigEndian) {
            for (int i = 0; i < size; i++) {
                value = (value << 8) | (buffer[offset + i] & 0xffL);
            }
        }
        else {
            for (int i = size - 1; i >= 0; i--) {
                value = (value << 8) | (buffer[offset + i] & 0xffL);
            }
        }
        return value;
    }

    private static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Read a whole request body as UTF-8, for the endpoints that take a JSON document. */
    private String readRequestBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Send a {@link JsonResult}. Unlike {@link #sendResponse}, this uses real HTTP status codes;
     * the body is always a JSON document, so a caller gets a machine-readable reason either way.
     */
    private void sendJsonResponse(HttpExchange exchange, JsonResult result) throws IOException {
        byte[] bytes = result.body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(result.status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
