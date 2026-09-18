"""MCP client service for connecting to MCP servers and using their tools with persistent connections."""

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    MCP_AVAILABLE = True
except ImportError:
    try:
        # Try alternative import path
        from mcp.client import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        MCP_AVAILABLE = True
    except ImportError:
        MCP_AVAILABLE = False
        # Define dummy types for when MCP is not available
        if TYPE_CHECKING:
            from mcp import ClientSession, StdioServerParameters
        else:
            ClientSession = Any
            StdioServerParameters = Any

from core.integrations.mcp.child_env import ca_bundle_env
from core.integrations.mcp.service import MCPService
from core.secrets import get_secret

logger = logging.getLogger(__name__)


class _Job:
    """One request handed to a session's owner task, plus a future for the reply."""

    __slots__ = ("kind", "args", "future")

    def __init__(
        self, kind: str, args: Dict[str, Any], future: "Optional[asyncio.Future]"
    ):
        self.kind = kind
        self.args = args
        self.future = future


class PersistentServerSession:
    """Manages a persistent connection to an MCP server.

    anyio cancel scopes — created implicitly by ``stdio_client()`` and
    ``ClientSession`` (each opens a task group internally) — must be entered
    and exited by the same asyncio Task. FastAPI runs every HTTP request in
    its own Task, and `/internal/tools/invoke` is called once per tool call,
    so a naive implementation that enters those context managers from one
    request's Task and exits/re-enters them (on reconnect) from another's
    violates that invariant:
        RuntimeError: Attempted to exit a cancel scope that isn't the
        current task's current cancel scope
    To avoid this, all connect/call/reconnect/cleanup work for a given
    server happens inside a single dedicated background task (``_run``)
    that this session owns for its whole lifetime. Every other task talks
    to it by dropping a ``_Job`` on ``self._queue`` and awaiting the job's
    future — never by touching the underlying session/streams directly.
    """

    def __init__(self, server_name: str, server_params):
        self.server_name = server_name
        self.server_params = server_params
        self.is_connected = False
        self._queue: "asyncio.Queue[_Job]" = asyncio.Queue()
        self._owner_task: Optional[asyncio.Task] = None
        self._owner_task_lock = asyncio.Lock()

    async def _ensure_owner_task(self) -> None:
        async with self._owner_task_lock:
            if self._owner_task is None or self._owner_task.done():
                self._owner_task = asyncio.create_task(
                    self._run(), name=f"mcp-owner-{self.server_name}"
                )

    async def _submit(self, kind: str, args: Optional[Dict[str, Any]] = None) -> Any:
        await self._ensure_owner_task()
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        await self._queue.put(_Job(kind, args or {}, future))
        return await future

    async def connect(self) -> bool:
        """Establish persistent connection to the server."""
        return await self._submit("connect")

    async def disconnect(self):
        """Disconnect from the server and stop its owner task."""
        if self._owner_task is None:
            return
        await self._submit("disconnect")
        await self._queue.put(_Job("stop", {}, None))
        try:
            await asyncio.wait_for(self._owner_task, timeout=5.0)
        except Exception:
            pass
        self._owner_task = None

    async def call_tool(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call a tool using the persistent session."""
        return await self._submit(
            "call_tool", {"tool_name": tool_name, "arguments": arguments}
        )

    async def list_tools(self):
        """List tools from the persistent session."""
        return await self._submit("list_tools")

    async def _run(self) -> None:
        """Owner task body. Owns the session/stdio contexts for their entire
        lifetime — every ``__aenter__``/``__aexit__`` call on them happens
        here, in this one task, so no cancel scope ever crosses a task
        boundary."""
        session: Optional[ClientSession] = None
        session_context = None
        stdio_context = None

        async def do_connect() -> bool:
            nonlocal session, session_context, stdio_context
            if self.is_connected and session is not None:
                return True
            try:
                stdio_context = stdio_client(self.server_params)
                read_stream, write_stream = await stdio_context.__aenter__()

                session_context = ClientSession(read_stream, write_stream)
                session = await session_context.__aenter__()
                await session.initialize()

                self.is_connected = True
                logger.info(
                    f"✓ Established persistent connection to {self.server_name}"
                )
                return True
            except Exception as e:
                logger.error(f"Failed to connect to {self.server_name}: {e}")
                await do_cleanup()
                return False

        async def do_cleanup() -> None:
            nonlocal session, session_context, stdio_context
            try:
                if session_context:
                    try:
                        await session_context.__aexit__(None, None, None)
                    except Exception:
                        pass
                if stdio_context:
                    try:
                        await stdio_context.__aexit__(None, None, None)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error during cleanup of {self.server_name}: {e}")
            finally:
                session = None
                session_context = None
                stdio_context = None
                self.is_connected = False

        try:
            while True:
                job = await self._queue.get()

                if job.kind == "stop":
                    if job.future is not None and not job.future.done():
                        job.future.set_result(None)
                    break

                try:
                    if job.kind == "connect":
                        result: Any = await do_connect()

                    elif job.kind == "disconnect":
                        await do_cleanup()
                        result = None

                    elif job.kind == "list_tools":
                        if not self.is_connected or session is None:
                            if not await do_connect():
                                raise RuntimeError(
                                    f"Failed to connect to {self.server_name}"
                                )
                        result = await session.list_tools()

                    elif job.kind == "call_tool":
                        if not self.is_connected or session is None:
                            logger.warning(
                                f"Session not connected for {self.server_name}, "
                                "attempting to reconnect..."
                            )
                            await do_cleanup()
                            if not await do_connect():
                                raise RuntimeError(
                                    f"Failed to connect to {self.server_name}"
                                )

                        tool_name = job.args["tool_name"]
                        try:
                            raw = await session.call_tool(
                                tool_name, job.args["arguments"]
                            )
                            content_list = []
                            for content_item in raw.content:
                                if hasattr(content_item, "text"):
                                    content_list.append(
                                        {"type": "text", "text": content_item.text}
                                    )
                                elif hasattr(content_item, "type"):
                                    content_list.append(
                                        {
                                            "type": str(content_item.type),
                                            "text": str(content_item),
                                        }
                                    )
                                else:
                                    content_list.append(
                                        {"type": "text", "text": str(content_item)}
                                    )
                            result = {
                                "error": (
                                    raw.isError if hasattr(raw, "isError") else False
                                ),
                                "content": content_list,
                            }
                        except Exception as e:
                            logger.error(
                                f"Tool call failed for {self.server_name}.{tool_name}: {e}"
                            )
                            # Drop the (possibly broken) session so the next
                            # call reconnects from a clean slate.
                            await do_cleanup()
                            raise

                    else:
                        raise ValueError(f"Unknown MCP session job kind: {job.kind}")

                    if job.future is not None and not job.future.done():
                        job.future.set_result(result)

                except Exception as e:
                    if job.future is not None and not job.future.done():
                        job.future.set_exception(e)
        finally:
            await do_cleanup()


class MCPClient:
    """Client for connecting to MCP servers and using their tools with persistent connections."""

    def __init__(self, mcp_service: MCPService):
        """
        Initialize MCP client with persistent connection support.

        Args:
            mcp_service: MCPService instance for managing server processes
        """
        self.mcp_service = mcp_service
        self.persistent_sessions: Dict[str, PersistentServerSession] = {}
        self.tools_cache: Dict[str, List[Dict]] = {}
        self._connection_locks: Dict[str, threading.Lock] = (
            {}
        )  # Locks per server to prevent concurrent connections
        # Populated by connect_to_server — string reason on failure, and a
        # structured list of env var names when credentials are missing.
        self.last_errors: Dict[str, str] = {}
        self.last_missing_credentials: Dict[str, List[str]] = {}

    async def connect_to_server(
        self, server_name: str, persistent: bool = True
    ) -> bool:
        """
        Connect to an MCP server, cache its tools, and optionally maintain persistent connection.

        Only connects if the server is enabled in the MCP service. On failure, the
        exception message is recorded on ``self.last_errors[server_name]`` so the
        Settings → MCP UI can surface *why* a connection failed (missing binary,
        credentials, package not installed) instead of a generic "Failed to connect".

        Args:
            server_name: Name of the server to connect to
            persistent: If True, maintain persistent connection for reuse

        Returns:
            True if successful, False otherwise
        """
        # Defensive init for deployments that upgraded without reinstantiating
        # the client — keeps the legacy __init__ compatible.
        if not hasattr(self, "last_errors"):
            self.last_errors: Dict[str, str] = {}
        if not hasattr(self, "last_missing_credentials"):
            self.last_missing_credentials: Dict[str, List[str]] = {}
        # Clear any stale state from a prior attempt so the UI always
        # reflects the most recent connect.
        self.last_errors.pop(server_name, None)
        self.last_missing_credentials.pop(server_name, None)

        if not MCP_AVAILABLE:
            logger.error("MCP SDK not available")
            self.last_errors[server_name] = "MCP SDK not installed in the backend venv"
            return False

        if server_name not in self.mcp_service.servers:
            logger.error(f"Unknown server: {server_name}")
            self.last_errors[server_name] = "Server not present in mcp-config.json"
            return False

        # Skip disabled servers
        if not self.mcp_service.is_server_enabled(server_name):
            logger.debug(f"Server {server_name} is disabled, skipping connection")
            return False

        # Check if already connected with cached tools
        if server_name in self.persistent_sessions and server_name in self.tools_cache:
            if self.persistent_sessions[server_name].is_connected:
                logger.debug(f"Already connected to {server_name}")
                return True

        server = self.mcp_service.servers[server_name]

        # Credential gate: if the server declared ${VAR} placeholders in
        # its mcp-config.json entry and those env vars resolve empty,
        # short-circuit without spawning a child. This is dormancy by
        # design — per #124's conclusion, pre-configuration is not a
        # failure. The UI's existing "Not Configured" treatment takes
        # over once it sees connected=false + a missing_credentials list.
        missing = self._missing_credentials_for(server)
        if missing:
            msg = f"missing credentials: {', '.join(missing)}"
            self.last_errors[server_name] = msg
            self.last_missing_credentials[server_name] = missing
            logger.info(
                "MCP server %s dormant — waiting on env vars: %s",
                server_name,
                ", ".join(missing),
            )
            return False

        try:
            # Create stdio server parameters. stdio_client narrows the child
            # environment to a six-name allowlist, so a CA bundle set in the
            # backend's environment has to be forwarded rather than inherited.
            server_params = StdioServerParameters(
                command=server.command,
                args=server.args,
                env={**ca_bundle_env(), **(server.env or {})},
            )

            if persistent:
                # Create persistent session
                if server_name not in self.persistent_sessions:
                    self.persistent_sessions[server_name] = PersistentServerSession(
                        server_name, server_params
                    )

                # Connect
                if not await self.persistent_sessions[server_name].connect():
                    return False

                # Get tools from the persistent session (routed through its
                # owner task — see PersistentServerSession)
                tools_result = await self.persistent_sessions[server_name].list_tools()

            else:
                # Temporary connection just to get tools
                async with stdio_client(server_params) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        tools_result = await session.list_tools()

            # Cache tools
            self.tools_cache[server_name] = []
            for tool in tools_result.tools:
                # Get input schema - handle both dict and object formats
                input_schema = tool.inputSchema
                if hasattr(input_schema, "model_dump"):
                    input_schema = input_schema.model_dump()
                elif hasattr(input_schema, "dict"):
                    input_schema = input_schema.dict()
                elif not isinstance(input_schema, dict):
                    input_schema = dict(input_schema) if input_schema else {}

                # Ensure it's a valid JSON schema
                if not isinstance(input_schema, dict):
                    input_schema = {}

                self.tools_cache[server_name].append(
                    {
                        "name": tool.name,
                        "description": tool.description or "",
                        "inputSchema": input_schema,
                    }
                )

            logger.info(
                f"Connected to {server_name}, found {len(self.tools_cache[server_name])} tools"
            )
            return True

        except Exception as e:
            # Preserve the exception text so the UI can surface the real
            # reason (e.g. "FileNotFoundError: uvx", "ModuleNotFoundError:
            # mempalace", "missing env var GITHUB_TOKEN") instead of a
            # generic "Failed to connect".
            self.last_errors[server_name] = f"{type(e).__name__}: {e}"
            logger.error(f"Failed to connect to {server_name}: {e}")
            return False

    def _missing_credentials_for(self, server) -> List[str]:
        # Resolves through get_secret, so a credential saved via the integration
        # wizard (encrypted store, not the process env) does not read as dormant.
        required = getattr(server, "required_env_vars", None) or []
        if not required:
            return []
        missing: List[str] = []
        for var in required:
            if not get_secret(var):
                missing.append(var)
        return missing

    def get_missing_credentials(self, server_name: str) -> Optional[List[str]]:
        """Return the list of unset required env vars from the last connect."""
        return getattr(self, "last_missing_credentials", {}).get(server_name)

    def get_last_error(self, server_name: str) -> Optional[str]:
        """Return the most recent connect-failure reason for a server, if any."""
        return getattr(self, "last_errors", {}).get(server_name)

    # Per-server rate limit between auto-retry attempts. Prevents a
    # misconfigured secret (wrong value, typo) from hammering the MCP
    # child process with connect storms on every /connections/status
    # poll. 15s balances "user saves key and sees it online quickly"
    # with "don't spin up 20 subprocesses a minute on a stuck setup".
    _RETRY_MIN_INTERVAL_S = 15.0

    async def retry_dormant_if_ready(self) -> Dict[str, bool]:
        """Re-attempt connect for any dormant server whose required env
        vars have since resolved (e.g. user saved the credential via the
        integration wizard). Safe to call from a read-path endpoint:
        no-op when nothing's dormant or when creds are still missing.

        Returns a dict ``{server_name: connected_bool}`` recording what
        we actually tried this call — the common case is an empty dict.
        """
        # Defensive init — mirrors connect_to_server's compat shim.
        if not hasattr(self, "_last_retry_at"):
            self._last_retry_at: Dict[str, float] = {}
        if not hasattr(self, "last_missing_credentials"):
            return {}

        import time

        now = time.monotonic()
        attempted: Dict[str, bool] = {}

        # Snapshot the keys — ``last_missing_credentials`` is mutated
        # by ``connect_to_server`` we're about to call.
        candidates = [
            name
            for name, missing in list(self.last_missing_credentials.items())
            if missing
        ]
        for server_name in candidates:
            server = self.mcp_service.servers.get(server_name)
            if server is None:
                continue
            # Cheap precheck — skip unless creds actually resolve now.
            if self._missing_credentials_for(server):
                continue
            # Rate-limit: don't retry the same server more than once
            # per _RETRY_MIN_INTERVAL_S seconds.
            last = self._last_retry_at.get(server_name, 0.0)
            if now - last < self._RETRY_MIN_INTERVAL_S:
                continue
            self._last_retry_at[server_name] = now
            try:
                attempted[server_name] = await self.connect_to_server(
                    server_name, persistent=True
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Dormant-retry for %s raised: %s", server_name, exc)
                attempted[server_name] = False
        if attempted:
            connected = sum(1 for v in attempted.values() if v)
            logger.info(
                "Auto-reconnect: %d/%d dormant server(s) came online",
                connected,
                len(attempted),
            )
        return attempted

    async def list_tools(
        self, server_name: Optional[str] = None
    ) -> Dict[str, List[Dict]]:
        """
        List available tools from MCP servers.

        Args:
            server_name: Optional server name to list tools from. If None, lists from all servers.

        Returns:
            Dictionary mapping server names to lists of tool definitions
        """
        if not MCP_AVAILABLE:
            return {}

        tools = {}

        if server_name:
            if server_name in self.tools_cache:
                tools[server_name] = self.tools_cache[server_name]
            else:
                # Try to connect and get tools
                if await self.connect_to_server(server_name):
                    tools[server_name] = self.tools_cache.get(server_name, [])
        else:
            # List tools from all servers
            for name in self.mcp_service.list_servers():
                if name in self.tools_cache:
                    tools[name] = self.tools_cache[name]
                else:
                    # Try to connect
                    if await self.connect_to_server(name):
                        tools[name] = self.tools_cache.get(name, [])

        return tools

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Call a tool on an MCP server using persistent connection with timeout.

        Args:
            server_name: Name of the server
            tool_name: Name of the tool to call
            arguments: Tool arguments
            timeout: Timeout in seconds (default: 30)

        Returns:
            Tool result dictionary
        """
        import json as _json
        import time as _time

        if not MCP_AVAILABLE:
            return {
                "error": "MCP SDK not available",
                "content": [{"type": "text", "text": "MCP SDK not available"}],
            }

        if server_name not in self.mcp_service.servers:
            return {
                "error": f"Unknown server: {server_name}",
                "content": [{"type": "text", "text": f"Unknown server: {server_name}"}],
            }

        # OTEL span for transport-level MCP call
        _mcp_span = None
        _mcp_t0 = _time.monotonic()
        try:
            from opentelemetry.trace import SpanKind
            from opentelemetry.trace import StatusCode as _SC

            from core.telemetry import get_tracer

            _mcp_tracer = get_tracer("vigil.core.integrations.mcp.client")
            _mcp_span = _mcp_tracer.start_span(
                "mcp.call_tool",
                kind=SpanKind.CLIENT,
                attributes={
                    "mcp.server.name": server_name,
                    "mcp.transport": "stdio",
                    "vigil.tool.name": tool_name,
                    "vigil.tool.input_size": len(_json.dumps(arguments, default=str)),
                },
            )
        except Exception:
            _SC = None

        # Ensure we have a persistent session
        if server_name not in self.persistent_sessions:
            logger.info(f"Creating persistent connection to {server_name}...")
            if not await self.connect_to_server(server_name, persistent=True):
                _err = {
                    "error": True,
                    "content": [
                        {
                            "type": "text",
                            "text": f"Failed to connect to server: {server_name}",
                        }
                    ],
                }
                try:
                    if _mcp_span is not None:
                        _mcp_span.set_attribute("vigil.tool.success", False)
                        _mcp_span.end()
                except Exception:
                    pass
                return _err

        persistent_session = self.persistent_sessions[server_name]

        async def _call_tool_persistent():
            try:
                return await persistent_session.call_tool(tool_name, arguments)
            except Exception as e:
                logger.error(f"Error in tool call {tool_name} on {server_name}: {e}")
                raise

        try:
            # Apply timeout
            result = await asyncio.wait_for(_call_tool_persistent(), timeout=timeout)
            try:
                if _mcp_span is not None:
                    is_err = (
                        result.get("error", False)
                        if isinstance(result, dict)
                        else False
                    )
                    _mcp_span.set_attribute("vigil.tool.success", not is_err)
                    _mcp_span.set_attribute(
                        "vigil.tool.output_size", len(_json.dumps(result, default=str))
                    )
                    _mcp_span.set_attribute(
                        "vigil.tool.duration_ms",
                        round((_time.monotonic() - _mcp_t0) * 1000, 1),
                    )
                    _mcp_span.end()
            except Exception:
                pass
            return result
        except asyncio.TimeoutError:
            logger.error(
                f"Tool call {tool_name} on {server_name} timed out after {timeout}s"
            )
            try:
                if _mcp_span is not None and _SC is not None:
                    _mcp_span.set_attribute("vigil.tool.success", False)
                    _mcp_span.set_status(_SC.ERROR, f"Timeout after {timeout}s")
                    _mcp_span.end()
            except Exception:
                pass
            return {
                "error": True,
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool call timed out after {timeout} seconds. The MCP server may not be responding.",
                    }
                ],
            }
        except Exception as e:
            logger.error(f"Error calling tool {tool_name} on {server_name}: {e}")
            try:
                if _mcp_span is not None:
                    _mcp_span.set_attribute("vigil.tool.success", False)
                    _mcp_span.end()
            except Exception:
                pass
            return {
                "error": True,
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
            }

    def get_tools_for_claude(self) -> List[Dict]:
        """
        Get all available tools formatted for Claude's tool use API.

        Returns:
            List of tool definitions in Claude's format
        """
        all_tools = []

        for server_name, tools in self.tools_cache.items():
            for tool in tools:
                # Format tool for Claude API
                claude_tool = {
                    "name": f"{server_name}_{tool['name']}",
                    "description": f"[{server_name}] {tool['description']}",
                    "input_schema": tool.get("inputSchema", {}),
                }
                all_tools.append(claude_tool)

        return all_tools

    async def disconnect_from_server(self, server_name: str) -> bool:
        """
        Disconnect from a specific MCP server.

        Args:
            server_name: Name of the server to disconnect from

        Returns:
            True if successful, False otherwise
        """
        if server_name in self.persistent_sessions:
            try:
                await self.persistent_sessions[server_name].disconnect()
                del self.persistent_sessions[server_name]
                logger.info(f"Disconnected from {server_name}")
                return True
            except Exception as e:
                logger.error(f"Error disconnecting from {server_name}: {e}")
                return False
        return True

    def get_connection_status(self) -> Dict[str, bool]:
        """
        Get connection status for all servers.

        Returns:
            Dictionary mapping server names to connection status
        """
        status = {}
        for server_name in self.mcp_service.list_servers():
            if server_name in self.persistent_sessions:
                status[server_name] = self.persistent_sessions[server_name].is_connected
            else:
                status[server_name] = False
        return status

    async def close_all(self):
        """Close all persistent MCP server connections and clear cache."""
        logger.info("Closing all MCP server connections...")

        # Disconnect all persistent sessions sequentially to avoid context issues
        for server_name in list(self.persistent_sessions.keys()):
            try:
                await self.persistent_sessions[server_name].disconnect()
                logger.info(f"Disconnected from {server_name}")
            except Exception as e:
                logger.error(f"Error disconnecting from {server_name}: {e}")

        # Clear all state
        self.persistent_sessions.clear()
        self.tools_cache.clear()

        logger.info("All MCP connections closed")


# An MCPClient owns persistent stdio child processes that only its creator closes, so
# exactly one may exist per process. The owner builds it and installs it here.
_process_client: Optional[MCPClient] = None


def build_mcp_client() -> Optional[MCPClient]:
    """Build a client, or None when the MCP SDK is not installed."""
    if not MCP_AVAILABLE:
        logger.warning("MCP SDK not available. Install with: pip install mcp")
        return None
    return MCPClient(MCPService())


def set_process_mcp_client(client: Optional[MCPClient]) -> None:
    global _process_client
    _process_client = client


# None until an owner (the API lifespan, daemon startup) has installed a client.
def process_mcp_client() -> Optional[MCPClient]:
    return _process_client
