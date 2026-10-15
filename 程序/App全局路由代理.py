#!/usr/bin/env python3
"""Codex App 的 JSONL 路由入口；为已有 start/resume/fork 请求补入 provider。

普通 CLI 调用使用 exec 原样交还官方程序。代理不生成 turn，不读写任务历史。
控制器契约：route_enabled() -> bool；load_route() -> {provider, mode, state_dir}。
"""

from __future__ import annotations

import collections
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any


sys.dont_write_bytecode = True
REAL_CODEX = "/Applications/ChatGPT.app/Contents/Resources/codex"
CONTROLLER = Path(__file__).with_name("App全局路由.py")
ROUTED_METHODS = frozenset(("thread/start", "thread/resume", "thread/fork"))
MANAGED_METHODS = ROUTED_METHODS | {"turn/start"}
PROVIDERS = {"team": "sg_team", "original": "custom-api", "personal": "openai"}
CHUNK_SIZE = 65536
QUEUE_WATERMARK = 1024 * 1024
LOG_LIMIT = 2 * 1024 * 1024
LOG_NAME = "运行记录.jsonl"
ROUTE_ERROR = -32098
ROUTE_ERROR_MESSAGE = "Managed global route is unavailable; no request was forwarded."
WS = " \t\r\n"


def _bad_constant(value: str) -> None:
    raise ValueError("non-JSON numeric constant")


# Parsing values never feeds a reserializer: original numeric/string spelling is retained.
DECODER = json.JSONDecoder(parse_constant=_bad_constant)


class InvalidRoutedRequest(ValueError):
    pass


class RestartRequired(RuntimeError):
    pass


@dataclass(frozen=True)
class Member:
    key: str
    start: int
    end: int


@dataclass
class Request:
    text: str
    obj: dict[str, Any]
    members: list[Member]
    close: int
    method: str

    def id_text(self) -> str | None:
        fields = [m for m in self.members if m.key == "id"]
        if not fields:
            return None
        return self.text[fields[-1].start : fields[-1].end]


def _skip_ws(text: str, offset: int) -> int:
    while offset < len(text) and text[offset] in WS:
        offset += 1
    return offset


def _object_members(text: str, start: int) -> tuple[list[Member], int]:
    """Return raw value ranges and the closing brace; the caller validates JSON first."""
    pos = _skip_ws(text, start)
    if pos >= len(text) or text[pos] != "{":
        raise InvalidRoutedRequest("object expected")
    pos = _skip_ws(text, pos + 1)
    result: list[Member] = []
    while text[pos] != "}":
        key, pos = DECODER.raw_decode(text, pos)
        if not isinstance(key, str):
            raise InvalidRoutedRequest("object key expected")
        pos = _skip_ws(text, pos)
        if text[pos] != ":":
            raise InvalidRoutedRequest("colon expected")
        value_start = _skip_ws(text, pos + 1)
        _, value_end = DECODER.raw_decode(text, value_start)
        result.append(Member(key, value_start, value_end))
        pos = _skip_ws(text, value_end)
        if text[pos] == ",":
            pos = _skip_ws(text, pos + 1)
        elif text[pos] != "}":
            raise InvalidRoutedRequest("object delimiter expected")
    return result, pos


def parse_routed_request(line: bytes, methods: frozenset[str] = ROUTED_METHODS) -> Request | None:
    """Unknown methods, JSON-RPC responses and malformed frames remain transparent."""
    try:
        text = line.decode("utf-8")
        obj = DECODER.decode(text)
        if not isinstance(obj, dict) or obj.get("method") not in methods:
            return None
        members, close = _object_members(text, 0)
        return Request(text, obj, members, close, obj["method"])
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None


def _only_member(members: list[Member], key: str) -> Member | None:
    found = [m for m in members if m.key == key]
    if len(found) > 1:
        raise InvalidRoutedRequest("duplicate routing field")
    return found[0] if found else None


def transform_request(line: bytes, provider: str) -> bytes:
    """Pure byte-preserving transform; only params provider values may change.

    Object insertion preserves all existing fields and their exact spelling, including
    huge numeric values, opaque context, escaped strings and JSON-RPC request IDs.
    """
    req = parse_routed_request(line)
    if req is None:
        return line
    if provider not in PROVIDERS.values():
        raise InvalidRoutedRequest("unsupported provider")
    for key in ("method", "params", "id"):
        _only_member(req.members, key)
    encoded_provider = json.dumps(provider, ensure_ascii=True)
    params_member = _only_member(req.members, "params")
    edits: list[tuple[int, int, str]] = []
    if params_member is None:
        if req.method != "thread/start":
            raise InvalidRoutedRequest("thread params missing")
        prefix = "," if req.members else ""
        edits.append((req.close, req.close, prefix + '"params":{"modelProvider":' + encoded_provider + "}"))
    else:
        params = req.obj.get("params")
        if not isinstance(params, dict):
            raise InvalidRoutedRequest("params must be an object")
        members, close = _object_members(req.text, params_member.start)
        provider_member = _only_member(members, "modelProvider")
        if provider_member:
            edits.append((provider_member.start, provider_member.end, encoded_provider))
        else:
            prefix = "," if members else ""
            edits.append((close, close, prefix + '"modelProvider":' + encoded_provider))
        config_member = _only_member(members, "config")
        if config_member and params.get("config") is not None:
            if not isinstance(params["config"], dict):
                raise InvalidRoutedRequest("config must be an object")
            config_members, _ = _object_members(req.text, config_member.start)
            config_provider = _only_member(config_members, "model_provider")
            if config_provider:
                edits.append((config_provider.start, config_provider.end, encoded_provider))
    transformed = req.text
    for start, end, replacement in sorted(edits, reverse=True):
        transformed = transformed[:start] + replacement + transformed[end:]
    return transformed.encode("utf-8")


def route_error(req: Request, invalid_params: bool = False, restart_required: bool = False) -> bytes | None:
    raw_id = req.id_text()
    if raw_id is None:  # A notification gets no synthetic JSON-RPC response.
        return None
    code = -32602 if invalid_params else ROUTE_ERROR
    message = "Invalid thread routing parameters; no request was forwarded." if invalid_params else ROUTE_ERROR_MESSAGE
    if restart_required:
        code = -32099
        message = "This thread has not loaded the current global provider. Fully quit and reopen Codex App before sending; no turn was forwarded."
    prefix = '{"jsonrpc":"2.0",' if req.obj.get("jsonrpc") == "2.0" else "{"
    return (prefix + '"id":' + raw_id + ',"error":' + json.dumps({"code": code, "message": message}, separators=(",", ":")) + "}\n").encode("utf-8")


def is_app_server_serve(argv: list[str]) -> bool:
    """Recognize the official stdio serve command without hijacking CLI helpers.

    The App launches -c <setting> ... app-server --analytics-default-enabled.
    Other app-server subcommands, help, and non-stdio transports use the official
    executable directly. Unknown positional suffixes also pass through.
    """
    with_value = {"-c", "--config", "--enable", "--disable", "--profile", "-p", "--cd", "-C", "--model", "-m", "--sandbox", "-s", "--ask-for-approval", "-a", "--add-dir", "--image", "-i"}
    no_value = {"--oss", "--full-auto", "--dangerously-bypass-approvals-and-sandbox", "--search", "--no-alt-screen"}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("--help", "-h", "--version", "-V", "--"):
            return False
        if arg == "app-server":
            break
        if arg in with_value:
            i += 2
            continue
        if arg in no_value or any(arg.startswith(option + "=") for option in with_value if option.startswith("--")) or (arg.startswith("-c") and len(arg) > 2):
            i += 1
            continue
        return False
    else:
        return False
    i += 1
    while i < len(argv):
        arg = argv[i]
        if arg in {"--analytics-default-enabled", "--stdio", "--strict-config"}:
            i += 1
        elif arg in {"-c", "--config", "--code-mode-host"}:
            if i + 1 >= len(argv):
                return False
            i += 2
        elif arg.startswith(("--config=", "--code-mode-host=")) or (arg.startswith("-c") and len(arg) > 2):
            i += 1
        elif arg == "--listen":
            if i + 1 >= len(argv) or argv[i + 1] not in {"stdio", "stdio://"}:
                return False
            i += 2
        elif arg in {"--listen=stdio", "--listen=stdio://"}:
            i += 1
        else:
            return False
    return True


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


class Audit:
    """Best-effort private metadata only. Never log raw requests, keys or errors."""

    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)

    def write(self, event: str, **fields: Any) -> None:
        directory_fd = log_fd = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            directory_fd = os.open(self.state_dir, flags)
            directory = os.fstat(directory_fd)
            if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) & 0o077:
                return
            log_fd = os.open(LOG_NAME, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
            info = os.fstat(log_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                return
            fcntl.flock(log_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = {"event": event, "time": _utc_now(), "wrapper_pid": os.getpid(), **fields}
            payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            if len(payload) > 8192:
                return
            # Keep only this owned log bounded; never touch another file or directory.
            if os.fstat(log_fd).st_size + len(payload) > LOG_LIMIT:
                os.ftruncate(log_fd, 0)
                reset = {"event": "log_retention_reset", "time": _utc_now(), "wrapper_pid": os.getpid()}
                os.write(log_fd, (json.dumps(reset, separators=(",", ":")) + "\n").encode("utf-8"))
            os.write(log_fd, payload)
        except (OSError, ValueError, TypeError):
            pass
        finally:
            if log_fd is not None:
                os.close(log_fd)
            if directory_fd is not None:
                os.close(directory_fd)


def load_controller(path: Path = CONTROLLER) -> Any:
    spec = importlib.util.spec_from_file_location("_codex_app_global_route_controller", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("controller unavailable")
    module = importlib.util.module_from_spec(spec)
    # Some standard-library decorators look up their module during import.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if not callable(getattr(module, "route_enabled", None)) or not callable(getattr(module, "load_route", None)):
        raise RuntimeError("controller contract unavailable")
    return module


class RouteState:
    def __init__(self, path: Path):
        self.path = path
        self.controller: Any | None = None
        self.audit: Audit | None = None

    def read(self) -> dict[str, Any] | None:
        # Retry import after a missing controller is restored; do not fail open.
        if self.controller is None:
            self.controller = load_controller(self.path)
        if not self.controller.route_enabled():
            return None
        route = self.controller.load_route()
        if not isinstance(route, dict) or route.get("mode") not in PROVIDERS or route.get("provider") != PROVIDERS[route["mode"]] or not isinstance(route.get("state_dir"), (str, Path)):
            raise RuntimeError("invalid route contract")
        self.audit = Audit(Path(route["state_dir"]))
        return route


class ByteQueue:
    def __init__(self) -> None:
        self.parts: collections.deque[memoryview] = collections.deque()
        self.size = 0

    def append(self, data: bytes) -> None:
        if data:
            self.parts.append(memoryview(data))
            self.size += len(data)

    def write(self, fd: int) -> None:
        if not self.parts:
            return
        view = self.parts[0]
        count = os.write(fd, view[:CHUNK_SIZE])
        self.size -= count
        if count == len(view):
            self.parts.popleft()
        else:
            self.parts[0] = view[count:]

    def clear(self) -> None:
        self.parts.clear()
        self.size = 0


class Lines:
    def __init__(self) -> None:
        self.data = bytearray()
        self.scan = 0

    def append(self, data: bytes) -> None:
        self.data.extend(data)

    def pop(self, eof: bool = False) -> bytes | None:
        end = self.data.find(b"\n", self.scan)
        if end < 0:
            self.scan = len(self.data)
            if not eof or not self.data:
                return None
            end = len(self.data) - 1
        line = bytes(self.data[: end + 1])
        del self.data[: end + 1]
        self.scan = 0
        return line


def _request_key(obj: dict[str, Any]) -> tuple[str, str] | None:
    value = obj.get("id")
    if isinstance(value, str):
        return "s", value
    if isinstance(value, int) and not isinstance(value, bool):
        return "i", str(value)
    return None


def _thread_id(obj: dict[str, Any]) -> str | None:
    params = obj.get("params")
    value = params.get("threadId") if isinstance(params, dict) else None
    return value if isinstance(value, str) and len(value) <= 200 else None


def run_proxy(argv: list[str], *, real_binary: str = REAL_CODEX, controller_path: Path = CONTROLLER, shutdown_grace: float = 5.0, kill_grace: float = 2.0) -> int:
    """One App-owned proxy and one original child; no listener, daemon, or model call."""
    selection = RouteState(controller_path)
    selection.controller = load_controller(controller_path)
    preflight = getattr(selection.controller, "preflight", None)
    if callable(preflight):
        try:
            preflight()
        except Exception:
            print("Codex App self-heal preflight failed closed; see private status/log.", file=sys.stderr)
            return 78
    # A dedicated process group allows narrowly scoped shutdown of this child tree.
    child = subprocess.Popen([real_binary, *argv], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, start_new_session=True, bufsize=0)
    assert child.stdin is not None and child.stdout is not None
    app_in, app_out = sys.stdin.fileno(), sys.stdout.fileno()
    child_in, child_out = child.stdin.fileno(), child.stdout.fileno()
    for fd in (app_in, app_out, child_in, child_out):
        os.set_blocking(fd, False)
    try:
        route = selection.read()
        if route and selection.audit:
            selection.audit.write("child_spawn", pid=child.pid, provider=route["provider"], mode=route["mode"], wrapper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    except Exception:
        # Actual routed requests receive a bounded protocol error; never leak exceptions.
        pass

    to_child, to_app = ByteQueue(), ByteQueue()
    input_lines, output_lines = Lines(), Lines()
    pending: collections.OrderedDict[tuple[str, str], dict[str, Any]] = collections.OrderedDict()
    effective_providers: dict[str, str | None] = {}
    input_eof = output_eof = False
    app_output_open = True
    child_input_open = True
    shutdown_started: float | None = None
    term_sent_at: float | None = None
    killed = False
    received_signal = 0
    old_handlers: dict[int, Any] = {}
    selector = selectors.SelectSelector()

    def signal_handler(signum: int, frame: Any) -> None:
        nonlocal received_signal
        received_signal = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        old_handlers[signum] = signal.signal(signum, signal_handler)

    def send_child_signal(signum: int) -> None:
        # Descendants can retain stdout after the direct child exits. The dedicated
        # group is still ours in that case; never signal the App or another group.
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    def process_input(line: bytes) -> None:
        req = parse_routed_request(line, MANAGED_METHODS)
        if req is None:
            to_child.append(line)
            return
        route = None
        try:
            route = selection.read()
            if route is None:
                to_child.append(line)
                return
            if req.method == "turn/start":
                thread_id = _thread_id(req.obj)
                if thread_id is None or effective_providers.get(thread_id) != route["provider"]:
                    raise RestartRequired("restart required")
                to_child.append(line)
                if selection.audit:
                    selection.audit.write("turn_forwarded", pid=child.pid, method=req.method, threadId=thread_id, provider=route["provider"], mode=route["mode"])
                return
            rewritten = transform_request(line, route["provider"])
        except Exception as exc:
            error = route_error(req, isinstance(exc, InvalidRoutedRequest), isinstance(exc, RestartRequired))
            if error is not None:
                to_app.append(error)
            if selection.audit:
                selection.audit.write("route_rejected", pid=child.pid, method=req.method, threadId=_thread_id(req.obj))
            return
        to_child.append(rewritten)
        metadata = {"pid": child.pid, "method": req.method, "threadId": _thread_id(req.obj), "provider": route["provider"], "mode": route["mode"]}
        if selection.audit:
            selection.audit.write("route_request", **metadata)
        key = _request_key(req.obj)
        if key is not None:
            pending[key] = metadata
            pending.move_to_end(key)
            if len(pending) > 4096:
                pending.popitem(last=False)

    def process_output(line: bytes) -> None:
        # The complete original frame is sent unchanged regardless of audit parsing.
        to_app.append(line)
        try:
            obj = DECODER.decode(line.decode("utf-8"))
            if not isinstance(obj, dict) or "method" in obj:
                return
            key = _request_key(obj)
            metadata = pending.pop(key, None) if key is not None else None
            if metadata is None:
                return
            result = obj.get("result")
            actual_provider = None
            actual_thread = None if metadata["method"] == "thread/fork" else metadata["threadId"]
            if isinstance(result, dict):
                actual_provider = result.get("modelProvider")
                thread = result.get("thread")
                if isinstance(thread, dict):
                    if isinstance(thread.get("id"), str) and len(thread["id"]) <= 200:
                        actual_thread = thread["id"]
            if not isinstance(actual_provider, str) or len(actual_provider) > 100:
                actual_provider = None
            response_error = "error" in obj
            if actual_thread is not None and not response_error:
                effective_providers[actual_thread] = actual_provider
            if selection.audit:
                selection.audit.write("route_response", **{**metadata, "threadId": actual_thread}, responseProvider=actual_provider, responseError=response_error)
                if not response_error and actual_provider != metadata["provider"]:
                    selection.audit.write("route_mismatch", **{**metadata, "threadId": actual_thread}, responseProvider=actual_provider)
        except (ValueError, UnicodeDecodeError, TypeError, RecursionError):
            pass

    try:
        while True:
            now = time.monotonic()
            if received_signal:
                send_child_signal(received_signal)
                received_signal = 0
                input_eof = True
                to_child.clear()
                input_lines = Lines()
                shutdown_started = shutdown_started or now
                term_sent_at = term_sent_at or now
            if input_eof and shutdown_started is None:
                shutdown_started = now
            if not app_output_open:
                if term_sent_at is None:
                    send_child_signal(signal.SIGTERM)
                    term_sent_at = now
                to_app.clear()
                input_eof = True
                to_child.clear()
                input_lines = Lines()
            if shutdown_started is not None and term_sent_at is None and now - shutdown_started >= shutdown_grace:
                send_child_signal(signal.SIGTERM)
                term_sent_at = now
            if term_sent_at is not None and not killed and now - term_sent_at >= kill_grace:
                send_child_signal(signal.SIGKILL)
                killed = True

            # Bound completed-frame queues, while allowing a single large JSONL frame.
            while to_child.size < QUEUE_WATERMARK and to_app.size < QUEUE_WATERMARK:
                line = input_lines.pop(eof=input_eof)
                if line is None:
                    break
                process_input(line)
            while app_output_open and to_app.size < QUEUE_WATERMARK:
                line = output_lines.pop(eof=output_eof)
                if line is None:
                    break
                process_output(line)

            if input_eof and not input_lines.data and not to_child.size and child_input_open:
                child.stdin.close()
                child_input_open = False
            returncode = child.poll()
            if returncode is not None:
                # A descendant can hold a pipe open after its parent has exited.
                # Start the same bounded, narrowly scoped shutdown in that case.
                shutdown_started = shutdown_started or now
                input_eof = True
                to_child.clear()
                input_lines = Lines()
            if returncode is not None and output_eof and (not app_output_open or (not to_app.size and not output_lines.data)):
                return returncode if returncode >= 0 else 128 - returncode

            for key in list(selector.get_map().values()):
                selector.unregister(key.fd)
            if not input_eof and child_input_open and to_child.size < QUEUE_WATERMARK and to_app.size < QUEUE_WATERMARK:
                selector.register(app_in, selectors.EVENT_READ, "app_in")
            if not output_eof and (not app_output_open or to_app.size < QUEUE_WATERMARK):
                selector.register(child_out, selectors.EVENT_READ, "child_out")
            if child_input_open and to_child.size:
                selector.register(child_in, selectors.EVENT_WRITE, "child_in")
            if app_output_open and to_app.size:
                selector.register(app_out, selectors.EVENT_WRITE, "app_out")

            for key, _ in selector.select(0.1):
                try:
                    if key.data == "app_in":
                        data = os.read(app_in, CHUNK_SIZE)
                        if data:
                            input_lines.append(data)
                        else:
                            input_eof = True
                    elif key.data == "child_out":
                        data = os.read(child_out, CHUNK_SIZE)
                        if data and app_output_open:
                            output_lines.append(data)
                        elif not data:
                            output_eof = True
                    elif key.data == "child_in":
                        to_child.write(child_in)
                    elif key.data == "app_out":
                        to_app.write(app_out)
                except BlockingIOError:
                    continue
                except (BrokenPipeError, ConnectionResetError):
                    if key.data == "app_out":
                        app_output_open = False
                    elif key.data == "child_in":
                        child.stdin.close()
                        child_input_open = False
                        to_child.clear()
                        input_eof = True
                        input_lines = Lines()
                    else:
                        raise
    finally:
        selector.close()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if child_input_open:
            child.stdin.close()
        child.stdout.close()
        send_child_signal(signal.SIGTERM)
        if child.poll() is None:
            try:
                child.wait(timeout=kill_grace)
            except subprocess.TimeoutExpired:
                send_child_signal(signal.SIGKILL)
                child.wait()
        group_deadline = time.monotonic() + kill_grace
        while True:
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= group_deadline:
                send_child_signal(signal.SIGKILL)
                break
            time.sleep(0.02)
        if selection.audit:
            selection.audit.write("child_exit", pid=child.pid, exitCode=child.returncode)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not is_app_server_serve(argv):
        os.execv(REAL_CODEX, [REAL_CODEX, *argv])
        return 127
    return run_proxy(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError):
        # Keep diagnostics bounded and free of config contents or credential values.
        print("Codex App global-route wrapper could not start the official app-server.", file=sys.stderr)
        raise SystemExit(127)
