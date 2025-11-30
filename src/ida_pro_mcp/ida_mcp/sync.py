import os
import time
import logging
import queue
import functools
from enum import IntEnum
import idaapi
import ida_kernwin
import idc
from .rpc import McpToolError

# ============================================================================
# IDA Synchronization & Error Handling
# ============================================================================

ida_major, ida_minor = map(int, idaapi.get_kernel_version().split("."))

# Setup logging
_log_file = os.environ.get("MCP_LOG_FILE")
_sync_logger = logging.getLogger("ida-mcp-sync")
if _log_file:
    _sync_logger.setLevel(logging.DEBUG)
    _fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    _fh = logging.FileHandler(_log_file, mode="a")
    _fh.setFormatter(_fmt)
    _sync_logger.addHandler(_fh)
else:
    _sync_logger.setLevel(logging.WARNING)


class IDAError(McpToolError):
    def __init__(self, message: str):
        super().__init__(message)

    @property
    def message(self) -> str:
        return self.args[0]


class IDASyncError(Exception):
    pass


logger = logging.getLogger(__name__)


class IDASafety(IntEnum):
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


call_stack = queue.LifoQueue()


def _sync_wrapper(ff, safety_mode: IDASafety):
    """Call a function ff with a specific IDA safety_mode."""
    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = f"Invalid safety mode {safety_mode} over function {ff.__name__}"
        logger.error(error_str)
        raise IDASyncError(error_str)

    # NOTE: This is not actually a queue, there is one item in it at most
    res_container = queue.Queue()
    start_time = time.time()
    func_name = ff.__name__
    mode_name = "READ" if safety_mode == IDASafety.SAFE_READ else "WRITE"
    _sync_logger.debug(f"[SYNC] {func_name} ({mode_name}) - queued for execute_sync")

    def runned():
        exec_start = time.time()
        _sync_logger.debug(f"[SYNC] {func_name} - started on main thread (waited {exec_start - start_time:.2f}s)")

        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = f"Call stack is not empty while calling the function {func_name} from {last_func_name}"
            raise IDASyncError(error_str)

        call_stack.put(func_name)
        try:
            # Show wait dialog to indicate IDA is processing
            ida_kernwin.show_wait_box(f"MCP: {func_name}...")
            result = ff()
            res_container.put(result)
        except Exception as x:
            _sync_logger.error(f"[SYNC] {func_name} - exception: {x}")
            res_container.put(x)
        finally:
            ida_kernwin.hide_wait_box()
            call_stack.get()
            _sync_logger.debug(f"[SYNC] {func_name} - finished ({time.time() - exec_start:.2f}s)")

    idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    total_time = time.time() - start_time
    if total_time > 5:
        _sync_logger.warning(f"[SYNC] {func_name} - slow operation ({total_time:.2f}s total)")
    if isinstance(res, Exception):
        raise res
    return res


def sync_wrapper(ff, safety_mode: IDASafety):
    """Wrapper for IDA synchronization (matches 1.4.0 behavior)."""
    return _sync_wrapper(ff, safety_mode)


def idawrite(f):
    """Decorator for marking a function as modifying the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)

    return wrapper


def idaread(f):
    """Decorator for marking a function as reading from the IDB."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)

    return wrapper


def is_window_active():
    """Returns whether IDA is currently active"""
    # Source: https://github.com/OALabs/hexcopy-ida/blob/8b0b2a3021d7dc9010c01821b65a80c47d491b61/hexcopy.py#L30
    using_pyside6 = (ida_major > 9) or (ida_major == 9 and ida_minor >= 2)

    try:
        if using_pyside6:
            import PySide6.QtWidgets as QApplication
        else:
            import PyQt5.QtWidgets as QApplication

        app = QApplication.instance()
        if app is None:
            return False

        for widget in app.topLevelWidgets():
            if widget.isActiveWindow():
                return True
    except Exception:
        # Headless mode or other error (this is not a critical feature)
        pass
    return False
