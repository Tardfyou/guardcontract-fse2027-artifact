"""Deny network socket creation and transmission before controlled SDK imports."""
import ctypes
import errno
import hashlib
from pathlib import Path
import socket


def install():
    socket_fds = []
    for path in Path("/proc/self/fd").iterdir():
        try:
            target = path.readlink().as_posix()
        except FileNotFoundError:
            continue
        if target.startswith("socket:"):
            socket_fds.append(path.name)
    if socket_fds:
        raise RuntimeError("offline_filter_inherited_socket")
    library_path = Path("/lib/x86_64-linux-gnu/libseccomp.so.2").resolve()
    library = ctypes.CDLL(str(library_path), use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint32]
    library.seccomp_attr_set.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)
    if not context:
        raise RuntimeError("offline_filter_init")
    blocked = ("socket", "connect", "sendto", "sendmsg", "sendmmsg")
    try:
        # libseccomp attribute 4 is TSYNC: apply the filter to existing threads too.
        if library.seccomp_attr_set(context, 4, 1) != 0:
            raise RuntimeError("offline_filter_thread_sync")
        for name in blocked:
            syscall = library.seccomp_syscall_resolve_name(name.encode())
            if syscall < 0 or library.seccomp_rule_add(context, 0x00050000 | errno.EPERM, syscall, 0) != 0:
                raise RuntimeError("offline_filter_rule")
        if library.seccomp_load(context) != 0:
            raise RuntimeError("offline_filter_load")
    finally:
        library.seccomp_release(context)
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as exc:
        if exc.errno != errno.EPERM:
            raise RuntimeError("offline_filter_probe_errno") from exc
    else:
        connection.close()
        raise RuntimeError("offline_filter_probe_failed")
    return {"mechanism": "kernel_seccomp", "blocked_syscalls": list(blocked), "thread_sync": True,
            "inherited_socket_fds": [], "socket_creation_probe": "EPERM", "library": str(library_path),
            "library_sha256": hashlib.sha256(library_path.read_bytes()).hexdigest()}
