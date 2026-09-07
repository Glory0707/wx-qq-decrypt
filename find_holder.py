# -*- coding: utf-8 -*-
"""find_holder.py — 枚举系统文件句柄, 找出打开 nt_msg.db 的进程"""
import ctypes
import ctypes.wintypes as wt
import sys

ntdll = ctypes.WinDLL("ntdll")
k32 = ctypes.WinDLL("kernel32")
advapi = ctypes.WinDLL("advapi32")

TARGETS = ["nt_msg.db", "nt_msg.db-wal", "group_info.db"]

# --- 类型与常量 ---
class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wt.USHORT),
                ("MaximumLength", wt.USHORT),
                ("Buffer", ctypes.c_void_p)]

class OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [("TypeName", UNICODE_STRING),
                ("TotalNumberOfHandles", wt.ULONG),
                ("TotalNumberOfObjects", wt.ULONG)]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [("Object", ctypes.c_void_p),
                ("ProcessId", wt.ULONG),
                ("Handle", wt.ULONG),
                ("GrantedAccess", wt.ULONG),
                ("CreatorBackTraceIndex", wt.USHORT),
                ("ObjectTypeIndex", wt.USHORT),
                ("HandleAttributes", wt.ULONG),
                ("Reserved", wt.ULONG)]

SystemExtendedHandleInformation = 64
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
DUPLICATE_SAME_ACCESS = 0x2
CURRENT_PROCESS = ctypes.c_void_p(-1).value


def get_handle_list():
    length = 0x1000000
    while True:
        buf = ctypes.create_string_buffer(length)
        ret = ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation,
                                             buf, length, ctypes.byref(wt.ULONG()))
        if ret != STATUS_INFO_LENGTH_MISMATCH:
            break
        length *= 2
    count = ctypes.c_size_t.from_buffer(buf).value
    entries = ctypes.cast(buf, ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))
    return [entries[i] for i in range(count)]


def dup_handle(src_pid, src_handle):
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD]
    k32.DuplicateHandle.restype = wt.BOOL
    hproc = k32.OpenProcess(0x0040, False, src_pid)
    if not hproc:
        return None
    try:
        dup = wt.HANDLE()
        # FILE_READ_ATTRIBUTES: 足以查询路径, 避免同权限复制失败
        ok = k32.DuplicateHandle(hproc, ctypes.c_void_p(src_handle),
                                 ctypes.c_void_p(0xFFFFFFFFFFFFFFFF),
                                 ctypes.byref(dup), 0x0080, False, 0)
        return dup.value if ok else None
    finally:
        k32.CloseHandle(ctypes.c_void_p(hproc))


def handle_name(h):
    # 用 GetFinalPathNameByHandle (仅对自身进程副本有效)
    size = wt.ULONG(1024)
    buf = ctypes.create_unicode_buffer(1024)
    try:
        r = k32.GetFinalPathNameByHandleW(wt.HANDLE(h), buf, 1024, 0)
        if 0 < r < 1024:
            return buf.value
    except Exception:
        pass
    return None


def main():
    # 目标进程白名单过滤: 只看 QQ 相关, 避免全系统遍历太慢
    import psutil
    qq_pids = {p.pid: p.info["name"] for p in psutil.process_iter(["name"])
               if p.info["name"] and "qq" in p.info["name"].lower()}
    print("QQ 进程:", qq_pids, flush=True)
    found = {}
    entries = get_handle_list()
    print("总句柄数:", len(entries), flush=True)
    for e in entries:
        pid = e.ProcessId
        if pid not in qq_pids:
            continue
        if (e.GrantedAccess & 0x1) == 0 and (e.GrantedAccess & 0x2) == 0:
            continue
        h = dup_handle(pid, e.Handle)
        if not h:
            continue
        try:
            name = handle_name(h)
            if name:
                for t in TARGETS:
                    if name.endswith(t) and "nt_db" in name:
                        found.setdefault(t, []).append((pid, name))
                        print(f"[HIT] {t} -> PID {pid} : {name}", flush=True)
        finally:
            k32.CloseHandle(wt.HANDLE(h))
    print("done:", {k: v for k, v in found.items()}, flush=True)


if __name__ == "__main__":
    main()
