# -*- coding: utf-8 -*-
"""qq_scan_db.py — 对指定 QQ 库做已知明文派生密钥扫描
用法: python qq_scan_db.py <db文件名> [pid]
"""
import ctypes
import multiprocessing as mp
import os
import sys

sys.path.insert(0, r".")
import wx4
from Crypto.Cipher import AES

DB_NAME = sys.argv[1]
PID = int(sys.argv[2]) if len(sys.argv) > 2 else 21084
SRC = os.path.join(r"<QQ_NT_DB>", DB_NAME)
OUT = os.path.join(r".\qq_derived_keys", DB_NAME + ".key")
RES = 48

f = open(SRC, "rb")
f.seek(1024)
page1 = f.read(4096)
CT = page1[16:32]
IV = page1[4048:4064]


def worker(data):
    out = []
    for i in range(0, len(data) - 32):
        K = data[i:i + 32]
        if len(set(K)) < 12:
            continue
        pt = AES.new(K, AES.MODE_CBC, IV).decrypt(CT)
        if pt[:2] == b"\x10\x00" and pt[5] == 0x40 and pt[6] == 0x20 and pt[7] == 0x20:
            out.append((K.hex(), i, pt[:24].hex()))
    return out


def main():
    _k32 = wx4._k32
    _k32.OpenProcess.restype = ctypes.c_void_p
    h = _k32.OpenProcess(wx4.PROCESS_VM_READ | wx4.PROCESS_QUERY_INFORMATION, False, PID)
    if not h:
        print("open fail", flush=True)
        return
    regions = [(b, s) for b, s in wx4.iter_regions(h) if s <= 0x40000000]
    print(f"{DB_NAME}: regions={len(regions)}", flush=True)
    tasks = [wx4.read_region(h, b, s) for b, s in regions if s > 0]

    found = False
    with mp.Pool(processes=10) as pool:
        for i, res in enumerate(pool.imap_unordered(worker, tasks, chunksize=1)):
            if res:
                kh = res[0][0]
                print(f"FOUND {DB_NAME}: key={kh} pt={res[0][2]}", flush=True)
                os.makedirs(os.path.dirname(OUT), exist_ok=True)
                with open(OUT, "w") as fh:
                    fh.write(kh)
                found = True
                break
            if i % 200 == 0:
                print(f"  {i}/{len(tasks)}", flush=True)
    if not found:
        print(f"{DB_NAME}: no hit", flush=True)


if __name__ == "__main__":
    main()
