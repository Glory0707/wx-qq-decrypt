# -*- coding: utf-8 -*-
"""scan_derived.py — 在 21084 进程内存中已知明文搜索 nt_msg 的派生 AES 密钥
判据: AES-256-CBC(ct=file[1040:1056], iv=页尾变体) 的明文以 SQLite 页头特征开头
"""
import ctypes
import hashlib
import multiprocessing as mp
import os
import sys

import numpy as np
from Crypto.Cipher import AES

sys_path = r"."
sys.path.insert(0, sys_path)
import wx4

PID = int(sys.argv[1]) if len(sys.argv) > 1 else 0
SRC = r"<QQ_NT_DB>\nt_msg.db"
OUT = r".\nt_msg_enc_key.bin"

f = open(SRC, "rb")
f.seek(1024)
page1 = f.read(4096)
CT = page1[16:32]           # 页1第一个密文块 (盐后)
IV48 = page1[4048:4064]     # reserve=48 布局的 IV
IV80 = page1[4016:4032]     # reserve=80 布局的 IV
IV16 = page1[4080:4096]     # reserve=16 布局的 IV
IV36 = page1[4060:4076]     # reserve=36 布局的 IV
IVS = [("r48", IV48), ("r80", IV80), ("r16", IV16), ("r36", IV36)]

EXPECT0 = b"\x10\x00"       # 页大小 4096 (大端)


def worker(task):
    data, ivs = task
    out = []
    n = len(data) - 32
    dec = AES.new
    for i in range(0, n):
        K = data[i:i + 32]
        # 快速熵预筛: 派生密钥应高熵 (>=12 种字节), 滤掉大量重复区
        if len(set(K)) < 12:
            continue
        for ivname, iv in ivs:
            pt = dec(K, AES.MODE_CBC, iv).decrypt(CT)
            if pt[:2] == EXPECT0 and pt[5] == 0x40 and pt[6] == 0x20 and pt[7] == 0x20:
                out.append((K.hex(), ivname, i, pt[:24].hex()))
    return out


def main():
    _k32 = wx4._k32
    _k32.OpenProcess.restype = ctypes.c_void_p
    h = _k32.OpenProcess(wx4.PROCESS_VM_READ | wx4.PROCESS_QUERY_INFORMATION, False, PID)
    if not h:
        print("open fail", flush=True)
        return
    regions = [(base, size) for base, size in wx4.iter_regions(h) if size <= 0x40000000]
    total = sum(s for _, s in regions)
    print(f"regions={len(regions)} total={total/1e9:.2f}GB", flush=True)

    tasks = []
    for base, size in regions:
        data = wx4.read_region(h, base, size)
        if data:
            tasks.append((data, IVS))

    with mp.Pool(processes=10) as pool:
        for i, res in enumerate(pool.imap_unordered(worker, tasks, chunksize=1)):
            if res:
                print("FOUND:", res, flush=True)
                for kh, ivname, off, pt in res:
                    with open(OUT, "wb") as fh:
                        fh.write(bytes.fromhex(kh))
                return
            if i % 100 == 0:
                print(f"  region {i}/{len(tasks)}", flush=True)
    print("done, no hit", flush=True)


if __name__ == "__main__":
    main()
