# -*- coding: utf-8 -*-
"""wx4.py — 微信 4.x (xwechat_files) 密钥提取与数据库批量解密。

用法:
  python wx4.py keyscan  [--db <用于验证的加密库, 默认 contact.db>] [--out wx_keys.txt]
  python wx4.py decrypt  [--key <64hex>] [--src <db_storage目录>] [--dst <输出目录>]
  python wx4.py all      # keyscan + decrypt 一条龙

原理 (SQLCipher 4, WeChat 4.x):
  - 密钥: Weixin.exe 进程内存中形如 x'<64位hex>' 的 raw key (32 字节, 加密不做 KDF)
  - 文件头 16 字节为 salt; mac_salt = salt ^ 0x3a
  - mac_key = PBKDF2-HMAC-SHA512(key, mac_salt, 2, 32)
  - 每页 4096B = [密文][IV 16B][HMAC-SHA512 64B], HMAC 覆盖 密文+IV+页号LE32
  - 解密后每页写回 [明文][IV][HMAC] 并把第 1 页开头替换为 SQLite 标准头
"""
import argparse
import ctypes
import hashlib
import hmac
import os
import re
import struct
import sys
from Crypto.Cipher import AES

PAGE_SZ = 4096
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64  # SHA512
RESERVE_SZ = IV_SZ + HMAC_SZ  # 80
KDF_ITER = 256000  # SQLCipher 4 默认; 4.1.x 以 32B raw key 作 passphrase 过 KDF
KEY_RE = re.compile(rb"x'([0-9a-fA-F]{64})'")
BARE_HEX_RE = re.compile(rb"(?<![0-9a-fA-F])([0-9a-f]{64})(?![0-9a-fA-F])")
# 4.1.x 密钥缓冲描述符: {ptr(8), len=LE64(0x20), cap=LE64(0x2f)}
# 定长锚: len 字段 (00x7+0x20) + cap 字段前 7 字节; cap 本体放宽为 >=0x20
STUB_LEN = b"\x00" * 7 + b"\x20" + b"\x00" * 7
DEFAULT_SRC = r"<XWECHAT_DB_STORAGE>"
DEFAULT_DST = r".\local\decrypted"

# ---------------- 进程内存扫描 (ctypes) ----------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong),
                ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong),
                ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]


def find_pids(image_name):
    import psutil
    pids = []
    for p in psutil.process_iter(["name"]):
        try:
            if p.info["name"] and p.info["name"].lower() == image_name:
                pids.append(p.pid)
        except Exception:
            continue
    return pids


def iter_regions(proc):
    addr = 0
    max_addr = 0x7FFFFFFEFFFF
    while addr < max_addr:
        mbi = MBI()
        r = _k32.VirtualQueryEx(proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE
                and not (mbi.Protect & PAGE_GUARD) and size > 0):
            yield base, size
        addr = base + size
        if addr <= base:
            break


OVERLAP = 512  # 跨块边界保护: 下一块向回退重叠字节

def read_region(proc, base, size, chunk=0x1000000):
    result = bytearray()
    off = 0
    while off < size:
        n = min(chunk, size - off)
        b = ctypes.create_string_buffer(n)
        read = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(proc, ctypes.c_void_p(base + off), b, n, ctypes.byref(read))
        if not ok or read.value == 0:
            result.extend(b"\x00" * n)  # 中部不可读, 补零跳过
        else:
            result.extend(b.raw[:read.value])
            if read.value < n:
                result.extend(b"\x00" * (n - read.value))
        off += n
        if off < size:
            off = max(0, off - OVERLAP)
            del result[len(result) - OVERLAP:]  # 丢弃旧尾, 下块回退重读, 避免重复膨胀
    return bytes(result)


def read_at(proc, addr, size):
    b = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = _k32.ReadProcessMemory(proc, ctypes.c_void_p(addr), b, size, ctypes.byref(read))
    return b.raw[:read.value] if ok and read.value else b""


def scan_process(pid, patterns):
    _k32.OpenProcess.restype = ctypes.c_void_p
    h = _k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) 失败 err={ctypes.get_last_error()} (需要管理员?)")
    found = set()
    stub_keys = set()
    try:
        regions = list(iter_regions(h))
        total = sum(s for _, s in regions)
        print(f"  PID {pid}: {len(regions)} 个已提交区域, {total/1e9:.2f} GB")
        for base, size in regions:
            data = read_region(h, base, min(size, 0x40000000))
            for pat in patterns:
                for m in pat.finditer(data):
                    found.add(m.group(1).decode("ascii"))
            # 结构体特征: 定位 {ptr, len=0x20, cap} 描述符, 解引用取 32B key
            i = data.find(STUB_LEN)
            while i != -1:
                if i >= 8:
                    ptr = int.from_bytes(data[i - 8:i], "little")
                    if 0x10000 <= ptr < 0x7FFFFFFF0000:
                        k = read_at(h, ptr, 32)
                        if len(k) == 32:
                            stub_keys.add(k)
                i = data.find(STUB_LEN, i + 1)
        print(f"  PID {pid} 扫描完成")
    finally:
        _k32.CloseHandle(ctypes.c_void_p(h))
    return found, stub_keys


def potential_key(k):
    """密钥级熵初筛: 过滤全零/重复/明文 buffer"""
    if len(set(k)) < 15:
        return False
    if sum(32 <= b <= 126 for b in k) > 24:
        return False
    return True


# ---------------- SQLCipher 4 (WeChat 4.x) 验证与解密 ----------------

def derive_keys(key32, salt):
    """返回 (enc_key, mac_key): 4.1.x 走 256000 轮 KDF"""
    mac_salt = bytes(x ^ 0x3A for x in salt)
    enc = hashlib.pbkdf2_hmac("sha512", key32, salt, KDF_ITER, 32)
    mac = hashlib.pbkdf2_hmac("sha512", enc, mac_salt, 2, 32)
    return enc, mac


def check_key(key32, db_path, kdf=True):
    """用第 1 页 HMAC 校验候选密钥; kdf=False 兼容老版 raw-key 直用"""
    try:
        with open(db_path, "rb") as f:
            head = f.read(PAGE_SZ)
    except OSError:
        return False
    if len(head) < PAGE_SZ:
        return False
    salt = head[:SALT_SZ]
    page1 = head[SALT_SZ:]
    if kdf:
        enc, mac_key = derive_keys(key32, salt)
    else:
        mac_salt = bytes(x ^ 0x3A for x in salt)
        enc, mac_key = key32, hashlib.pbkdf2_hmac("sha512", key32, mac_salt, 2, 32)
    hm = hmac.new(mac_key, digestmod="sha512")
    hm.update(page1[:-RESERVE_SZ + IV_SZ])
    hm.update(struct.pack("<I", 1))
    return hmac.compare_digest(hm.digest(), page1[-RESERVE_SZ + IV_SZ:][:HMAC_SZ])


def decrypt_db(src, dst, enc_key):
    with open(src, "rb") as f:
        blob = f.read()
    if len(blob) < PAGE_SZ:
        return False
    with open(dst, "wb") as f:
        f.write(b"SQLite format 3\x00")
        pages = [blob[SALT_SZ:PAGE_SZ]]
        pages += [blob[i:i + PAGE_SZ] for i in range(PAGE_SZ, len(blob), PAGE_SZ)]
        for idx, page in enumerate(pages):
            # 第 1 页 4080B (4096-盐), 其余 4096B; 统一从尾部取 IV 解密
            iv = page[-RESERVE_SZ:-RESERVE_SZ + IV_SZ]
            pt = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(page[:-RESERVE_SZ])
            f.write(pt)
            f.write(page[-RESERVE_SZ:])
    return True


def keyscan(db_check, out_file):
    import psutil  # noqa: F401  (find_pids 依赖)
    pids = find_pids("weixin.exe")
    if not pids:
        print("Weixin.exe 未运行, 无法内存取钥")
        return []
    hex_cands, stub_cands = set(), set()
    patterns = [KEY_RE, BARE_HEX_RE]
    for pid in pids:
        try:
            hx, sk = scan_process(pid, patterns)
            hex_cands |= hx
            stub_cands |= sk
        except OSError as e:
            print(f"  PID {pid}: {e}")
    stub_cands = {k for k in stub_cands if potential_key(k)}
    print(f"候选: 结构体指针 {len(stub_cands)} 个, hex 串 {len(hex_cands)} 个, 开始验证 (256000 轮 KDF)...")
    keys = []
    for k in sorted(stub_cands):
        for kdf in (True, False):
            if check_key(k, db_check, kdf=kdf):
                keys.append((k, kdf))
                print(f"[OK] {k.hex()} (kdf={kdf})")
    for hx in sorted(hex_cands):
        k = bytes.fromhex(hx)
        if potential_key(k) and check_key(k, db_check, kdf=False):
            keys.append((k, False))
            print(f"[OK] {hx} (raw, kdf=False)")
    if keys:
        with open(out_file, "w", encoding="utf-8") as f:
            for k, kdf in keys:
                f.write(f"{k.hex()}\tkdf={kdf}\n")
        print(f"已保存 {len(keys)} 把密钥 -> {out_file}")
    else:
        print("未能验证出有效密钥")
    return keys


def load_keys(key_arg):
    """返回 [(key32, kdf)]"""
    if key_arg:
        return [(bytes.fromhex(key_arg), True)]
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wx_keys.txt")
    keys = []
    if os.path.exists(path):
        for l in open(path, encoding="utf-8"):
            parts = l.strip().split("\t")
            if len(parts[0]) == 64:
                kdf = "kdf=False" not in l
                keys.append((bytes.fromhex(parts[0]), kdf))
    return keys


def decrypt_all(key_arg, src, dst):
    keys = load_keys(key_arg)
    if not keys:
        print("无可用密钥, 先跑 keyscan 或传 --key")
        return 1
    ok = bad = 0
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith(".db"):
                continue
            s = os.path.join(root, fn)
            rel = os.path.relpath(s, src)
            d = os.path.join(dst, rel)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            done = False
            for k, kdf in keys:
                if check_key(k, s, kdf=kdf):
                    salt = open(s, "rb").read(SALT_SZ)
                    enc = (derive_keys(k, salt)[0] if kdf else k)
                    if decrypt_db(s, d, enc):
                        print(f"[OK] {rel}")
                        ok += 1
                    else:
                        print(f"[SKIP] {rel} (过小)")
                    done = True
                    break
            if not done:
                print(f"[FAIL] {rel}")
                bad += 1
    print(f"完成: 成功 {ok}, 失败 {bad}, 输出目录 {dst}")
    return 0 if bad == 0 else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    kc = sub.add_parser("keyscan")
    kc.add_argument("--db", default=os.path.join(DEFAULT_SRC, "contact", "contact.db"))
    kc.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "wx_keys.txt"))
    dc = sub.add_parser("decrypt")
    dc.add_argument("--key", default=None)
    dc.add_argument("--src", default=DEFAULT_SRC)
    dc.add_argument("--dst", default=DEFAULT_DST)
    al = sub.add_parser("all")
    al.add_argument("--key", default=None)
    args = ap.parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if args.cmd == "keyscan":
        keyscan(args.db, args.out)
    elif args.cmd == "decrypt":
        sys.exit(decrypt_all(args.key, args.src, args.dst))
    elif args.cmd == "all":
        keys = keyscan(os.path.join(DEFAULT_SRC, "contact", "contact.db"),
                       os.path.join(os.path.dirname(os.path.abspath(__file__)), "wx_keys.txt"))
        if keys:
            sys.exit(decrypt_all(None, DEFAULT_SRC, DEFAULT_DST))


if __name__ == "__main__":
    main()
