# -*- coding: utf-8 -*-
"""qqnt.py — QQ NT (Windows) 数据库密钥扫描与解密。

用法:
  python qqnt.py keyscan [--db nt_msg.db] [--out qq_keys.txt]
  python qqnt.py decrypt [--key <32字符passphrase>] [--src nt_db目录] [--dst 输出目录]
  python qqnt.py all

原理:
  - 库文件头部有 1024 字节私有头 (protobuf, 含 key_meta), 之后才是 SQLCipher 数据
  - passphrase: 16 字节可打印 ASCII, 形如 #xxxxxxxxxxxx@xx (由服务器按账号下发)
  - SQLCipher 参数: page=4096, kdf=PBKDF2-HMAC-SHA512(4000轮), HMAC-SHA1(reserve 48)
  - 每页 = [密文 4048][IV 16][填充 12][HMAC 20]
"""
import argparse
import hashlib
import hmac
import os
import re
import struct
import sys

PAGE_SZ = 4096
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 20  # SHA1
RESERVE_SZ = IV_SZ + HMAC_SZ
RESERVE_SZ = (RESERVE_SZ + 15) // 16 * 16  # 48
KDF_ITER = 4000
HEADER_SZ = 1024
PAT_STRICT = re.compile(rb"(#[\x21-\x7e]{12}@[\x21-\x7e]{2})")
PAT_LOOSE = re.compile(rb"([\x21-\x7e]{16})")
DEFAULT_SRC = r"<QQ_NT_DB>"
DEFAULT_DST = r".\decrypted_qq"

# ---- 复用 wx4 的进程内存扫描 (ctypes) ----
from wx4 import find_pids, scan_process, read_at  # noqa: E402


def check_key(passphrase, db_path, hdr=HEADER_SZ, kdf_iter=KDF_ITER,
              hmac_alg="sha1", reserve=RESERVE_SZ):
    try:
        with open(db_path, "rb") as f:
            f.seek(hdr)
            page = f.read(PAGE_SZ)
    except OSError:
        return False
    if len(page) < PAGE_SZ:
        return False
    salt = page[:SALT_SZ]
    mac_salt = bytes(x ^ 0x3A for x in salt)
    enc = hashlib.pbkdf2_hmac("sha512", passphrase, salt, kdf_iter, 32)
    mk = hashlib.pbkdf2_hmac("sha512", enc, mac_salt, 2, 32)
    hm = hmac.new(mk, digestmod=hmac_alg)
    hm.update(page[:-reserve + IV_SZ])
    hm.update(struct.pack("<I", 1))
    return hmac.compare_digest(hm.digest(), page[-reserve + IV_SZ:][:20 if hmac_alg == "sha1" else 32])


def keyscan(db_check, out_file):
    pids = find_pids("qq.exe")
    if not pids:
        print("QQ.exe 未运行")
        return []
    cands = set()
    for pid in pids:
        try:
            hx, _ = scan_process(pid, [PAT_STRICT])
            cands |= {h.encode() for h in hx}
            print(f"  PID {pid}: 累计候选 {len(cands)}")
        except OSError as e:
            print(f"  PID {pid}: {e}")
    # 宽松补充: 含 @ 的 16 字节可打印串
    if not cands:
        for pid in pids:
            try:
                hx, _ = scan_process(pid, [PAT_LOOSE])
                cands |= {h.encode() for h in hx if b"@" in h.encode()}
            except OSError:
                pass
    cands = {c for c in cands if len(c) == 16}
    print(f"候选 {len(cands)} 个, 验证中 (每个 4000 轮 PBKDF2)...")
    keys = []
    for c in sorted(cands):
        for hdr in (HEADER_SZ, 0):
            if check_key(c, db_check, hdr=hdr):
                keys.append((c, hdr))
                print(f"[OK] {c.decode()} (hdr={hdr})")
                break
    if keys:
        with open(out_file, "w", encoding="utf-8") as f:
            for k, hdr in keys:
                f.write(f"{k.decode()}\thdr={hdr}\n")
        print(f"已保存 -> {out_file}")
    else:
        print("未验证出有效密钥")
    return keys


def load_key(key_arg):
    """密钥文件行格式: [db<TAB>]<hex>；也接受 --key 直传 passphrase 字符串"""
    if key_arg:
        return [(key_arg.encode(), HEADER_SZ)]
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qq_keys_live.txt")
    keys = []
    seen = set()
    if os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            parts = [p.strip() for p in line.strip().split("\t") if p.strip()]
            if not parts:
                continue
            hx = parts[-1]
            try:
                k = bytes.fromhex(hx)
            except ValueError:
                k = hx.encode()
            if k not in seen and 8 <= len(k) <= 64:
                seen.add(k)
                keys.append((k, HEADER_SZ))
    return keys


def decrypt_db(src, dst, passphrase, hdr):
    with open(src, "rb") as f:
        blob = f.read()
    data = blob[hdr:] if hdr else blob
    if len(data) < PAGE_SZ:
        return False
    salt = data[:SALT_SZ]
    enc = hashlib.pbkdf2_hmac("sha512", passphrase, salt, KDF_ITER, 32)
    from Crypto.Cipher import AES
    with open(dst, "wb") as f:
        f.write(b"SQLite format 3\x00")
        pages = [data[SALT_SZ:PAGE_SZ]]
        pages += [data[i:i + PAGE_SZ] for i in range(PAGE_SZ, len(data), PAGE_SZ)]
        for page in pages:
            # 第 1 页 4080B (4096-盐), 其余 4096B; 统一从尾部取 IV 解密
            iv = page[-RESERVE_SZ:-RESERVE_SZ + IV_SZ]
            f.write(AES.new(enc, AES.MODE_CBC, iv).decrypt(page[:-RESERVE_SZ]))
            f.write(page[-RESERVE_SZ:])
    return True


def decrypt_all(key_arg, src, dst):
    keys = load_key(key_arg)
    if not keys:
        print("无可用密钥, 先 keyscan 或 --key")
        return 1
    ok = bad = 0
    for fn in sorted(os.listdir(src)):
        if not fn.endswith(".db") or "fts" in fn:
            continue
        s = os.path.join(src, fn)
        d = os.path.join(dst, fn)
        os.makedirs(dst, exist_ok=True)
        done = False
        for k, hdr in keys:
            for h in {hdr, HEADER_SZ, 0}:
                if check_key(k, s, hdr=h):
                    if decrypt_db(s, d, k, h):
                        print(f"[OK] {fn} (hdr={h})")
                        ok += 1
                    done = True
                    break
            if done:
                break
        if not done:
            print(f"[FAIL] {fn}")
            bad += 1
    print(f"完成: 成功 {ok}, 失败 {bad}, 输出 {dst}")
    return 0 if bad == 0 else 1


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    kc = sub.add_parser("keyscan")
    kc.add_argument("--db", default=os.path.join(DEFAULT_SRC, "nt_msg.db"))
    kc.add_argument("--out", default=os.path.join(here, "qq_keys.txt"))
    dc = sub.add_parser("decrypt")
    dc.add_argument("--key")
    dc.add_argument("--src", default=DEFAULT_SRC)
    dc.add_argument("--dst", default=DEFAULT_DST)
    sub.add_parser("all")
    args = ap.parse_args()
    os.chdir(here)
    if args.cmd == "keyscan":
        keyscan(args.db, args.out)
    elif args.cmd == "decrypt":
        sys.exit(decrypt_all(args.key, args.src, args.dst))
    else:
        if keyscan(os.path.join(DEFAULT_SRC, "nt_msg.db"), os.path.join(here, "qq_keys.txt")):
            sys.exit(decrypt_all(None, DEFAULT_SRC, DEFAULT_DST))


if __name__ == "__main__":
    main()
