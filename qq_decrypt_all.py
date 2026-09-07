# -*- coding: utf-8 -*-
"""qq_decrypt_all.py — 用真 sqlcipher3 批量解密 nt_db → decrypted_qq
密钥来自 qq_keys_live.txt (tab 分隔, 末列为 hex/明文密钥), 逐库尝试。
"""
import os
import sqlite3
import sys

import sqlcipher3.dbapi2 as sc

SRC = r"<QQ_NT_DB>"
DST = r".\local\decrypted_qq"
HERE = os.path.dirname(os.path.abspath(__file__))


def load_keys():
    keys = []
    path = os.path.join(HERE, "qq_keys_live.txt")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            parts = [p.strip() for p in line.strip().split("\t") if p.strip()]
            if not parts:
                continue
            k = parts[-1]
            if k not in keys:
                keys.append(k)
    return keys


def open_enc(clear_path, key):
    con = sc.connect(clear_path, isolation_level=None)
    con.execute("PRAGMA cipher_page_size = 4096;")
    con.execute(f"PRAGMA key = '{key}';")
    con.execute("PRAGMA kdf_iter = 4000;")
    con.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA1;")
    con.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;")
    con.execute("SELECT count(*) FROM sqlite_master;").fetchone()
    return con


def main():
    os.makedirs(DST, exist_ok=True)
    keys = load_keys()
    print("keys:", keys, flush=True)
    ok = bad = 0
    for fn in sorted(os.listdir(SRC)):
        if not fn.endswith(".db") or "fts" in fn or fn.endswith(".bak"):
            continue
        src = os.path.join(SRC, fn)
        clear = os.path.join(HERE, "_clear.db")
        # 剥 1024 字节头
        with open(src, "rb") as f, open(clear, "wb") as out:
            f.seek(1024)
            while chunk := f.read(64 << 20):
                out.write(chunk)
        out_db = os.path.join(DST, fn.replace(".db", "_plain.db"))
        done = False
        for key in keys:
            con = None
            try:
                con = open_enc(clear, key)
                if os.path.exists(out_db):
                    os.remove(out_db)
                # 注意: sqlcipher 连接上的 VACUUM INTO 产物仍是同密钥加密库!
                # 明文导出必须 ATTACH 明文库(KEY='') + sqlcipher_export
                con.execute(f"ATTACH DATABASE '{out_db}' AS plain KEY '';")
                con.execute("SELECT sqlcipher_export('plain');")
                con.execute("DETACH plain;")
                con.close()
                print(f"[OK] {fn} (key={key[:8]}...)", flush=True)
                done = True
                break
            except Exception:
                if con:
                    try:
                        con.close()
                    except Exception:
                        pass
        if done:
            ok += 1
        else:
            print(f"[FAIL] {fn}", flush=True)
            bad += 1
    print(f"完成: {ok} 成功, {bad} 失败 -> {DST}", flush=True)


if __name__ == "__main__":
    main()
