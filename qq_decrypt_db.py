# -*- coding: utf-8 -*-
"""qq_decrypt_db.py — 用派生密钥解密指定 QQ 库
用法: python qq_decrypt_db.py <db文件名>
读取 qq_derived_keys/<db>.key 中的 hex 密钥 (AES-256, reserve=48)
"""
import os
import sys

from Crypto.Cipher import AES

HERE = r"."
SRC_DIR = r"<QQ_NT_DB>"
DST_DIR = os.path.join(HERE, "decrypted_qq")
RES = 48

db = sys.argv[1]
key_hex = open(os.path.join(HERE, "qq_derived_keys", db + ".key")).read().strip()
ENC = bytes.fromhex(key_hex)
src = os.path.join(SRC_DIR, db)
dst = os.path.join(DST_DIR, db.replace(".db", "_plain.db"))
os.makedirs(DST_DIR, exist_ok=True)

blob = open(src, "rb").read()
data = blob[1024:]
with open(dst, "wb") as f:
    f.write(b"SQLite format 3\x00")
    pages = [data[16:4096]] + [data[i:i + 4096] for i in range(4096, len(data), 4096)]
    for page in pages:
        iv = page[-RES:-RES + 16]
        f.write(AES.new(ENC, AES.MODE_CBC, iv).decrypt(page[:-RES]))
        f.write(page[-RES:])

import sqlite3
con = sqlite3.connect(dst)
ic = con.execute("PRAGMA integrity_check").fetchone()[0]
tabs = con.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
con.close()
print(f"{db}: integrity={ic} tables={tabs} size={os.path.getsize(dst):,}")
