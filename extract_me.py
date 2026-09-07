# -*- coding: utf-8 -*-
"""extract_me.py — 从解密后的微信库提取"本人消息"聚合摘要（不落原始聊天内容）。

统计维度：高频对话（按我发出条数）、发文小时分布（作息信号）、主题关键词频次、
消息类型分布、长文本样本（自我表达候选）。输出为 Markdown，仅含统计与短样本。

用法:
    python extract_me.py --decrypted local/decrypted --out _wx_digest.md \
        --keywords "工作|项目|会议|代码|考试"
"""
import argparse
import glob
import hashlib
import os
import re
import sqlite3
import time
import zlib
from collections import Counter


def try_zstd(b):
    try:
        import zstandard as zstd
        return zstd.ZstdDecompressor().decompress(b).decode("utf-8", "replace")
    except Exception:
        pass
    try:
        return zlib.decompress(b).decode("utf-8", "replace")
    except Exception:
        return None


def get_text(row, cols):
    d = dict(zip(cols, row))
    c = d.get("message_content")
    ct = d.get("WCDB_CT_message_content")
    if isinstance(c, bytes):
        if ct == 4:  # 微信 4.x: WCDB 压缩标记 4 = zstd
            t = try_zstd(c)
            if t is not None:
                return t
        try:
            return c.decode("utf-8", "replace")
        except Exception:
            return ""
    return c or ""


def main():
    ap = argparse.ArgumentParser(description="本人消息聚合摘要（不导出原文）")
    ap.add_argument("--decrypted", default="local/decrypted", help="wx4.py decrypt 的输出目录")
    ap.add_argument("--out", default="_wx_digest.md", help="输出 Markdown 路径")
    ap.add_argument("--keywords", default="工作|项目|会议|代码|文件|计划|考试|学习",
                    help="主题关键词正则（用 | 分隔）")
    ap.add_argument("--top", type=int, default=25, help="高频对话条数")
    ap.add_argument("--samples", type=int, default=60, help="长文本样本上限")
    args = ap.parse_args()

    kw_pat = re.compile("(" + args.keywords + ")")
    # 长文本候选: 稍长的、含表达性字眼的文本
    notable_pat = re.compile(r"(觉得|决定|想|目标|希望|选择|重要|原则|打算|计划)")

    chats = {}      # username -> stats
    kw_counter = Counter()
    hour_hist = Counter()
    notable = []
    type_counter = Counter()

    contact_db = os.path.join(args.decrypted, "contact", "contact.db")
    names = {}
    if os.path.exists(contact_db):
        con = sqlite3.connect(contact_db)
        try:
            for u, nick, remark in con.execute("SELECT username, nick_name, remark FROM contact"):
                names[u] = remark or nick or u
        except Exception as e:
            print("contact.db:", e)
        con.close()
    md5map = {hashlib.md5(u.encode()).hexdigest(): u for u in names}

    dbs = sorted(glob.glob(os.path.join(args.decrypted, "message", "message_*.db")))
    dbs = [p for p in dbs if not any(x in os.path.basename(p)
                                     for x in ("fts", "resource", "biz", "media"))]
    print("message dbs:", [os.path.basename(p) for p in dbs])

    for db in dbs:
        con = sqlite3.connect(db)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
        for t in tables:
            cols = [r[1] for r in con.execute(f"PRAGMA table_info([{t}])")]
            username = md5map.get(t[4:])  # 表名 = md5(对方wxid)
            sel = "local_type, create_time, message_content"
            sel += ", WCDB_CT_message_content" if "WCDB_CT_message_content" in cols else ""
            sender_col = "is_sender" if "is_sender" in cols else None
            if sender_col:
                sel += f", {sender_col}"
            try:
                rows = con.execute(f"SELECT {sel} FROM [{t}]").fetchall()
            except Exception as e:
                print(t, "ERR", e)
                continue
            st = chats.setdefault(username or f"unknown:{t}", {
                "total": 0, "mine": 0, "my_text": 0, "my_chars": 0,
                "first": None, "last": None, "nick": names.get(username, "")})
            colnames = [c.strip() for c in sel.split(",")]
            for r in rows:
                d = dict(zip(colnames, r))
                ts = d.get("create_time") or 0
                st["total"] += 1
                st["first"] = min(st["first"] or ts, ts) if ts else st["first"]
                st["last"] = max(st["last"] or ts, ts)
                mine = (d.get("is_sender") == 1) if sender_col else True
                if not mine:
                    continue
                st["mine"] += 1
                type_counter[d.get("local_type")] += 1
                hour_hist[time.localtime(ts).tm_hour if ts else 0] += 1
                if d.get("local_type") == 1:  # 1 = 纯文本
                    txt = get_text(r, colnames)
                    if not txt:
                        continue
                    st["my_text"] += 1
                    st["my_chars"] += len(txt)
                    for m in kw_pat.finditer(txt):
                        kw_counter[m.group(1)] += 1
                    if len(txt) >= 80 and notable_pat.search(txt) and len(notable) < args.samples:
                        notable.append((ts, (username or "?"), txt[:200]))
        con.close()

    lines = ["# 微信本人消息聚合摘要（自动生成）", ""]
    top = sorted(chats.items(), key=lambda kv: -kv[1]["mine"])[: args.top]
    lines.append("## 高频对话（按我发出条数）")
    for u, st in top:
        f = time.strftime("%Y-%m", time.localtime(st["first"])) if st["first"] else "?"
        l = time.strftime("%Y-%m-%d", time.localtime(st["last"])) if st["last"] else "?"
        lines.append(f"- {st['nick'] or u} | 我发 {st['mine']} 条"
                     f"(文本{st['my_text']}/{st['my_chars']}字) 共{st['total']} | {f}~{l}")
    lines.append("")
    lines.append("## 我的发文小时分布（作息信号）")
    peak = max(hour_hist.values()) if hour_hist else 1
    for h in range(24):
        c = hour_hist.get(h, 0)
        if c:
            lines.append(f"- {h:02d}:00 {'#' * min(60, c // max(1, peak // 50))} {c}")
    lines.append("")
    lines.append("## 主题关键词频次（我的文本消息）")
    for k, v in kw_counter.most_common(40):
        lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append(f"## 消息类型分布（我发出） {dict(type_counter.most_common(10))}")
    lines.append("")
    lines.append(f"## 长文本样本（自我表达候选，时间倒序前 {args.samples}）")
    for ts, u, txt in sorted(notable, reverse=True):
        lines.append(f"- [{time.strftime('%Y-%m-%d', time.localtime(ts))} → {names.get(u, u)[:12]}] {txt}")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("written:", args.out, len(lines), "lines")


if __name__ == "__main__":
    main()
