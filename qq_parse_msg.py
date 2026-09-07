# -*- coding: utf-8 -*-
"""qq_parse_msg.py — QQ NT nt_msg_plain.db 消息解析（40800 protobuf → 可读文本）

用法:
  python qq_parse_msg.py                          # c2c+group 全量导出 -> QQ_聊天记录.txt
  python qq_parse_msg.py --table group_msg_table --limit 20
  python qq_parse_msg.py --json out.json          # 结构化导出

原理: 40800 列为多层 protobuf 容器, 无 schema 递归解码后按字段号映射
字段表参考 miniyu157/qq-dump (chat_export/proto_maps.py)
"""
import argparse
import base64
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "decrypted_qq", "nt_msg_plain.db")
PROFILE_DB = os.path.join(HERE, "decrypted_qq", "profile_info_plain.db")

# ---------------- protobuf 原始解码 ----------------

def _read_varint(buf, i):
    r = 0
    shift = 0
    while True:
        b = buf[i]
        r |= (b & 0x7F) << shift
        i += 1
        if not b & 0x80:
            return r, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def looks_like_protobuf(buf):
    if not buf:
        return False
    try:
        i = 0
        fields = set()
        while i < len(buf):
            tag, i = _read_varint(buf, i)
            f, w = tag >> 3, tag & 7
            if f == 0 or f > 100000:
                return False
            if w == 0:
                _, i = _read_varint(buf, i)
            elif w == 1:
                i += 8
            elif w == 2:
                ln, i = _read_varint(buf, i)
                if ln < 0 or i + ln > len(buf):
                    return False
                i += ln
            elif w == 5:
                i += 4
            else:
                return False
            fields.add(f)
        return i == len(buf) and bool(fields)
    except (IndexError, ValueError):
        return False


def raw_decode(buf, depth=0):
    """无 schema 递归解码; 返回 dict {field: value|list}"""
    if depth > 12:
        return buf
    out = {}
    i = 0
    try:
        while i < len(buf):
            tag, i = _read_varint(buf, i)
            f, w = tag >> 3, tag & 7
            if w == 0:
                v, i = _read_varint(buf, i)
            elif w == 1:
                v = buf[i:i + 8]
                i += 8
            elif w == 2:
                ln, i = _read_varint(buf, i)
                v = buf[i:i + ln]
                i += ln
                sub = raw_decode(v, depth + 1) if looks_like_protobuf(v) else None
                if isinstance(sub, dict) and sub:
                    v = sub
                else:
                    try:
                        s = v.decode("utf-8")
                        if all(ch >= " " or ch in "\n\r\t" for ch in s):
                            v = s
                    except UnicodeDecodeError:
                        pass
            elif w == 5:
                v = buf[i:i + 4]
                i += 4
            else:
                raise ValueError
            if f in out:
                if not isinstance(out[f], list):
                    out[f] = [out[f]]
                out[f].append(v)
            else:
                out[f] = v
        return out
    except (IndexError, ValueError):
        return buf


def flatten(d, prefix=""):
    """{45101: 'a', 45101+1: [...]} -> key 唯一化的扁平 dict"""
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, list) and len(v) == 1:
            v = v[0]
        out[key] = v
    return out

# ---------------- 字段映射 (miniyu157/qq-dump proto_maps) ----------------

FIELD_NAMES = {
    45002: "msg_type", 45003: "msg_sub_type",
    45101: "text",
    45402: "file_name", 45405: "file_size",
    45923: "ptt_to_text",
    45411: "img_w", 45412: "img_h", 45418: "img_original",
    45424: "img_md5", 45802: "img_url_198", 45803: "img_url_720", 45804: "img_url_org",
    45829: "img_flash",
    45410: "video_dur", 45413: "video_w", 45414: "video_h",
    47404: "reply_time", 47413: "reply_summary", 47423: "reply_origin",
    47703: "recall_uid", 47713: "recall_suffix",
    47901: "ark_json",
    48157: "call_summary",
    48175: "feed_source", 48176: "feed_content", 48178: "feed_text", 48182: "feed_uin",
    48214: "gray_xml", 48274: "gray_text",
    48403: "redbag", 48412: "redbag_type", 48443: "redbag_title",
    47602: "qqface", 47611: "qqface_reaction", 52138: "bubble_face",
    52152: "location_text",
    48701: "markdown",
    80900: "market_face",
}

MSG_TYPE = {1: "文本", 2: "图片", 3: "文件", 4: "语音", 5: "视频", 6: "QQ表情",
            7: "引用", 8: "灰条提示", 9: "红包", 10: "卡片", 11: "商城表情",
            14: "Markdown", 17: "按钮", 21: "通话", 26: "空间动态", 27: "戳一戳",
            28: "位置共享", 44: "Bot"}

RENAME = {"msg_type": "45002", "text": "45101", "file_name": "45402",
          "gray_xml": "48214", "gray_text": "48274", "ark_json": "47901",
          "redbag_title": "48443", "qqface": "47602", "market_face": "80900",
          "reply_summary": "47413", "markdown": "48701", "call_summary": "48157"}

IGNORE_LEN5 = set("""40010 40020 40021 45001 45004 45005 45008 45102 45103 45104 45105 45106
45108 45109 45110 45111 45112 45403 45406 45407 45408 45409 45415 45416 45421 45422 45423
45501 45503 45504 45505 45507 45509 45510 45511 45512 45513 45514 45515 45516 45517 45518
45519 45526 45550 45554 45600 45601 45801 45805 45806 45807 45815 45816 45817 45818 45819
45820 45821 45822 45823 45824 45825 45826 45827 45828 45830 45851 45852 45853 45862 45863
45865 45903 45906 45907 45909 45911 45912 45922 45924 45925 45926 45954 47401 47402 47403
47411 47415 47416 47418 47419 47422 47424 47601 47603 47604 47605 47606 47607 47608 47609
47612 47613 47614 47615 47616 47617 47618 47619 47620 47621 47622 47702 47704 47705 47706
47710 47711 47712 47714 47715 47902 47904 48151 48152 48153 48154 48155 48156 48172 48173
48174 48179 48180 48181 48183 48189 48191 48192 48210 48211 48212 48213 48215 48216 48217
48218 48220 48271 48272 48273 48275 48401 48402 48404 48405 48406 48407 48408 48409 48410
48411 48417 48418 48419 48421 48441 48442 48444 48445 48446 48447 48448 48449 48450 48451
48452 48453 48454 48461 48702 48703 48704 48720 48721 48751 48752 49154 49155 52132 52133
52134 52137 52139 80810 80824 80901 80902 80903 80905 80907 80908 80909 80910 80913 80935
80941 80942 80970 80975 80977 80978 80980 80981 80983 80995""".split())

# ---------------- 渲染 ----------------

def to_str(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(v).decode()
    return str(v)


def walk_names(d):
    """dict key 数字 -> 可读名 (递归), 并丢弃 IGNORE 噪声字段"""
    if isinstance(d, list):
        return [walk_names(x) for x in d]
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        ks = str(k)
        if len(ks) == 5 and ks in IGNORE_LEN5:
            continue
        nk = FIELD_NAMES.get(k, ks)
        out[nk] = walk_names(v)
    return out


def _deep_texts(v, out):
    """递归收集嵌套结构里的所有可读字符串"""
    if isinstance(v, dict):
        for x in v.values():
            _deep_texts(x, out)
    elif isinstance(v, list):
        for x in v:
            _deep_texts(x, out)
    elif isinstance(v, bytes):
        try:
            out.append(v.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    elif isinstance(v, str):
        out.append(v)


def render_element(elem):
    """单个消息元素 -> 一行可读文本"""
    if not isinstance(elem, dict):
        return to_str(elem)
    t = elem.get("msg_type")
    t = MSG_TYPE.get(t, t) if isinstance(t, int) else t
    text = elem.get("text")
    if text:
        return to_str(text)
    if "reply_summary" in elem or "reply_origin" in elem:
        buf = []
        _deep_texts(elem.get("reply_summary") or elem.get("reply_origin"), buf)
        s = " ".join(x for x in buf if x)[:80]
        return f"[引用] {s}" if s else "[引用]"
    if "file_name" in elem:
        return f"[文件] {to_str(elem['file_name'])}"
    if "img_md5" in elem or "img_url_198" in elem:
        extra = to_str(elem.get("file_name", ""))
        return f"[图片]{(' ' + extra) if extra else ''}"
    if "ptt_to_text" in elem and elem["ptt_to_text"]:
        return f"[语音→文字] {to_str(elem['ptt_to_text'])}"
    if "qqface" in elem:
        return to_str(elem["qqface"])
    if "market_face" in elem:
        return to_str(elem["market_face"])
    if "bubble_face" in elem:
        return f"[表情] {to_str(elem['bubble_face'])}"
    if "redbag_title" in elem:
        return f"[红包] {to_str(elem['redbag_title'])}"
    if "ark_json" in elem:
        return "[卡片链接]"
    if "gray_text" in elem or "gray_xml" in elem:
        g = elem.get("gray_text") or elem.get("gray_xml") or ""
        g = to_str(g)
        # xml 里抠纯文本
        import re
        g = re.sub(r"<[^>]+>", "", g)
        return f"[提示] {g[:120]}"
    if "call_summary" in elem:
        return f"[通话] {to_str(elem['call_summary'])}"
    if "location_text" in elem:
        return f"[位置] {to_str(elem['location_text'])}"
    if "markdown" in elem:
        return f"[MD] {to_str(elem['markdown'])[:200]}"
    if "feed_text" in elem or "feed_source" in elem or "feed_content" in elem:
        return "[提示] " + to_str(elem.get("feed_text") or elem.get("feed_source") or elem.get("feed_content"))[:100]
    if "recall_uid" in elem or "recall_suffix" in elem:
        return "[撤回]"
    # 兜底: 递归抓嵌套结构里的中文串 (引用原文/未知类型等)
    buf = []
    for k, v in elem.items():
        if k == "msg_type":
            continue
        _deep_texts(v, buf)
    s = " ".join(x for x in buf if x and "{" not in x)[:200]
    return f"[{t or '消息'}] {s}" if s else f"[{t or '未知'}]"


def parse_40800(blob):
    """40800 列 bytes -> (元素渲染文本列表, 结构化 dict)"""
    d = raw_decode(blob)
    d = walk_names(d)
    texts = []
    # 容器可能是 {N: [元素...]} 或直接元素
    elems = []
    for v in d.values():
        if isinstance(v, list):
            elems.extend(x for x in v if isinstance(x, dict))
        elif isinstance(v, dict):
            elems.append(v)
    for e in elems:
        texts.append(render_element(e))
    return texts, d

# ---------------- 主流程 ----------------

def load_uid_map():
    m = {}
    if os.path.exists(PROFILE_DB):
        con = sqlite3.connect(PROFILE_DB)
        try:
            for uid, uin, nick in con.execute(
                    'SELECT [1000],[1002],[20002] FROM profile_info_v2'):
                if uid:
                    m[uid] = f"{nick}({uin})" if uin else (nick or uid)
        except sqlite3.Error:
            pass
        con.close()
    # 群成员名片 (uid -> QQ号@群昵称), 补充非好友
    gi = os.path.join(HERE, "decrypted_qq", "group_info_plain.db")
    if os.path.exists(gi):
        con = sqlite3.connect(gi)
        try:
            for uid, uin, nick in con.execute(
                    'SELECT [1000],[1002],[20002] FROM group_member3'):
                if uid and uid not in m and (nick or uin):
                    m[uid] = f"{nick or '群友'}({uin})" if uin else (nick or uid)
        except sqlite3.Error:
            pass
        con.close()
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--table", default=None, help="c2c_msg_table / group_msg_table, 默认两者")
    ap.add_argument("--out", default=None, help="输出 txt (默认 QQ_聊天记录_<table>.txt)")
    ap.add_argument("--json", default=None, help="结构化 JSON 输出路径")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-name", action="store_true", help="不映射昵称")
    a = ap.parse_args()

    uid_map = {} if a.no_name else load_uid_map()
    tables = [a.table] if a.table else ["c2c_msg_table", "group_msg_table"]
    con = sqlite3.connect(a.db)

    for table in tables:
        cols = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
        if "40800" not in cols:
            print(f"[skip] {table}: 无 40800 列")
            continue
        is_group = table.startswith("group")
        out_txt = a.out or os.path.join(HERE, "decrypted_qq", f"QQ_聊天记录_{table}.txt")
        out_json = a.json
        n = con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        print(f"[{table}] {n} 条 -> {out_txt}", flush=True)
        jf = open(out_json, "w", encoding="utf-8") if out_json else None
        tf = open(out_txt, "w", encoding="utf-8")
        done = 0
        cur = con.execute(f'SELECT [40050],[40020],[40021],{("[40033],") if is_group else ""}[40800] '
                          f'FROM "{table}" WHERE [40800] IS NOT NULL ORDER BY [40050]')
        blob_idx = 4 if is_group else 3
        for row in cur:
            ts, sender, peer = row[0], row[1], row[2]
            blob = row[blob_idx]
            try:
                texts, struct = parse_40800(blob)
            except Exception as e:
                texts, struct = [f"[解析失败 {e}]"], {}
            if not texts:
                continue
            tstr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "?"
            sname = uid_map.get(sender, sender or "[系统]")
            if is_group:
                head = f"[{tstr}] 群{row[2]} {sname}"
            else:
                head = f"[{tstr}] {sname}"
            line = head + ": " + " | ".join(t for t in texts if t)
            tf.write(line + "\n")
            if jf:
                jf.write(json.dumps({"time": tstr, "sender": sender,
                                     "sender_name": sname, "struct": struct},
                                    ensure_ascii=False, default=to_str) + "\n")
            done += 1
            if a.limit and done >= a.limit:
                break
        tf.close()
        if jf:
            jf.close()
        print(f"  导出 {done} 条", flush=True)
    con.close()


if __name__ == "__main__":
    main()
